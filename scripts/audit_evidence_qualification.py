import base64
import copy
import unittest
from dataclasses import asdict
from unittest.mock import patch

from mlsecops import audit_evidence, audit_export, serving_context
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts.audit_correlation_qualification import lineage
from scripts.audit_export_qualification import encoded, records
from scripts.audit_snapshot_qualification import metadata


def expected():
    return asdict(serving_context.QualificationTrace(*["a" * 64] * 4, lineage=lineage()))


def binding():
    return {
        "campaign_id": "b" * 32,
        "source": {
            "source_revision": "1" * 40,
            "source_fingerprint": "2" * 64,
            "image_id": "sha256:" + "3" * 64,
        },
    }


def fixture():
    chunks = [encoded(records(bound=expected()))]
    manifest = metadata()
    manifest["policy"]["segment_bytes"] = 8192
    manifest["clock"]["mono"] = 104
    manifest["sequence"] = 4
    manifest["segments"][0].update(
        size=len(chunks[0]), first=100, last=103, sha256=digest(chunks[0])
    )
    public = canonical(audit_export.project(chunks)) + b"\n"
    outcomes = [
        {
            "exchange": 1,
            "request_id": "1" * 32,
            "route": "predict",
            "status": 200,
            "admitted": True,
        },
        {
            "exchange": 2,
            "request_id": "4" * 32,
            "route": "predict",
            "status": 401,
            "admitted": False,
        },
    ]
    return canonical(manifest), chunks, outcomes, public


def packet():
    return audit_evidence.create(*fixture(), binding=binding())


def check(content, **changes):
    return audit_evidence.verify(
        content, **{"binding": binding(), "expected_context": expected(), **changes}
    )


class AuditEvidenceContracts(unittest.TestCase):
    def test_primary_bytes_recompute_correlated_journal_public_export_and_http_outcomes(self):
        content = packet()
        result = check(content)
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["scope"], "private-primary-audit-packet-not-full-M13")
        self.assertEqual(result["packet_sha256"], digest(content))
        self.assertEqual(result["observed_responses"], 2)
        self.assertEqual(result["correlation"]["events"], 4)
        self.assertEqual(result["public"]["requests"]["completed"], 1)
        self.assertNotIn("http_outcomes", result)
        self.assertNotIn("segments", result)

    def test_wrong_campaign_source_context_and_digest_do_not_pass(self):
        for replacement in (
            {},
            {**binding(), "campaign_id": "c" * 32},
            {**binding(), "source": {**binding()["source"], "source_revision": "f" * 40}},
        ):
            with self.assertRaises(Rejected):
                check(packet(), binding=replacement)
        with self.assertRaises(Rejected):
            check(packet(), expected_context={**expected(), "model_sha256": "f" * 64})
        value = decode(packet())
        value["segments"][0] = base64.b64encode(b"tampered").decode()
        with self.assertRaises(Rejected):
            check(canonical(value))

    def test_manifest_byte_digest_sequence_and_schema_are_enforced(self):
        original, chunks, outcomes, public = fixture()
        for field, replacement in (
            ("sequence", 5),
            ("segments", []),
            ("schema_version", True),
        ):
            manifest = decode(original)
            manifest[field] = replacement
            with self.subTest(field=field), self.assertRaises(Rejected):
                check(
                    audit_evidence.create(
                        canonical(manifest), chunks, outcomes, public, binding=binding()
                    )
                )
        for field, replacement in (("size", 1), ("sha256", "f" * 64)):
            manifest = decode(original)
            manifest["segments"][0][field] = replacement
            with self.assertRaises(Rejected):
                check(
                    audit_evidence.create(
                        canonical(manifest), chunks, outcomes, public, binding=binding()
                    )
                )

    def test_invalid_primary_byte_type_source_shape_and_context_binding_reject(self):
        manifest, chunks, outcomes, public = fixture()
        with self.assertRaises(Rejected):
            audit_evidence.create("not-bytes", chunks, outcomes, public, binding=binding())
        for field in binding()["source"]:
            replacement = {**binding(), "source": {**binding()["source"], field: "invalid"}}
            content = audit_evidence.create(manifest, chunks, outcomes, public, binding=replacement)
            with self.assertRaises(Rejected):
                check(content, binding=replacement)
        context = expected()
        context["lineage"]["source_revision"] = "f" * 40
        with self.assertRaises(Rejected):
            check(packet(), expected_context=context)

    def test_unknown_fields_schema_types_and_noncanonical_encoding_reject(self):
        for field, replacement in (
            ("extra", "PRIVATE"),
            ("schema_version", True),
            ("release_ready", True),
            ("binding", {}),
            ("segments", []),
            ("segments", {}),
            ("manifest", "!!!!"),
            ("manifest", None),
            ("manifest", " YQ=="),
            ("public_export", "YR=="),
            ("http_outcomes", {}),
        ):
            value = decode(packet())
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(Rejected):
                check(canonical(value))
        for content in (b"null", b'{"x":1,"x":2}', b" " + packet(), "not-bytes"):
            with self.assertRaises(Rejected):
                check(content)
        with patch.object(audit_evidence, "MAX_PACKET", 10), self.assertRaises(Rejected):
            check(packet())

    def test_duplicate_missing_or_mismatched_http_outcomes_reject(self):
        original = decode(packet())
        variants = [
            [],
            original["http_outcomes"][1:],
            original["http_outcomes"] * 2,
            [{**original["http_outcomes"][0], "status": 503}],
            [{**original["http_outcomes"][0], "route": "ready"}],
            [
                *original["http_outcomes"],
                {
                    "exchange": 3,
                    "request_id": "5" * 32,
                    "route": "ready",
                    "status": 200,
                    "admitted": False,
                },
            ],
            [
                *original["http_outcomes"],
                {
                    "exchange": 3,
                    "request_id": "5" * 32,
                    "route": "predict",
                    "status": 422,
                    "admitted": False,
                },
            ],
        ]
        for outcomes in variants:
            value = copy.deepcopy(original)
            value["http_outcomes"] = outcomes
            with self.subTest(outcomes=outcomes), self.assertRaises(Rejected):
                check(canonical(value))

    def test_http_ledger_cannot_store_private_input_or_unsafe_values(self):
        for field, replacement in (
            ("request_id", "private-query"),
            ("route", "/v1/predict?secret=private"),
            ("status", True),
            ("status", 600),
            ("admitted", 1),
            ("exchange", True),
            ("raw_features", {"private": 1}),
        ):
            value = decode(packet())
            value["http_outcomes"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(Rejected):
                check(canonical(value))

    def test_unknown_404_exchanges_have_no_fabricated_response_identifier(self):
        value = decode(packet())
        value["http_outcomes"].extend(
            {
                "exchange": number,
                "request_id": None,
                "route": "other",
                "status": 404,
                "admitted": False,
            }
            for number in (3, 4)
        )
        self.assertEqual(check(canonical(value))["observed_responses"], 4)
        for field, replacement in (("request_id", "f" * 32), ("status", 503), ("admitted", True)):
            changed = copy.deepcopy(value)
            changed["http_outcomes"][-1][field] = replacement
            with self.assertRaises(Rejected):
                check(canonical(changed))

    def test_admitted_429_503_cannot_disappear_as_pre_admission_errors(self):
        for status in (429, 503):
            value = decode(packet())
            value["http_outcomes"].append(
                {
                    "exchange": 3,
                    "request_id": "5" * 32,
                    "route": "predict",
                    "status": status,
                    "admitted": True,
                }
            )
            with self.assertRaises(Rejected):
                check(canonical(value))
            value["http_outcomes"][-1]["admitted"] = False
            self.assertEqual(check(canonical(value))["observed_responses"], 3)

    def test_substituted_public_export_and_forged_agreeing_summaries_reject(self):
        value = decode(packet())
        changed = decode(base64.b64decode(value["public_export"]))
        changed["events"] = 8
        value["public_export"] = base64.b64encode(canonical(changed) + b"\n").decode()
        with self.assertRaises(Rejected):
            check(canonical(value))
        value = decode(packet())
        value["public_export"] = base64.b64encode(
            base64.b64decode(value["public_export"]) + b" "
        ).decode()
        with self.assertRaises(Rejected):
            check(canonical(value))

    def test_rehashed_journal_tampering_still_rejects_against_expected_context_and_http(self):
        original, chunks, outcomes, public = fixture()
        for mutation in ("context", "status", "incomplete"):
            entries = [decode(line) for line in chunks[0].splitlines()]
            if mutation == "context":
                for entry in entries[1:]:
                    entry["event"]["context"]["model_sha256"] = "f" * 64
            elif mutation == "status":
                for entry in entries[1:]:
                    entry["event"].update(status=422, context=None)
            else:
                entries.pop()
            altered = encoded(entries)
            manifest = decode(original)
            manifest["sequence"] = len(entries)
            manifest["segments"][0].update(size=len(altered), sha256=digest(altered))
            rebuilt = canonical(audit_export.project([altered])) + b"\n"
            with self.subTest(mutation=mutation), self.assertRaises(Rejected):
                check(
                    audit_evidence.create(
                        canonical(manifest), [altered], outcomes, rebuilt, binding=binding()
                    )
                )


if __name__ == "__main__":
    unittest.main()
