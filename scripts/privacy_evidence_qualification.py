import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import acceptance, privacy_evidence
from mlsecops.contracts import Rejected, canonical, digest, write_json
from scripts.serving_output_qualification import expected, report

START = "2026-10-20T12:00:00+00:00"
END = "2026-10-20T12:05:00+00:00"
SUBJECT = dict.fromkeys(
    (
        "proposal_reference",
        "subject_sha256",
        "model_sha256",
        "candidate_reference",
        "evaluation_reference",
    ),
    "e" * 64,
)
CASES = (
    "original-signed-proposal-bound",
    "actual-release-remains-denied-without-assurance",
    "qualification-permit-is-not-release-approval",
    "source-candidate-loaded-without-resigning",
    "http-missing-auth-401",
    "independent-client-burst-boundary",
    "client-quota-refill-recovers",
    "client-admission-accounting",
    "primary-client-remains-available",
    "foreign-client-identity-401",
    "audit-http-pair-accepted",
    "audit-http-pair-durable",
    "privacy-http-input-and-output-matrix",
    "privacy-owned-audit-input-absent",
    "privacy-native-telemetry-disabled",
    "privacy-approved-metrics-cardinality",
    "closed-audit-private-primary-material-correlation",
    "closed-audit-public-export-schema-counters-and-canaries",
    "closed-audit-export-not-release-approval",
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged",
    "full-lifecycle-output-privacy",
)


def fixture():
    value = report()
    value.update(
        started_at="2026-10-20T12:01:00+00:00",
        finished_at="2026-10-20T12:02:00+00:00",
        cases=list(CASES),
    )
    value["runtime"] = {
        "client_quota": {
            "status": "pass",
            "release_ready": False,
            "boundary_statuses": [422, 429, 422, 429],
            "refill_statuses": [200, 200],
            "admitted_deltas": [2, 2, 4],
            "window_seconds": 0.1,
        },
        "http_audit": {
            "scope": "actual-candidate-http-audit-pair-not-full-M13",
            "status": "pass",
            "release_ready": False,
            "accepted_delta": 8,
            "durable_delta": 8,
        },
        "http_privacy": {
            "scope": "existing-serving-output-privacy-not-full-M13",
            "status": "pass",
            "release_ready": False,
            "request_cases": 12,
            "audit_events_confirmed": 36,
            "audit_files_scanned": 3,
            "approved_metric_series": 69,
            "ambient_signals_used": False,
        },
        "http_correlation": {
            "schema_version": 1,
            "scope": "candidate-qualification-private-correlation-not-full-M13",
            "status": "pass",
            "release_ready": False,
            "events": 336,
            "correlated_requests": 58,
            "completed_200": 58,
            "without_context": 26,
            "failed_after_intent": 0,
        },
        "public_audit_window": {
            "schema_version": 1,
            "scope": "serving-audit-public-window-not-full-M13",
            "status": "pass",
            "release_ready": False,
            "events": 336,
            "requests": {"aborted": 0, "completed": 84, "unresolved": 0},
            "routes": {"predict": 79, "ready": 5},
            "context_kinds": {
                "candidate-qualification": 58,
                "none": 26,
                "release-selection": 0,
            },
        },
        "output_privacy": {
            "schema_version": 1,
            "scope": "serving-lifecycle-output-privacy-not-full-M13",
            "status": "pass",
            "release_ready": False,
            "canary_count": 6,
            "fd_lifecycle_complete": True,
            "native_stderr_bytes": 0,
            "stdout_characters": 10,
            "stderr_characters": 0,
        },
    }
    return value


def check(value, **changes):
    arguments = {
        "expected_source": expected(),
        "expected_subject": SUBJECT,
        "started_at": START,
        "observed_at": END,
    }
    return privacy_evidence.checked_candidate(canonical(value), **{**arguments, **changes})


class PrivacyEvidenceContracts(unittest.TestCase):
    def test_private_verifier_summary_does_not_return_report_or_claim_full_M13(self):
        value = fixture()
        result = check(value)
        self.assertEqual(result["scope"], "checked-candidate-privacy-evidence-not-full-M13")
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["receipt_sha256"], digest(canonical(value)))
        self.assertEqual(result["request_count"], 84)
        self.assertEqual(result["correlated_requests"], 58)
        self.assertEqual(result["events"], 336)
        for field in ("campaign_id", "model_sha256", "qualification_permit_sha256", "limitations"):
            self.assertNotIn(field, result)
        value["runtime"].clear()
        self.assertEqual(result["request_count"], 84)

    def test_format_checks_do_not_enable_incomplete_acceptance_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "policies/local-cpu.json", {"environment": "local-cpu"})
            with (
                patch.object(acceptance, "command", return_value="b" * 40),
                patch.object(acceptance, "source_fingerprint", return_value="c" * 64),
            ):
                result = acceptance.report("M13", "local-cpu", root)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["cases"], [])

    def test_wrong_source_subject_status_or_legacy_schema_rejected(self):
        for field, replacement in (
            ("source", {}),
            ("source_dirty", True),
            ("status", "inconclusive"),
            ("release_ready", True),
            ("schema_version", True),
            ("scope", "release-approved"),
            ("campaign_id", "not-a-campaign"),
            ("qualification_permit_sha256", None),
            ("reference_response_sha256", "wrong"),
            *((name, "f" * 64) for name in SUBJECT),
        ):
            value = fixture()
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(Rejected):
                check(value)
        for source in ({}, {**expected(), "source_revision": "z" * 40}):
            with self.assertRaises(Rejected):
                check(fixture(), expected_source=source)
        for image in (None, "mutable:tag", "sha256:wrong"):
            with self.assertRaises(Rejected):
                check(fixture(), expected_source={**expected(), "image_id": image})
        with self.assertRaises(Rejected):
            check(fixture(), expected_subject={})

    def test_freshness_rejects_replay_future_naive_and_reversed_intervals(self):
        for start, finish in (
            ("2026-10-20T11:59:59+00:00", "2026-10-20T12:02:00+00:00"),
            ("2026-10-20T12:01:00+00:00", "2026-10-20T12:05:01+00:00"),
            ("2026-10-20T12:01:00", "2026-10-20T12:02:00+00:00"),
            ("2026-10-20T12:03:00+00:00", "2026-10-20T12:02:00+00:00"),
            (None, "2026-10-20T12:02:00+00:00"),
            ("not-time", "2026-10-20T12:02:00+00:00"),
        ):
            value = fixture()
            value.update(started_at=start, finished_at=finish)
            with self.subTest(start=start, finish=finish), self.assertRaises(Rejected):
                check(value)
        for arguments in ({"started_at": END, "observed_at": START}, {"observed_at": None}):
            with self.assertRaises(Rejected):
                check(fixture(), **arguments)

    def test_each_mandatory_case_duplicate_and_malformed_case_rejected(self):
        for name in CASES:
            value = fixture()
            value["cases"].remove(name)
            with self.subTest(name=name), self.assertRaises(Rejected):
                check(value)
        for cases in ([], list(CASES) + [CASES[0]], list(CASES) + [1], "pass"):
            value = fixture()
            value["cases"] = cases
            with self.assertRaises(Rejected):
                check(value)

    def test_existing_native_mixed_case_ids_are_accepted_without_normalization(self):
        value = fixture()
        value["cases"].extend(["http-ready-after-actual-ONNX-load", "http-golden-CPU-consistency"])
        self.assertEqual(check(value)["status"], "pass")
        value["cases"].remove("original-signed-proposal-bound")
        value["cases"].append("Original-signed-proposal-bound")
        with self.assertRaises(Rejected):
            check(value)

    def test_limitations_must_be_a_bounded_nonempty_list_of_strings(self):
        for replacement in (None, 0, {}, [True], [], [""], ["x" * 4097], ["x"] * 65):
            value = fixture()
            value["limitations"] = replacement
            with self.subTest(replacement=type(replacement)), self.assertRaises(Rejected):
                check(value)

    def test_large_json_integers_are_rejected_without_overflow(self):
        for elapsed in (10**400, -(10**400)):
            value = fixture()
            value["runtime"]["client_quota"]["window_seconds"] = elapsed
            with self.assertRaises(Rejected):
                check(value)

    def test_consistent_totals_cannot_contradict_disjoint_required_phases(self):
        for completed, correlated, ready in ((84, 84, 5), (84, 58, 0), (12, 1, 2), (15, 6, 2)):
            value = fixture()
            value["runtime"]["http_correlation"].update(
                events=4 * completed,
                correlated_requests=correlated,
                completed_200=correlated,
                without_context=completed - correlated,
            )
            value["runtime"]["public_audit_window"].update(
                events=4 * completed,
                requests={"completed": completed, "aborted": 0, "unresolved": 0},
                routes={"predict": completed - ready, "ready": ready},
                context_kinds={
                    "candidate-qualification": correlated,
                    "none": completed - correlated,
                    "release-selection": 0,
                },
            )
            with (
                self.subTest(completed=completed, correlated=correlated),
                self.assertRaises(Rejected),
            ):
                check(value)

    def test_missing_or_inconclusive_required_component_rejected(self):
        for name in fixture()["runtime"]:
            for remove in (True, False):
                value = fixture()
                if remove:
                    del value["runtime"][name]
                else:
                    value["runtime"][name]["status"] = "inconclusive"
                with self.subTest(name=name, remove=remove), self.assertRaises(Rejected):
                    check(value)

    def test_false_privacy_observations_and_quota_outcomes_rejected(self):
        for section, field, replacement in (
            ("http_audit", "durable_delta", 7),
            ("http_privacy", "ambient_signals_used", True),
            ("http_privacy", "approved_metric_series", 70),
            ("http_privacy", "request_cases", True),
            ("http_privacy", "audit_files_scanned", 0),
            ("output_privacy", "fd_lifecycle_complete", False),
            ("output_privacy", "native_stderr_bytes", 1),
            ("output_privacy", "canary_count", 5),
            ("output_privacy", "stdout_characters", 65537),
            ("client_quota", "boundary_statuses", [200, 200, 200, 200]),
            ("client_quota", "admitted_deltas", [2, 2, True]),
            ("client_quota", "window_seconds", 1),
            ("client_quota", "window_seconds", True),
        ):
            value = fixture()
            value["runtime"][section][field] = replacement
            with self.subTest(section=section, field=field), self.assertRaises(Rejected):
                check(value)

    def test_private_public_counter_mismatch_empty_context_and_unresolved_requests_rejected(self):
        for section, path, replacement in (
            ("http_correlation", ("events",), 332),
            ("http_correlation", ("correlated_requests",), 0),
            ("http_correlation", ("completed_200",), 57),
            ("http_correlation", ("without_context",), 25),
            ("http_correlation", ("failed_after_intent",), 1),
            ("public_audit_window", ("events",), True),
            ("public_audit_window", ("requests", "unresolved"), 1),
            ("public_audit_window", ("requests", "aborted"), 1),
            ("public_audit_window", ("requests", "completed"), 83),
            ("public_audit_window", ("routes", "predict"), 78),
            ("public_audit_window", ("context_kinds", "candidate-qualification"), 57),
            ("public_audit_window", ("context_kinds", "release-selection"), 1),
        ):
            value = fixture()
            target = value["runtime"][section]
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = replacement
            with self.subTest(section=section, path=path), self.assertRaises(Rejected):
                check(value)

    def test_self_consistent_counters_cannot_claim_fewer_requests_than_privacy_matrix(self):
        value = fixture()
        value["runtime"]["http_correlation"].update(
            events=4, correlated_requests=1, completed_200=1, without_context=0
        )
        value["runtime"]["public_audit_window"].update(
            events=4,
            requests={"completed": 1, "aborted": 0, "unresolved": 0},
            routes={"predict": 1, "ready": 0},
            context_kinds={"candidate-qualification": 1, "none": 0, "release-selection": 0},
        )
        with self.assertRaises(Rejected):
            check(value)

    def test_nested_unapproved_public_export_fields_and_raw_document_faults_rejected(self):
        for section in (
            "http_privacy",
            "http_correlation",
            "public_audit_window",
            "output_privacy",
        ):
            value = fixture()
            value["runtime"][section]["private_url"] = "postgresql://synthetic.invalid/private"
            with self.subTest(section=section), self.assertRaises(Rejected):
                check(value)
        arguments = {
            "expected_source": expected(),
            "expected_subject": copy.deepcopy(SUBJECT),
            "started_at": START,
            "observed_at": END,
        }
        for content in (b"{}", b'{"a":1,"a":2}', b"null", b"x" * (1024 * 1024 + 1)):
            with self.assertRaises(Rejected):
                privacy_evidence.checked_candidate(content, **arguments)
        with self.assertRaisesRegex(Rejected, "privacy_evidence_bytes"):
            privacy_evidence.checked_candidate("not-bytes", **arguments)


if __name__ == "__main__":
    unittest.main()
