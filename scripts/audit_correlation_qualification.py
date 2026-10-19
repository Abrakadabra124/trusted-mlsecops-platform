import copy
import dataclasses
import unittest

from mlsecops import audit_event, audit_export, audit_lineage, audit_retention, serving_context
from mlsecops.contracts import Rejected, canonical
from scripts import serving_core_qualification as core
from scripts.audit_export_qualification import encoded, records


def lineage():
    return audit_lineage.Lineage(
        source_revision="1" * 40,
        source_fingerprint="2" * 64,
        source_sha256="0" * 64,
        source_approval_sha256="3" * 64,
        dataset_sha256="4" * 64,
        lineage_sha256="5" * 64,
        run_sha256="6" * 64,
        evaluation_sha256="7" * 64,
    )


def trace(kind="release"):
    if kind == "release":
        return serving_context.ReleaseTrace(
            "8" * 64,
            "b" * 64,
            "c" * 64,
            lineage=lineage(),
            authorization_sha256="9" * 64,
            assurance_sha256="a" * 64,
            approval_sha256="d" * 64,
        )
    return serving_context.QualificationTrace(
        "8" * 64, "9" * 64, "b" * 64, "c" * 64, lineage=lineage()
    )


class CorrelationSchemaContracts(unittest.TestCase):
    def test_mutable_reference_cannot_hide_behind_deepcopy(self):
        class MutableReference:
            def __init__(self):
                self.value = "a" * 64
                self.copied = False

            def __deepcopy__(self, memo):
                self.copied = True
                return self.value

        reference = MutableReference()
        with self.assertRaisesRegex(Rejected, "audit_lineage_invalid"):
            audit_lineage.Lineage(**{**dataclasses.asdict(lineage()), "run_sha256": reference})
        self.assertFalse(reference.copied)

    def test_nested_lineage_is_frozen_bounded_and_not_printed(self):
        value = lineage()
        for name, private in dataclasses.asdict(value).items():
            self.assertNotIn(private, repr(value))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(value, name, "f" * len(private))
        self.assertEqual(audit_lineage.checked(dataclasses.asdict(value)), value)
        for name in dataclasses.asdict(value):
            for wrong in (None, True, "private@example.invalid", "A" * 64, "a" * 63, "a" * 65):
                fields = dataclasses.asdict(value)
                fields[name] = wrong
                with self.subTest(name=name, wrong=wrong), self.assertRaises(Rejected):
                    audit_lineage.checked(fields)
        for fields in ({}, {**dataclasses.asdict(value), "private_url": "secret"}, []):
            with self.assertRaises(Rejected):
                audit_lineage.checked(fields)

    def test_correlated_types_keep_authorities_distinct_and_generation_binding(self):
        for value in (trace(), trace("candidate")):
            self.assertEqual(value.schema_version, 2)
            self.assertFalse(value.release_ready)
            self.assertNotIn(value.lineage.source_revision, repr(value))
            self.assertIs(
                serving_context.bind(value, bundle_sha256="b" * 64, model_sha256="c" * 64), value
            )
            with self.assertRaises(Rejected):
                serving_context.bind(value, bundle_sha256="f" * 64, model_sha256="c" * 64)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                value.lineage = lineage()
            fields = dataclasses.asdict(value)
            fields["lineage"]["run_sha256"] = "f" * 64
            self.assertEqual(value.lineage.run_sha256, "6" * 64)
        self.assertFalse(hasattr(trace("candidate"), "approval_sha256"))
        self.assertFalse(hasattr(trace(), "permit_sha256"))

    def test_schema_two_rejects_missing_extra_mutable_or_wrong_authority_fields(self):
        for kind in ("release", "candidate"):
            original = dataclasses.asdict(trace(kind))
            variants = []
            for field in original:
                changed = copy.deepcopy(original)
                del changed[field]
                variants.append(changed)
            variants.extend(
                [
                    {**original, "schema_version": 3},
                    {**original, "schema_version": 1},
                    {**original, "schema_version": True},
                    {**original, "lineage": None},
                    {
                        **original,
                        "lineage": {**original["lineage"], "run_sha256": "not-a-reference"},
                    },
                    {**original, "private_features": [1, 2]},
                    {
                        **original,
                        "permit_sha256" if kind == "release" else "approval_sha256": "e" * 64,
                    },
                ]
            )
            for changed in variants:
                with self.subTest(kind=kind, changed=changed), self.assertRaises(Rejected):
                    audit_event.checked_context(changed)
            self.assertEqual(audit_event.checked_context(original), original)
        for value in (trace(), trace("candidate")):
            fields = {
                field.name: getattr(value, field.name)
                for field in dataclasses.fields(value)
                if field.init
            }
            fields["lineage"] = dataclasses.asdict(lineage())
            with self.assertRaises(Rejected):
                type(value)(**fields)

    def test_maximum_correlated_jsonl_record_preserves_existing_admission_limit(self):
        sizes = []
        for context in (trace(), trace("candidate")):
            for record in records(bound=dataclasses.asdict(context)):
                record.update(sequence=2**63 - 1, recorded_at_ns=2**63 - 1)
                self.assertEqual(audit_event.checked(record["event"]), record["event"])
                content = canonical(record) + b"\n"
                sizes.append(len(content))
                self.assertLessEqual(len(content), audit_retention.MAX_RECORD)
        self.assertEqual(audit_retention.MAX_RECORD, 2048)
        self.assertGreater(max(sizes), 1000)

    def test_legacy_read_survives_but_public_export_never_contains_new_private_fields(self):
        for context in (
            serving_context.ReleaseContext("8" * 64, "b" * 64, "c" * 64),
            trace(),
            trace("candidate"),
        ):
            source = encoded(records(bound=dataclasses.asdict(context)))
            public = audit_export.project([source])
            self.assertEqual(public["requests"]["completed"], 1)
            self.assertFalse(public["release_ready"])
            if context.schema_version == 2:
                for private in dataclasses.asdict(context.lineage).values():
                    self.assertIn(private.encode(), source)
                    self.assertNotIn(private.encode(), canonical(public))

    def test_lineage_replacement_inside_one_request_is_rejected(self):
        values = records(bound=dataclasses.asdict(trace()))
        values[2]["event"]["context"]["lineage"]["run_sha256"] = "f" * 64
        with self.assertRaises(Rejected):
            audit_export.project([encoded(values)])

    def test_engine_uses_loaded_generation_snapshot_and_keeps_lineage_off_public_payload(self):
        fixture = core.ServingCoreContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        context = dataclasses.replace(
            trace(),
            bundle_sha256=fixture.loaded.subject_sha256,
            model_sha256=fixture.loaded.model_sha256,
        )
        fixture.loaded.audit_context = context
        fixture.engine.activate()
        fixture.loaded.audit_context = dataclasses.replace(
            context, lineage=dataclasses.replace(lineage(), run_sha256="f" * 64)
        )
        result = fixture.engine.predict_result([[0.5] * 6])
        self.assertIs(result.audit_context, context)
        for private in dataclasses.asdict(lineage()).values():
            self.assertNotIn(private.encode(), canonical(result.payload))


if __name__ == "__main__":
    unittest.main()
