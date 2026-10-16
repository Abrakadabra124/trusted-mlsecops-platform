import dataclasses
import unittest

from mlsecops import serving_context
from mlsecops.contracts import Rejected, canonical, digest
from scripts import serving_core_qualification


class ContextContracts(unittest.TestCase):
    def test_scopes_are_disjoint_frozen_and_have_no_approval_claim(self):
        release = serving_context.ReleaseContext("a" * 64, "b" * 64, "c" * 64)
        candidate = serving_context.QualificationContext("d" * 64, "e" * 64, "b" * 64, "c" * 64)
        self.assertEqual(release.kind, "release-selection")
        self.assertEqual(candidate.kind, "candidate-qualification")
        for context in (release, candidate):
            self.assertEqual(context.schema_version, 1)
            self.assertFalse(context.release_ready)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                context.model_sha256 = "f" * 64
            self.assertNotIn("b" * 64, repr(context))
        self.assertFalse(hasattr(candidate, "selection_sha256"))
        self.assertFalse(hasattr(release, "permit_sha256"))
        projection = dataclasses.asdict(candidate)
        projection["model_sha256"] = "f" * 64
        self.assertEqual(candidate.model_sha256, "c" * 64)

    def test_each_reference_rejects_noncanonical_or_mutable_values(self):
        for constructor, count in (
            (serving_context.ReleaseContext, 3),
            (serving_context.QualificationContext, 4),
        ):
            for position in range(count):
                for invalid in (None, True, {}, [], b"a" * 64, "A" * 64, "a" * 63, "a" * 65):
                    values = ["a" * 64] * count
                    values[position] = invalid
                    with self.subTest(constructor=constructor.__name__, position=position):
                        with self.assertRaisesRegex(Rejected, "serving_context_invalid"):
                            constructor(*values)

    def test_binding_rejects_unknown_type_and_either_identity_mismatch(self):
        context = serving_context.ReleaseContext("a" * 64, "b" * 64, "c" * 64)
        self.assertIs(
            serving_context.bind(context, bundle_sha256="b" * 64, model_sha256="c" * 64), context
        )
        for value, bundle, model in (
            (None, "b" * 64, "c" * 64),
            (dataclasses.asdict(context), "b" * 64, "c" * 64),
            (context, "f" * 64, "c" * 64),
            (context, "b" * 64, "f" * 64),
        ):
            with self.assertRaisesRegex(Rejected, "serving_context_binding"):
                serving_context.bind(value, bundle_sha256=bundle, model_sha256=model)


class ContextEngineContracts(unittest.TestCase):
    def setUp(self):
        fixture = serving_core_qualification.ServingCoreContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.engine, self.loaded, self.reader = fixture.engine, fixture.loaded, fixture.reader
        self.loaded.audit_context = serving_context.QualificationContext(
            "d" * 64, "e" * 64, self.loaded.subject_sha256, self.loaded.model_sha256
        )

    def test_snapshot_survives_reader_change_and_never_enters_public_payload(self):
        self.engine.activate()
        context = self.loaded.audit_context
        generation = self.engine.generation
        self.loaded.audit_context = serving_context.ReleaseContext(
            "f" * 64, self.loaded.subject_sha256, self.loaded.model_sha256
        )
        self.reader.reference = "0" * 64
        for result in (self.engine.check_result(), self.engine.predict_result([[0.5] * 6])):
            self.assertIs(result.audit_context, context)
            self.assertIs(result.generation, generation)
            self.assertNotIn("d" * 64, canonical(result.payload).decode())
            self.assertNotIn("e" * 64, canonical(result.payload).decode())
            self.assertNotIn("audit_context", result.payload)
        self.assertEqual(self.engine.check(), self.engine.check_result().payload)
        self.assertEqual(
            self.engine.predict([[0.5] * 6]), self.engine.predict_result([[0.5] * 6]).payload
        )

    def test_unverified_or_mismatched_context_prevents_activation(self):
        for context in (
            None,
            {"selection_sha256": "d" * 64},
            serving_context.ReleaseContext("d" * 64, "a" * 64, "f" * 64),
        ):
            self.loaded.audit_context = context
            with self.assertRaisesRegex(Rejected, "serving_activation_rejected"):
                self.engine.activate()
            self.assertIsNone(self.engine.loaded)
            self.assertIsNone(self.engine.audit_context)
            self.assertTrue(self.engine.generation.is_set())

    def test_failed_recheck_does_not_return_or_retain_success_context(self):
        for operation in (
            self.engine.check_result,
            lambda: self.engine.predict_result([[0.5] * 6]),
        ):
            self.reader.check.side_effect = None
            self.engine.activate()
            self.reader.check.side_effect = Rejected("PRIVATE-CANARY")
            with self.assertRaises(Rejected):
                operation()
            self.assertIsNone(self.engine.audit_context)
            self.assertTrue(self.engine.generation.is_set())

    def test_completed_snapshot_stays_bound_to_old_generation_not_new_activation(self):
        self.engine.activate()
        previous = self.engine.check_result()
        self.loaded.audit_context = serving_context.ReleaseContext(
            "f" * 64, self.loaded.subject_sha256, digest(self.loaded.model)
        )
        self.engine.activate()
        current = self.engine.check_result()
        self.assertNotEqual(previous.audit_context.kind, current.audit_context.kind)
        self.assertTrue(previous.generation.is_set())
        self.assertFalse(current.generation.is_set())
        for operation in (
            self.engine.check_result,
            lambda **kw: self.engine.predict_result([[0.5] * 6], **kw),
        ):
            with self.assertRaisesRegex(Rejected, "serving_generation_changed"):
                operation(generation=previous.generation)
        self.assertFalse(current.generation.is_set())


if __name__ == "__main__":
    unittest.main()
