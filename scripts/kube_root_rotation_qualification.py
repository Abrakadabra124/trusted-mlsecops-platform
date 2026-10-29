"""Real signatures with controlled authority transport for the native coordinator."""

import copy
import unittest
from unittest.mock import patch

from mlsecops import signing, trust_rotation
from mlsecops.contracts import Rejected, canonical, digest
from scripts import kube_root_rotation as native
from scripts import trust_rotation_qualification as fixtures


class NativeRootRotation(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RotationContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.fixture.payload.update(
            revoked_artifacts=[native.ARTIFACT],
            revoked_keys=[native.KEY],
        )
        self.previous = self.fixture.fixture.envelope()
        self.metadata = {
            "environment": "local-cpu",
            "root_public": self.fixture.old_public,
            "version": 1,
            "sha256": digest(canonical(self.previous)),
            "envelope": self.previous,
            "clock": self.fixture.clock,
        }
        self.selected = False
        self.mutated = False
        self.fault = None
        self.package = native.prepare(self.metadata, self.fixture.old_key, self.fixture.new_key)
        self.intent = signing.verify(
            self.package["authorization"], trust_rotation.KIND, self.fixture.old_public
        )
        self.receipt = {
            "state": "rotated-not-activated",
            "version": 2,
            "document_sha256": self.intent["next_sha256"],
            "rotation_sha256": digest(canonical(self.package)),
            "root_sha256": trust_rotation.key_id(self.fixture.new_public),
            "reused": False,
            "release_ready": False,
        }
        self.enterContext(
            patch.object(native.trust_authority, "current", return_value=("owned", self.metadata))
        )
        self.enterContext(patch.object(native.trust_authority, "update", side_effect=self.update))
        self.migrate = self.enterContext(
            patch.object(
                native.trust_root_store,
                "migrate",
                side_effect=[{"reused": False}, {"reused": True}],
            )
        )
        self.enterContext(patch.object(native.trust_root_store, "rotate", side_effect=self.rotate))
        self.real_snapshot = native.snapshot
        self.enterContext(
            patch.object(native, "snapshot", side_effect=lambda state: self.snapshot())
        )
        self.models = self.enterContext(
            patch.object(native, "model_snapshot", side_effect=lambda state: {"unchanged": True})
        )

    def update(self, *args, **kwargs):
        if self.selected:
            raise Rejected("untrusted_key")

    def snapshot(self):
        prior = self.fixture.fixture.payload
        result = {
            "authority": {
                "identity": {
                    "root_sha256": trust_rotation.key_id(self.fixture.old_public),
                    "volume": "fixed",
                },
                "version": 1,
                "policy_sha256": prior["promotion_policy_sha256"],
                "revoked_artifacts": prior["revoked_artifacts"],
                "revoked_keys": prior["revoked_keys"],
            },
            "records": {
                "migrations": ["v1", "v2"],
                "documents": [[1, self.metadata["sha256"]]],
                "rotations": [],
            },
        }
        if self.selected:
            result["authority"]["identity"]["root_sha256"] = self.receipt["root_sha256"]
            result["authority"]["version"] = 2
            result["authority"]["revoked_keys"] = sorted(
                [*prior["revoked_keys"], trust_rotation.key_id(self.fixture.old_public)]
            )
            result["records"]["documents"].append([2, self.receipt["document_sha256"]])
            result["records"]["rotations"].append([2, self.receipt["rotation_sha256"]])
            if self.fault == "history":
                result["records"]["documents"][0][1] = "0" * 64
        if self.mutated:
            result["records"]["migrations"] = ["changed"]
        if self.fault == "controls":
            result["authority"]["revoked_artifacts"] = []
        return copy.deepcopy(result)

    def rotate(self, state, package, **kwargs):
        intent = trust_rotation.authorization(package, self.fixture.old_public)
        if intent["previous_sha256"] != self.metadata["sha256"]:
            if self.fault == "missing-refusal":
                return self.receipt
            if self.fault == "wrong-refusal":
                raise Rejected("different-cause")
            if self.fault == "refusal-write":
                self.mutated = True
            raise Rejected("rotation_head_changed")
        trust_rotation.verify(
            package,
            previous=self.previous,
            environment="local-cpu",
            current_root=self.fixture.old_public,
            next_root=self.fixture.new_public,
            clock=self.fixture.clock,
        )
        result = {**self.receipt, "reused": self.selected}
        if self.selected and self.fault == "retry":
            result["version"] = 3
        if self.fault == "receipt":
            result["release_ready"] = True
        self.selected = True
        return result

    def exercise(self):
        return native.exercise("state", self.fixture.old_key, self.fixture.new_key)

    def test_signed_transition_retires_old_key_without_erasing_history(self):
        report = self.exercise()
        self.assertEqual(report["status"], "pass")
        self.assertFalse(report["release_ready"])
        self.assertEqual(report["next_public"], self.fixture.new_public)
        self.assertEqual(report["receipt"]["version"], 2)
        self.assertEqual(
            set(report["negative"]),
            {
                "previous-reference",
                "removed-revocation",
                "missing-acceptance",
                "retired-key-update",
            },
        )
        self.assertTrue(report["retry"]["reused"])

    def test_prepare_binds_real_dual_signatures_and_rejects_wrong_source_key(self):
        self.assertEqual(
            trust_rotation.verify(
                self.package,
                previous=self.previous,
                environment="local-cpu",
                current_root=self.fixture.old_public,
                next_root=self.fixture.new_public,
                clock=self.fixture.clock,
            ),
            self.intent,
        )
        with self.assertRaises(Rejected):
            native.prepare(self.metadata, self.fixture.new_key, self.fixture.old_key)

    def test_modified_refusal_history_invalid_receipt_or_retry_fails_qualification(self):
        for fault in (
            "refusal-write",
            "receipt",
            "history",
            "retry",
            "controls",
            "missing-refusal",
            "wrong-refusal",
        ):
            with self.subTest(fault=fault):
                self.selected = self.mutated = False
                self.migrate.side_effect = [{"reused": False}, {"reused": True}]
                self.fault = fault
                with self.assertRaises(Rejected):
                    self.exercise()

    def test_transition_rejects_key_reuse_missing_revocations_and_identity_change(self):
        before = self.snapshot()
        self.selected = True
        after = self.snapshot()
        for section, field, value in (
            ("authority", "version", 4),
            ("authority", "policy_sha256", "0" * 64),
            ("authority", "revoked_keys", []),
            ("authority", "revoked_artifacts", []),
            ("records", "rotations", []),
            ("records", "migrations", []),
        ):
            altered = copy.deepcopy(after)
            altered[section][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                native.transition(before, altered, self.receipt)
        after["authority"]["identity"]["volume"] = "different"
        with self.assertRaises(Rejected):
            native.transition(before, after, self.receipt)

    def test_migration_retry_and_model_storage_change_are_not_ignored(self):
        self.migrate.side_effect = [{"reused": False}, {"reused": False}]
        with self.assertRaisesRegex(Rejected, "rotation_migration_retry"):
            self.exercise()
        self.migrate.side_effect = [{"reused": False}, {"reused": True}]
        self.models.side_effect = [{"unchanged": True}, {"unchanged": False}]
        with self.assertRaisesRegex(Rejected, "rotation_native_model_storage_changed"):
            self.exercise()

    def test_snapshot_collects_all_document_and_rotation_hashes(self):
        from mlsecops.trust_targets import Target

        expected = self.snapshot()
        with (
            patch.object(
                native.kube_trust, "admin", return_value=canonical(expected["records"]).decode()
            ) as admin,
            patch.object(
                native, "authority_snapshot", return_value=expected["authority"]
            ) as authority,
        ):
            self.assertEqual(self.real_snapshot("state"), expected)
        authority.assert_called_once_with("state", Target.PRIMARY)
        for table in ("ml_trust.documents", "ml_trust.root_rotations", "ml_trust.migrations"):
            self.assertIn(table, admin.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
