import copy
import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import kube_rollback_native as native


class NativeRollbackContracts(unittest.TestCase):
    def setUp(self):
        self.previous = {
            "package": {"envelope": {}},
            "policy_envelope": {},
            "assurance_envelope": {},
            "approval_envelope": {},
            "reports": {},
            "trusted_root": "controlled-root",
        }
        self.target = {
            "sequence": 1,
            "request_sha256": "a" * 64,
            "subject_sha256": "b" * 64,
            "proposal_reference": digest(canonical({})),
            "environment": "local-cpu",
        }
        self.current = {**self.target, "sequence": 2, "request_sha256": "c" * 64}
        self.receipt = {
            **self.target,
            "sequence": 3,
            "request_sha256": "d" * 64,
            "release_ready": False,
            "state": "recorded-not-activated",
            "trust": {"version": 1},
        }
        self.prior = {"sequence": 1, "subject_sha256": "b" * 64, "environment": "local-cpu"}
        self.approval = {"sequence": 1, "issued_at": 100, "expires_at": 1000}
        self.selected = False
        self.retry = 0
        self.fault = None
        self.changed = False
        self.enterContext(patch.object(native.time, "time", return_value=200))
        self.enterContext(
            patch.object(native.release_authorization, "verify", return_value=self.prior)
        )
        self.enterContext(
            patch.object(
                native.release_policy,
                "checked",
                side_effect=lambda value, kind, public: (
                    {"identities": {"approver": {"public_key": "controlled"}}}
                    if kind == "promotion-policy"
                    else self.approval
                ),
            )
        )
        self.enterContext(
            patch.object(
                native.signing, "sign", side_effect=lambda value, kind, key: copy.deepcopy(value)
            )
        )
        self.stage = self.enterContext(
            patch.object(native, "stage", side_effect=lambda *args: args[4])
        )
        self.enterContext(patch.object(native, "snapshot", side_effect=self.snapshot))
        self.enterContext(patch.object(native.kube_promotion, "invoke", side_effect=self.invoke))

    def snapshot(self, state):
        return {
            "objects": {"candidates": {"unchanged": True}, "releases": {"changed": self.changed}},
            "promotion": {
                "migration": {"version": 1},
                "tables": {
                    "authorities": {
                        "rows": 1,
                        "changed": self.selected and self.fault == "authority",
                    },
                    "events": {"rows": 3 if self.selected else 2},
                    "heads": {"rows": 1},
                },
            },
        }

    def invoke(self, root, state, config, request, image):
        rollback = request["rollback"]
        reason = None
        if rollback["from_request_sha256"] == "0" * 64:
            reason = "rollback_from_history"
        elif rollback["target_request_sha256"] == "0" * 64:
            reason = "rollback_target_history"
        elif request["expires_at"] == 999:
            reason = "rollback_head_changed"
        if reason is not None:
            if self.fault == "negative-write":
                self.changed = True
            return {
                "status": "rejected",
                "receipt": None,
                "release_ready": False,
                "reason": "generic" if self.fault == "generic" else reason,
            }
        self.selected = True
        self.retry += 1
        receipt = copy.deepcopy(self.receipt)
        receipt["trust"]["version"] = self.retry
        if self.fault == "receipt":
            receipt["sequence"] = 2
        if self.retry == 2:
            if self.fault == "retry":
                receipt["subject_sha256"] = "e" * 64
            if self.fault == "retry-write":
                self.changed = True
        return {"status": "recorded-not-activated", "receipt": receipt, "release_ready": False}

    def exercise(self):
        return native.exercise(
            "root", "state", "image", {}, self.previous, self.target, self.current, "key"
        )

    def test_explicit_rollback_retry_and_three_exact_negative_checks(self):
        report = self.exercise()
        self.assertEqual(report["sequence_path"], [1, 2, 3])
        self.assertEqual(len(report["negative"]), 3)
        self.assertFalse(report["release_ready"])
        self.assertEqual(
            report["admitted"]["receipt"]["subject_sha256"], self.target["subject_sha256"]
        )

    def test_wrong_fixture_history_rejects_before_staging(self):
        self.prior["sequence"] = 2
        with self.assertRaisesRegex(Rejected, "rollback_fixture_history"):
            self.exercise()
        self.stage.assert_not_called()

    def test_generic_refusal_cannot_prove_history_guard(self):
        self.fault = "generic"
        with self.assertRaisesRegex(Rejected, "rollback_native_refusal_or_mutation"):
            self.exercise()

    def test_negative_with_storage_change_is_not_success(self):
        self.fault = "negative-write"
        with self.assertRaisesRegex(Rejected, "rollback_native_refusal_or_mutation"):
            self.exercise()

    def test_wrong_positive_receipt_is_rejected(self):
        self.fault = "receipt"
        with self.assertRaisesRegex(Rejected, "rollback_native_receipt"):
            self.exercise()

    def test_authority_mutation_is_not_rollback(self):
        self.fault = "authority"
        with self.assertRaisesRegex(Rejected, "rollback_native_history_transition"):
            self.exercise()

    def test_retry_cannot_change_identity_or_snapshot(self):
        for fault in ("retry", "retry-write"):
            self.selected, self.retry, self.changed, self.fault = False, 0, False, fault
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(Rejected, "rollback_native_retry"),
            ):
                self.exercise()


if __name__ == "__main__":
    unittest.main()
