import copy
import unittest

from mlsecops import trust_gate
from mlsecops.contracts import Rejected
from scripts.trust_gate_fixtures import fixture


class TrustGateContracts(unittest.TestCase):
    def test_additional_observations_are_validated_even_when_not_required(self):
        native, source = fixture()
        extra = {
            "id": "additional-diagnostic",
            "status": "pass",
            "expected": False,
            "actual": False,
        }
        native["actual_inference"]["native"]["cases"].append(extra)
        trust_gate.reconcile(native, source)
        extra["actual"] = 0
        with self.assertRaises(Rejected):
            trust_gate.reconcile(native, source)

    def signer(self):
        from scripts.trust_trace_qualification import outage

        _, source = fixture()
        cases = {
            "initial-controlled-release-recorded-not-ready",
            "final-three-rotations-four-events",
            "all-retired-keys-stay-revoked",
            "owned-databases-removed",
            "source-state-and-revision-unchanged",
        }
        values = {}
        for sequence, role in enumerate(("publisher", "assessor", "approver"), 2):
            cases.update(
                role + "-" + s
                for s in (
                    "online-policy-denies-old-handoff",
                    "cold-before-store-policy-change",
                    "old-worker-removed",
                    "rotation-preserves-head-not-ready",
                    "old-config-after-store",
                    "new-policy-with-old-selection",
                    "missing-M22-not-approved",
                    "denied-release-no-journal-write",
                    "new-selection-with-new-subject",
                    "no-auto-reactivation",
                    "explicit-new-worker",
                    "old-instance-remains-fenced",
                    "worker-cleanup",
                )
            )
            cases.update(
                role + "-" + phase + "-" + suffix
                for phase in ("before", "after")
                for suffix in ("http-200", "model-and-subject", "prediction-shape", "golden-1e-6")
            )
            online = {"version": sequence, "document_sha256": format(sequence, "x") * 64}
            trace = outage()
            trace.pop("fault")
            trace["trust_receipt"] = {**online, "reused": False}
            values[role] = {
                "trace": trace,
                "before_golden_error": 0.0,
                "after_golden_error": 0.0,
                "model_sha256": "d" * 64,
                "release_ready": False,
                "rotation": {
                    "head": {
                        "sequence": sequence - 1,
                        "request_sha256": format(sequence - 1, "x") * 64,
                    },
                    "trust": online,
                    "release_ready": False,
                    "reused": False,
                },
                "selection": {
                    "sequence": sequence,
                    "request_sha256": format(sequence, "x") * 64,
                    "subject_sha256": format(sequence + 3, "x") * 64,
                    "trust": online,
                    "release_ready": False,
                },
            }
        return {
            **source,
            "source_dirty": False,
            "status": "pass",
            "release_ready": False,
            "workers_removed": 6,
            "model_sha256": "d" * 64,
            "cases": [
                {"id": n, "status": "pass", "expected": True, "actual": True} for n in sorted(cases)
            ],
            "transitions": values,
        }, source

    def test_all_three_signers_need_bound_trace_selection_and_cleanup(self):
        value, source = self.signer()
        self.assertEqual(
            set(trust_gate.release_signers(value, source)), {"publisher", "assessor", "approver"}
        )
        for change in (
            lambda v: v["cases"].pop(),
            lambda v: v["cases"].append(v["cases"][0]),
            lambda v: v.update(workers_removed=5),
            lambda v: v.update(image_id="wrong"),
            lambda v: v["transitions"].pop("approver"),
            lambda v: v["transitions"]["publisher"]["trace"]["trust_receipt"].update(version=True),
            lambda v: v["transitions"]["assessor"]["selection"].update(
                subject_sha256=v["transitions"]["publisher"]["selection"]["subject_sha256"]
            ),
            lambda v: v["transitions"]["approver"]["rotation"]["head"].update(
                request_sha256="0" * 64
            ),
            lambda v: v["transitions"]["publisher"].update(after_golden_error=0.1),
        ):
            bad = copy.deepcopy(value)
            change(bad)
            with self.assertRaises(Rejected):
                trust_gate.release_signers(bad, source)

    def test_complete_matrix_binds_actual_candidate_without_granting_release(self):
        native, source = fixture()
        result = trust_gate.reconcile(native, source)
        self.assertEqual(result["actual_candidate"], native["actual"]["candidate"])
        self.assertEqual(result["model"], native["actual"]["model"])
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["first_503_seconds"]["actual-outage"], 59.9)
        self.assertAlmostEqual(result["approval_expiry_seconds"], -0.2)

    def test_candidate_source_and_summary_cannot_replace_primary_evidence(self):
        native, source = fixture()
        for path, wrong in (
            (("source_revision",), "0" * 40),
            (("source_dirty",), True),
            (("release_ready",), True),
            (("actual", "candidate"), "0" * 64),
            (("actual", "parent_refusal"), "approved"),
            (("actual_inference", "source"), {}),
            (("actual_inference", "model_sha256"), "0" * 64),
            (("actual_inference", "native", "subject_sha256"), "0" * 64),
            (("actual_inference", "native", "max_golden_error"), float("nan")),
            (("actual_inference", "native", "cases", 0, "actual"), False),
            (("actual_inference", "trust_lifecycle", "outage", "snapshot_sha256"), "0" * 64),
            (
                (
                    "actual_inference",
                    "trust_lifecycle",
                    "outage",
                    "probe",
                    "lifecycle",
                    "trace",
                    1,
                    "http_status",
                ),
                200,
            ),
            (("actual_inference", "key_revocation", "authority_target"), "model-revocation"),
            (("actual_inference", "root_rotation", "permit_sha256"), "0" * 64),
        ):
            value = copy.deepcopy(native)
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = wrong
            with self.subTest(path=path), self.assertRaises(Rejected):
                trust_gate.reconcile(value, source)

    def test_missing_scenario_skipped_case_or_changed_peer_is_rejected(self):
        native, source = fixture()
        for change in (
            lambda v: v["actual_inference"]["trust_lifecycle"].pop("blackhole"),
            lambda v: v["actual_inference"]["native"]["cases"].pop(),
            lambda v: v["actual_inference"]["native"]["cases"][0].update(status="skipped"),
            lambda v: v["actual_inference"]["native"]["cases"][0].update(
                expected=False, actual=False
            ),
            lambda v: v["actual_inference"]["independent_authorities"]["states"]["after_model"][
                "primary"
            ].update(version=99),
            lambda v: v["actual_inference"]["independent_authorities"]["states"]["after_key"][
                "model-revocation"
            ].update(version=99),
            lambda v: v["actual_inference"]["independent_authorities"]["cold"]["primary"][
                "cases"
            ].pop(),
            lambda v: v["approval_expiry"].update(expired_retry_ledger_unchanged=False),
            lambda v: v["unexpired_replay"].update(prior_expires_at_epoch=99),
            lambda v: v["unexpired_replay"]["refused"].update(
                reason="release_expired_or_future_document"
            ),
            lambda v: v["authorized_rollback"]["negative"].pop("from_request_sha256"),
            lambda v: v["authorized_rollback"]["admitted"]["receipt"].update(sequence=2),
            lambda v: v["authorized_rollback"].update(from_model="0" * 64),
            lambda v: v["authorized_rollback"]["revoked_retry"].update(
                status="recorded-not-activated"
            ),
        ):
            value = copy.deepcopy(native)
            change(value)
            with self.assertRaises(Rejected):
                trust_gate.reconcile(value, source)
        for wrong in (None, [], {}, {**native, "actual_inference": None}):
            with self.assertRaises(Rejected):
                trust_gate.reconcile(wrong, source)


if __name__ == "__main__":
    unittest.main()
