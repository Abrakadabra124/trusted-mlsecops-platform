"""Candidate campaign ordering and failure cleanup without local infrastructure."""

import copy
import io
import re
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.signing import encode64
from mlsecops.trust_targets import Target
from scripts import kube_candidate_campaign as campaign
from scripts import kube_candidate_faults as faults
from scripts import kube_candidate_native as native
from scripts import kube_candidate_terminals as terminals
from scripts import kube_owned_probe as ownership
from scripts import kube_serving_native as probes
from scripts.kube_authority_pair_qualification import isolation, states


class CandidateCampaign(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.events = []
        self.calls = []
        self.failure_at = None
        self.mutation_at = None
        self.mutation = {}
        self.clock = 1000
        self.advance_after = None
        self.advance_to = 1421
        self.change_snapshot_after = None
        self.original = Rejected("original_candidate_probe_failure")
        self.model, self.subject = "m" * 64, "b" * 64
        self.public = encode64(b"p" * 32)
        self.next_public = encode64(b"n" * 32)
        self.key_id = digest(b"p" * 32)
        self.current = states()
        for row in self.current.values():
            row["identity"]["root_sha256"] = digest(b"n" * 32)
        self.snapshot = {"promotion": "unchanged"}
        self.profile = {"image_id": "image-id"}
        self.refusal = {
            "campaign_id": "a" * 32,
            "candidate": "c" * 64,
            "proposal": "d" * 64,
            "model": self.model,
        }
        package = {"envelope": {"subject": self.subject}}
        self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.enterContext(patch.object(native, "hosted"))
        self.enterContext(patch.object(campaign, "hosted"))
        self.enterContext(patch.object(ownership, "hosted"))
        self.enterContext(
            patch.object(
                native, "command", side_effect=lambda cmd: "r" * 40 if "rev-parse" in cmd else ""
            )
        )
        self.enterContext(patch.object(native, "source_fingerprint", return_value="f" * 64))
        self.enterContext(
            patch.object(
                native,
                "read_json",
                side_effect=lambda p: (
                    {"approver": self.public} if p.name == "trusted-keys.json" else {}
                ),
            )
        )
        self.enterContext(patch.object(native.release_bundle, "load", return_value=package))
        self.enterContext(
            patch.object(
                native,
                "bind_proposal",
                return_value=(
                    {
                        "policy": {"environment": "local-cpu"},
                        "candidate_reference": self.refusal["candidate"],
                        "evaluation_reference": digest(b"signed evaluation"),
                    },
                    {
                        "model": b"model",
                        "subject_sha256": self.subject,
                        "manifest": {"issued_at": 900, "expires_at": 2000},
                    },
                ),
            )
        )
        self.enterContext(
            patch.object(native.signing, "create_key", return_value=encode64(b"q" * 32))
        )
        self.enterContext(
            patch.object(
                native.signing,
                "load_key",
                return_value=Mock(
                    public_key=Mock(
                        return_value=Mock(public_bytes_raw=Mock(return_value=b"r" * 32))
                    )
                ),
            )
        )
        self.signatures = []

        def sign(value, kind, key):
            result = {"payload": copy.deepcopy(value), "kind": kind}
            self.signatures.append(result)
            return result

        self.enterContext(patch.object(native.signing, "sign", side_effect=sign))
        self.enterContext(patch.object(native.time, "time", side_effect=lambda: self.clock))
        self.enterContext(patch.object(native.kube_trust, "bootstrap"))
        self.enterContext(patch.object(native.trust_authority, "install"))
        self.enterContext(patch.object(native.trust_authority, "update"))
        self.enterContext(patch.object(native, "run_worker", return_value=({}, {})))
        batch = Mock()
        batch.consume.return_value = (
            SimpleNamespace(tolist=lambda: [0.5]),
            None,
            {"model_digest": self.model},
        )
        self.enterContext(patch.object(native, "PredictionBatch", return_value=batch))
        self.enterContext(
            patch.object(
                native.kube_storage,
                "admin",
                side_effect=lambda state, sql: re.search("'([a-f0-9]{64})'", sql)[1],
            )
        )
        self.enterContext(patch.object(native, "ledger", return_value={"ledger": "unchanged"}))
        for module in (native, faults, terminals, campaign):
            self.enterContext(
                patch.object(
                    module, "snapshot", side_effect=lambda state: copy.deepcopy(self.snapshot)
                )
            )
        self.enterContext(
            patch.object(terminals, "capture", side_effect=lambda *a: copy.deepcopy(self.current))
        )
        self.enterContext(patch.object(native, "exercise_root", side_effect=self.root_transition))
        self.enterContext(patch.object(probes, "invoke", side_effect=self.probe))
        self.enterContext(patch.object(faults, "Coordinator", side_effect=self.coordinator))
        self.enterContext(
            patch.object(
                ownership.service, "directory", return_value=Mock(exists=Mock(return_value=True))
            )
        )
        self.enterContext(
            patch.object(
                ownership.audit_state, "validate", return_value={"pins": {"serving": "pin"}}
            )
        )
        self.enterContext(
            patch.object(
                ownership.observations,
                "snapshot",
                return_value={"pin": "pin", "permissions": {"private": True}, "records": []},
            )
        )
        self.enterContext(patch.object(ownership.service, "validate", return_value={}))
        self.enterContext(
            patch.object(
                ownership.service, "pod", return_value={"metadata": {"uid": "returned-owner"}}
            )
        )
        self.counter = 0

        def collector(*args):
            self.counter += 1
            return {"heartbeats": {"serving": self.counter}, "records": []}

        self.enterContext(patch.object(ownership.audit, "collector", side_effect=collector))

        @contextmanager
        def transfer(state):
            self.events.append("suspend")
            report = {"before": "original-owner"}
            try:
                yield report
            finally:
                self.events.append("return")
                report.update(after="returned-owner", release_ready=False)

        self.enterContext(patch.object(ownership.handoff, "transfer", transfer))

    def root_transition(self, state, profile, config, expected, **kwargs):
        self.events.extend(["root-live", "root-return", "observer-update", "peer-rotation"])
        self.root_permit = copy.deepcopy(config["permit_envelope"])
        self.assertEqual(kwargs["expires_at"], 1600)
        return {"next_public": self.next_public, "minimum_trust_version": 7}

    def coordinator(self, state, fault, policy, key, model, **kwargs):
        test = self
        selected = kwargs["target"]

        class Coordinator:
            changed = False

            def __enter__(self):
                return self

            def __call__(self, phase):
                if phase == "ready":
                    if fault in ("outage", "blackhole", "policy-change"):
                        self.changed = True
                    else:
                        row = test.current[selected.value]
                        field, value = (
                            ("revoked_artifacts", model)
                            if fault == "revocation"
                            else ("revoked_keys", kwargs["revoked_key"])
                        )
                        row[field].append(value)
                        row[field].sort()
                        row["version"] += 1
                        row["history_sha256"] = digest((row["history_sha256"] + "append").encode())
                else:
                    self.restore()

            def restore(self):
                if self.changed:
                    test.events.append("restore:" + fault)
                    self.changed = False

            def __exit__(self, *error):
                self.restore()

        return Coordinator()

    def probe(self, state, profile, config, expected, **options):
        self.assertNotIn("restore_failure", options)
        self.assertTrue(options["candidate_probe"])
        rotated = "root-live" in self.events
        if not rotated:
            self.root_permit = copy.deepcopy(config["permit_envelope"])
        self.assertEqual(config["trust_root"], self.next_public if rotated else encode64(b"r" * 32))
        self.assertEqual(config["permit_envelope"], self.root_permit)
        self.assertEqual(config["expected_permit"], digest(canonical(self.root_permit["payload"])))
        selected = options.get("trust_target", Target.PRIMARY)
        self.assertEqual(config.get("trust_target", "primary"), selected.value)
        for row in self.current.values():
            row["policy_sha256"] = config["expected_permit"]
        label = expected.get("fault", "matrix")
        if expected.get("cold_only"):
            label = "cold-key" if selected is Target.PRIMARY else "cold-model"
        elif label == "revocation":
            label = "model-revocation"
        self.events.append(label)
        self.calls.append((label, copy.deepcopy(config), copy.deepcopy(expected)))
        index = len(self.calls)
        coordinator = options.get("coordinator")
        report = {
            "status": "pass",
            "release_ready": False,
            "model_sha256": self.model,
            "subject_sha256": self.subject,
            "authority_target": selected.value,
            **isolation(selected, self.current),
        }
        try:
            if coordinator is not None:
                coordinator("ready")
            if self.failure_at == index:
                raise self.original
            if coordinator is not None:
                coordinator("denied")
                report["lifecycle"] = {"fault": expected["fault"]}
            if expected.get("cold_only"):
                case = (
                    "cold-key-revocation" if selected is Target.PRIMARY else "cold-model-revocation"
                )
                cause = (
                    "trust_key_revoked" if selected is Target.PRIMARY else "trust_artifact_revoked"
                )
                report.update(
                    scope="candidate-cold-revocation",
                    cases=[
                        {
                            "id": "initial-worker-absence",
                            "status": "pass",
                            "actual": 0,
                            "expected": 0,
                        },
                        {"id": case, "status": "pass", "actual": cause, "expected": cause},
                        {"id": "cold-worker-absence", "status": "pass", "actual": 0, "expected": 0},
                    ],
                )
            if self.advance_after == index:
                self.clock = self.advance_to
            if self.change_snapshot_after == index:
                self.snapshot = {"promotion": "changed"}
            if self.mutation_at == index:
                report.update(self.mutation)
            return report
        finally:
            self.events.append("cleanup:" + label)

    def qualify(self, **modes):
        return native.qualify(
            self.root,
            self.root,
            "image",
            prepared=(self.profile, self.refusal),
            qualification_key=self.root / "root.pem",
            **{"include_key_revocation": True, "include_trust_lifecycle": True, **modes},
        )

    def test_pinned_m12_real_window_and_separate_authority(self):

        arguments = (self.root, self.root, "image")
        prepared = (self.profile, self.refusal)
        for conflict in (
            dict(privacy=True),
            dict(security=True),
            dict(qualification_key=self.root / "key"),
        ):
            with (
                self.subTest(conflict=conflict),
                self.assertRaisesRegex(Rejected, "pinned_M12_mode"),
            ):
                native.qualify(*arguments, prepared=prepared, pinned_m12=True, **conflict)
        with self.assertRaisesRegex(Rejected, "pinned_M12_mode"):
            native.qualify(*arguments, pinned_m12=True)
        for seconds in (239, 240):
            self.clock = 2000 - seconds
            with (
                self.subTest(seconds=seconds),
                patch.object(
                    native, "campaign_authority", return_value=(self.root / "original", "root")
                ),
                patch.object(
                    native,
                    "invoke",
                    return_value={"model_sha256": self.model, "subject_sha256": self.subject},
                ) as invoke,
            ):
                if seconds == 239:
                    with self.assertRaisesRegex(Rejected, "candidate_inference_window"):
                        native.qualify(*arguments, prepared=prepared, pinned_m12=True)
                    invoke.assert_not_called()
                    native.trust_authority.update.assert_not_called()
                else:
                    report = native.qualify(*arguments, prepared=prepared, pinned_m12=True)
                    self.assertEqual(report["proposal_expires_at"], 2000)
                    self.assertEqual(report["proposal_reference"], self.refusal["proposal"])
                    self.assertEqual(
                        invoke.call_args.kwargs["trust_target"], Target.MODEL_REVOCATION
                    )
                    config = invoke.call_args.args[2]
                    self.assertEqual(config["trust_target"], Target.MODEL_REVOCATION.value)
                    self.assertEqual(config["permit_envelope"]["payload"]["expires_at"], 2000)
                    backend = native.trust_authority.install.call_args.kwargs["backend"]
                    self.assertEqual(backend.keywords, {"target": Target.MODEL_REVOCATION})
                    self.assertIs(
                        native.trust_authority.update.call_args.kwargs["backend"], backend
                    )
                    self.assertEqual(
                        native.trust_authority.update.call_args.args[2].name,
                        "qualification-authority.pem",
                    )

    def test_eight_post_root_jobs_share_one_return_and_same_permit(self):
        report = self.qualify()
        self.assertEqual(
            [c[0] for c in self.calls],
            [
                "matrix",
                "outage",
                "blackhole",
                "policy-change",
                "model-revocation",
                "key-revocation",
                "cold-key",
                "cold-model",
            ],
        )
        self.assertEqual(
            self.events[:5],
            ["root-live", "root-return", "observer-update", "peer-rotation", "suspend"],
        )
        self.assertEqual(self.events.count("suspend"), 1)
        self.assertEqual(self.events.count("return"), 1)
        self.assertEqual(self.events[-2:], ["cleanup:cold-model", "return"])
        self.assertEqual(
            report["qualification_permit_sha256"], digest(canonical(self.root_permit["payload"]))
        )
        self.assertEqual(
            self.root_permit["payload"]["expires_at"] - self.root_permit["payload"]["issued_at"],
            600,
        )
        self.assertEqual(report["model_sha256"], self.model)
        self.assertEqual(report["evaluation_reference"], digest(b"signed evaluation"))
        self.assertEqual(report["subject_sha256"], self.subject)
        owner = report["trust_lifecycle_ownership_return"]
        self.assertGreater(owner["heartbeat_after"], owner["heartbeat_before"])
        self.assertFalse(owner["release_ready"])
        reports = [
            report["native"],
            *(r["probe"] for r in report["trust_lifecycle"].values()),
            report["model_revocation"],
            report["key_revocation"],
            *report["independent_authorities"]["cold"].values(),
        ]
        self.assertEqual(len(reports), 8)
        self.assertTrue(all("ownership_return" not in r for r in reports))
        self.assertTrue(all(r["model_sha256"] == self.model for r in reports))
        self.assertTrue(all(r["subject_sha256"] == self.subject for r in reports))

    def test_each_failed_job_stops_later_jobs_and_returns_after_cleanup_and_restore(self):
        for failed in range(1, 9):
            with self.subTest(failed=failed):
                case = CandidateCampaign()
                case.setUp()
                try:
                    case.failure_at = failed
                    with self.assertRaises(Rejected) as raised:
                        case.qualify()
                    self.assertIs(raised.exception, case.original)
                    self.assertEqual(len(case.calls), failed)
                    self.assertEqual(case.events.count("return"), 1)
                    label = case.calls[-1][0]
                    ending = ["cleanup:" + label]
                    if label in ("outage", "blackhole", "policy-change"):
                        ending.append("restore:" + label)
                    ending.append("return")
                    self.assertEqual(case.events[-len(ending) :], ending)
                finally:
                    case.doCleanups()

    def test_wrong_candidate_digest_stops_the_campaign_and_still_returns(self):
        for position in (1, 2, 5, 6, 7, 8):
            with self.subTest(position=position):
                case = CandidateCampaign()
                case.setUp()
                try:
                    case.mutation_at = position
                    case.mutation = {"subject_sha256": "e" * 64}
                    with self.assertRaises(Rejected):
                        case.qualify()
                    self.assertEqual(len(case.calls), position)
                    self.assertEqual(case.events.count("return"), 1)
                finally:
                    case.doCleanups()

    def test_expiring_permit_stops_before_next_fault_without_renewal(self):
        self.advance_after = 2
        with self.assertRaisesRegex(Rejected, "candidate_trust_window"):
            self.qualify()
        self.assertEqual([c[0] for c in self.calls], ["matrix", "outage"])
        self.assertEqual(self.events.count("return"), 1)
        self.assertEqual(len(self.signatures), 2)  # Original and unsigned-proposal negative only.

    def test_exact_180_seconds_retains_all_jobs_without_renewing_permit(self):
        self.advance_after, self.advance_to = 1, 1420
        report = self.qualify()
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(self.events.count("return"), 1)
        self.assertEqual(self.root_permit["payload"]["expires_at"], 1600)
        self.assertFalse(report["release_ready"])

    def test_changed_matrix_ledger_prevents_faults_but_returns_owner(self):
        self.change_snapshot_after = 1
        with self.assertRaisesRegex(Rejected, "candidate_inference_promotion_state_changed"):
            self.qualify()
        self.assertEqual([c[0] for c in self.calls], ["matrix"])
        self.assertEqual(self.events[-2:], ["cleanup:matrix", "return"])

    def test_eight_passed_jobs_cannot_replace_fresh_final_owner_heartbeat(self):
        with (
            patch.object(ownership.audit, "collector", return_value={"heartbeats": {"serving": 1}}),
            patch.object(ownership.time, "monotonic", side_effect=[0, 121]),
            self.assertRaisesRegex(Rejected, "owned_probe_return_heartbeat_deadline"),
        ):
            self.qualify()
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(self.events.count("return"), 1)

    def test_nonindependent_modes_keep_each_owned_invoke(self):
        for keys, lifecycle, jobs in ((False, False, 1), (True, False, 2), (False, True, 4)):
            with self.subTest(keys=keys, lifecycle=lifecycle):
                case = CandidateCampaign()
                case.setUp()
                try:
                    report = case.qualify(
                        include_key_revocation=keys, include_trust_lifecycle=lifecycle
                    )
                    self.assertEqual(len(case.calls), jobs)
                    self.assertEqual(case.events.count("return"), jobs)
                    self.assertNotIn("root-live", case.events)
                    self.assertNotIn("trust_lifecycle_ownership_return", report)
                    self.assertIn("ownership_return", report["native"])
                finally:
                    case.doCleanups()


if __name__ == "__main__":
    unittest.main()
