import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_serving_faults as faults


class FaultContracts(unittest.TestCase):
    def test_progress_rejects_wrong_fault_order_duplicates_and_private_text(self):
        ready = {"event": "trust-fault", "phase": "ready", "fault": "outage"}
        denied = {**ready, "phase": "denied"}
        raw = canonical(ready) + b"\n" + canonical(denied) + b"\n"
        self.assertEqual(faults.progress(raw, "outage"), ["ready", "denied"])
        for content in [
            canonical(denied),
            raw + canonical(denied),
            b"PRIVATE",
            canonical({**ready, "extra": "PRIVATE"}),
            canonical({**ready, "fault": "revocation"}),
            b"x" * 65537,
            b"[]",
            b'{"status":"unknown"}',
        ]:
            with self.subTest(content=content[:100]), self.assertRaises(Rejected):
                faults.progress(content, "outage")
        self.assertEqual(faults.progress(raw + b'{"status":"pass"}', "outage"), ["ready", "denied"])
        with self.assertRaises(Rejected):
            faults.Coordinator("state", "unknown", "a" * 64, "key", "b" * 64)
        with self.assertRaises(Rejected):
            faults.Coordinator("state", "revocation", "a" * 64, "key", "b" * 64)("denied")

    def test_outage_restores_same_owned_authority_even_on_probe_failure(self):
        document = {
            "kind": "StatefulSet",
            "metadata": {"name": "postgres", "namespace": "ml-trust"},
        }
        marker = {"resources": {"StatefulSet/ml-trust/postgres": "own"}, "volume_uid": "vol"}
        scaled = [1]

        def scale(state, doc, uid, replicas):
            self.assertEqual(uid, "own")
            scaled[0] = replicas

        with (
            patch.object(faults.kube_trust, "validate", return_value=marker),
            patch.object(faults.kube_trust, "desired", return_value=[document]),
            patch.object(
                faults.kube_storage, "reference", return_value="StatefulSet/ml-trust/postgres"
            ),
            patch.object(
                faults.kube_storage, "get", side_effect=lambda *a: {"spec": {"replicas": scaled[0]}}
            ),
            patch.object(faults, "scale", side_effect=scale) as scaler,
            patch.object(faults, "kubectl"),
        ):
            coordinator = faults.Coordinator("state", "outage", "a" * 64, "key", "b" * 64)
            with self.assertRaisesRegex(Rejected, "injected_failure"):
                with coordinator:
                    coordinator("ready")
                    raise Rejected("injected_failure")
            self.assertEqual([c.args[-1] for c in scaler.call_args_list], [0, 1])
            with patch.object(
                faults.kube_trust, "validate", return_value={**marker, "volume_uid": "foreign"}
            ):
                coordinator.changed = True
                with self.assertRaisesRegex(Rejected, "volume_changed"):
                    coordinator.restore()

    def test_policy_change_is_restored_but_revocation_is_monotonic(self):
        for fault in ["policy-change", "revocation"]:
            with patch.object(
                faults.trust_authority, "update", return_value={"version": 2}
            ) as update:
                with faults.Coordinator("state", fault, "a" * 64, "key", "b" * 64) as coordinator:
                    coordinator("ready")
                    coordinator("denied")
                self.assertEqual(update.call_count, 2 if fault == "policy-change" else 1)
                if fault == "revocation":
                    self.assertEqual(update.call_args.kwargs["revoked_artifacts"], ["b" * 64])
                else:
                    self.assertEqual(update.call_args.args[1], "a" * 64)

    def test_ack_targets_only_fixed_marker_and_stdin_json(self):
        with patch.object(faults, "kubectl") as kubectl:
            faults.acknowledge("state", "owned-pod", "ready", "outage")
        args = kubectl.call_args.args
        self.assertIn("owned-pod", args[1])
        self.assertIn("ml-serving", args[1])
        self.assertEqual(args[2], {"phase": "ready", "fault": "outage"})
        self.assertIn("mlsecops-trust-ready.json", args[1][-1])
        with self.assertRaises(Rejected):
            faults.acknowledge("state", "owned-pod", "../../bad", "outage")


if __name__ == "__main__":
    unittest.main()
