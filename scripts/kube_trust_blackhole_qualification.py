import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_trust_blackhole as blackhole


class BlackholeContracts(unittest.TestCase):
    def test_scoped_drop_has_uid_bound_cleanup_even_after_unknown_create(self):
        for unknown in (False, True):
            state = [None]

            def kubectl(root, args, value=None):
                if args[0] == "create":
                    state[0] = copy.deepcopy(value)
                    state[0]["metadata"]["uid"] = "owned-uid"
                    if unknown:
                        raise TimeoutError("private")
                    return SimpleNamespace(stdout=canonical(state[0]))
                self.assertEqual(args[0], "delete")
                self.assertEqual(value["preconditions"], {"uid": "owned-uid"})
                self.assertIn("/namespaces/ml-trust/ciliumnetworkpolicies/", args[1])
                state[0] = None

            with (
                patch.object(blackhole, "workspace_id", return_value="workspace"),
                patch.object(
                    blackhole.kube_trust,
                    "validate",
                    return_value={"volume_uid": "v", "pod_uid": "p"},
                ),
                patch.object(
                    blackhole.kube_storage, "get", side_effect=lambda *args: copy.deepcopy(state[0])
                ),
                patch.object(blackhole, "kubectl", side_effect=kubectl),
            ):
                fault = blackhole.Blackhole("state")
                if unknown:
                    with self.assertRaises(TimeoutError):
                        fault.start()
                else:
                    fault.start()
                spec = fault.document["spec"]
                self.assertEqual(spec["endpointSelector"], {"matchLabels": {"k8s:app": "postgres"}})
                labels = spec["ingressDeny"][0]["fromEndpoints"][0]["matchLabels"]
                self.assertEqual(labels[blackhole.POD_NAMESPACE], "ml-serving")
                self.assertEqual(labels[blackhole.ACCOUNT], "serving")
                fault.close()
                fault.close()
                self.assertIsNone(state[0])

    def test_collision_or_changed_uid_never_deletes_foreign_policy(self):
        with (
            patch.object(blackhole, "workspace_id", return_value="workspace"),
            patch.object(
                blackhole.kube_trust, "validate", return_value={"volume_uid": "v", "pod_uid": "p"}
            ),
            patch.object(blackhole.kube_storage, "get") as get,
            patch.object(blackhole, "kubectl") as kubectl,
        ):
            fault = blackhole.Blackhole("state")
            get.return_value = {"metadata": {"uid": "foreign"}}
            with self.assertRaises(Rejected):
                fault.start()
            fault.close()
            kubectl.assert_not_called()
            fault.attempted = True
            fault.uid = "owned"
            with self.assertRaises(Rejected):
                fault.close()
            kubectl.assert_not_called()

    def test_cleanup_handles_absence_and_rejects_missing_identity_or_changed_authority(self):
        with (
            patch.object(blackhole, "workspace_id", return_value="workspace"),
            patch.object(
                blackhole.kube_trust, "validate", return_value={"volume_uid": "v", "pod_uid": "p"}
            ) as validate,
            patch.object(blackhole.kube_storage, "get", return_value=None) as get,
            patch.object(blackhole, "kubectl") as kubectl,
        ):
            fault = blackhole.Blackhole("state")
            fault.attempted = True
            fault.marker = {"volume_uid": "v", "pod_uid": "p"}
            fault.close()
            self.assertFalse(fault.attempted)
            fault.attempted = True
            get.return_value = {
                **fault.document,
                "metadata": {**fault.document["metadata"], "uid": ""},
            }
            with self.assertRaisesRegex(Rejected, "identity"):
                fault.close()
            kubectl.assert_not_called()
            get.return_value = {
                **fault.document,
                "metadata": {**fault.document["metadata"], "uid": "owned"},
            }
            with self.assertRaisesRegex(Rejected, "cleanup_incomplete"):
                fault.close()
            get.return_value = None
            validate.return_value = {"volume_uid": "foreign", "pod_uid": "p"}
            with self.assertRaisesRegex(Rejected, "authority_changed"):
                fault.close()


if __name__ == "__main__":
    unittest.main()
