"""Ordinary unit checks for installed image identity, retries, and rollback."""

import copy
import json
import unittest
from unittest.mock import patch

from mlsecops import local_path_rollout as rollout
from mlsecops.contracts import Rejected


class RolloutTests(unittest.TestCase):
    def setUp(self):
        self.ref = rollout.pin.REPOSITORY + "@sha256:" + "a" * 64
        self.config = "sha256:" + "b" * 64
        self.enterContext(patch.object(rollout.pin, "PUBLISHED_REFERENCE", self.ref))
        self.enterContext(patch.object(rollout.pin, "PUBLISHED_CONFIG", self.config))
        self.check_owner = self.enterContext(patch.object(rollout, "validate_cluster"))
        self.old = {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "local-path-provisioner",
                            "image": rollout.STOCK,
                            "imagePullPolicy": "Never",
                        }
                    ]
                }
            }
        }
        self.live = {"metadata": {"uid": "owned"}, "spec": copy.deepcopy(self.old)}
        self.enterContext(
            patch.object(rollout, "deployment", side_effect=lambda state: copy.deepcopy(self.live))
        )
        self.ready = self.enterContext(
            patch.object(rollout, "ready", return_value={"pod_uid": "ready"})
        )
        self.patch = self.enterContext(
            patch.object(rollout, "patch_spec", side_effect=self.replace)
        )
        self.cri = self.enterContext(
            patch.object(
                rollout,
                "command",
                return_value=json.dumps({"status": {"id": self.config, "repoDigests": [self.ref]}}),
            )
        )

    def replace(self, state, uid, before, after):
        self.assertEqual((self.live["metadata"]["uid"], self.live["spec"]), (uid, before))
        self.live["spec"] = copy.deepcopy(after)

    def test_moves_only_owned_baseline_and_repeated_call_is_read_only(self):
        self.assertTrue(rollout.ensure(None)["changed"])
        self.assertFalse(rollout.ensure(None)["changed"])
        self.assertEqual(self.patch.call_count, 1)
        self.assertEqual(rollout.controller(self.live["spec"])["image"], self.ref)
        self.assertEqual(self.check_owner.call_count, 2)

    def test_wrong_registry_or_config_rolls_back_before_reporting_failure(self):
        for details in (
            {"id": self.config, "repoDigests": [self.ref + "0"]},
            {"id": self.config, "repoDigests": self.ref},
            {"id": "sha256:" + "0" * 64, "repoDigests": [self.ref]},
        ):
            self.cri.return_value = json.dumps({"status": details})
            with (
                self.subTest(details=details),
                self.assertRaisesRegex(Rejected, "published_cri_mismatch"),
            ):
                rollout.ensure(None)
            self.assertEqual(self.live["spec"], self.old)
            self.assertEqual(self.ready.call_args.args[-1], rollout.LOCAL_PATH_CONFIG)

    def test_foreign_deployment_and_unpublished_reference_are_refused_before_mutation(self):
        rollout.controller(self.live["spec"])["image"] = "example.invalid/foreign:latest"
        with self.assertRaisesRegex(Rejected, "baseline_unrecognized"):
            rollout.ensure(None)
        with (
            patch.object(rollout.pin, "PUBLISHED_REFERENCE", None),
            self.assertRaisesRegex(Rejected, "pin_missing"),
        ):
            rollout.ensure(None)
        self.patch.assert_not_called()

    def test_changed_deployment_is_preserved_when_rollback_loses_ownership(self):
        def foreign(*args):
            self.live["metadata"]["uid"] = "other"
            raise Rejected("timeout")

        self.patch.side_effect = foreign
        with self.assertRaisesRegex(Rejected, "restore_ownership_changed"):
            rollout.ensure(None)
        self.patch.assert_called_once()
        self.assertEqual(self.live["metadata"]["uid"], "other")
