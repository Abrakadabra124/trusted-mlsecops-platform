import unittest
from contextlib import ExitStack
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import image_audit as audit
from scripts import image_cilium_operator_inventory as registry


class OperatorSupplement(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(ExitStack())
        self.resolve = stack.enter_context(
            patch.object(registry, "resolve", return_value={"ok": True})
        )
        scans = audit.image_kubernetes_scans
        self.batch = stack.enter_context(patch.object(scans, "run_batch"))
        self.join = stack.enter_context(patch.object(scans, "join"))
        self.valid = stack.enter_context(patch.object(scans, "join_valid", return_value=True))
        self.component = {
            "observed_reference": registry.REFERENCE,
            "image_config_id": registry.CONFIG,
            "package_observation": {"sample": True},
        }
        self.target = {"reference": registry.REFERENCE, "config_id": registry.CONFIG}

    def supplement(self):
        return audit.supplement_system_image(
            self.component,
            self.target,
            "sbom",
            "scan",
            2,
            "run",
            "cache",
            "db",
            "db-files",
            registry=registry,
        )

    def test_inventory_and_target_checked_before_launch(self):
        for values, field in (
            (self.target, "reference"),
            (self.target, "config_id"),
            (self.target, "containerd_reference"),
            (self.component, "observed_reference"),
            (self.component, "image_config_id"),
        ):
            with self.subTest(field=field), patch.dict(values, {field: "foreign"}):
                with self.assertRaises(Rejected):
                    self.supplement()
        self.resolve.return_value = None
        with self.assertRaises(Rejected):
            self.supplement()
        self.batch.assert_not_called()

    def test_full_join_is_verified_against_the_observed_target(self):
        self.assertIs(self.supplement(), self.join.return_value)
        self.resolve.assert_called_once_with(
            self.component["package_observation"], registry.REFERENCE
        )
        self.batch.assert_called_once_with("run", "cache", "db", "db-files", registry=registry)
        self.join.assert_called_once_with(
            self.component,
            "sbom",
            "scan",
            2,
            self.batch.return_value,
            registry.REFERENCE,
            "db",
            registry=registry,
        )
        self.valid.assert_called_once_with(self.join.return_value, self.target, registry=registry)
        self.valid.return_value = False
        with self.assertRaisesRegex(Rejected, "reconciliation"):
            self.supplement()
