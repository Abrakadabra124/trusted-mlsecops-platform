"""Explicit one-time provisioning; no network or local infrastructure is started."""

import importlib.util
import io
import runpy
import sys
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from mlsecops import security_event_outbox as outbox
from mlsecops import security_event_store as journal
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_events_qualification as fixtures


class ProvisionContracts(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.security_event_provision"))
        from mlsecops import security_event_provision

        self.subject = security_event_provision
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.now = time.time_ns() // 1_000_000
        self.fx.document.update(issued_at_ms=self.now - 1000, expires_at_ms=self.now + 600000)
        for producer in self.fx.document["producers"]:
            producer["heartbeat_required"] = producer["role"] == "trust"
        self.enterContext(patch.object(self.subject, "ROOT", str(self.fx.directory / "state")))

    def config(self, role="promoter"):
        return {
            "schema_version": 1,
            "role": role,
            "registry": signing.sign(
                self.fx.document, "security-event-config", self.fx.keys["root"]
            ),
            "registry_root": self.fx.publics["root"],
            "registry_sha256": digest(canonical(self.fx.document)),
            "producer_id": digest(signing.decode64(self.fx.publics[role])),
        }

    def test_invalid_profile_refuses_before_any_filesystem_initialization(self):
        value = self.config()
        changes = (
            {**value, "schema_version": True},
            {**value, "schema_version": 2},
            {**value, "state_directory": "/other"},
            {**value, "role": "worker"},
            {**value, "role": "trust"},
            {**value, "role": []},
            {**value, "producer_id": "0" * 64},
            {**value, "registry_sha256": "0" * 64},
            {**value, "registry_root": self.fx.publics["worker"]},
            {},
            None,
        )
        with (
            patch.object(journal, "initialize") as collector,
            patch.object(outbox, "initialize") as source,
        ):
            for changed in changes:
                with self.subTest(profile=type(changed).__name__), self.assertRaises(Rejected):
                    self.subject.provision(changed)
            collector.assert_not_called()
            source.assert_not_called()

    def test_trust_heartbeat_is_mandatory_before_initialization(self):
        for producer in self.fx.document["producers"]:
            producer["heartbeat_required"] = producer["role"] == "serving"
        with patch.object(outbox, "initialize") as initialize, self.assertRaises(Rejected):
            self.subject.provision(self.config("trust"))
        initialize.assert_not_called()

    def test_role_selects_only_its_existing_journal_and_verifies_readback(self):
        for role in ("collector", "trust", "promoter", "serving"):
            store = Mock()
            with (
                patch.object(journal, "initialize", return_value="a" * 64) as collector,
                patch.object(outbox, "initialize", return_value="b" * 64) as producer,
                patch.object(journal, "Store", return_value=store) as collector_store,
                patch.object(outbox, "Store", return_value=store) as producer_store,
            ):
                value = self.config(role)
                report = self.subject.provision(value)
                self.assertEqual(
                    report,
                    {
                        "schema_version": 1,
                        "role": role,
                        "producer_id": value["producer_id"],
                        "registry_sha256": value["registry_sha256"],
                        "state_sha256": ("a" if role == "collector" else "b") * 64,
                        "release_ready": False,
                    },
                )
                selected = collector if role == "collector" else producer
                selected.assert_called_once()
                self.assertEqual(selected.call_args.args[0], self.subject.ROOT)
                (producer if role == "collector" else collector).assert_not_called()
                (producer_store if role == "collector" else collector_store).assert_not_called()
                store.snapshot.assert_called_once_with()

    def test_readback_failure_is_not_reported_as_success(self):
        with (
            patch.object(journal, "initialize", return_value="a" * 64),
            patch.object(
                journal, "Store", return_value=Mock(snapshot=Mock(side_effect=Rejected("readback")))
            ),
            self.assertRaisesRegex(Rejected, "readback"),
        ):
            self.subject.provision(self.config("collector"))

    def test_cli_has_finite_failure_and_no_initialization_on_bad_input(self):
        path = self.fx.directory / "provision.json"
        path.write_bytes(canonical(self.config()))
        for error, code in ((Rejected("private fixture"), 1), (KeyboardInterrupt(), 130)):
            output, errors = io.StringIO(), io.StringIO()
            with (
                redirect_stdout(output),
                redirect_stderr(errors),
                patch.object(self.subject, "enforce"),
                patch.object(self.subject, "provision", side_effect=error),
            ):
                self.assertEqual(self.subject.main(["--config", str(path)]), code)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "security_provision_rejected\n")
        with (
            redirect_stdout(io.StringIO()) as output,
            redirect_stderr(io.StringIO()),
            patch.object(self.subject, "enforce"),
            patch.object(self.subject, "provision", return_value={"release_ready": False}),
        ):
            self.assertEqual(self.subject.main(["--config", str(path)]), 0)
        self.assertEqual(output.getvalue(), '{"release_ready":false}\n')
        for arguments in (["--config", "relative"], [], ["--unexpected"]):
            with (
                redirect_stderr(io.StringIO()),
                patch.object(self.subject, "enforce"),
                patch.object(self.subject, "provision") as initialize,
            ):
                self.assertEqual(self.subject.main(arguments), 1)
                initialize.assert_not_called()

    def test_module_entrypoint_rejects_relative_config_without_side_effects(self):
        with (
            patch("mlsecops.process_privacy.enforce"),
            patch.object(sys, "argv", ["security-event-provision", "--config", "relative"]),
            redirect_stderr(io.StringIO()) as errors,
            patch.object(journal, "initialize") as collector,
            patch.object(outbox, "initialize") as producer,
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(self.subject.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(errors.getvalue(), "security_provision_rejected\n")
        collector.assert_not_called()
        producer.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "real private journals require Linux")
    def test_existing_or_incomplete_state_cannot_be_silently_reinitialized(self):
        for role in ("collector", "trust", "promoter", "serving"):
            root = self.fx.directory / role
            with patch.object(self.subject, "ROOT", str(root)):
                config = self.config(role)
                report = self.subject.provision(config)
                identity, state = (root / name for name in ("identity", "state"))
                before = (identity.read_bytes(), state.read_bytes())
                self.assertEqual(digest(before[0]), report["state_sha256"])
                self.assertEqual(root.stat().st_mode & 0o777, 0o700)
                for path in (identity, state):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(Rejected):
                    self.subject.provision(config)
                self.assertEqual(before, (identity.read_bytes(), state.read_bytes()))
                identity.unlink()
                with self.assertRaises(Rejected):
                    self.subject.provision(config)
                self.assertFalse(identity.exists())
                self.assertEqual(state.read_bytes(), before[1])


if __name__ == "__main__":
    unittest.main()
