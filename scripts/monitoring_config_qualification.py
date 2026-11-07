"""Explicit pins and separated identities for configured monitoring processes."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import (
    monitoring_config,
    monitoring_delivery,
    monitoring_runtime,
    serving_http,
    signing,
)
from mlsecops.contracts import Rejected, canonical, digest
from scripts.monitoring_qualification import reference


class ConfigurationContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.keys = {
            role: self.root / (role + ".pem") for role in ("reference", "producer", "sink", "label")
        }
        self.public = {role: signing.create_key(path) for role, path in self.keys.items()}
        self.reference = reference()
        self.reference_file = self.root / "reference.json"
        self.reference_file.write_bytes(
            canonical(signing.sign(self.reference, "monitor-reference", self.keys["reference"]))
        )
        self.config = {
            "schema_version": 1,
            "reference_file": str(self.reference_file),
            "reference_sha256": digest(canonical(self.reference)),
            "reference_public": self.public["reference"],
            "producer_key_file": str(self.keys["producer"]),
            "label_public": self.public["label"],
            "sink_public": self.public["sink"],
            "sink_port": 8910,
            "epoch": "b" * 32,
            "state_directory": str(self.root / "epochs"),
            "state_sha256": "d" * 64,
        }
        self.path = self.root / "monitor.json"
        self.write()

    def write(self, **changes):
        self.path.write_bytes(canonical({**self.config, **changes}))

    def test_configured_producer_is_inactive_and_has_no_startup_network_side_effect(self):
        runtime = monitoring_config.producer(str(self.path))
        self.assertIs(type(runtime), monitoring_runtime.Runtime)
        self.assertIsNone(runtime.task)
        self.assertEqual(runtime.snapshot()["reference_sha256"], self.config["reference_sha256"])
        self.assertEqual(runtime.snapshot()["state"], "inactive")

    def test_unknown_fields_paths_versions_keys_and_reference_tampering_are_rejected(self):
        for changes in (
            {"extra": 1},
            {"schema_version": True},
            {"reference_file": "relative"},
            {"producer_key_file": False},
            {"sink_port": 0},
            {"epoch": "bad"},
            {"reference_sha256": "f" * 64},
            {"reference_public": self.public["sink"]},
            {"reference_public": "bad"},
        ):
            with self.subTest(fields=list(changes)):
                self.write(**changes)
                with self.assertRaises((Rejected, OSError)):
                    monitoring_config.producer(str(self.path))
        self.write()
        envelope = signing.sign(self.reference, "monitor-reference", self.keys["reference"])
        envelope["payload"] = signing.encode64(canonical({**self.reference, "true_positives": 100}))
        self.reference_file.write_bytes(canonical(envelope))
        with self.assertRaises(Rejected):
            monitoring_config.producer(str(self.path))
        for invalid in (None, False, [], "relative.json"):
            with self.assertRaises(Rejected):
                monitoring_config.producer(invalid)

    def test_reference_authority_cannot_be_producer_sink_or_label_authority(self):
        for role in ("producer", "sink", "label"):
            with self.subTest(role=role):
                self.reference_file.write_bytes(
                    canonical(signing.sign(self.reference, "monitor-reference", self.keys[role]))
                )
                self.write(reference_public=self.public[role])
                with self.assertRaisesRegex(Rejected, "monitor_reference_roles"):
                    monitoring_config.producer(str(self.path))

    def test_sink_configuration_is_explicit_and_does_not_start_listener(self):
        config = {
            "schema_version": 1,
            "reference_sha256": self.config["reference_sha256"],
            "producer_public": self.public["producer"],
            "receipt_key_file": str(self.keys["sink"]),
            "port": 8910,
            "epoch": self.config["epoch"],
            "state_directory": self.config["state_directory"],
            "state_sha256": self.config["state_sha256"],
        }
        self.path.write_bytes(canonical(config))
        app, port = monitoring_config.sink(str(self.path))
        self.assertIs(type(app), monitoring_delivery.App)
        self.assertEqual(port, 8910)
        for change in (
            {"host": "0.0.0.0"},
            {"port": True},
            {"receipt_key_file": "relative"},
            {"receipt_key_file": str(self.keys["producer"])},
        ):
            self.path.write_bytes(canonical({**config, **change}))
            with self.assertRaises(Rejected):
                monitoring_config.sink(str(self.path))

    def test_serving_cli_loads_optional_signed_monitor_before_creating_engine(self):
        token, metric = self.root / "token", self.root / "metrics-token"
        token.write_text("b" * 64)
        metric.write_text("c" * 64)
        token.chmod(0o600)
        metric.chmod(0o600)
        config = {
            "storage_client": str(self.root / "storage"),
            "trust_client": str(self.root / "trust"),
            "context": {"policy": {"environment": "local-cpu"}},
            "trusted_root": self.public["reference"],
            "trust_root": self.public["sink"],
            "expected_policy": "a" * 64,
            "expected_serving_image": "sha256:" + "c" * 64,
            "minimum_sequence": 1,
            "minimum_trust_version": 1,
            "audit_directory": str(self.root / "audit"),
            "token_file": str(token),
            "metrics_token_file": str(metric),
            "monitor_file": str(self.path),
        }
        serving_path = self.root / "serving.json"
        serving_path.write_bytes(canonical(config))
        with patch.object(serving_http, "create_app") as create:
            serving_http.configured(serving_path)
            self.assertIs(type(create.call_args.kwargs["monitor"]), monitoring_runtime.Runtime)
        for changes in ({"monitor_file": "relative"}, {"metrics_token_file": None}):
            adjusted = {**config, **changes}
            if adjusted["metrics_token_file"] is None:
                del adjusted["metrics_token_file"]
            serving_path.write_bytes(canonical(adjusted))
            with patch.object(serving_http.serving, "Engine", Mock()) as engine:
                with self.assertRaises(Rejected):
                    serving_http.configured(serving_path)
                engine.assert_not_called()


if __name__ == "__main__":
    unittest.main()
