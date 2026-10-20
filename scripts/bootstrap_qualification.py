import io
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import bootstrap
from mlsecops.contracts import Rejected, canonical, digest, read_json
from mlsecops.signing import ROLES


def snapshot(directory):
    return {
        path.relative_to(directory).as_posix(): digest(path.read_bytes())
        for path in directory.rglob("*")
        if path.is_file()
    }


class BootstrapIdentityContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / "state"
        self.root = Path(__file__).resolve().parents[1]
        collector = patch.object(bootstrap, "collect", return_value={"scope": "controlled-test"})
        self.inventory = collector.start()
        self.addCleanup(collector.stop)

    def test_repeat_preserves_identity_keys_and_existing_data(self):
        first = bootstrap.initialize(self.root, self.state)
        (self.state / "approved" / "sentinel").write_bytes(b"existing-data")
        before = snapshot(self.state)
        self.assertEqual(bootstrap.initialize(self.root, self.state), first)
        self.assertEqual(snapshot(self.state), before)

    def test_missing_key_or_trust_anchor_never_regenerates_identity(self):
        for name in ("trusted-keys.json", *(f"keys/{role}.pem" for role in ROLES)):
            state = self.state / name.replace("/", "-").replace(".", "-")
            bootstrap.initialize(self.root, state)
            (state / name).unlink()
            before = snapshot(state)
            with self.subTest(name=name):
                with self.assertRaises(Rejected):
                    bootstrap.initialize(self.root, state)
                self.assertEqual(snapshot(state), before)
                self.assertFalse((state / name).exists())

    def test_invalid_identity_is_rejected_before_any_workspace_change(self):
        bootstrap.initialize(self.root, self.state)
        identity = read_json(self.state / "workspace.json")
        for field, value in (
            ("schema_version", True),
            ("workspace_id", "not-an-identity"),
            ("workspace_id", None),
            ("extra", "unexpected"),
        ):
            (self.state / "workspace.json").write_bytes(canonical({**identity, field: value}))
            before = snapshot(self.state)
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                bootstrap.initialize(self.root, self.state)
            self.assertEqual(snapshot(self.state), before)

    def test_mismatched_or_invalid_private_key_never_rewrites_trust_anchor(self):
        bootstrap.initialize(self.root, self.state)
        private = self.state / "keys" / "curator.pem"
        for replacement in ((self.state / "keys" / "evaluator.pem").read_bytes(), b"invalid"):
            private.write_bytes(replacement)
            before = snapshot(self.state)
            with self.assertRaises(Rejected):
                bootstrap.initialize(self.root, self.state)
            self.assertEqual(snapshot(self.state), before)

    def test_missing_tool_or_incompatible_environment_never_creates_state(self):
        for reason in ("required_tool_missing:docker", "incompatible_docker_profile"):
            self.inventory.side_effect = Rejected(reason)
            with self.assertRaisesRegex(Rejected, reason):
                bootstrap.initialize(self.root, self.state)
            self.assertFalse(self.state.exists())

    def test_unowned_or_linked_workspace_is_rejected_without_changes(self):
        self.state.mkdir()
        (self.state / "owner-data").write_bytes(b"not-owned")
        before = snapshot(self.state)
        with self.assertRaisesRegex(Rejected, "refusing_nonempty_unowned_workspace"):
            bootstrap.initialize(self.root, self.state)
        self.assertEqual(snapshot(self.state), before)
        with (
            patch.object(Path, "is_symlink", return_value=True),
            self.assertRaisesRegex(Rejected, "symlink_state"),
        ):
            bootstrap.initialize(self.root, self.state)
        self.assertEqual(snapshot(self.state), before)

    def test_cli_returns_failure_for_incomplete_identity_and_preserves_state(self):
        with (
            patch.object(sys, "argv", ["bootstrap", "--state", str(self.state)]),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(bootstrap.main(), 0)
        (self.state / "trusted-keys.json").unlink()
        before = snapshot(self.state)
        with (
            patch.object(sys, "argv", ["bootstrap", "--state", str(self.state)]),
            redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(bootstrap.main(), 1)
        self.assertIn("Bootstrap rejected:", errors.getvalue())
        self.assertEqual(snapshot(self.state), before)

    def test_module_entrypoint_uses_owned_bootstrap(self):
        with (
            patch("mlsecops.inventory.collect", return_value={"scope": "controlled-test"}),
            patch.object(sys, "argv", ["bootstrap", "--state", str(self.state)]),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as outcome,
        ):
            runpy.run_path(bootstrap.__file__, run_name="__main__")
        self.assertEqual(outcome.exception.code, 0)
        self.assertTrue((self.state / "trusted-keys.json").is_file())


if __name__ == "__main__":
    unittest.main()
