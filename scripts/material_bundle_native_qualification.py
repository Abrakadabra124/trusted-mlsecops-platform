import contextlib
import copy
import io
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mlsecops.contracts import Rejected, read_json, write_json
from scripts import material_bundle_native as native
from scripts import material_bundle_qualification as fixtures


class NativeBundleContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.MaterialBundleContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.MaterialBundleContracts.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.MaterialBundleContracts()
        self.fixture.setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.root = self.state / "root"
        context = self.fixture.context
        self.expected = context["expected"]
        write_json(self.root / "policies/local-cpu.json", context["policy"])
        write_json(self.state / "storage-trust.json", context["trust"])
        write_json(self.state / "trusted-keys.json", {"approver": self.fixture.public})
        write_json(
            self.state / "storage-demo.json",
            {
                "candidate": {"candidate_reference": context["candidate_reference"]},
                "evaluation_reference": context["evaluation_reference"],
            },
        )
        (self.state / "keys").mkdir()
        (self.state / "keys/approver.pem").write_bytes(self.fixture.key.read_bytes())
        self.published = {}
        self.denial = "storage_read_rejected:42501"

    def get(self, client, table, reference):
        role = Path(client).name
        if role == "serving" and table != "releases":
            if self.denial is None:
                return b"bypass"
            raise Rejected(self.denial)
        if table == "releases":
            return self.published[reference]
        return self.fixture.get(role, table, reference)

    def put(self, client, table, content):
        if Path(client).name == "serving":
            raise Rejected("storage_write_rejected:42501")
        self.assertEqual((Path(client).name, table), ("promoter", "releases"))
        reference = native.digest(content)
        self.published.setdefault(reference, content)
        return reference

    def qualify(self, **changes):
        settings = {
            "validate": {"return_value": {"container_id": "owned"}},
            "source_fingerprint": {"return_value": self.expected["source_fingerprint"]},
            "command": {"return_value": self.expected["source_revision"]},
            "resolve_image": {"return_value": self.expected["image_id"]},
            "metadata_snapshot": {"return_value": {"evaluations": {"objects": 2}}},
            "release_snapshot": {"side_effect": lambda client: set(self.published)},
        }
        settings.update(changes)
        with contextlib.ExitStack() as stack:
            for name, values in settings.items():
                stack.enter_context(patch.object(native, name, **values))
            stack.enter_context(patch.object(native.storage, "get", side_effect=self.get))
            stack.enter_context(patch.object(native.storage, "put", side_effect=self.put))
            stack.enter_context(
                patch.object(
                    native.storage,
                    "connection_parameters",
                    side_effect=lambda client: {"user": "ml_" + Path(client).name},
                )
            )
            return native.qualify(self.root, self.state, "controlled")

    def test_real_signatures_roundtrip_and_all_runner_cases(self):
        report = self.qualify()
        self.assertEqual(report["status"], "pass")
        self.assertEqual(len(report["cases"]), 12)
        self.assertEqual(report["objects"], 9)
        self.assertEqual(len(self.published), 10)
        self.assertFalse(report["release_ready"])
        self.assertEqual(report["full_M10"], "inconclusive")

    def test_negative_bypass_or_wrong_rejection_fails_runner(self):
        for denial in (None, "wrong_reason"):
            self.denial = denial
            with self.subTest(denial=denial), self.assertRaisesRegex(Rejected, "native_negative"):
                self.qualify()

    def test_changed_metadata_inputs_and_release_set_are_not_accepted(self):
        with self.assertRaisesRegex(Rejected, "metadata_changed"):
            self.qualify(metadata_snapshot={"side_effect": [{"before": True}, {"after": True}]})
        with self.assertRaisesRegex(Rejected, "release_set"):
            self.qualify(release_snapshot={"return_value": set()})
        for name, initial in (
            ("source_fingerprint", self.expected["source_fingerprint"]),
            ("command", self.expected["source_revision"]),
            ("resolve_image", self.expected["image_id"]),
            ("validate", {"container_id": "owned"}),
        ):
            changed = {"container_id": "other"} if name == "validate" else "changed"
            with self.subTest(name=name), self.assertRaisesRegex(Rejected, "inputs_changed"):
                self.qualify(**{name: {"side_effect": [initial, changed]}})

    def test_same_reference_different_readback_is_rejected(self):
        read = native.material_bundle.read

        def changed(client, reference, **arguments):
            result = read(client, reference, **arguments)
            if Path(client).name == "serving":
                result["model"] = b"changed"
            return result

        with patch.object(native.material_bundle, "read", side_effect=changed):
            with self.assertRaisesRegex(Rejected, "readback_mismatch"):
                self.qualify()

    def test_nondeterministic_index_and_reference_are_rejected(self):
        original = native.material_bundle.create
        created = []

        def create(*arguments, **keywords):
            result = original(*arguments, **keywords)
            created.append(result)
            if len(created) == 2:
                result = copy.deepcopy(result)
                result["envelope"]["payload"] = "changed"
            return result

        with patch.object(native.material_bundle, "create", side_effect=create):
            with self.assertRaisesRegex(Rejected, "nondeterministic"):
                self.qualify()
        with patch.object(native.material_bundle, "publish", side_effect=["a" * 64, "b" * 64]):
            with self.assertRaisesRegex(Rejected, "idempotency"):
                self.qualify()

    def test_release_snapshot_checks_real_identity_and_bound(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchone.return_value = ("ml_serving",)
        connection.execute.return_value.fetchall.return_value = [("a" * 64,)]
        with patch.object(native.storage, "connect", return_value=connection):
            self.assertEqual(native.release_snapshot("serving"), {"a" * 64})
            connection.execute.return_value.fetchone.return_value = ("other",)
            with self.assertRaisesRegex(Rejected, "sql_identity"):
                native.release_snapshot("serving")
            connection.execute.return_value.fetchone.return_value = ("ml_serving",)
            connection.execute.return_value.fetchall.return_value *= 2001
            with self.assertRaisesRegex(Rejected, "too_large"):
                native.release_snapshot("serving")

    def test_cli_sanitizes_failure_and_does_not_retain_pass(self):
        report = {
            "scope": "controlled",
            "status": "pass",
            "cases": [],
            "full_M10": "inconclusive",
            "bundle_reference": "a" * 64,
        }
        output = self.state / "evidence/material-bundle-native.json"
        for error in (None, Rejected("private-details"), OSError("private-path")):
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                patch.object(native.sys, "argv", ["native", "--state", str(self.state)]),
                patch.object(native, "qualify", return_value=report, side_effect=error),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(native.main(), 1 if error else 0)
            self.assertNotIn("private", stdout.getvalue() + stderr.getvalue())
            self.assertEqual(read_json(output)["status"], "fail" if error else "pass")

    def test_cli_unsafe_output_and_repeated_write_failure_are_sanitized(self):
        for target in ("safe_child", "write_json"):
            with (
                patch.object(native.sys, "argv", ["native", "--state", str(self.state)]),
                patch.object(native, target, side_effect=Rejected("unsafe-path")),
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(native.main(), 1)
            self.assertNotIn("unsafe-path", stderr.getvalue())

    def test_module_entrypoint_rejects_missing_state(self):
        with (
            patch.object(native.sys, "argv", ["native", "--state", str(self.state / "missing")]),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as result,
        ):
            runpy.run_module("scripts.material_bundle_native", run_name="__main__")
        self.assertEqual(result.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
