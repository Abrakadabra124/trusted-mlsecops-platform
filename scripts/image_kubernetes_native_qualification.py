"""Controlled hosted-driver qualification. Never starts Docker or infrastructure."""

import copy
import importlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, read_json
from scripts import image_audit as audit
from scripts.image_audit_qualification import fixtures

OWNER = {
    "repository": "Abrakadabra124/trusted-mlsecops-platform",
    "run_id": "42",
    "run_attempt": "1",
    "job": "validate",
    "source_revision": "a" * 40,
}
ENV = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "Linux",
    "RUNNER_ARCH": "X64",
    "GITHUB_REPOSITORY": OWNER["repository"],
    "GITHUB_RUN_ID": "42",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_JOB": "validate",
    "GITHUB_SHA": "a" * 40,
    "KUBERNETES_REPOSITORY_VISIBILITY": "public",
}


class NativeTests(unittest.TestCase):
    def setUp(self):
        name = "scripts.image_kubernetes_native"
        self.assertIsNotNone(importlib.util.find_spec(name), "native driver is not implemented")
        self.api = importlib.import_module(name)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.state = self.api.prepare(self.root, OWNER)
        self.calls = []
        self.present = set()
        self.serial = 0
        self.documents = {}
        self.scanner_failure = None
        self.db_change = False

    def execute(self, args, output, timeout, cidfile=None, *, output_limit=None):
        self.calls.append((args, output, timeout, output_limit))
        self.assertTrue(output.is_absolute())
        content = b""
        if args[:3] == ["docker", "container", "ls"]:
            cid = args[-1].removeprefix("id=")
            self.assertRegex(cid, r"^[0-9a-f]{64}$")
            content = (cid + "\n").encode() if cid in self.present else b""
        elif args[:3] == ["docker", "rm", "-f"]:
            self.assertEqual(len(args), 4)
            self.present.discard(args[3])
        output.write_bytes(content)
        return 0

    def scanner(self, run, name, image, arguments, mounts=(), network=False):
        self.calls.append((name, image, arguments, mounts, network))
        self.assertTrue(run.is_absolute())
        self.assertTrue(all(p.is_absolute() for p, _, _ in mounts))
        self.serial += 1
        (run / f"{name}.cid").write_text(f"{self.serial:064x}")
        (run / f"{name}.log").write_bytes(b"private scanner output")
        if name == self.scanner_failure:
            self.present.add(f"{self.serial:064x}")
            raise Rejected("SECRET-runtime-error")
        report = fixtures()[1]
        report["descriptor"]["db"]["status"]["built"] = datetime.now(UTC).isoformat()
        # Every invocation uses one fixed descriptor as well as the same DB bytes.
        self.built = getattr(self, "built", report["descriptor"]["db"]["status"]["built"])
        report["descriptor"]["db"]["status"]["built"] = self.built
        code = 0
        if name == "db-update":
            self.assertTrue(network)
            (mounts[0][0] / "database").write_bytes(b"fixed database")
        elif name.endswith("-sbom"):
            self.assertFalse(network)
            self.assertEqual(arguments, ["docker-archive:/input/image.tar", "-o", "syft-json"])
            sbom = fixtures()[0]
            config = next(t["config_id"] for t in self.api.targets() if name == t["name"] + "-sbom")
            sbom["source"]["metadata"]["imageID"] = config
            for p in sbom["artifacts"]:
                p["locations"] = [{"path": "/var/lib/dpkg/status"}]
            report = sbom
        elif name.endswith("-scan"):
            self.assertFalse(network)
            self.assertEqual(mounts[0][1:], ("/cache", False))
            self.assertEqual(mounts[1][1:], ("/input/sbom.json", False))
            self.assertEqual(
                arguments, ["sbom:/input/sbom.json", "--fail-on", "high", "-o", "json"]
            )
            config = next(t["config_id"] for t in self.api.targets() if name == t["name"] + "-scan")
            report["source"]["target"]["imageID"] = config
            report["matches"] = [fixtures()[2]]
            code = 2
        else:
            self.assertFalse(network)
            self.assertEqual(mounts[0][1:], ("/cache", False))
            purl = arguments[0]
            if purl.startswith("pkg:pypi/"):
                package, version, kind, advisory = (
                    "urllib3",
                    "1.26.7",
                    "python",
                    "GHSA-v845-jxx5-vc9f",
                )
            else:
                package, version = purl.removeprefix("pkg:golang/").split("@")
                kind, advisory = "go-module", "CVE-2023-39325"
            report["matches"] = [
                {
                    "artifact": {"name": package, "version": version, "type": kind},
                    "vulnerability": {"id": advisory, "severity": "High"},
                }
            ]
            code = 2
        path = run / f"{name}.json"
        path.write_bytes(canonical(report))
        if self.db_change and name.endswith("-scan"):
            (run / "cache" / "database").write_bytes(b"mutated")
        return code, path

    def batch(self, run, cache, database, db_files):
        self.assertEqual(
            len([c for c in self.calls if isinstance(c[0], str) and c[0].endswith("-scan")]), 4
        )
        directory = run / "kubernetes-modules"
        directory.mkdir()
        for i in range(28):
            (directory / f"module-{i:02d}.cid").write_text(f"{100 + i:064x}")
        return SimpleNamespace(directory=directory)  # Intentionally not JSON serializable.

    def join(self, component, sbom, report, code, batch, reference, database, timestamp=None):
        self.assertEqual(component["sbom_digest"], audit.file_hash(sbom))
        self.assertEqual(component["report_digest"], audit.file_hash(report))
        self.assertEqual(component["package_observation"]["image_id"], component["image_config_id"])
        self.assertEqual(reference, component["observed_reference"])
        self.assertTrue(component["scan_executed"])
        self.assertEqual(component["status"], "fail")
        self.assertEqual(code, 2)
        return {
            **copy.deepcopy(component),
            "sbom_validated": True,
            "coverage_profile": "kubernetes-supplemental",
        }

    def boundaries(self):
        stack = ExitStack()
        stack.enter_context(patch.object(audit, "execute", side_effect=self.execute))
        stack.enter_context(patch.object(audit, "scanner", side_effect=self.scanner))
        stack.enter_context(
            patch.object(
                audit,
                "inspect_image",
                side_effect=lambda ref: {
                    "Id": next(
                        (t["config_id"] for t in self.api.targets() if t["reference"] == ref),
                        "sha256:" + "f" * 64,
                    )
                },
            )
        )
        stack.enter_context(
            patch.object(audit, "identity", side_effect=lambda path, details: details["Id"])
        )
        stack.enter_context(
            patch.object(self.api.aliases, "resolve", return_value={"validated": True})
        )
        stack.enter_context(patch.object(self.api.scans, "run_batch", side_effect=self.batch))
        stack.enter_context(patch.object(self.api.scans, "read_batch", return_value=[{}] * 28))
        stack.enter_context(patch.object(self.api.scans, "join", side_effect=self.join))
        stack.enter_context(patch.object(self.api.scans, "coverage_valid", return_value=True))
        stack.enter_context(
            patch.object(
                self.api.image_scope,
                "coverage",
                return_value={"status": "pass", "expected_images": 4, "covered_images": 4},
            )
        )
        stack.enter_context(patch.object(self.api, "source", return_value="b" * 64))
        return stack

    def test_negative_unknown_inventory_stops_before_any_module_scan(self):
        with self.boundaries(), patch.object(self.api.aliases, "resolve", return_value=None):
            with self.assertRaises(Rejected):
                self.api.validate(self.root, self.state)
            self.api.scans.run_batch.assert_not_called()

    def test_binding_scans_all_four_and_one_batch_replays_after_cleanup(self):
        with self.boundaries():
            result = self.api.validate(self.root, self.state)
            self.api.scans.run_batch.assert_called_once()
            self.assertEqual(self.api.scans.join.call_count, 8)
        self.assertEqual(result["validation_status"], "pass")
        self.assertEqual(result["vulnerability_status"], "fail")
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["supplemental_scans"], 28)
        self.assertEqual(
            result["validation_coverage"],
            {"status": "pass", "expected_images": 4, "covered_images": 4},
        )
        self.assertEqual(result["cleanup"]["verified"], 40)
        raw = json.dumps(result)
        for forbidden in (
            "package_observation",
            "findings",
            str(self.root),
            "directory",
            "private scanner output",
        ):
            self.assertNotIn(forbidden, raw)
        pulls = [c[0][-1] for c in self.calls if c[0][:2] == ["docker", "pull"]]
        self.assertEqual(len(pulls), 6)
        self.assertTrue(all("@sha256:" in p for p in pulls))

    def test_failed_scanner_cleanup_continues_and_removes_only_recorded_id(self):
        self.scanner_failure = "db-update"
        with self.boundaries(), self.assertRaises(Rejected):
            self.api.validate(self.root, self.state)
        with patch.object(audit, "execute", side_effect=self.execute):
            result = self.api.cleanup(self.state, OWNER)
        self.assertTrue(result["verified"] > 0)
        self.assertEqual(result["status"], "pass")
        self.assertFalse(self.present)
        self.assertEqual(len([c for c in self.calls if c[0][:3] == ["docker", "rm", "-f"]]), 1)

    def test_missing_cid_and_invalid_cid_do_not_prevent_other_cleanup(self):
        run = self.state / "run"
        (run / "db-update.attempt").write_bytes(b"attempted\n")
        (run / "control-pypi.cid").write_bytes(b"--all")
        (run / "control-module.cid").write_text("e" * 64)
        self.present.add("e" * 64)
        with patch.object(audit, "execute", side_effect=self.execute):
            result = self.api.cleanup(self.state, OWNER)
        self.assertEqual(result, {"status": "inconclusive", "expected": 3, "verified": 1})
        self.assertFalse(self.present)

    def test_owned_directory_cannot_be_reused_or_reowned(self):
        with self.assertRaises((Rejected, FileExistsError)):
            self.api.prepare(self.root, OWNER)
        with self.assertRaises(Rejected):
            self.api.cleanup(self.state, {**OWNER, "run_id": "43"})

    def test_snapshot_mutation_never_grants_validation(self):
        self.db_change = True
        with self.boundaries(), self.assertRaises(Rejected):
            self.api.validate(self.root, self.state)

    def test_hosted_owner_is_fixed_and_rejects_wrong_or_incomplete_environment(self):
        with (
            patch.dict(os.environ, ENV, clear=True),
            patch.object(self.api.sys, "platform", "linux"),
        ):
            self.assertEqual(self.api.owner(), OWNER)
            for key in ENV:
                with self.subTest(key=key), patch.dict(os.environ, {key: "foreign value"}):
                    with self.assertRaises(Rejected):
                        self.api.owner()
        with (
            patch.dict(os.environ, ENV, clear=True),
            patch.object(self.api.sys, "platform", "win32"),
        ):
            with self.assertRaises(Rejected):
                self.api.owner()

    def test_failure_json_does_not_leak_exception_or_private_report(self):
        with (
            patch.object(self.api, "owner", return_value=OWNER),
            patch.object(self.api, "private_output", return_value=nullcontext()),
            patch.object(self.api, "prepare", return_value=self.state),
            patch.object(self.api, "validate", side_effect=Rejected("SECRET-runtime-error")),
            patch.object(audit, "execute", side_effect=self.execute),
        ):
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = self.api.main(["validate"], self.root)
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result["validation_status"], "inconclusive")
        self.assertFalse(result["release_ready"])
        self.assertNotIn("SECRET", output.getvalue())

    def test_source_requires_exact_head_and_clean_tracked_and_untracked_tree(self):
        with (
            patch.object(audit, "command", side_effect=["a" * 40, ""]),
            patch.object(audit, "source_fingerprint", return_value="b" * 64),
        ):
            self.assertEqual(self.api.source(self.root, OWNER), "b" * 64)
            self.assertIn("status", audit.command.call_args.args[0])
            self.assertIn("--untracked-files=all", audit.command.call_args.args[0])
        for outputs in (
            ["f" * 40],
            ["a" * 40, " M scripts/image_kubernetes_native.py"],
            ["a" * 40, "?? scripts/foreign.py"],
        ):
            with patch.object(audit, "command", side_effect=outputs), self.assertRaises(Rejected):
                self.api.source(self.root, OWNER)

    def test_failure_context_is_closed_and_identifies_attempted_module(self):
        directory = self.state / "run" / "kubernetes-modules"
        directory.mkdir()
        (directory / "output-03").mkdir()
        (directory / "output-99").mkdir()
        for error, label in (
            (Rejected("PRIVATE"), "contract_rejected"),
            (OSError("PRIVATE"), "io_failure"),
            (KeyboardInterrupt(), "interrupted"),
            (ValueError("PRIVATE"), "unexpected_failure"),
        ):
            result = self.api.failure_context(
                {"phase": "supplemental", "case_index": None}, self.state, error
            )
            self.assertEqual(
                result, {"phase": "supplemental", "case_index": 3, "exception_label": label}
            )
            self.assertNotIn("PRIVATE", json.dumps(result))

    def test_rejection_location_exposes_only_owned_module_and_line(self):
        from scripts import image_go_supplemental_contract as reader

        try:
            reader.assess("PRIVATE-CANARY", "bad", {}, {}, b"private", 0, {})
        except Rejected as error:
            result = self.api.failure_context(
                {"phase": "supplemental", "case_index": 23}, None, error
            )
        self.assertTrue(result["contract_locations"])
        for location in result["contract_locations"]:
            self.assertEqual(set(location), {"module", "line"})
            self.assertEqual(location["module"], "reader")
            self.assertIs(type(location["line"]), int)
        self.assertNotIn("PRIVATE-CANARY", str(result))
        self.assertNotIn(".py", str(result))
        cycle = Rejected("PRIVATE-CANARY")
        cycle.__context__ = cycle
        self.assertNotIn(
            "contract_locations", self.api.failure_context({"phase": "setup"}, None, cycle)
        )

    def test_cleanup_failure_modes_never_certify_absence(self):
        path = self.state / "run" / "db-update.cid"
        path.write_text("e" * 64)
        for raw, code in ((b"foreign", 0), (b"", 1), (b"e" * 64, 0), (b"a" * 4097, 0)):

            def execute(args, output, timeout, **kw):
                output.write_bytes(raw)
                return code

            with (
                self.subTest(raw=raw[:10], code=code),
                patch.object(audit, "execute", side_effect=execute),
            ):
                self.assertEqual(self.api.cleanup(self.state, OWNER)["status"], "inconclusive")
        with patch.object(audit, "execute", side_effect=OSError("daemon unavailable")):
            self.assertEqual(self.api.cleanup(self.state, OWNER)["verified"], 0)
        path.write_bytes(b"\xff")
        self.assertEqual(self.api.cleanup(self.state, OWNER)["status"], "inconclusive")

    def test_cleanup_duplicates_and_pending_batch_never_certify_absence(self):
        run = self.state / "run"
        (run / "db-update.cid").write_text("e" * 64)
        (run / "control-pypi.cid").write_text("e" * 64)
        with patch.object(audit, "execute", side_effect=self.execute):
            self.assertEqual(
                self.api.cleanup(self.state, OWNER),
                {"status": "inconclusive", "expected": 2, "verified": 1},
            )
            (run / "control-pypi.cid").unlink()
            (run / "batch.pending").write_bytes(b"attempted\n")
            self.assertEqual(self.api.cleanup(self.state, OWNER)["status"], "inconclusive")

    def test_scanner_writable_nested_cid_never_authorizes_foreign_container_removal(self):
        run = self.state / "run"
        writable = run / "kubernetes-modules" / "output-00"
        writable.mkdir(parents=True)
        (writable / "foreign.cid").write_text("f" * 64)
        (run / "unknown.cid").write_text("f" * 64)
        (run / "db-update.cid").write_text("e" * 64)
        self.present.update({"e" * 64, "f" * 64})
        with patch.object(audit, "execute", side_effect=self.execute):
            result = self.api.cleanup(self.state, OWNER)
        self.assertEqual(result, {"status": "pass", "expected": 1, "verified": 1})
        self.assertEqual(self.present, {"f" * 64})
        self.assertFalse(any("f" * 64 in str(c[0]) for c in self.calls))

    def test_snapshot_and_replay_and_coverage_fail_closed(self):
        cases = (
            (self.api.scans, "read_batch", {"return_value": [{}] * 27}),
            (self.api.scans, "coverage_valid", {"return_value": False}),
            (
                self.api.image_scope,
                "coverage",
                {
                    "return_value": {
                        "status": "inconclusive",
                        "expected_images": 4,
                        "covered_images": 3,
                    }
                },
            ),
            (self.api, "source", {"side_effect": ["b" * 64, "c" * 64]}),
            (
                self.api,
                "cleanup",
                {"return_value": {"status": "inconclusive", "expected": 40, "verified": 39}},
            ),
        )
        for index, (obj, name, kwargs) in enumerate(cases):
            root = self.root / str(index)
            root.mkdir()
            state = self.api.prepare(root, OWNER)
            self.calls.clear()
            with (
                self.subTest(name=name),
                self.boundaries(),
                patch.object(obj, name, **kwargs),
                self.assertRaises(Rejected),
            ):
                self.api.validate(root, state)
        root = self.root / "replay"
        root.mkdir()
        state = self.api.prepare(root, OWNER)
        self.calls.clear()
        count = 0

        def changed(*args):
            nonlocal count
            result = self.join(*args)
            count += 1
            if count > 4:
                result["matches"] = 99
            return result

        with (
            self.boundaries(),
            patch.object(self.api.scans, "join", side_effect=changed),
            self.assertRaises(Rejected),
        ):
            self.api.validate(root, state)

    def test_projection_rejects_unbounded_or_foreign_output(self):
        with self.boundaries():
            result = self.api.validate(self.root, self.state)
        components = read_json(self.state / "run" / "joined-components.json")
        for status in ("pass", "inconclusive"):
            changed = copy.deepcopy(components)
            for c in changed:
                c["status"] = status
            self.assertEqual(
                self.api.project(
                    changed, result["validation_coverage"], "b" * 64, {}, result["cleanup"]
                )["vulnerability_status"],
                status,
            )
        for key, value in (
            ("name", "PRIVATE"),
            ("status", "PRIVATE"),
            ("matches", 1000001),
            ("matches", True),
            ("catalogued_packages", -1),
            ("matches", 0),
        ):
            changed = copy.deepcopy(components)
            changed[0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(Rejected):
                self.api.project(
                    changed, result["validation_coverage"], "b" * 64, {}, result["cleanup"]
                )

    def test_cli_modes_and_cleanup_failure_are_safe(self):
        for args, fails in (
            (["unexpected", "SECRET"], False),
            (["cleanup"], False),
            (["validate"], False),
            (["cleanup"], True),
        ):
            with (
                patch.object(self.api, "owner", return_value=OWNER),
                patch.object(self.api, "prepare", return_value=self.state),
                patch.object(self.api, "private_output", return_value=nullcontext()),
                patch.object(
                    self.api,
                    "validate",
                    return_value={"validation_status": "pass", "release_ready": False},
                ),
                patch.object(
                    self.api,
                    "cleanup",
                    side_effect=Rejected("SECRET") if fails else None,
                    return_value={"status": "pass", "expected": 0, "verified": 0},
                ),
            ):
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    code = self.api.main(args, self.root)
            self.assertEqual(code, 1 if fails or args[0] == "unexpected" else 0)
            self.assertNotIn("SECRET", output.getvalue())
            self.assertFalse(json.loads(output.getvalue())["release_ready"])
        with self.assertRaises(KeyboardInterrupt):
            self.api.interrupted(15, None)

    def test_module_entry_rejects_without_hosted_authority(self):
        import runpy

        with (
            patch.object(self.api.sys, "argv", ["image_kubernetes_native.py", "wrong"]),
            patch.object(self.api.signal, "signal"),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as exited,
        ):
            runpy.run_path(str(Path(self.api.__file__)), run_name="__main__")
        self.assertEqual(exited.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
