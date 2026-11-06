import copy
import io
import json
import runpy
import sys
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import load_gate as gate
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, read_json, write_json
from scripts import kube_load_operator_qualification as operator_fixtures
from scripts import load_contracts
from scripts.load_resources_qualification import ORIGIN


def changed(value, path, replacement):
    value = copy.deepcopy(value)
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return value


class LoadGateContracts(unittest.TestCase):
    def setUp(self):
        fixture = operator_fixtures.OperatorContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root = fixture.root
        self.packet = fixture.op.destination
        native = fixture.finish()
        native.update(
            scope="actual-candidate-load-observation",
            status="pass",
            release_ready=False,
            full_M14="inconclusive",
            model_sha256="a" * 64,
            subject_sha256="b" * 64,
            operator_retained_reverified=True,
        )
        self.source = {
            "source_revision": "c" * 40,
            "source_fingerprint": "d" * 64,
            "image_id": "sha256:" + "e" * 64,
        }
        self.start = datetime.fromtimestamp(ORIGIN / 1e9 - 10, UTC).isoformat()
        self.finish = datetime.fromtimestamp(ORIGIN / 1e9 + 200, UTC).isoformat()
        self.value = {
            "source": self.source,
            "source_dirty": False,
            "schema_version": 1,
            "scope": "actual-candidate-kubernetes-inference",
            "status": "pass",
            "release_ready": False,
            "full_M14": "inconclusive",
            "native": native,
            "candidate_reference": "f" * 64,
            "proposal_reference": "1" * 64,
            "qualification_permit_sha256": "2" * 64,
            "model_sha256": "a" * 64,
            "subject_sha256": "b" * 64,
            "started_at": self.start,
            "finished_at": self.finish,
            "proposal_issued_at": int(ORIGIN / 1e9 - 20),
            "load_campaign_id": fixture.op.campaign,
        }
        self.artifacts = self.root / "candidate-inference" / fixture.op.campaign
        self.value["artifact_hashes"] = {}
        for name in ("reference.json", "config.json", "request.json", "probe.json"):
            write_json(self.artifacts / name, native if name == "probe.json" else {"fixture": name})
            self.value["artifact_hashes"][name] = digest(bounded_read(self.artifacts / name))
        self.controlled = {
            "scope": load_contracts.SCOPE,
            "status": "pass",
            "checks": 1,
            "cases": [{"id": "fixed", "status": "pass", "expected": True, "actual": True}],
        }

    def reconcile(self, value=None, source=None):
        return gate.reconcile(
            self.value if value is None else value,
            self.source if source is None else source,
            started=self.start,
            finished=self.finish,
        )

    def test_real_retained_composition_checks_hashes_measurement_and_resources(self):
        self.assertEqual(self.reconcile(), self.value["native"])
        result = gate.retained(self.root, self.value)
        self.assertEqual(len(result), 7)
        self.assertEqual(
            result["finish-request.json"],
            self.value["native"]["operator"]["retained_sha256"]["finish-request.json"],
        )
        self.assertNotIn("records", result)
        for bad in (False, 1, None):
            with self.assertRaises(Rejected):
                gate.require(bad)

    def test_subject_source_status_flags_time_and_golden_cannot_be_substituted(self):
        mutations = [
            (("source", "source_revision"), "0" * 40),
            (("source_dirty",), True),
            (("schema_version",), True),
            (("schema_version",), 2),
            (("scope",), "foreign"),
            (("status",), "inconclusive"),
            (("release_ready",), True),
            (("full_M14",), "pass"),
            (("candidate_reference",), "invalid"),
            (("started_at",), "2000-01-01T00:00:00+00:00"),
            (("finished_at",), "2999-01-01T00:00:00+00:00"),
            (("started_at",), self.start.split("+")[0]),
            (("proposal_issued_at",), True),
            (("proposal_issued_at",), -1),
            (("proposal_issued_at",), int(ORIGIN / 1e9 + 300)),
            (("native", "scope"), "foreign"),
            (("native", "status"), "fail"),
            (("native", "release_ready"), True),
            (("native", "full_M14"), "pass"),
            (("native", "profile_met"), False),
            (("native", "worker_cleanup_verified"), False),
            (("native", "operator_retained_reverified"), 1),
            (("native", "model_sha256"), "3" * 64),
            (("native", "golden", "model_sha256"), "3" * 64),
            (("native", "subject_sha256"), "3" * 64),
            (("native", "golden", "bundle_sha256"), "3" * 64),
            (("native", "golden", "rows_per_request"), True),
            (("native", "golden", "rows_per_request"), 2),
            (("native", "golden", "absolute_score_tolerance"), 0.1),
            (("native", "golden", "payload_sha256"), "invalid"),
            (("native", "measurement", "profile_met"), False),
            (("native", "overload", "profile_met"), False),
        ]
        for path, value in mutations:
            with (
                self.subTest(path=path, value=value),
                self.assertRaises((Rejected, ValueError, TypeError)),
            ):
                self.reconcile(changed(self.value, path, value))
        for key in self.source:
            for replacement in (False, "bad"):
                with self.subTest(key=key), self.assertRaises(Rejected):
                    self.reconcile(source={**self.source, key: replacement})

    def test_packet_and_artifact_bytes_are_checked_before_use(self):
        for directory, names in (
            (self.packet, gate.PACKETS),
            (self.artifacts, tuple(self.value["artifact_hashes"])),
        ):
            for name in names:
                with self.subTest(name=name):
                    content = bounded_read(directory / name)
                    try:
                        (directory / name).write_bytes(content + b" ")
                        with self.assertRaises(Rejected):
                            gate.retained(self.root, self.value)
                    finally:
                        (directory / name).write_bytes(content)
        for campaign in (True, "../foreign"):
            with self.assertRaises(Rejected):
                gate.retained(self.root, {**self.value, "load_campaign_id": campaign})

    def test_rehashed_packets_cannot_hide_false_summary_window_or_resource_values(self):
        mutations = [
            ("start-request.json", ("phase",), "finish"),
            ("start-request.json", ("campaign",), "f" * 32),
            ("start-request.json", ("payload", "golden", "model_sha256"), "f" * 64),
            ("finish-request.json", ("payload", "observation", "exhausted"), True),
            ("finish-request.json", ("payload", "summary", "measured", "successes"), 999),
            ("finish-request.json", ("payload", "overload", "recovered"), False),
            (
                "finish-request.json",
                ("payload", "diagnostics", "timings", "engine_wait", "count"),
                1,
            ),
            ("resources.json", ("window", "start_ns"), 1),
            ("resources.json", ("samples", "controller"), []),
            ("resources.json", ("compute", "kubelet_housekeeping_interval_seconds"), 10),
        ]
        for name, path, replacement in mutations:
            with self.subTest(name=name, path=path):
                content = bounded_read(self.packet / name)
                value = copy.deepcopy(self.value)
                try:
                    write_json(self.packet / name, changed(json.loads(content), path, replacement))
                    value["native"]["operator"]["retained_sha256"][name] = digest(
                        bounded_read(self.packet / name)
                    )
                    with self.assertRaises(Rejected):
                        gate.retained(self.root, value)
                finally:
                    (self.packet / name).write_bytes(content)
        for path, replacement in (
            (("native", "measurement", "measured", "successes"), 999),
            (("native", "overload", "elapsed_ns"), 20),
            (("native", "diagnostics", "timings", "engine_wait", "count"), 1),
            (("native", "operator", "resources", "worker", "samples"), 0),
            (("native", "operator", "summary_sha256"), "0" * 64),
            (("native", "operator", "diagnostics_sha256"), "0" * 64),
            (("started_at",), self.finish),
            (("finished_at",), self.start),
        ):
            with self.subTest(path=path), self.assertRaises(Rejected):
                gate.retained(self.root, changed(self.value, path, replacement))
        content = bounded_read(self.artifacts / "probe.json")
        write_json(self.artifacts / "probe.json", {"changed": True})
        self.value["artifact_hashes"]["probe.json"] = digest(
            bounded_read(self.artifacts / "probe.json")
        )
        with self.assertRaises(Rejected):
            gate.retained(self.root, self.value)
        (self.artifacts / "probe.json").write_bytes(content)

    def test_contract_inventory_skips_missing_methods_and_stderr_are_fail_closed(self):
        process = SimpleNamespace(returncode=0, stderr=b"", stdout=canonical(self.controlled))
        with (
            patch.object(gate.subprocess, "run", return_value=process),
            patch.object(load_contracts, "case_ids", return_value={"fixed"}) as names,
        ):
            self.assertEqual(gate.contracts(self.root), self.controlled)
            for field, value in (
                ("status", "fail"),
                ("scope", "foreign"),
                ("checks", True),
                ("checks", 2),
                ("cases", []),
            ):
                process.stdout = canonical({**self.controlled, field: value})
                with self.assertRaises(Rejected):
                    gate.contracts(self.root)
            process.stdout = canonical(self.controlled)
            names.return_value = set()
            with self.assertRaises(Rejected):
                gate.contracts(self.root)
            names.return_value = {"fixed"}
            process.returncode = 1
            with self.assertRaises(Rejected):
                gate.contracts(self.root)
            process.returncode = 0
            process.stderr = b"PRIVATE"
            with self.assertRaises(Rejected):
                gate.contracts(self.root)

    def test_fresh_composition_rechecks_source_methods_and_private_report(self):
        private = self.root / "evidence/kubernetes-load-private.json"
        observed = {"source": self.source, "status": "pass", "native": self.value["native"]}

        def run(*args):
            write_json(private, self.value)
            return observed

        with (
            patch.object(gate, "hosted"),
            patch.object(gate, "materials", return_value={"fixed": "a"}) as methods,
            patch.object(gate, "source", return_value=self.source) as source,
            patch.object(gate, "contracts", return_value=self.controlled),
            patch.object(gate.kube_load_native, "run", side_effect=run),
            patch.object(gate, "now", side_effect=[self.start, self.finish, self.finish]) as clock,
        ):
            result = gate.qualify(self.root, self.root)
            self.assertEqual(result["status"], "pass")
            self.assertFalse(result["release_ready"])
            self.assertEqual(result["checks"], 7)
            for what in ("source", "methods", "private", "status", "native", "observed-source"):
                with self.subTest(what=what):
                    clock.side_effect = [self.start, self.finish, self.finish]
                    source.side_effect = None
                    methods.side_effect = None
                    observed.update(status="pass", source=self.source, native=self.value["native"])
                    if what == "source":
                        source.side_effect = [
                            self.source,
                            {**self.source, "source_revision": "f" * 40},
                        ]
                    if what == "methods":
                        methods.side_effect = [{"fixed": "a"}, {"fixed": "b"}]
                    if what == "status":
                        observed["status"] = "fail"
                    if what == "native":
                        observed["native"] = {}
                    if what == "observed-source":
                        observed["source"] = {}
                    original = gate.retained

                    def retained(*args):
                        checked = original(*args)
                        if what == "private":
                            private.write_bytes(private.read_bytes() + b" ")
                        return checked

                    with (
                        patch.object(gate, "retained", side_effect=retained),
                        self.assertRaises(Rejected),
                    ):
                        gate.qualify(self.root, self.root)
                    self.assertEqual(
                        read_json(self.root / "evidence/load-gate.json")["status"], "inconclusive"
                    )

    def test_dispatch_requires_environment_and_redacts_failures(self):
        from mlsecops import acceptance

        root = Path(__file__).resolve().parents[1]
        self.assertEqual(acceptance.report("M14", "local-cpu", root, self.root)["exit_code"], 2)
        for name in ("workspace.json", "kubeconfig", "storage.json", "storage-demo.json"):
            (self.root / name).write_bytes(b"fixture")
        evidence = {
            "status": "pass",
            "started_at": self.start,
            "source_dirty": False,
            "cases": [],
            "checks": 0,
            "metrics": {},
            "limitations": [],
            "artifact_hashes": {},
            "input_digests": {"model": "a" * 64},
        }
        with patch.object(gate, "qualify", return_value=evidence) as qualify:
            self.assertEqual(acceptance.report("M14", "local-cpu", root, self.root)["exit_code"], 0)
            for error, code in (
                (Rejected("trust_hosted_runner_required"), 2),
                (OSError("PRIVATE"), 2),
                (Rejected("PRIVATE"), 1),
                (ValueError("PRIVATE"), 1),
                (KeyError("PRIVATE"), 1),
                (TypeError("PRIVATE"), 1),
            ):
                qualify.side_effect = error
                result = acceptance.report("M14", "local-cpu", root, self.root)
                self.assertEqual(result["exit_code"], code)
                self.assertNotIn("PRIVATE", canonical(result).decode())
        with (
            patch.object(gate, "hosted", side_effect=Rejected("guard")),
            patch.object(gate, "write_json") as write,
            self.assertRaisesRegex(Rejected, "guard"),
        ):
            gate.qualify(root, self.root)
        write.assert_not_called()


class LoadContractRunner(unittest.TestCase):
    def test_missing_skipped_failed_duplicate_and_expected_failure_are_not_passes(self):
        class Sample(unittest.TestCase):
            def test_ok(self):
                pass

            def test_skip(self):
                self.skipTest("PRIVATE")

            def test_failure(self):
                self.fail("PRIVATE")

            @unittest.expectedFailure
            def test_expected(self):
                self.fail("PRIVATE")

        for names in (
            ("test_ok",),
            ("test_skip",),
            ("test_failure",),
            ("test_expected",),
            ("test_ok", "test_ok"),
            (),
        ):
            suite = unittest.TestSuite(Sample(name) for name in names)
            with patch.object(unittest.defaultTestLoader, "loadTestsFromNames", return_value=suite):
                value = load_contracts.qualify()
            self.assertEqual(value["status"], "pass" if names == ("test_ok",) else "fail")
            self.assertNotIn("PRIVATE", str(value))
        self.assertTrue(load_contracts.case_ids())
        for platform in ("win32", "linux"):
            for failure in (False, True):
                suite = unittest.TestSuite([Sample("test_failure" if failure else "test_ok")])
                with (
                    patch.object(sys, "platform", platform),
                    patch("mlsecops.runtime_bootstrap.initialize") as initialize,
                    patch.object(
                        unittest.defaultTestLoader, "loadTestsFromNames", return_value=suite
                    ),
                    redirect_stdout(io.StringIO()),
                    self.assertRaises(SystemExit) as exit,
                ):
                    runpy.run_path(load_contracts.__file__, run_name="__main__")
                self.assertEqual(exit.exception.code, int(failure))
                self.assertEqual(initialize.call_count, int(platform == "linux"))
        with (
            patch.object(sys, "platform", "linux"),
            patch("mlsecops.runtime_bootstrap.initialize", side_effect=Rejected("controlled-stop")),
            patch.object(unittest.defaultTestLoader, "loadTestsFromNames") as loader,
            self.assertRaisesRegex(Rejected, "controlled-stop"),
        ):
            runpy.run_path(load_contracts.__file__, run_name="__main__")
        loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
