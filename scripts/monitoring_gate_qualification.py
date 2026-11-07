"""M15 rejects stale, incomplete or cross-candidate evidence before admission."""

import copy
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import feedback, signing
from mlsecops import monitoring_gate as gate
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import feedback_native, feedback_native_qualification, monitoring_contracts
from scripts import monitoring_packet_qualification as packet_fixtures
from scripts import monitoring_reference_qualification as reference_fixtures

SOURCE = {
    "source_revision": "a" * 40,
    "source_fingerprint": "b" * 64,
    "image_id": "sha256:" + "c" * 64,
}
START = "2026-11-07T01:00:00+00:00"
END = "2026-11-07T01:01:00+00:00"


def observation():
    return {
        "schema_version": 1,
        "source": SOURCE,
        "source_dirty": False,
        "scope": "actual-candidate-kubernetes-inference",
        "status": "pass",
        "release_ready": False,
        "full_M15": "inconclusive",
        "started_at": START,
        "finished_at": END,
        "monitoring_campaign_id": "d" * 32,
        "candidate_reference": "e" * 64,
        "proposal_reference": "f" * 64,
        "qualification_permit_sha256": "1" * 64,
        "model_sha256": "2" * 64,
        "subject_sha256": "3" * 64,
        "native": {
            "scope": "actual-candidate-monitoring-observation",
            "status": "pass",
            "release_ready": False,
            "full_M15": "inconclusive",
            "worker_cleanup_verified": True,
            "model_sha256": "2" * 64,
            "subject_sha256": "3" * 64,
        },
    }


class MonitoringGateContracts(unittest.TestCase):
    def test_source_time_identity_and_terminal_state_are_mandatory(self):
        value = observation()
        gate.reconcile(value, SOURCE, started=START, finished=END)
        for key, replacement in (
            ("source", {}),
            ("source_dirty", 0),
            ("schema_version", True),
            ("status", "inconclusive"),
            ("scope", "fixture"),
            ("release_ready", True),
            ("full_M15", "pass"),
            ("started_at", "2026-11-06T00:00:00+00:00"),
            ("finished_at", "2026-11-08T00:00:00+00:00"),
            ("started_at", "2026-11-07T01:00:00"),
            ("monitoring_campaign_id", "../private"),
            ("candidate_reference", "bad"),
        ):
            with self.subTest(key=key), self.assertRaises((Rejected, ValueError, TypeError)):
                gate.reconcile({**value, key: replacement}, SOURCE, started=START, finished=END)
        for key, replacement in (
            ("status", "fail"),
            ("scope", "fixture"),
            ("release_ready", 0),
            ("full_M15", "pass"),
            ("worker_cleanup_verified", 1),
            ("model_sha256", "9" * 64),
            ("subject_sha256", "9" * 64),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                gate.reconcile(
                    {**value, "native": {**value["native"], key: replacement}},
                    SOURCE,
                    started=START,
                    finished=END,
                )
        for key in SOURCE:
            with self.subTest(key=key), self.assertRaises(Rejected):
                gate.reconcile(value, {**SOURCE, key: "bad"}, started=START, finished=END)

    def test_contract_child_requires_exact_inventory_and_empty_stderr(self):
        cases = [{"id": "one", "status": "pass", "expected": True, "actual": True}]
        value = {"scope": monitoring_contracts.SCOPE, "status": "pass", "checks": 1, "cases": cases}
        with (
            patch.object(monitoring_contracts, "case_ids", return_value={"one"}),
            patch.object(gate.subprocess, "run") as run,
        ):
            run.return_value = SimpleNamespace(returncode=0, stdout=canonical(value), stderr=b"")
            self.assertEqual(gate.contracts(Path.cwd()), value)
            for key, changed in (
                ("scope", "old"),
                ("status", "fail"),
                ("checks", True),
                ("checks", 2),
                ("cases", []),
                ("cases", cases * 2),
            ):
                run.return_value = SimpleNamespace(
                    returncode=0, stdout=canonical({**value, key: changed}), stderr=b""
                )
                with self.subTest(key=key), self.assertRaises(Rejected):
                    gate.contracts(Path.cwd())
            for code, stderr in ((1, b""), (0, b"PRIVATE")):
                run.return_value = SimpleNamespace(
                    returncode=code, stdout=canonical(value), stderr=stderr
                )
                with patch.object(gate, "contract_diagnostic"), self.assertRaises(Rejected):
                    gate.contracts(Path.cwd())
            run.return_value = SimpleNamespace(returncode=0, stdout=canonical(value), stderr=b"")
            with (
                patch.object(monitoring_contracts, "case_ids", return_value=set()),
                self.assertRaises(Rejected),
            ):
                gate.contracts(Path.cwd())

    def test_dispatch_redacts_failure_and_does_not_claim_missing_environment(self):
        from mlsecops import acceptance

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            root = Path(__file__).resolve().parents[1]
            self.assertEqual(acceptance.report("M15", "local-cpu", root, state)["exit_code"], 2)
            for name in ("workspace.json", "kubeconfig", "storage.json", "storage-demo.json"):
                (state / name).write_bytes(b"fixture")
            with patch.object(gate, "qualify", side_effect=Rejected("PRIVATE")):
                result = acceptance.report("M15", "local-cpu", root, state)
                self.assertEqual(result["exit_code"], 1)
                self.assertNotIn("PRIVATE", canonical(result).decode())
            with (
                patch.object(gate, "hosted", side_effect=Rejected("owned")),
                patch.object(gate, "write_json") as write,
                self.assertRaises(Rejected),
            ):
                gate.qualify(root, state)
            write.assert_not_called()


class RetainedMonitoringGateContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        packet_fixtures.PacketContracts.setUpClass()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        fixture = packet_fixtures.PacketContracts()
        payload = fixture.payload()
        trace = payload["context"]
        epoch = fixture.arguments["epoch"]
        self.directory = self.state / ("evidence/monitoring/" + epoch)
        self.payload = payload
        self.value = observation()
        self.value.update(
            monitoring_campaign_id=epoch,
            model_sha256=trace["model_sha256"],
            subject_sha256=trace["bundle_sha256"],
            proposal_reference=trace["proposal_sha256"],
            qualification_permit_sha256=trace["permit_sha256"],
        )
        self.value["native"] = {
            **payload["summary"],
            "scope": "actual-candidate-monitoring-observation",
            "worker_cleanup_verified": True,
            "model_sha256": trace["model_sha256"],
            "subject_sha256": trace["bundle_sha256"],
            "operator_retained_reverified": payload["summary"],
        }
        proof = feedback_native_qualification.proof()
        proof["input"] = feedback_native.fixture(payload["packet"])
        proof["stored"] = feedback.document(canonical(proof["input"]))
        proof["receipt"] = feedback.receipt(proof["stored"])
        proof["retry"] = proof["inspection"] = proof["receipt"]
        for name in ("after", "after_retry", "final"):
            proof[name]["quarantine"]["bytes"] = len(canonical(proof["stored"]))
        self.value["feedback_quarantine"] = feedback_native.verify(proof, payload["packet"])
        write_json(self.directory / "feedback/proof.json", proof)
        write_json(self.directory / "packet.json", payload)
        binding = {
            "reference": fixture.arguments["reference"],
            "context": trace,
            "campaign": epoch,
            "packet_hash": digest((self.directory / "packet.json").read_bytes()),
            "summary": payload["summary"],
        }
        write_json(self.directory / "binding.json", binding)
        self.public = {
            k: self.value[k]
            for k in (
                "source",
                "source_dirty",
                "started_at",
                "finished_at",
                "candidate_reference",
                "proposal_reference",
                "model_sha256",
                "subject_sha256",
                "qualification_permit_sha256",
                "native",
                "feedback_quarantine",
            )
        }
        self.public.update(
            campaign=epoch,
            status="pass",
            release_ready=False,
            binding_sha256=digest((self.directory / "binding.json").read_bytes()),
        )
        write_json(self.state / "evidence/kubernetes-monitoring-public.json", self.public)
        key = self.state / "reference.pem"
        public = signing.create_key(key)
        envelope = signing.sign(fixture.arguments["reference"], "monitor-reference", key)
        self.files = {n: {} for n in gate.ARTIFACTS}
        self.files.update(
            {
                "probe.json": self.value["native"],
                "config.json": {"expected_campaign": epoch},
                "request.json": {
                    "model": trace["model_sha256"],
                    "bundle": trace["bundle_sha256"],
                    "monitoring": {"reference": envelope, "reference_public": public},
                },
                "monitor-reference.json": {"envelope": envelope},
            }
        )
        self.candidate = self.state / ("candidate-inference/" + epoch)
        self.value["artifact_hashes"] = {}
        for name, value in self.files.items():
            write_json(self.candidate / name, value)
            self.value["artifact_hashes"][name] = digest((self.candidate / name).read_bytes())

    def test_primary_replay_reconstructs_real_http_windows_signatures_and_quarantine(self):
        files = gate.artifacts(self.state, self.value)
        metrics, hashes, lineage = gate.retained(self.state, self.value, files)
        self.assertEqual(metrics["observations"], 12000)
        self.assertEqual(metrics["feedback"]["submitted_records"], 10)
        self.assertEqual(len(hashes), 10)
        self.assertEqual(lineage, self.payload["context"]["lineage"])
        for name in gate.ARTIFACTS:
            path = self.candidate / name
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.subTest(name=name), self.assertRaises(Rejected):
                gate.artifacts(self.state, self.value)
            path.write_bytes(original)
        changed = copy.deepcopy(self.value)
        changed["native"]["observations"] = 11999
        with self.assertRaises(Rejected):
            gate.artifacts(self.state, changed)

    def test_summary_or_cross_candidate_artifacts_cannot_replace_primary(self):
        for name, key, replacement in (
            ("request.json", "model", "9" * 64),
            ("request.json", "bundle", "9" * 64),
            ("config.json", "expected_campaign", "9" * 32),
            ("monitor-reference.json", "envelope", {}),
        ):
            changed = copy.deepcopy(self.files)
            changed[name][key] = replacement
            with self.subTest(key=key), self.assertRaises(Rejected):
                gate.retained(self.state, self.value, changed)
        path = self.state / "evidence/kubernetes-monitoring-public.json"
        for key, replacement in (
            ("model_sha256", "9" * 64),
            ("campaign", "9" * 32),
            ("status", "fail"),
            ("release_ready", True),
        ):
            write_json(path, {**self.public, key: replacement})
            with self.subTest(key=key), self.assertRaises(Rejected):
                gate.retained(self.state, self.value, self.files)
        write_json(path, self.public)
        original = read_json(self.directory / "binding.json")
        changed = copy.deepcopy(original)
        changed["reference"]["positive_labels"] = 201
        write_json(self.directory / "binding.json", changed)
        with self.assertRaises(Rejected):
            gate.retained(self.state, self.value, self.files)
        for key in ("permit_sha256", "proposal_sha256", "bundle_sha256", "model_sha256"):
            changed = copy.deepcopy(original)
            changed["context"][key] = "9" * 64
            write_json(self.directory / "binding.json", changed)
            with self.subTest(key=key), self.assertRaises(Rejected):
                gate.retained(self.state, self.value, self.files)
        write_json(self.directory / "binding.json", original)
        actual = gate.kube_monitoring_native.reverify(self.state)
        for key, replacement in (
            ("status", "fail"),
            ("post_cleanup_reverified", 1),
            ("reference_sha256", "9" * 64),
        ):
            with (
                patch.object(
                    gate.kube_monitoring_native,
                    "reverify",
                    return_value={**actual, key: replacement},
                ),
                self.assertRaises(Rejected),
            ):
                gate.retained(self.state, self.value, self.files)

    def test_fresh_gate_and_offline_cleanup_pin_the_entire_primary_chain(self):
        private = self.state / "evidence/kubernetes-monitoring-private.json"

        def run(*args):
            write_json(private, self.value)
            return self.public

        controlled = {
            "scope": monitoring_contracts.SCOPE,
            "status": "pass",
            "checks": 1,
            "cases": [{"id": "test", "status": "pass", "expected": True, "actual": True}],
        }
        with (
            patch.object(gate, "hosted"),
            patch.object(gate, "materials", return_value={"fixture": "fixed"}) as materials,
            patch.object(gate, "source", return_value=SOURCE) as source,
            patch.object(gate, "contracts", return_value=controlled),
            patch.object(gate.kube_monitoring_native, "run", side_effect=run),
            patch.object(
                gate, "live_binding", return_value=self.payload["context"]["lineage"]
            ) as live,
            patch.object(gate, "now", side_effect=[START, END, END]) as clock,
        ):
            result = gate.qualify(self.state, self.state)
            self.assertEqual((result["status"], result["checks"]), ("pass", 8))
            write_json(self.state / "evidence/M15.json", {"status": "pass"})
            self.assertTrue(gate.post_cleanup(self.state)["post_cleanup_reverified"])
            for what in ("source", "methods", "lineage", "observed", "private"):
                source.side_effect = (
                    [SOURCE, {**SOURCE, "source_revision": "9" * 40}] if what == "source" else None
                )
                materials.side_effect = [{"fixture": "fixed"}, {}] if what == "methods" else None
                live.return_value = {} if what == "lineage" else self.payload["context"]["lineage"]
                clock.side_effect = [START, END, END]
                original_retained = gate.retained

                def retained(*args):
                    value = original_retained(*args)
                    if what == "private":
                        private.write_bytes(private.read_bytes() + b" ")
                    return value

                def changed_run(*args):
                    run()
                    return {} if what == "observed" else self.public

                with (
                    patch.object(gate, "retained", side_effect=retained),
                    patch.object(gate.kube_monitoring_native, "run", side_effect=changed_run),
                    self.subTest(what=what),
                    self.assertRaises(Rejected),
                ):
                    gate.qualify(self.state, self.state)
                self.assertEqual(
                    read_json(self.state / "evidence/monitoring-gate.json")["status"],
                    "inconclusive",
                )
        write_json(private, self.value)
        write_json(self.state / "evidence/monitoring-gate.json", result)
        for path in (
            private,
            self.state / "evidence/monitoring-gate-private.json",
            self.state / "evidence/M15.json",
            self.state / "evidence/monitoring-gate.json",
        ):
            content = path.read_bytes()
            value = read_json(path)
            if path == private:
                path.write_bytes(content + b" ")
            else:
                value[
                    "retained_packets"
                    if path.name == "monitoring-gate-private.json"
                    else "metrics"
                    if path.name == "monitoring-gate.json"
                    else "status"
                ] = {}
                write_json(path, value)
            with self.subTest(path=path.name), self.assertRaises(Rejected):
                gate.post_cleanup(self.state)
            path.write_bytes(content)


class LiveMonitoringBindingContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reference_fixtures.ReferenceContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        reference_fixtures.ReferenceContracts.tearDownClass()

    def test_signed_source_validation_and_permit_cannot_be_swapped(self):
        fixture = reference_fixtures.ReferenceContracts()
        fixture.setUp()
        self.addCleanup(fixture.fixture.doCleanups)
        frozen = fixture.build()
        package = fixture.package
        args = fixture.fixture.arguments
        context = args["context"]
        verified = (
            gate.verified_materials
        )  # The real signed package is checked below; SQL alone is substituted.
        from mlsecops import release_bundle

        verified = release_bundle.verify(package, **args)
        source = context["expected"]
        key = fixture.key.parent / "permit.pem"
        public = signing.create_key(key)
        permit = {
            "schema_version": 1,
            "purpose": gate.KIND,
            "campaign_id": "a" * 32,
            "environment": context["policy"]["environment"],
            "proposal_sha256": digest(canonical(package["envelope"])),
            "subject_sha256": verified["subject_sha256"],
            "model_sha256": digest(verified["model"]),
            **source,
            "issued_at": fixture.fixture.clock,
            "expires_at": fixture.fixture.clock + 600,
        }
        value = {
            "source": source,
            "actual_refusal": {"campaign_id": "b" * 32},
            "monitoring_campaign_id": "a" * 32,
            "candidate_reference": context["candidate_reference"],
            "proposal_reference": permit["proposal_sha256"],
            "model_sha256": permit["model_sha256"],
            "subject_sha256": permit["subject_sha256"],
            "qualification_permit_sha256": digest(canonical(permit)),
        }
        config = {
            "context": context,
            "publisher_public": args["publisher_public"],
            "permit_public": public,
            "permit_envelope": signing.sign(permit, gate.KIND, key),
            "expected_permit": value["qualification_permit_sha256"],
        }
        expected = {
            "model": value["model_sha256"],
            "bundle": value["subject_sha256"],
            "monitoring": {
                "reference": frozen["envelope"],
                "reference_public": fixture.public,
                "rows": fixture.rows,
            },
        }
        files = {"config.json": config, "request.json": expected, "monitor-reference.json": frozen}
        with (
            patch.object(
                gate,
                "verified_materials",
                return_value=(context, verified, package, args["publisher_public"]),
            ),
            patch.object(gate.time, "time", return_value=fixture.fixture.clock + 1),
        ):
            lineage = gate.live_binding(Path.cwd(), Path.cwd(), value, files)
            self.assertEqual(
                lineage["dataset_sha256"],
                gate.load_monitoring.reference(expected)["dataset_sha256"],
            )
            for field in (
                "candidate_reference",
                "proposal_reference",
                "model_sha256",
                "subject_sha256",
                "qualification_permit_sha256",
            ):
                with self.subTest(field=field), self.assertRaises(Rejected):
                    gate.live_binding(Path.cwd(), Path.cwd(), {**value, field: "9" * 64}, files)
            for name, field, replacement in (
                ("config.json", "publisher_public", "bad"),
                ("config.json", "context", {}),
                ("config.json", "expected_permit", "9" * 64),
            ):
                changed = copy.deepcopy(files)
                changed[name][field] = replacement
                with self.subTest(field=field), self.assertRaises(Rejected):
                    gate.live_binding(Path.cwd(), Path.cwd(), value, changed)
            changed = copy.deepcopy(files)
            changed["config.json"]["permit_envelope"] = signing.sign(
                {**permit, "campaign_id": "9" * 32}, gate.KIND, key
            )
            with self.assertRaises(Rejected):
                gate.live_binding(Path.cwd(), Path.cwd(), value, changed)
            for field, replacement in (
                ("validation_sha256", "9" * 64),
                ("validation_bytes", 0),
                ("split", "holdout"),
            ):
                changed = copy.deepcopy(files)
                changed["monitor-reference.json"]["evidence"][field] = replacement
                with self.subTest(field=field), self.assertRaises(Rejected):
                    gate.live_binding(Path.cwd(), Path.cwd(), value, changed)


class MonitoringInventoryContracts(unittest.TestCase):
    def test_missing_duplicate_skipped_failed_and_expected_failure_never_pass(self):
        class Sample(unittest.TestCase):
            def test_ok(self):
                pass

            def test_skip(self):
                self.skipTest("PRIVATE")

            def test_fail(self):
                self.fail("PRIVATE")

            @unittest.expectedFailure
            def test_expected(self):
                self.fail("PRIVATE")

        for names in (
            ("test_ok",),
            (),
            ("test_ok", "test_ok"),
            ("test_skip",),
            ("test_fail",),
            ("test_expected",),
        ):
            with patch.object(
                unittest.defaultTestLoader,
                "loadTestsFromNames",
                return_value=unittest.TestSuite(Sample(n) for n in names),
            ):
                result = monitoring_contracts.qualify()
                self.assertEqual(result["status"], "pass" if names == ("test_ok",) else "fail")
                self.assertNotIn("PRIVATE", str(result))
        self.assertTrue(monitoring_contracts.case_ids())
        for platform in ("win32", "linux"):
            for fail in (False, True):
                with (
                    patch.object(sys, "platform", platform),
                    patch("mlsecops.runtime_bootstrap.initialize") as initialize,
                    patch.object(
                        unittest.defaultTestLoader,
                        "loadTestsFromNames",
                        return_value=unittest.TestSuite(
                            [Sample("test_fail" if fail else "test_ok")]
                        ),
                    ),
                    patch.object(sys, "stdout", io.StringIO()),
                    self.assertRaises(SystemExit) as stopped,
                ):
                    runpy.run_path(monitoring_contracts.__file__, run_name="__main__")
                self.assertEqual(stopped.exception.code, int(fail))
                self.assertEqual(initialize.call_count, int(platform == "linux"))


if __name__ == "__main__":
    unittest.main()
