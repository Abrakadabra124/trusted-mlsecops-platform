import contextlib
import copy
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import kube_worker, load_diagnostics, load_measurement
from mlsecops.contracts import Rejected, canonical, decode, read_json
from scripts import kube_load_operator as operator
from scripts.kube_serving_runtime_qualification import PROFILE
from scripts.load_clock_qualification import anchors
from scripts.load_golden_qualification import expected
from scripts.load_measurement_qualification import rows
from scripts.load_resources_qualification import ORIGIN, snapshot


class OperatorContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.op = operator.Coordinator(self.root, PROFILE, "a" * 32, expected())
        self.job = operator.kube_serving_runtime.document(PROFILE, "b" * 32)
        self.job["metadata"]["uid"] = "job-uid"
        self.worker = {
            "metadata": {
                "name": "worker-one",
                "namespace": "ml-serve",
                "uid": "worker-uid",
                "ownerReferences": [{"uid": "job-uid", "controller": True}],
            },
            "spec": {
                **copy.deepcopy(self.job["spec"]["template"]["spec"]),
                "nodeName": operator.cluster.NODE,
            },
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {
                        "imageID": "containerd://" + PROFILE["image_id"],
                        "restartCount": 0,
                        "state": {"running": {}},
                    }
                ],
            },
        }
        self.probe = copy.deepcopy(self.worker)
        self.probe["metadata"].update(name="probe-one", namespace="ml-serving", uid="probe-uid")
        self.op.probe = copy.deepcopy(self.probe)
        self.seconds, self.deleted, self.failure = 0, False, False
        self.request = None
        self.stderr = b""
        self.acks = []
        self.addCleanup(patch.stopall)
        patch.object(operator, "kubectl", side_effect=self.kubectl).start()
        patch.object(kube_worker, "image_config", side_effect=lambda identity: identity).start()
        patch.object(
            operator.time, "time_ns", side_effect=lambda: ORIGIN + self.seconds * 1_000_000_000
        ).start()
        patch.object(operator.time, "monotonic", return_value=100).start()

    def kubectl(self, state, args, value=None, **kwargs):
        if args[0] == "exec":
            if args[-1] == "read":
                return SimpleNamespace(
                    stdout=canonical(self.request), returncode=int(self.failure), stderr=self.stderr
                )
            self.acks.append(copy.deepcopy(value))
            return SimpleNamespace(stdout=b"", returncode=0)
        if "--raw" in args:
            document = snapshot(self.seconds)
            document["node"]["nodeName"] = operator.cluster.NODE
            original = document["pods"][0]
            document["pods"] = []
            for pod in (self.probe, self.worker):
                entry = copy.deepcopy(original)
                entry["podRef"] = {
                    key: pod["metadata"][key] for key in ("name", "namespace", "uid")
                }
                document["pods"].append(entry)
        elif args[1] == "node":
            document = {
                "status": {
                    "capacity": {"cpu": "2", "memory": "8Gi"},
                    "nodeInfo": {
                        key: "fixture"
                        for key in (
                            "architecture",
                            "operatingSystem",
                            "kernelVersion",
                            "containerRuntimeVersion",
                            "kubeletVersion",
                        )
                    },
                }
            }
        elif args[1] == "job":
            if self.deleted:
                return SimpleNamespace(stdout=b"")
            document = self.job
        elif args[1] == "pods":
            document = {"items": [] if self.deleted else [self.worker]}
        elif args[1] == "pod":
            document = self.probe
        else:
            raise AssertionError(args)
        return SimpleNamespace(stdout=canonical(document), returncode=0)

    def start_payload(self):
        return {
            "session": "b" * 32,
            "job": self.job["metadata"]["name"],
            "job_uid": "job-uid",
            "pod_uid": "worker-uid",
            "golden": self.op.golden,
        }

    def begin(self):
        self.request = {
            "phase": "start",
            "campaign": self.op.campaign,
            "payload": self.start_payload(),
        }
        self.op.observe(self.probe)

    def finish_payload(self):
        observation = {
            "records": rows(),
            "elapsed_ns": 130_000_000_000,
            "exhausted": False,
            "clock": anchors(),
        }
        summary = load_measurement.summarize(
            **{key: observation[key] for key in ("records", "elapsed_ns", "exhausted")}
        )
        limited = load_diagnostics.reasons()
        limited["overload"]["overloaded"] = 32
        return {
            "observation": observation,
            "summary": summary,
            "golden": self.op.golden,
            "diagnostics": load_diagnostics.result(load_diagnostics.Timings(), limited),
            "overload": {
                "attempts": 40,
                "correct": 8,
                "limited": 32,
                "errors": 0,
                "elapsed_ns": 10_000_000,
                "recovered": True,
                "profile_met": True,
            },
        }

    def finish(self):
        self.begin()
        for i in range(10, 141, 10):
            self.seconds = i
            self.op.sample()
        self.request = {
            "phase": "finish",
            "campaign": self.op.campaign,
            "payload": self.finish_payload(),
        }
        self.op.observe(self.probe)
        payload = self.request["payload"]
        return {
            "operator": self.op.receipt,
            "measurement": payload["summary"],
            "overload": payload["overload"],
            "diagnostics": payload["diagnostics"],
            "golden": self.op.golden,
            "worker_cleanup_verified": True,
            "profile_met": True,
        }

    def test_real_contract_composition_retention_and_independent_cleanup(self):
        self.op.probe = None
        report = self.finish()
        self.assertEqual(self.op.phases, ["start", "finish"])
        self.assertEqual([value["status"] for value in self.acks], ["pass", "pass"])
        self.assertEqual(self.op.finish(report, canonical(report) + b"\n"), report)
        self.op.observe(self.probe)  # after finish, no exec against an exiting child
        self.assertEqual(len(self.acks), 2)
        with self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"):
            self.op.reverify()
        self.deleted = True
        self.assertTrue(self.op.reverify())
        self.assertEqual(
            set(read_json(self.op.destination / "resources.json")["samples"]),
            {"controller", "worker"},
        )
        self.assertFalse(report["operator"]["resources"]["worker"]["true_peak_memory_measured"])

    def test_phase_binding_duplicates_replay_and_exec_failure(self):
        self.op.observe(self.probe)  # no pending packet
        for request in (
            {"phase": "finish", "campaign": self.op.campaign, "payload": {}},
            {"phase": "start", "campaign": "foreign", "payload": {}},
            {"phase": "unknown", "campaign": self.op.campaign, "payload": {}},
            {"phase": "start", "campaign": self.op.campaign, "payload": []},
        ):
            self.request = request
            with self.assertRaises(Rejected):
                self.op.observe(self.probe)
        self.request = None
        self.failure = True
        with self.assertRaisesRegex(Rejected, "load_exchange_read_failed"):
            self.op.observe(self.probe)
        self.probe["status"]["phase"] = "Failed"
        self.op.observe(self.probe)
        self.failure = False
        self.probe["status"]["phase"] = "Running"
        self.begin()
        self.seconds = 10
        self.op.last_sample = 0
        self.op.observe(self.probe)
        self.assertEqual(len(self.op.samples["worker"]), 2)
        self.assertEqual(len(self.acks), 1)
        self.request["payload"]["golden"] = {}
        with self.assertRaisesRegex(Rejected, "load_exchange_changed"):
            self.op.observe(self.probe)
        replaced = copy.deepcopy(self.probe)
        replaced["metadata"]["uid"] = "foreign"
        with self.assertRaisesRegex(Rejected, "load_probe_replaced"):
            self.op.observe(replaced)

    def test_conflicting_resource_pair_is_diagnosed_but_never_acknowledged_as_pass(self):
        self.begin()
        for i in range(10, 141, 10):
            self.seconds = i
            self.op.sample()
        pair = self.op.samples["worker"]
        conflict = {**pair[5], "cpu_core_ns": pair[5]["cpu_core_ns"] + 1}
        pair.insert(6, conflict)
        self.request = {
            "phase": "finish",
            "campaign": self.op.campaign,
            "payload": self.finish_payload(),
        }
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            self.assertRaisesRegex(Rejected, "reset_or_change"),
        ):
            self.op.observe(self.probe)
        diagnostic = decode(output.getvalue().encode())
        self.assertEqual(diagnostic["scope"], "load-resource-rejection-diagnostic")
        self.assertEqual(diagnostic["container"], "worker")
        self.assertEqual(diagnostic["samples"], pair[5:7])
        self.assertEqual(diagnostic["diagnostics"], self.request["payload"]["diagnostics"])
        self.assertEqual(diagnostic["measurement"], self.request["payload"]["summary"])
        self.assertFalse(diagnostic["release_ready"])
        self.assertEqual(self.op.phases, ["start"])
        self.assertEqual(self.acks[-1]["status"], "fail")
        self.assertIsNone(self.op.receipt)
        self.assertIn("resources.json", self.op.hashes)

    def test_failed_phase_is_acknowledged_as_failure_not_pass(self):
        self.request = {
            "phase": "start",
            "campaign": self.op.campaign,
            "payload": self.start_payload(),
        }
        with patch.object(self.op, "begin", side_effect=Rejected("load_bad_fixture")):
            with self.assertRaisesRegex(Rejected, "load_bad_fixture"):
                self.op.observe(self.probe)
        self.assertEqual(self.op.phases, [])
        self.assertEqual(self.acks[-1]["status"], "fail")

    def test_exit_status_race_is_bounded_and_cannot_acknowledge_a_request(self):
        self.failure = True
        self.stderr = b'error: container not found ("worker")'
        with patch.object(operator.time, "monotonic", side_effect=[0, 4, 5]):
            self.op.observe(self.probe)
            self.op.observe(self.probe)
            with self.assertRaisesRegex(Rejected, "load_exchange_read_failed"):
                self.op.observe(self.probe)
        self.assertEqual(self.acks, [])
        self.assertEqual(self.op.phases, [])
        self.failure = False
        self.op.observe(self.probe)
        self.assertIsNone(self.op.exec_exit_deadline)
        self.failure = True
        self.probe["spec"]["nodeName"] = "foreign"
        with self.assertRaisesRegex(Rejected, "load_exchange_read_failed"):
            self.op.observe(self.probe)

    def test_changed_uid_job_spec_image_restart_and_node_fail_closed(self):
        self.begin()
        for target, path, value in (
            (self.probe, ("metadata", "uid"), "foreign"),
            (self.probe, ("spec", "nodeName"), "foreign"),
            (self.probe, ("status", "containerStatuses", 0, "restartCount"), 1),
            (
                self.probe,
                ("status", "containerStatuses", 0, "imageID"),
                "containerd://sha256:" + "f" * 64,
            ),
            (self.job, ("metadata", "uid"), "foreign"),
            (self.worker, ("metadata", "uid"), "foreign"),
            (self.worker, ("spec", "nodeName"), "foreign"),
            (self.worker, ("status", "containerStatuses", 0, "restartCount"), 1),
        ):
            selected = target
            for part in path[:-1]:
                selected = selected[part]
            original = selected[path[-1]]
            selected[path[-1]] = value
            try:
                with self.subTest(path=path), self.assertRaises(Rejected):
                    self.op.sample()
            finally:
                selected[path[-1]] = original
        self.deleted = True
        with self.assertRaises(Rejected):
            self.op.identities()

    def test_packet_and_summary_changes_never_override_current_measurement(self):
        report = self.finish()
        for field, value in (
            ("operator", {}),
            ("measurement", {}),
            ("overload", {}),
            ("diagnostics", {}),
            ("golden", {}),
            ("worker_cleanup_verified", 1),
            ("profile_met", 1),
        ):
            mutated = {**report, field: value}
            with self.assertRaises(Rejected):
                self.op.finish(mutated, canonical(mutated) + b"\n")
        with self.assertRaises(Rejected):
            self.op.finish(report, canonical(report) + b"\nprivate")
        path = self.op.destination / "resources.json"
        content = path.read_bytes()
        path.write_bytes(content + b" ")
        with self.assertRaisesRegex(Rejected, "load_retained_changed"):
            self.op.reverify()
        path.write_bytes(content)
        self.op.hashes.pop("resources.json")
        with self.assertRaisesRegex(Rejected, "load_retained_incomplete"):
            self.op.reverify()

    def test_incomplete_resource_tail_and_changed_golden_or_summary_fail(self):
        self.begin()
        for field, value in (("golden", {}), ("summary", {})):
            payload = self.finish_payload()
            payload[field] = value
            with self.assertRaises(Rejected):
                self.op.end(payload)
        with (
            patch.object(self.op, "sample"),
            patch.object(operator.time, "monotonic", side_effect=[0, 31]),
            self.assertRaisesRegex(Rejected, "load_resource_tail_missing"),
        ):
            self.op.end(self.finish_payload())

    def test_tail_wait_and_failed_retained_write_are_not_silently_accepted(self):
        self.begin()
        for seconds in range(10, 131, 10):
            self.seconds = seconds
            self.op.sample()
        with patch.object(
            operator.time, "sleep", side_effect=lambda _: setattr(self, "seconds", 140)
        ) as sleep:
            self.assertIn("resources", self.op.end(self.finish_payload()))
            sleep.assert_called_once_with(2)
        with (
            patch.object(operator, "bounded_read", return_value=b"changed"),
            self.assertRaisesRegex(Rejected, "load_retained_write"),
        ):
            self.op.retain("bad.json", {})

    def test_missing_initial_metrics_retry_but_identity_failure_is_immediate(self):
        with (
            patch.object(
                self.op, "sample", side_effect=[Rejected("load_resource_missing"), None]
            ) as sample,
            patch.object(operator.time, "sleep"),
        ):
            self.op.begin(self.start_payload())
        self.assertEqual(sample.call_count, 2)
        with (
            patch.object(
                self.op, "sample", side_effect=Rejected("load_worker_pod_changed")
            ) as sample,
            self.assertRaises(Rejected),
        ):
            self.op.begin(self.start_payload())
        self.assertEqual(sample.call_count, 1)
        for field, value in (("session", "foreign"), ("golden", {}), ("job", "foreign")):
            with self.assertRaises(Rejected):
                self.op.begin({**self.start_payload(), field: value})
        self.op.samples["worker"] = [{}] * 256
        with self.assertRaisesRegex(Rejected, "load_resource_samples_limit"):
            self.op.sample()

    def test_campaign_hosted_guard_and_overload_accounting(self):
        with self.assertRaises(Rejected):
            operator.Coordinator(self.root, PROFILE, "foreign", expected())
        with (
            patch.object(operator, "hosted") as hosted,
            patch.object(operator.cluster, "validate_cluster") as validate,
        ):
            self.op.start()
            hosted.assert_called_once()
            validate.assert_called_once_with(self.root)
        correct = self.finish_payload()["overload"]
        self.assertIs(operator.overload(correct), correct)
        for field, value in (
            ("attempts", 39),
            ("correct", True),
            ("errors", 1),
            ("recovered", 1),
            ("profile_met", 1),
            ("profile_met", False),
            ("elapsed_ns", -1),
        ):
            with self.assertRaises(Rejected):
                operator.overload({**correct, field: value})


if __name__ == "__main__":
    unittest.main()
