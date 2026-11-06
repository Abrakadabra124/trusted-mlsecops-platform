import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import audit_evidence_qualification as audit_fixture
from scripts import kube_privacy_operator as operator
from scripts.kube_serving_runtime_qualification import PROFILE, MemoryAPI


class OperatorHandoffContracts(unittest.TestCase):
    def test_worker_capture_uses_verified_initial_snapshot_and_terminal_exact_output(self):
        api = MemoryAPI()
        document = operator.kube_serving_runtime.document(PROFILE, "a" * 32)
        job = api.request("jobs", method="POST", value=document)
        initial = api.pod()
        terminal = copy.deepcopy(initial)
        terminal["status"]["phase"] = "Succeeded"
        terminal["status"]["containerStatuses"][0]["state"] = {"terminated": {"exitCode": 0}}
        payload = {
            "job": document["metadata"]["name"],
            "job_uid": "job-uid",
            "pod_uid": "pod-uid",
            "pod": initial,
            "session": "a" * 32,
            "stream": operator.signing.encode64(b"reply\n"),
            "needles": [operator.signing.encode64(f"canary-{i}".encode()) for i in range(9)],
        }
        receipt = {
            "status": "pass",
            "release_ready": False,
            "terminal": True,
            "exact_output": True,
            "bytes": 6,
            "sha256": "d" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:

            def execute(value, current=terminal, clocks=(0, 21)):
                control = operator.Coordinator(
                    Path(directory), PROFILE, {"campaign_id": "c" * 32}, {}
                )
                calls = iter([job, *(current if type(current) is list else [current])])
                with (
                    patch.object(operator.time, "monotonic", side_effect=clocks),
                    patch.object(operator.time, "sleep"),
                    patch.object(
                        operator,
                        "kubectl",
                        side_effect=lambda *a, **k: SimpleNamespace(
                            returncode=0, stdout=canonical(next(calls))
                        ),
                    ),
                    patch.object(
                        operator, "capture", return_value=(receipt, b"reply\n")
                    ) as capture,
                ):
                    result = control.worker(value)
                return result, capture

            result, capture = execute(payload)
            self.assertEqual(result, receipt)
            self.assertEqual(capture.call_args.kwargs["expected_output"], b"reply\n")
            self.assertTrue(capture.call_args.kwargs["terminal"])
            self.assertEqual(len(capture.call_args.kwargs["needles"]), 9)
            for mutate in (
                lambda v: v.update(job_uid="foreign"),
                lambda v: v.update(session="../x"),
                lambda v: v.update(job="foreign"),
                lambda v: v["needles"].pop(),
                lambda v: v.update(pod_uid="foreign"),
            ):
                value = copy.deepcopy(payload)
                mutate(value)
                with self.subTest(mutate=mutate), self.assertRaises(Rejected):
                    execute(value)
            changed = copy.deepcopy(terminal)
            changed["metadata"]["uid"] = "foreign"
            with self.assertRaisesRegex(Rejected, "privacy_worker_pod_changed"):
                execute(payload, changed)
            changed = copy.deepcopy(terminal)
            changed["spec"]["containers"][0]["image"] = "foreign"
            with self.assertRaisesRegex(Rejected, "privacy_worker_pod_changed"):
                execute(payload, changed)
            with self.assertRaisesRegex(Rejected, "privacy_worker_terminal_deadline"):
                execute(payload, initial)
            result, _ = execute(payload, [initial, terminal], clocks=(0, 1))
            self.assertEqual(result, receipt)

    def test_audit_packet_reverified_and_canaries_scanned_after_base64_decode(self):
        content = audit_fixture.packet()
        binding, context = audit_fixture.binding(), audit_fixture.expected()
        with tempfile.TemporaryDirectory() as directory:
            control = operator.Coordinator(Path(directory), {}, binding, context)
            control.needles = (b"1" * 32,) + tuple(f"canary-{i}".encode() for i in range(8))
            with (
                patch.object(operator.kube_storage, "validate") as storage,
                self.assertRaisesRegex(Rejected, "privacy_audit_canary"),
            ):
                control.audit({"packet": operator.signing.encode64(content)})
            storage.assert_not_called()
            control.needles = tuple(f"canary-{i}".encode() for i in range(9))
            docs = [
                {
                    "kind": "StatefulSet",
                    "metadata": {"namespace": ns, "name": "postgres"},
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"name": "postgres", "image": "postgres@sha256:" + "d" * 64}
                                ]
                            }
                        }
                    },
                }
                for ns in ("ml-storage", "ml-trust")
            ]
            captures = []

            def capture(state, pod, **kwargs):
                captures.append(kwargs)
                return {"bytes": 0, "terminal": False}, b""

            with (
                patch.object(
                    operator.kube_storage,
                    "validate",
                    return_value={
                        "resources": {operator.kube_storage.reference(docs[0]): "storage-owner"}
                    },
                ),
                patch.object(operator.kube_storage, "desired", return_value=[docs[0]]),
                patch.object(
                    operator.kube_trust,
                    "validate",
                    return_value={
                        "resources": {operator.kube_storage.reference(docs[1]): "trust-owner"}
                    },
                ),
                patch.object(operator.kube_trust, "desired", return_value=[docs[1]]),
                patch.object(
                    operator,
                    "kubectl",
                    return_value=SimpleNamespace(
                        returncode=0,
                        stdout=canonical({"spec": docs[0]["spec"]["template"]["spec"]}),
                    ),
                ) as api,
                patch.object(operator, "verify_running_image") as image,
                patch.object(operator, "capture", side_effect=capture),
            ):
                result = control.audit({"packet": operator.signing.encode64(content)})
                self.assertEqual(
                    [c.args[1] for c in image.call_args_list], ["sha256:" + "d" * 64] * 2
                )
                api.return_value.stdout = canonical({"spec": {}})
                with self.assertRaisesRegex(Rejected, "privacy_service_spec"):
                    control.audit({"packet": operator.signing.encode64(content)})
            self.assertEqual(result["status"], "pass")
            self.assertEqual(set(control.services), {"ml-storage", "ml-trust"})
            self.assertEqual([v["owner_uid"] for v in captures], ["storage-owner", "trust-owner"])
            self.assertTrue(
                all("terminal" not in v and "expected_output" not in v for v in captures)
            )

    def test_ordered_requests_are_idempotent_and_acknowledged_without_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            control = operator.Coordinator(Path(directory), {}, {"campaign_id": "a" * 32}, {})
            current = [{"phase": "worker", "campaign": "a" * 32, "payload": {}}]
            acknowledgements = []

            def kubectl(state, args, value=None, **kwargs):
                if value is None:
                    return SimpleNamespace(returncode=0, stdout=canonical(current[0]))
                acknowledgements.append(value)
                return SimpleNamespace(returncode=0, stdout=b"")

            with (
                patch.object(operator, "kubectl", side_effect=kubectl),
                patch.object(control, "worker", return_value={"count": 1}) as worker,
                patch.object(control, "audit", return_value={"count": 2}) as audit,
                patch("builtins.print") as output,
            ):
                control.observe({"metadata": {"name": "probe"}})
                control.observe({"metadata": {"name": "probe"}})
                current[0]["payload"] = {"changed": True}
                with self.assertRaisesRegex(Rejected, "privacy_operator_request_changed"):
                    control.observe({"metadata": {"name": "probe"}})
                current[0]["payload"] = {}
                current[0]["phase"] = "audit"
                control.observe({"metadata": {"name": "probe"}})
            self.assertEqual(control.phases, ["worker", "audit"])
            self.assertEqual(len(acknowledgements), 2)
            self.assertTrue(all(v["status"] == "pass" for v in acknowledgements))
            worker.assert_called_once()
            audit.assert_called_once()
            output.assert_not_called()

    def test_operator_failure_sends_negative_ack_so_worker_can_clean_up(self):
        with tempfile.TemporaryDirectory() as directory:
            control = operator.Coordinator(Path(directory), {}, {"campaign_id": "a" * 32}, {})
            request = {"phase": "worker", "campaign": "a" * 32, "payload": {}}
            calls = []

            def kubectl(state, args, value=None, **kwargs):
                if value is not None:
                    calls.append(value)
                return SimpleNamespace(
                    returncode=0, stdout=canonical(request) if value is None else b""
                )

            with (
                patch.object(operator, "kubectl", side_effect=kubectl),
                patch.object(control, "worker", side_effect=Rejected("private-detail")),
                patch("builtins.print") as output,
            ):
                control.observe({"metadata": {"name": "probe"}})
            self.assertTrue(control.failed)
            self.assertEqual(calls[0]["status"], "fail")
            self.assertIsNone(calls[0]["result"])
            self.assertNotIn("private-detail", str(output.call_args_list))

    def test_missing_request_is_wait_not_success_and_foreign_campaign_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            control = operator.Coordinator(Path(directory), {}, {"campaign_id": "a" * 32}, {})
            with patch.object(
                operator, "kubectl", return_value=SimpleNamespace(returncode=0, stdout=b"null")
            ):
                control.observe({"metadata": {"name": "probe"}})
            self.assertEqual(control.phases, [])
            for request in (
                {"phase": "audit", "campaign": "a" * 32, "payload": {}},
                {"phase": "worker", "campaign": "b" * 32, "payload": {}},
                {"phase": "other", "campaign": "a" * 32, "payload": {}},
            ):
                with (
                    self.subTest(request=request),
                    patch.object(
                        operator,
                        "kubectl",
                        return_value=SimpleNamespace(returncode=0, stdout=canonical(request)),
                    ),
                    self.assertRaises(Rejected),
                ):
                    control.observe({"metadata": {"name": "probe"}})

    def test_terminal_report_requires_complete_log_and_both_private_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            control = operator.Coordinator(Path(directory), {}, {"campaign_id": "a" * 32}, {})
            control.phases = list(operator.PHASES)
            control.worker_receipt, control.audit_receipt = {"worker": True}, {"audit": True}
            control.services = {"ml-storage": {"bytes": 10}, "ml-trust": {"bytes": 20}}
            control.needles = (b"private-canary",)
            report = {"worker_observation": control.worker_receipt, "audit": control.audit_receipt}
            raw = canonical(report) + b"\n"
            result = control.finish(report, raw)
            self.assertEqual(result["operator_observation"]["service_bytes"], 30)
            self.assertFalse(result["operator_observation"]["release_ready"])
            for content in (raw[:-1], b"prefix\n" + raw, raw + b"extra\n"):
                with self.subTest(content=content), self.assertRaises(Rejected):
                    control.finish(report, content)
            for field, value in (
                ("failed", True),
                ("phases", ["worker"]),
                ("worker_receipt", {}),
                ("audit_receipt", {}),
                ("services", {}),
                ("needles", (b"audit",)),
            ):
                with (
                    self.subTest(field=field),
                    patch.object(control, field, value),
                    self.assertRaises(Rejected),
                ):
                    control.finish(report, raw)

    def test_encoding_is_bounded_and_canonical(self):
        self.assertEqual(operator.decoded("YQ==", 1), b"a")
        for content in (None, "", "YQ===", "YWI=", "YR==", "%%%%"):
            with self.subTest(content=content), self.assertRaises(Rejected):
                operator.decoded(content, 1)

    def test_exec_exit_race_defers_only_for_same_terminal_pod(self):
        initial = {
            "metadata": {"name": "probe", "uid": "owned"},
            "spec": {},
            "status": {"phase": "Running"},
        }
        with tempfile.TemporaryDirectory() as directory:
            for phase, uid in (
                ("Succeeded", "owned"),
                ("Failed", "owned"),
                ("Running", "owned"),
                ("Succeeded", "foreign"),
            ):
                current = {
                    **initial,
                    "metadata": {**initial["metadata"], "uid": uid},
                    "status": {"phase": phase},
                }
                control = operator.Coordinator(Path(directory), {}, {"campaign_id": "a" * 32}, {})
                with patch.object(
                    operator,
                    "kubectl",
                    side_effect=[
                        SimpleNamespace(returncode=1, stdout=b"", stderr=b"private"),
                        SimpleNamespace(returncode=0, stdout=canonical(current)),
                    ],
                ):
                    if uid == "owned" and phase in {"Succeeded", "Failed"}:
                        control.observe(initial)
                        self.assertEqual(control.phases, [])
                    else:
                        with self.assertRaisesRegex(Rejected, "privacy_operator_exec_failed"):
                            control.observe(initial)


if __name__ == "__main__":
    unittest.main()
