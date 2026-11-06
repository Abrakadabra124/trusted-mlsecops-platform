"""Hosted operator for private worker/audit observation, without serving privileges."""

import re
import time

from mlsecops import (
    audit_evidence,
    audit_snapshot,
    kube_serving_runtime,
    kube_storage,
    kube_trust,
    signing,
)
from mlsecops.cluster import kubectl
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    canonical,
    decode,
    digest,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.kube_worker import verify_running_image
from scripts.kube_privacy_diagnostic import validated
from scripts.kube_privacy_exchange import DIRECTORY, MAX_REQUEST, PHASES
from scripts.kube_privacy_logs import MAX_BYTES, capture


def decoded(value, maximum):
    if type(value) is not str or not 1 <= len(value) <= 4 * ((maximum + 2) // 3):
        raise Rejected("privacy_operator_encoding")
    content = signing.decode64(value)
    if not 1 <= len(content) <= maximum or signing.encode64(content) != value:
        raise Rejected("privacy_operator_encoding")
    return content


def exec_failure(stderr):
    content = stderr[:8192]
    category = next(
        (
            name
            for marker, name in (
                (b"ModuleNotFoundError", "module_missing"),
                (b"PermissionError", "permission"),
                (b"artifact_unavailable", "artifact_unavailable"),
                (b"artifact_changed", "artifact_changed"),
                (b"artifact_too_large", "artifact_too_large"),
                (b"completed pod", "container_completed"),
                (b"container not found", "container_missing"),
                (b"timed out", "timeout"),
            )
            if marker in content
        ),
        "unknown",
    )
    result = {
        "status": "fail",
        "scope": "privacy-operator",
        "stage": "request",
        "category": category,
    }
    frames = re.findall(
        rb'File "/app/((?:mlsecops|scripts)/[a-z_][a-z_0-9]*\.py)", line ([0-9]+)', content
    )
    for filename, line in frames:
        detail = validated(
            {"exception": "other", "source_file": filename.decode(), "source_line": int(line)}
        )
        if detail is not None:
            result["location"] = detail
    return result


class Coordinator:
    def __init__(self, state, profile, binding, context):
        self.state, self.profile, self.binding, self.context = state, profile, binding, context
        self.destination = safe_child(state, "evidence/privacy/" + binding["campaign_id"])
        self.requests, self.phases = {}, []
        self.failed = False
        self.step = "request"
        self.exec_exit_deadline = None
        self.needles = self.worker_receipt = self.audit_receipt = None
        self.services = {}

    def observe(self, pod):
        # invoke() has verified this probe's UID/spec/image immediately before calling.
        name = pod["metadata"]["name"]
        program = (
            "import sys; from pathlib import Path; from mlsecops.contracts import bounded_read; "
            f"p=Path('{DIRECTORY}/request.json'); "
            f"sys.stdout.buffer.write(bounded_read(p,{MAX_REQUEST}) if p.exists() else b'null')"
        )
        response = kubectl(
            self.state,
            ["exec", name, "-n", "ml-serving", "-c", "worker", "--", "python", "-c", program],
            check=False,
        )
        if response.returncode:
            diagnostic = exec_failure(response.stderr)
            current = decode(
                kubectl(self.state, ["get", "pod", name, "-n", "ml-serving", "-o", "json"]).stdout
            )
            same = current["metadata"]["uid"] == pod["metadata"]["uid"] and canonical(
                current["spec"]
            ) == canonical(pod["spec"])
            if same and current["status"]["phase"] in {"Succeeded", "Failed"}:
                # The process can exit between wait_job's Running snapshot and
                # exec. Let the terminal path inspect its complete output.
                return
            if (
                same
                and current["status"]["phase"] == "Running"
                and diagnostic["category"] in {"container_missing", "container_completed"}
            ):
                observed_at = time.monotonic()
                if self.exec_exit_deadline is None:
                    self.exec_exit_deadline = observed_at + 5
                if observed_at < self.exec_exit_deadline:
                    # CRI can remove an exited process before kubelet publishes
                    # the terminal Pod status. No request is acknowledged here.
                    return
            atomic_write(self.destination / "exec-private.stderr", response.stderr)
            print(canonical(diagnostic).decode(), flush=True)
            raise Rejected("privacy_operator_exec_failed")
        self.exec_exit_deadline = None
        request = decode(response.stdout, MAX_REQUEST)
        if request is None:
            return
        require_fields(request, ("phase", "campaign", "payload"))
        phase = request["phase"]
        reference = digest(canonical(request))
        if phase not in PHASES or request["campaign"] != self.binding["campaign_id"]:
            raise Rejected("privacy_operator_binding")
        if phase in self.requests:
            if self.requests[phase] != reference:
                raise Rejected("privacy_operator_request_changed")
            return
        if self.failed or [*self.phases, phase] != list(PHASES)[: len(self.phases) + 1]:
            raise Rejected("privacy_operator_order")
        self.requests[phase] = reference
        write_json(self.destination / (phase + "-request.json"), request)
        try:
            self.step = phase
            result = (self.worker if phase == "worker" else self.audit)(request["payload"])
            self.phases.append(phase)
            status = "pass"
        except Exception:
            self.failed = True
            result, status = None, "fail"
            print(
                canonical(
                    {"status": "fail", "scope": "privacy-operator", "stage": self.step}
                ).decode(),
                flush=True,
            )
        ack = {"phase": phase, "request_sha256": reference, "status": status, "result": result}
        program = (
            "import sys; from pathlib import Path; from mlsecops.contracts import decode,write_json; "
            f"write_json(Path('{DIRECTORY}/{phase}-ack.json'),decode(sys.stdin.buffer.read(65537),65536))"
        )
        kubectl(
            self.state,
            ["exec", "-i", name, "-n", "ml-serving", "-c", "worker", "--", "python", "-c", program],
            ack,
        )

    def worker(self, payload):
        require_fields(
            payload, ("job", "job_uid", "pod_uid", "pod", "session", "stream", "needles")
        )
        if (
            type(payload["session"]) is not str
            or re.fullmatch("[a-f0-9]{32}", payload["session"]) is None
        ):
            raise Rejected("privacy_worker_session")
        expected = kube_serving_runtime.document(self.profile, payload["session"])
        if payload["job"] != expected["metadata"]["name"]:
            raise Rejected("privacy_worker_job")
        self.step = "worker-owner"
        job = decode(
            kubectl(
                self.state, ["get", "job", payload["job"], "-n", "ml-serve", "-o", "json"]
            ).stdout
        )
        if job["metadata"]["uid"] != payload["job_uid"] or not kube_storage.matches(expected, job):
            raise Rejected("privacy_worker_job")
        initial = payload["pod"]
        kube_serving_runtime.verify_pod(
            initial, expected["spec"]["template"]["spec"], payload["job_uid"], self.profile
        )
        if (
            initial["metadata"]["uid"] != payload["pod_uid"]
            or initial["metadata"]["namespace"] != "ml-serve"
        ):
            raise Rejected("privacy_worker_pod")
        stream = decoded(payload["stream"], MAX_BYTES)
        if type(payload["needles"]) is not list or len(payload["needles"]) != 9:
            raise Rejected("privacy_worker_canary_inventory")
        self.needles = tuple(decoded(value, 4096) for value in payload["needles"])
        name = initial["metadata"]["name"]
        self.step = "worker-terminal"
        deadline = time.monotonic() + 20
        while True:
            current = decode(
                kubectl(self.state, ["get", "pod", name, "-n", "ml-serve", "-o", "json"]).stdout
            )
            if current["metadata"]["uid"] != payload["pod_uid"] or canonical(
                current["spec"]
            ) != canonical(initial["spec"]):
                raise Rejected("privacy_worker_pod_changed")
            if current["status"]["phase"] in {"Succeeded", "Failed"}:
                break
            if time.monotonic() >= deadline:
                raise Rejected("privacy_worker_terminal_deadline")
            time.sleep(0.1)
        self.step = "worker-logs"
        receipt, raw = capture(
            self.state,
            current,
            owner_uid=payload["job_uid"],
            container="worker",
            needles=self.needles,
            expected_output=stream,
            terminal=True,
        )
        atomic_write(self.destination / "worker-private.log", raw)
        write_json(self.destination / "worker-receipt.json", receipt)
        self.worker_receipt = {
            k: receipt[k]
            for k in ("status", "release_ready", "terminal", "exact_output", "bytes", "sha256")
        }
        return self.worker_receipt

    def audit(self, payload):
        require_fields(payload, ("packet",))
        packet = decoded(payload["packet"], MAX_REQUEST)
        result = audit_evidence.verify(packet, binding=self.binding, expected_context=self.context)
        value = decode(packet, MAX_REQUEST)
        # Decode primary segments before scanning; base64 is not redaction.
        channels = [
            decoded(value["manifest"], MAX_REQUEST),
            decoded(value["public_export"], MAX_REQUEST),
            *(decoded(v, MAX_REQUEST) for v in value["segments"]),
        ]
        if any(needle in content for content in channels for needle in self.needles):
            raise Rejected("privacy_audit_canary")
        audit_snapshot.store_packet(self.destination / "audit-evidence", packet)
        self.step = "service-logs"
        for module in (kube_storage, kube_trust):
            marker = module.validate(self.state)
            document = next(v for v in module.desired(self.state) if v["kind"] == "StatefulSet")
            namespace = document["metadata"]["namespace"]
            owner = marker["resources"][kube_storage.reference(document)]
            pod = decode(
                kubectl(
                    self.state, ["get", "pod", "postgres-0", "-n", namespace, "-o", "json"]
                ).stdout
            )
            if not kube_storage.matches(document["spec"]["template"]["spec"], pod["spec"]):
                raise Rejected("privacy_service_spec")
            image = document["spec"]["template"]["spec"]["containers"][0]["image"]
            if type(image) is not str or re.fullmatch(r"[^@]+@sha256:[a-f0-9]{64}", image) is None:
                raise Rejected("privacy_service_image")
            verify_running_image(pod, image.rsplit("@", 1)[1])
            receipt, raw = capture(
                self.state, pod, owner_uid=owner, container="postgres", needles=self.needles
            )
            atomic_write(self.destination / (namespace + "-private.log"), raw)
            write_json(self.destination / (namespace + "-receipt.json"), receipt)
            self.services[namespace] = receipt
        self.audit_receipt = result
        return result

    def finish(self, report, raw):
        if (
            self.failed
            or self.phases != list(PHASES)
            or raw != canonical(report) + b"\n"
            or report.get("worker_observation") != self.worker_receipt
            or report.get("audit") != self.audit_receipt
            or set(self.services) != {"ml-storage", "ml-trust"}
            or any(needle in raw for needle in self.needles)
        ):
            raise Rejected("privacy_operator_incomplete")
        # finish runs only after the exact probe Pod has terminated successfully.
        # Re-read the stored bytes; agreement between two in-memory receipts is not proof.
        retained = audit_evidence.verify(
            audit_snapshot.load_packet(self.destination / "audit-evidence"),
            binding=self.binding,
            expected_context=self.context,
        )
        if canonical(retained) != canonical(self.audit_receipt):
            raise Rejected("privacy_operator_retained_packet_changed")
        result = {
            **report,
            "operator_observation": {
                "status": "pass",
                "release_ready": False,
                "worker_terminal": True,
                "retained_packet_reverified": True,
                "service_windows": len(self.services),
                "service_bytes": sum(v["bytes"] for v in self.services.values()),
            },
        }
        write_json(self.destination / "report.json", result)
        return result
