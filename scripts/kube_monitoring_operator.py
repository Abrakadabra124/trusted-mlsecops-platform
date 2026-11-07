"""Retain and reverify the owned probe's private packet; never publish raw inputs."""

import dataclasses
import time

from mlsecops import monitoring_packet
from mlsecops.cluster import kubectl
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.load_exchange import MAX_PACKET
from scripts.kube_privacy_operator import exec_failure
from scripts.kube_trust_native import hosted


class Coordinator:
    def __init__(self, state, profile, campaign, reference, context):
        self.state, self.profile, self.campaign = state, profile, campaign
        self.reference, self.context = reference, context
        self.destination = safe_child(state, "evidence/monitoring/" + campaign)
        self.destination.mkdir(parents=True, mode=0o700)
        self.probe = self.request_hash = self.packet_hash = self.summary = None
        self.exit_deadline = None

    def start(self):
        hosted()

    def retain_binding(self):
        self.reverify()
        document = {
            "reference": self.reference,
            "context": dataclasses.asdict(self.context),
            "campaign": self.campaign,
            "packet_hash": self.packet_hash,
            "summary": self.summary,
        }
        write_json(self.destination / "binding.json", document)
        return digest(bounded_read(self.destination / "binding.json"))

    def verify(self, payload):
        require_fields(payload, ("packet", "summary", "context", "sink_public", "label_public"))
        if payload["context"] != dataclasses.asdict(self.context):
            raise Rejected("monitor_operator_context")
        result = monitoring_packet.verify(
            payload["packet"],
            reference=self.reference,
            reference_sha256=digest(canonical(self.reference)),
            context=self.context,
            sink_public=payload["sink_public"],
            label_public=payload["label_public"],
            epoch=self.campaign,
        )
        if result != payload["summary"]:
            raise Rejected("monitor_operator_summary")
        return result

    def observe(self, pod):
        if self.probe is None:
            self.probe = decode(canonical(pod))
        if pod["metadata"]["uid"] != self.probe["metadata"]["uid"]:
            raise Rejected("monitor_operator_probe_replaced")
        if self.request_hash is not None:
            return
        name = pod["metadata"]["name"]
        result = kubectl(
            self.state,
            [
                "exec",
                name,
                "-n",
                "ml-serving",
                "-c",
                "worker",
                "--",
                "python",
                "-m",
                "mlsecops.load_exchange",
                "read",
            ],
            check=False,
        )
        if result.returncode:
            category = exec_failure(result.stderr)["category"]
            if category in ("container_missing", "container_completed"):
                if self.exit_deadline is None:
                    self.exit_deadline = time.monotonic() + 5
                if time.monotonic() < self.exit_deadline:
                    return
            raise Rejected("monitor_operator_read_failed")
        self.exit_deadline = None
        request = decode(result.stdout, MAX_PACKET)
        if request is None:
            return
        require_fields(request, ("phase", "campaign", "payload"))
        if request["phase"] != "finish" or request["campaign"] != self.campaign:
            raise Rejected("monitor_operator_binding")
        summary = self.verify(request["payload"])
        write_json(self.destination / "packet.json", request["payload"])
        content = bounded_read(self.destination / "packet.json", MAX_PACKET)
        if content != canonical(request["payload"]) + b"\n":
            raise Rejected("monitor_operator_write")
        self.packet_hash = digest(content)
        self.summary = summary
        reference = digest(canonical(request))
        kubectl(
            self.state,
            [
                "exec",
                "-i",
                name,
                "-n",
                "ml-serving",
                "-c",
                "worker",
                "--",
                "python",
                "-m",
                "mlsecops.load_exchange",
                "ack",
            ],
            {
                "phase": "finish",
                "request_sha256": reference,
                "status": "pass",
                "result": {"packet_sha256": summary["packet_sha256"]},
            },
        )
        self.request_hash = reference

    def reverify(self):
        if self.packet_hash is None:
            raise Rejected("monitor_operator_packet_missing")
        content = bounded_read(self.destination / "packet.json", MAX_PACKET)
        if digest(content) != self.packet_hash:
            raise Rejected("monitor_operator_packet_changed")
        result = self.verify(decode(content, MAX_PACKET))
        if result != self.summary:
            raise Rejected("monitor_operator_summary_changed")
        return result

    def finish(self, report, raw):
        if raw != canonical(report) + b"\n":
            raise Rejected("monitor_operator_output")
        result = self.reverify()
        if (
            any(report.get(key) != value for key, value in result.items())
            or report.get("model_sha256") != self.context.model_sha256
            or report.get("subject_sha256") != self.context.bundle_sha256
            or report.get("worker_cleanup_verified") is not True
        ):
            raise Rejected("monitor_operator_report")
        return report
