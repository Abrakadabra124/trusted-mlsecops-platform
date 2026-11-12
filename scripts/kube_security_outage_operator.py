"""Hosted-only audit fault ownership and independent retention of ML evidence."""

import dataclasses
import time

from mlsecops import security_outage_exchange as exchange
from mlsecops import security_outage_packet
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
from scripts import kube_security_boundary
from scripts import kube_security_native as audit
from scripts.kube_privacy_diagnostic import location, validated
from scripts.kube_privacy_operator import exec_failure
from scripts.kube_promotion_snapshot import read as snapshot
from scripts.kube_trust_native import hosted


class Coordinator:
    def __init__(self, state, profile, campaign, reference, context, golden):
        exchange.identity(campaign, 32)
        self.state, self.profile, self.campaign = state, profile, campaign
        self.reference, self.context, self.golden = reference, context, golden
        self.destination = safe_child(state, "evidence/security-outage/" + campaign)
        self.destination.mkdir(parents=True, mode=0o700)
        self.pod = self.marker = self.before = self.boundary = self.recovery = None
        self.fault = self.packet_hash = self.summary = self.exit_deadline = None
        self.phases, self.requests, self.results = [], {}, {}
        self.fault_resources, self.timeline = [], {}

    def start(self):
        hosted()
        self.marker = audit.kube_security_events.validate(self.state, profile=self.profile)
        self.before = snapshot(self.state)

    def close(self):
        if self.fault is not None:
            self.fault.__exit__(None, None, None)
            # A failed generator __exit__ is not retryable itself. Keep its
            # resource/UID inventory until a separate verified delete succeeds.
            if self.fault_resources:
                audit.kube_promotion.cleanup(
                    self.state, self.fault_resources, namespace=audit.resources.NAMESPACE
                )
                self.fault_resources.clear()
            self.fault = None

    def act(self, phase, payload):
        if phase == "finish":
            if (
                self.phases != list(exchange.PHASES[:-1])
                or self.fault is not None
                or self.recovery is None
            ):
                raise Rejected("security_outage_incomplete")
            require_fields(payload, ("packet", "summary"))
            result = security_outage_packet.verify(
                payload["packet"],
                reference=self.reference,
                context=self.context,
                golden=self.golden,
                campaign=self.campaign,
            )
            if result != payload["summary"]:
                raise Rejected("security_outage_summary")
            security_outage_packet.verify_timeline(payload["packet"], self.timeline)
            write_json(self.destination / "packet.json", payload["packet"])
            self.packet_hash = digest(
                bounded_read(self.destination / "packet.json", exchange.MAX_PACKET)
            )
            self.summary = result
            write_json(
                self.destination / "binding.json",
                {
                    "reference": self.reference,
                    "context": dataclasses.asdict(self.context),
                    "golden": {
                        "body": self.golden.body.decode(),
                        "model": self.golden.model,
                        "bundle": self.golden.bundle,
                        "score": self.golden.score,
                    },
                    "campaign": self.campaign,
                    "packet_hash": self.packet_hash,
                    "summary": result,
                    "boundary": self.boundary,
                    "recovery": self.recovery,
                    "base_snapshot_sha256": digest(canonical(self.before)),
                },
            )
            return {"packet_sha256": result["packet_sha256"]}
        if payload != {} or self.marker is None or self.before is None:
            raise Rejected("security_outage_action_binding")
        if phase == "ready":
            audit.health(self.state, self.profile)
        elif phase == "outage":
            if self.fault is not None:
                raise Rejected("security_outage_already_active")
            fault = audit.outage(
                self.state, self.marker["workspace_id"], owned=self.fault_resources
            )
            self.fault = fault
            fault.__enter__()
            audit.health(self.state, self.profile, False)
        elif phase == "attempt":
            if self.fault is None:
                raise Rejected("security_outage_missing_fault")
            self.boundary = kube_security_boundary.invoke(self.state, self.profile)
            if snapshot(self.state) != self.before:
                raise Rejected("security_outage_SQL_or_CAS_changed")
        elif phase == "recover":
            if self.fault is None or self.boundary is None:
                raise Rejected("security_outage_missing_refusal")
            self.close()
            audit.health(self.state, self.profile)
            marker = audit.kube_security_events.validate(self.state, profile=self.profile)
            if marker != self.marker:
                raise Rejected("security_outage_collector_identity_changed")
            outbox = audit.job(self.state, self.profile, audit.PROMOTER)
            inbox = audit.collector(self.state, marker)
            pending = self.boundary["pending"]
            sent = [r for r in outbox["records"] if r["id"] == pending["event_id"]]
            received = [r for r in inbox["records"] if r["id"] == pending["event_id"]]
            if (
                len(sent) != 1
                or sent != received
                or sent[0]["envelope"] != pending["envelope_sha256"]
                or sent[0]["kind"] != "promotion.denied"
                or sent[0]["receipt"] is None
                or outbox["pin"] != self.boundary["outbox_pin"]
                or snapshot(self.state) != self.before
            ):
                raise Rejected("security_outage_recovery_binding")
            self.recovery = {
                "original_denial": sent[0],
                "SQL_and_CAS_unchanged": True,
                "fault_removed": True,
            }
        else:
            raise Rejected("security_outage_phase")
        return {}

    def observe(self, pod):
        try:
            return self._observe(pod)
        except Exception as failure:
            # Report before Job deletion and ownership return can mask the cause.
            # Diagnostic readback is best effort and never turns failure into pass.
            report = {
                "status": "fail",
                "code": "security_outage_operator_rejected",
                "completed_phases": list(self.phases),
                "location": location(failure),
            }
            try:
                if self.pod is not None and pod["metadata"]["uid"] == self.pod["metadata"]["uid"]:
                    raw = kubectl(
                        self.state,
                        [
                            "logs",
                            pod["metadata"]["name"],
                            "-n",
                            "ml-serving",
                            "-c",
                            "worker",
                            "--tail=1",
                            "--limit-bytes=65537",
                        ],
                    ).stdout
                    if len(raw) <= 65536:
                        (self.destination / "failed-child-private.log").write_bytes(raw)
                        value = decode(raw, 65536)
                        if (
                            type(value) is dict
                            and set(value) == {"status", "release_ready", "code", "locations"}
                            and value["status"] == "fail"
                            and value["release_ready"] is False
                            and value["code"] == "security_green_probe_rejected"
                            and type(value["locations"]) is list
                            and 1 <= len(value["locations"]) <= 4
                            and all(validated(item) is not None for item in value["locations"])
                        ):
                            report["probe"] = value
            except Exception:
                pass
            print(canonical(report).decode(), flush=True)
            raise

    def _observe(self, pod):
        if self.pod is None:
            self.pod = decode(canonical(pod))
        if pod["metadata"]["uid"] != self.pod["metadata"]["uid"]:
            raise Rejected("security_outage_probe_replaced")
        args = [
            "exec",
            pod["metadata"]["name"],
            "-n",
            "ml-serving",
            "-c",
            "worker",
            "--",
            "python",
            "-m",
            "mlsecops.security_outage_exchange",
        ]
        response = kubectl(self.state, [*args, "read"], check=False)
        if response.returncode:
            category = exec_failure(response.stderr)["category"]
            if category in ("container_missing", "container_completed"):
                if self.exit_deadline is None:
                    self.exit_deadline = time.monotonic() + 5
                if time.monotonic() < self.exit_deadline:
                    return
            raise Rejected("security_outage_read_failed")
        self.exit_deadline = None
        value = decode(response.stdout, exchange.MAX_PACKET)
        if value is None:
            return
        exchange.request(value)
        phase, payload = value["phase"], value["payload"]
        if value["campaign"] != self.campaign or phase != "finish" and payload != {}:
            raise Rejected("security_outage_request_binding")
        reference = digest(canonical(value))
        if phase in self.requests:
            if phase != self.phases[-1] or reference != self.requests[phase]:
                raise Rejected("security_outage_request_changed")
        else:
            if [*self.phases, phase] != list(exchange.PHASES[: len(self.phases) + 1]):
                raise Rejected("security_outage_order")
            self.timeline[phase] = {
                "started_at_ms": time.time_ns() // 1000000,
                "started_ns": time.monotonic_ns(),
            }
            print(
                canonical(
                    {"stage": "security-outage-action", "phase": phase, "state": "begin"}
                ).decode(),
                flush=True,
            )
            result = self.act(phase, payload)
            if phase != "finish":
                self.timeline[phase].update(
                    finished_at_ms=time.time_ns() // 1000000,
                    finished_ns=time.monotonic_ns(),
                )
            print(
                canonical(
                    {"stage": "security-outage-action", "phase": phase, "state": "complete"}
                ).decode(),
                flush=True,
            )
            self.requests[phase], self.results[phase] = reference, result
            self.phases.append(phase)
            write_json(
                self.destination / "operator.json",
                {
                    "campaign": self.campaign,
                    "phases": self.phases,
                    "requests": self.requests,
                    "results": self.results,
                    "timeline": self.timeline,
                },
            )
        kubectl(
            self.state,
            ["exec", "-i", *args[1:], "ack"],
            {
                "phase": phase,
                "request_sha256": reference,
                "status": "pass",
                "result": self.results[phase],
            },
        )

    def reverify(self):
        if (
            self.phases != list(exchange.PHASES)
            or self.packet_hash is None
            or self.fault is not None
        ):
            raise Rejected("security_outage_retention_missing")
        content = bounded_read(self.destination / "packet.json", exchange.MAX_PACKET)
        if digest(content) != self.packet_hash:
            raise Rejected("security_outage_packet_changed")
        result = security_outage_packet.verify(
            decode(content, exchange.MAX_PACKET),
            reference=self.reference,
            context=self.context,
            golden=self.golden,
            campaign=self.campaign,
        )
        if result != self.summary:
            raise Rejected("security_outage_summary_changed")
        security_outage_packet.verify_timeline(decode(content, exchange.MAX_PACKET), self.timeline)
        return result

    def finish(self, report, raw):
        result = self.reverify()
        if raw != canonical(report) + b"\n" or report != {
            **result,
            "worker_cleanup_verified": True,
        }:
            raise Rejected("security_outage_report_changed")
        return {**report, "audit_boundary": self.boundary, "recovery": self.recovery}
