"""Owned hosted observer for private load records and container resource samples."""

import re
import time
from contextlib import suppress

from mlsecops import (
    cluster,
    kube_serving_runtime,
    kube_storage,
    load_clock,
    load_diagnostics,
    load_measurement,
)
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
from mlsecops.kube_worker import verify_running_image
from mlsecops.load_exchange import MAX_PACKET, PHASES
from mlsecops.load_golden import Golden
from scripts import load_resources
from scripts.kube_privacy_operator import exec_failure
from scripts.kube_trust_native import hosted


def overload(value):
    require_fields(
        value,
        ("attempts", "correct", "limited", "errors", "elapsed_ns", "recovered", "profile_met"),
    )
    if (
        any(
            type(value[k]) is not int or not 0 <= value[k] < 2**63
            for k in ("attempts", "correct", "limited", "errors", "elapsed_ns")
        )
        or value["attempts"] != 40
        or sum(value[k] for k in ("correct", "limited", "errors")) != 40
        or type(value["recovered"]) is not bool
        or type(value["profile_met"]) is not bool
        or value["profile_met"]
        != (
            value["limited"] > 0
            and value["errors"] == 0
            and value["recovered"]
            and value["elapsed_ns"] <= 3_000_000_000
        )
    ):
        raise Rejected("load_overload_accounting")
    return value


class Coordinator:
    def __init__(self, state, profile, campaign, expected):
        if type(campaign) is not str or re.fullmatch("[a-f0-9]{32}", campaign) is None:
            raise Rejected("load_campaign")
        self.state, self.profile, self.campaign = state, profile, campaign
        self.golden = Golden.from_expected(expected).binding()
        self.destination = safe_child(state, "evidence/load/" + campaign)
        self.destination.mkdir(parents=True, mode=0o700)
        self.phases, self.references, self.hashes = [], {}, {}
        self.samples = {"controller": [], "worker": []}
        self.probe = self.worker = self.receipt = None
        self.last_sample = 0
        self.exec_exit_deadline = None

    def start(self):
        hosted()
        cluster.validate_cluster(self.state)

    def observe(self, pod):
        if self.probe is None:
            self.probe = decode(canonical(pod))
        if pod["metadata"]["uid"] != self.probe["metadata"]["uid"]:
            raise Rejected("load_probe_replaced")
        if self.phases == list(PHASES):
            return
        if self.worker is not None and time.monotonic() - self.last_sample >= 2:
            self.sample()
        name = self.probe["metadata"]["name"]
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
            diagnostic = {**exec_failure(result.stderr), "scope": "load-operator"}
            current = self.get("pod", name, "ml-serving")
            same = (
                current["metadata"]["uid"] == self.probe["metadata"]["uid"]
                and current["spec"] == self.probe["spec"]
            )
            if same and current.get("status", {}).get("phase") in {"Succeeded", "Failed"}:
                return
            if same and diagnostic["category"] in {"container_missing", "container_completed"}:
                observed = time.monotonic()
                if self.exec_exit_deadline is None:
                    self.exec_exit_deadline = observed + 5
                if observed < self.exec_exit_deadline:
                    # CRI exit can precede terminal Pod status. A bounded wait
                    # permits the terminal path to read the actual probe error.
                    return
            print(canonical(diagnostic).decode(), flush=True)
            raise Rejected("load_exchange_read_failed")
        self.exec_exit_deadline = None
        request = decode(result.stdout, MAX_PACKET)
        if request is None:
            return
        require_fields(request, ("phase", "campaign", "payload"))
        phase, reference = request["phase"], digest(canonical(request))
        if (
            phase not in PHASES
            or request["campaign"] != self.campaign
            or type(request["payload"]) is not dict
        ):
            raise Rejected("load_exchange_binding")
        if phase in self.references:
            if self.references[phase] != reference:
                raise Rejected("load_exchange_changed")
            return
        if [*self.phases, phase] != list(PHASES)[: len(self.phases) + 1]:
            raise Rejected("load_exchange_order")
        self.retain(phase + "-request.json", request)
        try:
            value = (
                self.begin(request["payload"]) if phase == "start" else self.end(request["payload"])
            )
        except Exception:
            with suppress(Exception):
                self.acknowledge(phase, reference, "fail", {})
            raise
        self.references[phase] = reference
        self.phases.append(phase)
        self.acknowledge(phase, reference, "pass", value)

    def acknowledge(self, phase, reference, status, value):
        kubectl(
            self.state,
            [
                "exec",
                "-i",
                self.probe["metadata"]["name"],
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
            {"phase": phase, "request_sha256": reference, "status": status, "result": value},
        )

    def get(self, kind, name, namespace):
        return decode(
            kubectl(
                self.state, ["get", kind, name, "-n", namespace, "-o", "json"], timeout=10
            ).stdout
        )

    def retain(self, name, value):
        path = self.destination / name
        write_json(path, value)
        content = bounded_read(path, MAX_PACKET)
        if content != canonical(value) + b"\n":
            raise Rejected("load_retained_write")
        self.hashes[name] = digest(content)

    def begin(self, payload):
        require_fields(payload, ("session", "job", "job_uid", "pod_uid", "golden"))
        if (
            type(payload["session"]) is not str
            or re.fullmatch("[a-f0-9]{32}", payload["session"]) is None
            or payload["golden"] != self.golden
        ):
            raise Rejected("load_worker_binding")
        expected = kube_serving_runtime.document(self.profile, payload["session"])
        if expected["metadata"]["name"] != payload["job"]:
            raise Rejected("load_worker_job")
        self.worker = {**payload, "expected": expected}
        deadline = time.monotonic() + 30
        while True:
            try:
                self.sample()
                break
            except Rejected as failure:
                # A newly created container can precede its first Kubelet sample.
                # Identity failures are never retried or treated as missing metrics.
                if (
                    str(failure)
                    not in {"load_resource_missing", "load_resource_pod", "load_resource_sample"}
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(1)
        node = decode(
            kubectl(self.state, ["get", "node", cluster.NODE, "-o", "json"], timeout=10).stdout
        )
        self.compute = {
            "node_capacity": {key: node["status"]["capacity"][key] for key in ("cpu", "memory")},
            "node_info": {
                key: node["status"]["nodeInfo"][key]
                for key in (
                    "architecture",
                    "operatingSystem",
                    "kernelVersion",
                    "containerRuntimeVersion",
                    "kubeletVersion",
                )
            },
            "controller_resources": self.probe["spec"]["containers"][0]["resources"],
            "worker_resources": expected["spec"]["template"]["spec"]["containers"][0]["resources"],
        }
        return {"observed": True}

    def identities(self):
        probe = self.get("pod", self.probe["metadata"]["name"], "ml-serving")
        if (
            probe["metadata"]["uid"] != self.probe["metadata"]["uid"]
            or probe["spec"] != self.probe["spec"]
        ):
            raise Rejected("load_probe_changed")
        verify_running_image(probe, self.profile["image_id"])
        statuses = probe.get("status", {}).get("containerStatuses", [])
        if (
            len(statuses) != 1
            or statuses[0].get("restartCount") != 0
            or "running" not in statuses[0].get("state", {})
        ):
            raise Rejected("load_probe_not_running")
        job = self.get("job", self.worker["job"], "ml-serve")
        if job["metadata"]["uid"] != self.worker["job_uid"] or not kube_storage.matches(
            self.worker["expected"], job
        ):
            raise Rejected("load_worker_job_changed")
        pods = decode(
            kubectl(
                self.state,
                [
                    "get",
                    "pods",
                    "-n",
                    "ml-serve",
                    "-l",
                    "job-name=" + self.worker["job"],
                    "-o",
                    "json",
                ],
                timeout=10,
            ).stdout
        )["items"]
        if len(pods) != 1 or pods[0]["metadata"]["uid"] != self.worker["pod_uid"]:
            raise Rejected("load_worker_pod_changed")
        worker = pods[0]
        kube_serving_runtime.verify_pod(
            worker,
            self.worker["expected"]["spec"]["template"]["spec"],
            self.worker["job_uid"],
            self.profile,
        )
        for pod in (probe, worker):
            if pod["spec"].get("nodeName") != cluster.NODE:
                raise Rejected("load_resource_node_changed")
        return {"controller": probe, "worker": worker}

    def sample(self):
        if any(len(value) >= 256 for value in self.samples.values()):
            raise Rejected("load_resource_samples_limit")
        pods = self.identities()
        document = decode(
            kubectl(
                self.state,
                ["get", "--raw", "/api/v1/nodes/" + cluster.NODE + "/proxy/stats/summary"],
                timeout=10,
            ).stdout,
            2 * 1024 * 1024,
        )
        observed = time.time_ns()
        values = {
            name: load_resources.extract(
                document,
                {
                    "node": pod["spec"]["nodeName"],
                    "name": pod["metadata"]["name"],
                    "namespace": pod["metadata"]["namespace"],
                    "uid": pod["metadata"]["uid"],
                    "container": "worker",
                },
                observed_ns=observed,
            )
            for name, pod in pods.items()
        }
        for name, value in values.items():
            self.samples[name].append(value)
        self.last_sample = time.monotonic()

    def end(self, payload):
        require_fields(payload, ("observation", "summary", "overload", "golden", "diagnostics"))
        observation = payload["observation"]
        require_fields(observation, ("records", "exhausted", "elapsed_ns", "clock"))
        if payload["golden"] != self.golden:
            raise Rejected("load_golden_changed")
        summary = load_measurement.summarize(
            **{key: observation[key] for key in ("records", "exhausted", "elapsed_ns")}
        )
        if canonical(summary) != canonical(payload["summary"]):
            raise Rejected("load_summary_changed")
        overload(payload["overload"])
        load_diagnostics.checked(payload["diagnostics"], summary, payload["overload"])
        window = load_clock.window(observation["clock"], observation["elapsed_ns"])
        deadline = time.monotonic() + 30
        while True:
            self.sample()
            if all(
                min(values[-1]["cpu_at_ns"], values[-1]["memory_at_ns"])
                >= window["end_ns"] + window["uncertainty_ns"]
                for values in self.samples.values()
            ):
                break
            if time.monotonic() >= deadline:
                raise Rejected("load_resource_tail_missing")
            time.sleep(2)
        self.retain(
            "resources.json", {"samples": self.samples, "window": window, "compute": self.compute}
        )
        resources = {}
        for name, values in self.samples.items():
            try:
                resources[name] = load_resources.summarize(values, **window)
            except load_resources.SequenceRejected as failure:
                print(
                    canonical(
                        {
                            "scope": "load-resource-rejection-diagnostic",
                            "status": "fail",
                            "release_ready": False,
                            "container": name,
                            "samples": failure.samples,
                            "measurement": summary,
                            "diagnostics": payload["diagnostics"],
                        }
                    ).decode(),
                    flush=True,
                )
                raise
        self.receipt = {
            "summary_sha256": digest(canonical(summary)),
            "diagnostics_sha256": digest(canonical(payload["diagnostics"])),
            "resources": resources,
            "compute": self.compute,
        }
        return self.receipt

    def finish(self, report, raw):
        payload = decode(
            bounded_read(self.destination / "finish-request.json", MAX_PACKET), MAX_PACKET
        )["payload"]
        if (
            self.phases != list(PHASES)
            or report.get("operator") != self.receipt
            or report.get("measurement") != payload["summary"]
            or report.get("overload") != payload["overload"]
            or report.get("diagnostics") != payload["diagnostics"]
            or report.get("golden") != self.golden
            or report.get("worker_cleanup_verified") is not True
            or report.get("profile_met")
            is not (payload["summary"]["profile_met"] and payload["overload"]["profile_met"])
            or raw != canonical(report) + b"\n"
        ):
            raise Rejected("load_probe_report_changed")
        return report

    def reverify(self):
        for name, reference in self.hashes.items():
            if digest(bounded_read(self.destination / name, MAX_PACKET)) != reference:
                raise Rejected("load_retained_changed")
        if set(self.hashes) != {"start-request.json", "finish-request.json", "resources.json"}:
            raise Rejected("load_retained_incomplete")
        job = kubectl(
            self.state,
            [
                "get",
                "job",
                self.worker["job"],
                "-n",
                "ml-serve",
                "--ignore-not-found",
                "-o",
                "json",
            ],
            timeout=10,
        ).stdout
        pods = decode(
            kubectl(
                self.state,
                [
                    "get",
                    "pods",
                    "-n",
                    "ml-serve",
                    "-l",
                    "job-name=" + self.worker["job"],
                    "-o",
                    "json",
                ],
                timeout=10,
            ).stdout
        )["items"]
        if job.strip() or pods:
            raise Rejected("load_operator_worker_cleanup_unconfirmed")
        return True
