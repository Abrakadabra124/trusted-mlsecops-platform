"""Persistent, credential-free ONNX worker under namespace-scoped Kubernetes RBAC."""

import os
import re
import subprocess
import sys
import time

from mlsecops import serving_protocol as protocol
from mlsecops import serving_startup
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.controller_api import APIError, Client
from mlsecops.controller_worker import remove, validate_profile
from mlsecops.kube_storage import matches
from mlsecops.kube_worker import job_document, pod_spec
from mlsecops.serving_runtime import Channel
from mlsecops.serving_runtime import Worker as StdioWorker


def document(profile, session):
    spec = pod_spec(profile["image"], "serving", ["mlsecops.serving_worker"], memory="1Gi")
    container = spec["containers"][0]
    # TTY defaults to false and Kubernetes omits false from its JSON response.
    container.update(stdin=True, stdinOnce=True)
    container["resources"]["limits"]["cpu"] = "1"
    container["resources"]["requests"]["memory"] = "1Gi"
    value = job_document(f"serving-worker-{session}", "ml-serve", spec, 3600)
    value["spec"].update(parallelism=1, completions=1)
    return value


def verify_pod(pod, expected, uid, profile):
    if not matches(expected, pod["spec"]) or not any(
        owner.get("uid") == uid and owner.get("controller") is True
        for owner in pod["metadata"].get("ownerReferences", [])
    ):
        raise Rejected("serving_worker_pod_identity")
    spec = pod["spec"]
    container = spec["containers"][0]
    if (
        any(
            spec.get(key)
            for key in (
                "hostNetwork",
                "hostPID",
                "hostIPC",
                "shareProcessNamespace",
                "initContainers",
                "ephemeralContainers",
                "hostAliases",
            )
        )
        or any(
            container.get(key)
            for key in (
                "args",
                "env",
                "envFrom",
                "ports",
                "lifecycle",
                "livenessProbe",
                "readinessProbe",
                "startupProbe",
                "tty",
            )
        )
        or container["securityContext"].get("privileged")
        or container["securityContext"]["capabilities"].get("add")
        or spec["securityContext"].get("sysctls")
    ):
        raise Rejected("serving_worker_pod_contract")
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if (
        len(statuses) != 1
        or statuses[0].get("restartCount") != 0
        or "running" not in statuses[0].get("state", {})
    ):
        raise Rejected("serving_worker_not_running")
    observed = re.search(r"sha256:[0-9a-f]{64}$", statuses[0].get("imageID", ""))
    if observed is None or observed.group() not in {profile["manifest_id"], profile["config_id"]}:
        raise Rejected("serving_worker_image_mismatch")


class Worker(StdioWorker):
    def __init__(self, model, image, profile):
        self.profile = decode(canonical(profile))
        validate_profile(self.profile)
        if self.profile["image_id"] != image:
            raise Rejected("serving_image_pin")
        self.initial = protocol.load_request(model)
        self.binding = {name: self.initial[name] for name in ("session_id", "model_sha256")}
        self.image = image
        self.channel = None
        self.closed = False
        self.document = document(self.profile, self.binding["session_id"])
        self.name = self.document["metadata"]["name"]
        self.client = Client("serving")
        self.job_uid = None
        self.attempted = False
        self.pod_uid = None
        self.startup_failure = None

    def observe_job(self):
        try:
            observed = self.client.request("jobs", self.name)
        except APIError as error:
            if error.status == 404:
                return None
            raise
        uid = observed["metadata"]["uid"]
        if (
            not isinstance(uid, str)
            or not uid
            or not matches(self.document, observed)
            or self.job_uid is not None
            and uid != self.job_uid
        ):
            raise Rejected("serving_worker_job_identity")
        self.job_uid = uid
        return observed

    def start(self):
        if self.closed or self.initial is None:
            raise Rejected("serving_worker_start_state")
        initial, self.initial = self.initial, None
        phase = "create"
        try:
            self.attempted = True
            created = self.client.request("jobs", method="POST", value=self.document)
            self.job_uid = created["metadata"]["uid"]
            phase = "observe"
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if self.observe_job() is None:
                    raise Rejected("serving_worker_job_missing")
                pods = self.client.request("pods", job=self.name)["items"]
                if len(pods) > 1:
                    raise Rejected("serving_worker_pod_count")
                if pods:
                    pod = pods[0]
                    if pod.get("status", {}).get("phase") in {"Succeeded", "Failed"}:
                        raise Rejected("serving_worker_exited")
                    if pod.get("status", {}).get("phase") == "Running":
                        verify_pod(
                            pod,
                            self.document["spec"]["template"]["spec"],
                            self.job_uid,
                            self.profile,
                        )
                        self.pod_uid = pod["metadata"]["uid"]
                        break
                time.sleep(0.25)
            else:
                raise Rejected("serving_worker_start_deadline")
            phase = "attach"
            process = subprocess.Popen(
                [sys.executable, "-m", "mlsecops.kube_attach", "--pod", pod["metadata"]["name"]],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=os.name == "posix",
            )
            self.channel = Channel(process)
            self.channel.start()
            phase = "load"
            self.send(initial, timeout=30)
            return self
        except Exception as error:
            self.startup_failure = (
                phase,
                str(error) if str(error) in serving_startup.CAUSES else "unknown",
            )
            self.close()
            raise Rejected("serving_load_failed") from None

    def close(self):
        self.closed = True
        try:
            if self.channel is not None:
                process = self.channel.process
                try:
                    self.channel.close()
                finally:
                    if process.stderr is not None:
                        try:
                            if self.startup_failure is not None and process.poll() is not None:
                                code = serving_startup.bridge_code(process.stderr.read(513))
                                if code != "unknown":
                                    self.startup_failure = (self.startup_failure[0], code)
                        finally:
                            process.stderr.close()
                self.channel = None
        finally:
            if self.attempted or self.job_uid is not None:
                if self.observe_job() is not None:
                    remove(self.client, "jobs", self.name, self.job_uid)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if (
                        self.observe_job() is None
                        and not self.client.request("pods", job=self.name)["items"]
                    ):
                        self.job_uid = None
                        self.attempted = False
                        break
                    time.sleep(0.25)
                else:
                    raise Rejected("serving_cleanup_unconfirmed")
