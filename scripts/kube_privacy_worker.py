"""Qualification-only observer around the unchanged Kubernetes worker.

Records replies, never input feature rows. The external operator callback reads
the terminal Pod's CRI logs before the normal owned-resource cleanup deletes it.
No callback, credentials or extra RBAC is added to production configuration.
"""

from unittest.mock import patch

from mlsecops import kube_serving_runtime as runtime
from mlsecops.contracts import Rejected, canonical
from scripts.kube_privacy_logs import MAX_BYTES


class Channel:
    def __init__(self, delegate, records):
        self.delegate, self.records = delegate, records

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    def exchange(self, request, *, timeout):
        reply = self.delegate.exchange(request, timeout=timeout)
        content = canonical(reply) + b"\n"
        if len(self.records) + len(content) > MAX_BYTES:
            raise Rejected("privacy_worker_output_limit")
        self.records.extend(content)
        return reply


class Worker(runtime.Worker):
    def __init__(self, model, image, profile, *, observer):
        if not callable(observer):
            raise Rejected("privacy_worker_observer")
        self.records = bytearray()
        self.observer = observer
        self.observation = None
        self.observation_attempted = False
        self.pod_snapshot = None
        super().__init__(model, image, profile)

    def start(self):
        # Only this dedicated probe process starts this one worker. Keep the
        # real transport, protocol validation, image checks and deadlines.
        original = runtime.Channel
        with patch.object(
            runtime, "Channel", lambda process: Channel(original(process), self.records)
        ):
            result = super().start()
        try:
            pods = self.client.request("pods", job=self.name)["items"]
            if len(pods) != 1 or pods[0]["metadata"]["uid"] != self.pod_uid:
                raise Rejected("privacy_worker_start_identity")
            runtime.verify_pod(
                pods[0], self.document["spec"]["template"]["spec"], self.job_uid, self.profile
            )
            self.pod_snapshot = pods[0]
            return result
        except BaseException:
            super().close()
            raise

    def close(self):
        try:
            if self.job_uid is not None and not self.observation_attempted:
                self.observation_attempted = True
                if self.channel is None or not self.records:
                    raise Rejected("privacy_worker_capture_missing")
                self.channel.close()
                process = self.channel.process
                if process.poll() is None or process.stderr.read(65537):
                    raise Rejected("privacy_worker_bridge_output")
                self.observation = self.observer(self, bytes(self.records))
        finally:
            # Observer failure, timeout and interruption must never skip cleanup.
            super().close()
