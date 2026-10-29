import copy
import unittest
from unittest.mock import Mock, patch

from mlsecops import kube_serving_runtime as runtime
from mlsecops.contracts import Rejected
from mlsecops.controller_api import APIError

PROFILE = {
    "image": "trusted-mlsecops@sha256:" + "a" * 64,
    "image_id": "sha256:" + "b" * 64,
    "config_id": "sha256:" + "b" * 64,
    "manifest_id": "sha256:" + "a" * 64,
    "source_fingerprint": "c" * 64,
    "source_revision": "d" * 40,
}


class MemoryAPI:
    def __init__(self):
        self.job = None
        self.deleted = []
        self.create_lost = False

    def request(self, resource, name=None, method="GET", value=None, job=None):
        if method == "POST":
            self.job = copy.deepcopy(value)
            self.job["metadata"]["uid"] = "job-uid"
            if self.create_lost:
                raise OSError("lost create response")
            return self.job
        if method == "DELETE":
            if value["preconditions"]["uid"] != self.job["metadata"]["uid"]:
                raise APIError(409, "Unexpected")
            self.deleted.append(copy.deepcopy(value))
            self.job = None
            return {}
        if resource == "pods":
            return {"items": [] if self.job is None else [self.pod()]}
        if self.job is None:
            raise APIError(404, "NotFound")
        return self.job

    def pod(self):
        return {
            "metadata": {
                "name": "serving-worker-pod",
                "uid": "pod-uid",
                "namespace": "ml-serve",
                "ownerReferences": [{"uid": "job-uid", "controller": True}],
            },
            "spec": copy.deepcopy(self.job["spec"]["template"]["spec"]),
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {
                        "name": "worker",
                        "restartCount": 0,
                        "imageID": PROFILE["manifest_id"],
                        "state": {"running": {}},
                    }
                ],
            },
        }


class RuntimeContracts(unittest.TestCase):
    def worker(self):
        api = MemoryAPI()
        with patch.object(runtime, "Client", return_value=api):
            worker = runtime.Worker(b"model", PROFILE["image_id"], PROFILE)
        return worker, api

    def test_job_pins_worker_identity_command_io_resources_and_no_credentials(self):
        worker, _ = self.worker()
        spec = worker.document["spec"]["template"]["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["serviceAccountName"], "serving")
        self.assertEqual(len(spec["volumes"]), 1)
        self.assertEqual(spec["volumes"][0]["emptyDir"]["medium"], "Memory")
        container = spec["containers"][0]
        self.assertEqual(container["command"], ["python", "-m", "mlsecops.serving_worker"])
        self.assertEqual(container["image"], PROFILE["image"])
        self.assertTrue(container["stdin"])
        self.assertTrue(container["stdinOnce"])
        self.assertFalse(container["tty"])
        self.assertEqual(container["resources"]["limits"]["memory"], "1Gi")
        self.assertEqual(container["resources"]["limits"]["cpu"], "1")
        self.assertEqual(worker.document["spec"]["activeDeadlineSeconds"], 3600)

    def test_profile_and_image_mismatch_rejected_before_api(self):
        for profile in [
            {},
            {**PROFILE, "image": "untrusted:latest"},
            {**PROFILE, "image_id": "sha256:" + "e" * 64},
        ]:
            with patch.object(runtime, "Client") as client, self.assertRaises(Rejected):
                runtime.Worker(b"model", PROFILE["image_id"], profile)
            client.assert_not_called()

    def test_start_binds_image_model_and_one_process_then_close_confirms_absence(self):
        worker, api = self.worker()
        process, channel = Mock(), Mock()
        with (
            patch.object(runtime.subprocess, "Popen", return_value=process) as spawn,
            patch.object(runtime, "Channel", return_value=channel),
            patch.object(worker, "send") as send,
        ):
            self.assertIs(worker.start(), worker)
            self.assertEqual(send.call_count, 1)
            self.assertEqual(send.call_args.kwargs, {"timeout": 30})
            self.assertEqual(spawn.call_args.args[0][-2:], ["--pod", "serving-worker-pod"])
            worker.close()
        self.assertEqual(api.deleted[0]["preconditions"], {"uid": "job-uid"})
        self.assertEqual(api.deleted[0]["propagationPolicy"], "Foreground")
        self.assertIsNone(api.job)
        channel.close.assert_called_once()
        worker.close()
        with self.assertRaises(Rejected):
            worker.start()

    def test_start_failure_and_lost_creation_reply_clean_owned_job(self):
        for failure in ["create", "spawn", "thread", "load"]:
            worker, api = self.worker()
            api.create_lost = failure == "create"
            channel = Mock()
            if failure == "thread":
                channel.start.side_effect = RuntimeError("private")
            with (
                patch.object(
                    runtime.subprocess,
                    "Popen",
                    side_effect=OSError("private") if failure == "spawn" else None,
                ),
                patch.object(runtime, "Channel", return_value=channel),
                patch.object(
                    worker, "send", side_effect=Rejected("private") if failure == "load" else None
                ),
            ):
                with self.assertRaises(Rejected):
                    worker.start()
            self.assertIsNone(api.job)
            self.assertTrue(worker.closed)

    def test_changed_owner_image_or_pod_contract_never_spawns_transport(self):
        changes = [
            lambda p: p["metadata"]["ownerReferences"][0].update(uid="foreign"),
            lambda p: p["status"]["containerStatuses"][0].update(imageID="sha256:" + "f" * 64),
            lambda p: p["spec"].update(automountServiceAccountToken=True),
            lambda p: p["spec"]["containers"][0].update(
                env=[{"name": "PRIVATE", "value": "secret"}]
            ),
            lambda p: p["spec"]["containers"][0]["securityContext"].update(privileged=True),
        ]
        for change in changes:
            worker, api = self.worker()
            original = api.pod

            def changed():
                pod = original()
                change(pod)
                return pod

            api.pod = changed
            with patch.object(runtime.subprocess, "Popen") as spawn, self.assertRaises(Rejected):
                worker.start()
            spawn.assert_not_called()
            self.assertIsNone(api.job)

    def test_foreign_job_or_unconfirmed_removal_is_not_reported_clean(self):
        for failure in ["foreign", "delete"]:
            worker, api = self.worker()
            api.job = copy.deepcopy(worker.document)
            api.job["metadata"]["uid"] = "job-uid"
            worker.job_uid = "job-uid"
            if failure == "foreign":
                api.job["metadata"]["uid"] = "foreign"
            else:
                original = api.request

                def request(*args, **kwargs):
                    if kwargs.get("method") == "DELETE":
                        raise APIError(403, "Forbidden")
                    return original(*args, **kwargs)

                api.request = request
            with self.assertRaises(Rejected):
                worker.close()
            self.assertIsNotNone(api.job)
            self.assertEqual(api.deleted, [])

    def test_cleanup_attempts_job_even_when_channel_close_fails(self):
        worker, api = self.worker()
        api.job = copy.deepcopy(worker.document)
        api.job["metadata"]["uid"] = "job-uid"
        worker.job_uid = "job-uid"
        worker.channel = Mock()
        worker.channel.close.side_effect = Rejected("blocked pipe")
        with self.assertRaises(Rejected):
            worker.close()
        self.assertIsNone(api.job)

    def test_missing_failed_multiple_or_pending_pods_fail_with_cleanup(self):
        for situation in ["missing-job", "multiple-pods", "failed-pod", "no-pod", "pending-pod"]:
            worker, api = self.worker()
            original = api.request

            def request(resource, *args, **kwargs):
                result = original(resource, *args, **kwargs)
                if kwargs.get("method", "GET") != "GET" or api.job is None:
                    return result
                if situation == "missing-job" and resource == "jobs":
                    api.job = None
                    raise APIError(404, "NotFound")
                if resource == "pods":
                    if situation == "multiple-pods":
                        return {"items": [api.pod(), api.pod()]}
                    if situation == "no-pod":
                        return {"items": []}
                    if situation in {"failed-pod", "pending-pod"}:
                        result["items"][0]["status"]["phase"] = (
                            "Failed" if situation == "failed-pod" else "Pending"
                        )
                return result

            api.request = request
            ticks = iter([0, 0, 61, 62, 62, 62, 62])
            with (
                patch.object(runtime.time, "monotonic", side_effect=lambda: next(ticks, 62)),
                patch.object(runtime.time, "sleep"),
                self.assertRaises(Rejected),
            ):
                worker.start()
            self.assertIsNone(api.job)

    def test_running_pod_requires_one_nonrestarted_container_and_actual_digest(self):
        worker, api = self.worker()
        api.job = copy.deepcopy(worker.document)
        for status in [
            [],
            [{"restartCount": 1}],
            [{"restartCount": 0, "state": {"waiting": {}}}],
            [{"restartCount": 0, "state": {"running": {}}, "imageID": "latest"}],
        ]:
            pod = api.pod()
            pod["status"]["containerStatuses"] = status
            with self.assertRaises(Rejected):
                runtime.verify_pod(pod, api.job["spec"]["template"]["spec"], "job-uid", PROFILE)

    def test_cleanup_waits_for_foreground_deletion_and_rejects_remaining_pod(self):
        worker, api = self.worker()
        api.job = copy.deepcopy(worker.document)
        api.job["metadata"]["uid"] = "job-uid"
        worker.job_uid = "job-uid"
        original = api.request

        def request(resource, *args, **kwargs):
            if resource == "pods":
                return {"items": [{}]}
            return original(resource, *args, **kwargs)

        api.request = request
        with (
            patch.object(runtime.time, "monotonic", side_effect=[0, 0, 16]),
            patch.object(runtime.time, "sleep"),
            self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"),
        ):
            worker.close()

    def test_observation_does_not_hide_authorization_or_contract_failures(self):
        worker, api = self.worker()
        with (
            patch.object(api, "request", side_effect=APIError(403, "Forbidden")),
            self.assertRaises(APIError),
        ):
            worker.observe_job()
        for uid in [None, ""]:
            api.job = copy.deepcopy(worker.document)
            api.job["metadata"]["uid"] = uid
            with self.assertRaises(Rejected):
                worker.observe_job()
        api.job["metadata"]["uid"] = "job-uid"
        api.job["spec"]["template"]["spec"]["serviceAccountName"] = "foreign"
        with self.assertRaises(Rejected):
            worker.observe_job()


if __name__ == "__main__":
    unittest.main()
