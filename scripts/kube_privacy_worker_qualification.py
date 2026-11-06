import io
import unittest
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_privacy_worker as observed
from scripts.kube_serving_runtime_qualification import PROFILE, MemoryAPI


class WorkerObservationContracts(unittest.TestCase):
    def test_real_owned_cleanup_runs_after_observation_and_after_observer_failure(self):
        for fail in (False, True):
            api = MemoryAPI()

            def inspect(worker, content):
                self.assertIsNotNone(api.job)
                self.assertEqual(content, b"reply\n")
                if fail:
                    raise Rejected("operator_observation_failed")
                return {"status": "pass"}

            with patch.object(observed.runtime, "Client", return_value=api):
                worker = observed.Worker(b"model", PROFILE["image_id"], PROFILE, observer=inspect)
            worker.job_uid = api.request("jobs", method="POST", value=worker.document)["metadata"][
                "uid"
            ]
            worker.attempted = True
            worker.records.extend(b"reply\n")
            worker.channel = Mock()
            worker.channel.process.stderr = io.BytesIO()
            worker.channel.process.poll.return_value = 0
            if fail:
                with self.assertRaisesRegex(Rejected, "^operator_observation_failed$"):
                    worker.close()
            else:
                worker.close()
            self.assertIsNone(api.job)
            self.assertTrue(worker.closed)
            self.assertEqual(api.deleted[0]["preconditions"]["uid"], "job-uid")
            self.assertTrue(worker.channel is None)
            worker.close()
            self.assertEqual(len(api.deleted), 1)

    def test_noncallable_observer_rejected_before_worker_construction(self):
        with (
            patch.object(observed.runtime, "Client") as client,
            self.assertRaisesRegex(Rejected, "^privacy_worker_observer$"),
        ):
            observed.Worker(b"model", PROFILE["image_id"], PROFILE, observer=None)
        client.assert_not_called()

    def test_records_exact_reply_bytes_without_persisting_request_features(self):
        reply = {"score": 0.5, "request_id": "a" * 32}
        delegate = Mock(exchange=Mock(return_value=reply))
        records = bytearray()
        channel = observed.Channel(delegate, records)
        self.assertIs(channel.exchange({"features": "private-canary"}, timeout=2), reply)
        self.assertEqual(records, canonical(reply) + b"\n")
        self.assertNotIn(b"private-canary", records)
        self.assertIs(channel.process, delegate.process)
        channel.close()
        delegate.close.assert_called_once_with()

    def test_record_overflow_refuses_and_keeps_previous_complete_prefix(self):
        records = bytearray(b"x" * observed.MAX_BYTES)
        channel = observed.Channel(Mock(exchange=Mock(return_value={})), records)
        with self.assertRaisesRegex(Rejected, "privacy_worker_output_limit"):
            channel.exchange({}, timeout=2)
        self.assertEqual(len(records), observed.MAX_BYTES)

    def worker(self, observer=None, diagnostic=b""):
        worker = observed.Worker.__new__(observed.Worker)
        worker.job_uid = "owned-job"
        worker.records = bytearray(b"reply\n")
        worker.observer = observer or Mock(return_value={"status": "pass"})
        worker.observation = None
        worker.observation_attempted = False
        worker.channel = Mock()
        worker.channel.process.stderr = io.BytesIO(diagnostic)
        worker.channel.process.poll.return_value = 0
        return worker

    def test_channel_stops_then_observer_reads_before_owned_cleanup(self):
        order = []

        def inspect(worker, content):
            order.append("observe")
            self.assertEqual(content, b"reply\n")
            worker.channel.close.assert_called_once_with()
            return {"status": "pass"}

        worker = self.worker(inspect)
        worker.channel.close.side_effect = lambda: order.append("channel-close")
        with patch.object(
            observed.runtime.Worker, "close", side_effect=lambda: order.append("cleanup")
        ):
            worker.close()
            worker.close()
        self.assertEqual(order, ["channel-close", "observe", "cleanup", "cleanup"])
        self.assertEqual(worker.observation, {"status": "pass"})

    def test_observation_failure_and_interruption_still_run_base_cleanup(self):
        for error in (Rejected("capture_failed"), KeyboardInterrupt()):
            observer = Mock(side_effect=error)
            worker = self.worker(observer)
            with patch.object(observed.runtime.Worker, "close") as cleanup:
                with self.assertRaises(type(error)):
                    worker.close()
                worker.close()
            self.assertEqual(cleanup.call_count, 2)
            observer.assert_called_once_with(worker, b"reply\n")
            self.assertIsNone(worker.observation)

    def test_bridge_stderr_empty_stream_missing_channel_and_live_process_fail_closed(self):
        mutations = (
            lambda w: setattr(w.channel.process, "stderr", io.BytesIO(b"private-canary")),
            lambda w: setattr(w.channel.process, "stderr", io.BytesIO(b"x" * 65537)),
            lambda w: w.channel.process.poll.configure_mock(return_value=None),
            lambda w: w.records.clear(),
            lambda w: setattr(w, "channel", None),
        )
        for mutate in mutations:
            worker = self.worker()
            mutate(worker)
            with (
                self.subTest(mutate=mutate),
                patch.object(observed.runtime.Worker, "close") as cleanup,
            ):
                with self.assertRaises(Rejected):
                    worker.close()
                cleanup.assert_called_once_with()
                worker.observer.assert_not_called()

    def test_start_wraps_channel_only_inside_owned_worker_start(self):
        delegate = Mock()
        worker = self.worker()
        worker.client = Mock(request=Mock(return_value={"items": [{"metadata": {"uid": "pod"}}]}))
        worker.pod_uid = "pod"
        worker.name = "worker"
        worker.document = {"spec": {"template": {"spec": {}}}}
        worker.profile = {}
        original = observed.runtime.Channel

        def start():
            wrapped = observed.runtime.Channel("owned-process")
            self.assertIsInstance(wrapped, observed.Channel)
            self.assertIs(wrapped.records, worker.records)
            self.assertIs(wrapped.delegate, delegate)
            return worker

        with (
            patch.object(observed.runtime, "verify_pod"),
            patch.object(observed.runtime, "Channel", return_value=delegate) as factory,
        ):
            with patch.object(observed.runtime.Worker, "start", side_effect=start):
                self.assertIs(worker.start(), worker)
            factory.assert_called_once_with("owned-process")
            self.assertIs(observed.runtime.Channel, factory)
        self.assertIs(observed.runtime.Channel, original)

    def test_uncreated_worker_does_not_invent_an_observation(self):
        worker = self.worker()
        worker.job_uid = None
        with patch.object(observed.runtime.Worker, "close") as cleanup:
            worker.close()
        worker.observer.assert_not_called()
        cleanup.assert_called_once_with()
        self.assertIsNone(worker.observation)

    def test_start_snapshot_failure_cleans_owned_job_and_restores_real_channel(self):
        for pods, failure in (
            ([], None),
            ([{"metadata": {"uid": "foreign"}}], None),
            ([{"metadata": {"uid": "pod"}}], KeyboardInterrupt()),
        ):
            worker = self.worker()
            worker.client = Mock(request=Mock(return_value={"items": pods}))
            worker.name, worker.pod_uid = "worker", "pod"
            worker.document = {"spec": {"template": {"spec": {}}}}
            worker.profile = {}
            worker.pod_snapshot = None
            original = observed.runtime.Channel
            with (
                patch.object(observed.runtime.Worker, "start", return_value=worker),
                patch.object(observed.runtime.Worker, "close") as cleanup,
                patch.object(observed.runtime, "verify_pod", side_effect=failure),
                self.assertRaises(KeyboardInterrupt if failure else Rejected),
            ):
                worker.start()
            cleanup.assert_called_once_with()
            self.assertIsNone(worker.pod_snapshot)
            self.assertIs(observed.runtime.Channel, original)


if __name__ == "__main__":
    unittest.main()
