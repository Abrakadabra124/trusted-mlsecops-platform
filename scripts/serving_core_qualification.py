import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import serving, serving_context
from mlsecops.contracts import Rejected, digest


class ServingCoreContracts(unittest.TestCase):
    def setUp(self):
        self.loaded = SimpleNamespace(
            model=b"model",
            model_sha256=digest(b"model"),
            subject_sha256="a" * 64,
            expires_at=int(time.time()) + 3600,
            audit_context=serving_context.ReleaseContext("c" * 64, "a" * 64, digest(b"model")),
        )
        self.reader = Mock(image="sha256:" + "b" * 64)
        self.reader.trust.deadline = time.monotonic() + 60
        self.reader.load.return_value = self.loaded
        self.worker = Mock(
            image=self.reader.image, binding={"model_sha256": self.loaded.model_sha256}
        )
        self.worker.predict.side_effect = lambda rows: [0.75] * len(rows)
        self.patcher = patch.object(serving, "Worker", return_value=self.worker)
        self.constructor = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.engine = serving.Engine(self.reader)
        self.addCleanup(self.engine.close)

    def test_no_readiness_or_prediction_before_verified_load(self):
        for operation in (self.engine.check, lambda: self.engine.predict([[0.5] * 6])):
            with self.assertRaisesRegex(Rejected, "serving_not_ready"):
                operation()
        self.constructor.assert_not_called()

    def test_changed_or_mutable_model_never_reaches_worker_constructor(self):
        for value in (
            b"changed-after-reader-verification",
            bytearray(b"model"),
            memoryview(b"model"),
        ):
            with self.subTest(value=type(value).__name__):
                self.loaded.model = value
                self.constructor.reset_mock()
                with self.assertRaises(Rejected):
                    self.engine.activate()
                self.constructor.assert_not_called()
                self.assertIsNone(self.engine.loaded)
                self.assertIsNone(self.engine.worker)

    def test_explicit_worker_backend_never_falls_back_to_docker(self):
        factory = Mock(return_value=self.worker)
        self.engine.worker_factory = factory
        self.engine.activate()
        factory.assert_called_once_with(self.loaded.model, self.reader.image)
        self.constructor.assert_not_called()
        self.engine.clear()
        factory.side_effect = Rejected("backend unavailable")
        with self.assertRaises(Rejected):
            self.engine.activate()
        self.constructor.assert_not_called()
        self.assertIsNone(self.engine.loaded)

    def test_response_budget_bounds_and_expired_generation_cannot_fence_new_activation(self):
        with self.assertRaises(Rejected):
            self.engine.response_budget()
        self.engine.activate()
        original = self.engine.response_budget()
        self.assertLessEqual(original.remaining(), 10)
        self.reader.trust.deadline = time.monotonic() + 0.2
        near_expiry = self.engine.response_budget()
        with self.assertRaises(Rejected):
            near_expiry.remaining()
        self.reader.trust.deadline = time.monotonic() + 60
        self.engine.activate()
        current = self.engine.generation
        self.engine.expire(original.generation)
        self.assertFalse(current.is_set())
        self.assertTrue(original.generation.is_set())
        self.assertTrue(self.engine.check()["ready"])

    def test_queued_old_generation_cannot_execute_or_invalidate_new_worker(self):
        self.engine.activate()
        old = self.engine.response_budget()
        self.engine.activate()
        closes = self.worker.close.call_count
        for operation in (
            lambda: self.engine.check(generation=old.generation),
            lambda: self.engine.predict([[0.5] * 6], generation=old.generation),
        ):
            with self.assertRaisesRegex(Rejected, "serving_generation_changed"):
                operation()
        self.assertEqual(self.worker.close.call_count, closes)
        self.assertFalse(self.engine.generation.is_set())
        self.assertTrue(self.engine.check()["ready"])

    def test_release_expiry_limits_response_budget_and_clock_rollback_cannot_extend_it(self):
        self.loaded.expires_at = int(time.time()) + 2
        self.engine.activate()
        budget = self.engine.response_budget()
        self.assertLessEqual(budget.remaining(), 2)
        with patch.object(serving.time, "time", return_value=1):
            self.assertLessEqual(self.engine.response_budget().deadline, budget.deadline)

    def test_fenced_generation_discards_slow_trust_read_before_predicting(self):
        self.engine.activate()
        generation = self.engine.generation
        entered, release = threading.Event(), threading.Event()
        errors = []

        def check(loaded):
            entered.set()
            release.wait(3)

        def predict():
            try:
                self.engine.predict([[0.5] * 6])
            except Rejected as error:
                errors.append(str(error))

        self.reader.check.side_effect = check
        caller = threading.Thread(target=predict)
        caller.start()
        try:
            self.assertTrue(entered.wait(1))
            self.engine.expire(generation)
            self.assertTrue(generation.is_set())
            with self.assertRaises(Rejected):
                self.engine.response_budget()
        finally:
            release.set()
            caller.join(2)
        self.assertEqual(errors, ["serving_prediction_rejected"])
        self.worker.predict.assert_not_called()
        self.engine.drain()
        self.assertIsNone(self.engine.loaded)

    def test_same_bytes_pinned_image_and_mixed_abstain(self):
        self.engine.activate()
        self.constructor.assert_called_once_with(self.loaded.model, self.reader.image)
        result = self.engine.predict([[0.5] * 6, [2] * 6, [0.7] * 6])
        self.assertEqual(result["bundle_sha256"], self.loaded.subject_sha256)
        self.assertEqual(result["model_sha256"], self.loaded.model_sha256)
        self.assertEqual(
            [item["decision"] for item in result["predictions"]], ["score", "abstain", "score"]
        )
        self.assertEqual(self.worker.predict.call_args.args[0], [[0.5] * 6, [0.7] * 6])
        self.assertTrue(self.engine.check()["ready"])

    def test_failed_startup_and_wrong_worker_digest_never_become_ready(self):
        self.worker.binding["model_sha256"] = "f" * 64
        with self.assertRaisesRegex(Rejected, "serving_activation_rejected"):
            self.engine.activate()
        self.worker.close.assert_called_once()
        self.assertIsNone(self.engine.loaded)

    def test_heartbeat_start_failure_keeps_cleanup_safe_and_idempotent(self):
        with patch.object(
            serving.threading.Thread, "start", side_effect=RuntimeError("PRIVATE-CANARY")
        ):
            with self.assertRaisesRegex(Rejected, "^serving_activation_rejected$"):
                self.engine.activate()
        self.assertIsNone(self.engine.loaded)
        self.worker.close.assert_called_once()
        self.engine.close()
        self.engine.close()
        self.assertIsNone(self.engine.heartbeat)

    def test_activation_can_retry_heartbeat_start_after_transient_failure(self):
        with patch.object(
            serving.threading.Thread, "start", side_effect=RuntimeError("PRIVATE-CANARY")
        ):
            with self.assertRaises(Rejected):
                self.engine.activate()
        self.engine.activate()
        self.assertTrue(self.engine.heartbeat.is_alive())
        self.assertTrue(self.engine.check()["ready"])

    def test_failed_worker_start_retains_cleanup_handle_until_confirmed(self):
        self.worker.start.side_effect = Rejected("controlled-start-failure")
        self.worker.close.side_effect = OSError("PRIVATE-CANARY")
        try:
            with self.assertRaisesRegex(Rejected, "^serving_cleanup_unconfirmed$"):
                self.engine.activate()
            self.assertIsNone(self.engine.loaded)
            self.assertIs(self.engine.worker, self.worker)
        finally:
            self.worker.close.side_effect = None
        self.engine.close()
        self.assertIsNone(self.engine.worker)

    def test_revocation_after_inference_discards_result_and_closes_worker(self):
        self.engine.activate()
        self.reader.check.side_effect = [None, Rejected("revoked")]
        with self.assertRaisesRegex(Rejected, "serving_prediction_rejected"):
            self.engine.predict([[0.5] * 6])
        self.worker.predict.assert_called_once()
        self.engine.drain()
        self.worker.close.assert_called_once()
        self.assertIsNone(self.engine.loaded)

    def test_revocation_denial_does_not_wait_for_slow_cleanup_and_blocks_reload(self):
        self.engine.activate()
        self.reader.check.side_effect = Rejected("expired")
        cleanup_entered, release_cleanup, response_returned = (threading.Event() for _ in range(3))
        errors = []

        def cleanup():
            cleanup_entered.set()
            if not release_cleanup.wait(5):
                raise RuntimeError("controlled-cleanup-deadline")

        def predict():
            try:
                self.engine.predict([[0.5] * 6])
            except Rejected as error:
                errors.append(str(error))
            finally:
                response_returned.set()

        self.worker.close.side_effect = cleanup
        caller = threading.Thread(target=predict)
        caller.start()
        try:
            self.assertTrue(cleanup_entered.wait(1))
            self.assertTrue(response_returned.wait(1), "denial waits for Docker cleanup")
            self.assertEqual(errors, ["serving_prediction_rejected"])
            self.assertIsNone(self.engine.loaded)
            self.assertIsNone(self.engine.worker)
            with self.assertRaises(Rejected):
                self.engine.check()
            with self.assertRaises(Rejected):
                self.engine.activate()
            self.assertEqual(self.constructor.call_count, 1)
        finally:
            release_cleanup.set()
            caller.join(2)
        self.engine.drain()
        self.reader.check.side_effect = None
        self.engine.activate()
        self.assertTrue(self.engine.check()["ready"])

    def test_retirement_thread_start_failure_retains_worker_for_explicit_recovery(self):
        self.engine.activate()
        self.reader.check.side_effect = Rejected("expired")
        with patch.object(threading.Thread, "start", side_effect=RuntimeError("PRIVATE-CANARY")):
            with self.assertRaisesRegex(Rejected, "^serving_cleanup_unconfirmed$"):
                self.engine.predict([[0.5] * 6])
        self.assertIsNone(self.engine.loaded)
        self.assertIsNone(self.engine.worker)
        self.assertIs(self.engine.retiring, self.worker)
        self.worker.close.assert_not_called()
        self.engine.drain()
        self.assertIsNone(self.engine.retiring)
        self.worker.close.assert_called_once()

    def test_retirement_failure_retains_handle_and_close_retries(self):
        self.engine.activate()
        self.reader.check.side_effect = Rejected("expired")
        self.worker.close.side_effect = OSError("PRIVATE-CANARY")
        try:
            with self.assertRaises(Rejected):
                self.engine.predict([[0.5] * 6])
            self.engine.cleanup.join(2)
            with self.assertRaisesRegex(Rejected, "^serving_cleanup_unconfirmed$"):
                self.engine.drain()
            self.assertIs(self.engine.retiring, self.worker)
            self.assertIsNone(self.engine.loaded)
        finally:
            self.worker.close.side_effect = None
        self.engine.close()
        self.assertIsNone(self.engine.retiring)

    def test_abstention_still_requires_current_trust_and_live_worker(self):
        self.engine.activate()
        self.reader.check.side_effect = Rejected("expired")
        with self.assertRaises(Rejected):
            self.engine.predict([[2] * 6])
        self.worker.predict.assert_not_called()
        self.assertIsNone(self.engine.loaded)

    def test_bad_client_input_does_not_disable_valid_worker(self):
        self.engine.activate()
        for invalid in ([], [[True] * 6], [[float("nan")] * 6], [[1] * 5]):
            with self.subTest(invalid=invalid), self.assertRaises(Rejected):
                self.engine.predict(invalid)
        self.worker.close.assert_not_called()
        self.assertTrue(self.engine.check()["ready"])

    def test_reload_failure_does_not_fall_back_and_cleanup_can_retry(self):
        self.engine.activate()
        self.reader.load.side_effect = Rejected("new-release-invalid")
        with self.assertRaises(Rejected):
            self.engine.activate()
        self.worker.close.assert_called_once()
        with self.assertRaisesRegex(Rejected, "serving_not_ready"):
            self.engine.check()

    def test_worker_output_validation_and_process_failure_disable_session(self):
        self.engine.activate()
        self.worker.predict.return_value = [float("inf")]
        self.worker.predict.side_effect = None
        with self.assertRaises(Rejected):
            self.engine.predict([[0.5] * 6])
        self.assertIsNone(self.engine.loaded)

    def test_cleanup_failure_is_redacted_and_handle_is_retained_for_retry(self):
        self.engine.activate()
        self.worker.close.side_effect = OSError("PRIVATE-CANARY")
        with self.assertRaisesRegex(Rejected, "^serving_cleanup_unconfirmed$"):
            self.engine.close()
        self.assertIsNone(self.engine.loaded)
        self.assertIs(self.engine.worker, self.worker)
        self.worker.close.side_effect = None
        self.engine.close()
        self.assertIsNone(self.engine.worker)

    def test_closed_engine_and_overload_do_not_start_worker(self):
        self.engine.lock.acquire()
        try:
            with self.assertRaisesRegex(Rejected, "serving_busy"):
                self.engine.check()
        finally:
            self.engine.lock.release()
        self.engine.close()
        with self.assertRaisesRegex(Rejected, "serving_closed"):
            self.engine.activate()
        self.constructor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
