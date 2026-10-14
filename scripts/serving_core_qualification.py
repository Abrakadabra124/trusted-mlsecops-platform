import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import serving
from mlsecops.contracts import Rejected, digest


class ServingCoreContracts(unittest.TestCase):
    def setUp(self):
        self.loaded = SimpleNamespace(
            model=b"model", model_sha256=digest(b"model"), subject_sha256="a" * 64
        )
        self.reader = Mock(image="sha256:" + "b" * 64)
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

    def test_revocation_after_inference_discards_result_and_closes_worker(self):
        self.engine.activate()
        self.reader.check.side_effect = [None, Rejected("revoked")]
        with self.assertRaisesRegex(Rejected, "serving_prediction_rejected"):
            self.engine.predict([[0.5] * 6])
        self.worker.predict.assert_called_once()
        self.worker.close.assert_called_once()
        self.assertIsNone(self.engine.loaded)

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
