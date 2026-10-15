import threading
import time
import unittest
from unittest.mock import Mock

from mlsecops import release_authorization, release_bundle, serving
from mlsecops.contracts import digest
from mlsecops.model import predict, session
from scripts import promotion_qualification as fixtures
from scripts.serving_native import bind_real_runtime, site


class ServingNativeHarnessContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.PromotionAdmissionContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.PromotionAdmissionContracts.tearDownClass()

    def test_real_model_fixture_rebinds_capsule_release_and_authorization(self):
        fixture = fixtures.PromotionAdmissionContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        image = "sha256:" + "c" * 64
        features, expected = bind_real_runtime(fixture, image)
        decision = release_authorization.verify(**fixture.arguments, clock=fixture.clock)
        manifest = release_bundle.index(
            fixture.arguments["package"]["envelope"], fixture.fixture.bundle.materials.public
        )
        self.assertEqual(manifest["serving_image"], image)
        model = fixture.fixture.bundle.materials.fixture.model
        self.assertEqual(manifest["materials"]["model"], digest(model))
        runtime, _ = session(model)
        actual = predict(runtime, features)
        self.assertLessEqual(
            max(abs(left - right) for left, right in zip(actual, expected, strict=True)), 1e-5
        )
        self.assertFalse(decision["release_ready"])
        receipt = fixture.run_admission()
        self.assertEqual(receipt["subject_sha256"], decision["subject_sha256"])

    def test_real_loopback_http_helper_serves_and_shuts_down(self):
        engine = Mock()
        generation = threading.Event()
        engine.response_budget.side_effect = lambda: serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        engine.check.return_value = {"ready": True}
        with site(engine) as request:
            self.assertEqual(request("/livez", authorized=False), (200, {"status": "alive"}))
            self.assertEqual(request("/readyz")[0], 200)
            self.assertEqual(request("/readyz", authorized=False)[0], 401)
        self.assertGreaterEqual(engine.close.call_count, 1)


if __name__ == "__main__":
    unittest.main()
