import threading
import time
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from mlsecops import release_authorization, release_bundle, serving, serving_access
from mlsecops.contracts import Rejected, digest
from mlsecops.model import predict, session
from scripts import promotion_qualification as fixtures
from scripts import serving_native
from scripts.serving_access_qualification import credentials
from scripts.serving_native import bind_real_runtime, site


class ServingNativeHarnessContracts(unittest.TestCase):
    def test_check_http_preserves_accounting_across_default_credential_wrapper(self):
        engine = Mock()
        generation = threading.Event()
        engine.response_budget.side_effect = lambda: serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        engine.check.return_value = {"ready": True}
        engine.loaded.model_sha256, engine.loaded.subject_sha256 = "a" * 64, "b" * 64
        cases = []

        def predict(features, **keywords):
            return {
                "model_sha256": "a" * 64,
                "bundle_sha256": "b" * 64,
                "predictions": [
                    {
                        "decision": "abstain" if row[0] > 1 else "score",
                        "score": None if row[0] > 1 else 0.75,
                    }
                    for row in features
                ],
            }

        def confirmed(name, condition):
            self.assertTrue(condition, name)
            cases.append(name)

        def rejected(name, operation, reason):
            self.assertEqual(name, "native-malformed-model-never-ready")
            raise Rejected("stop_before_container_probe")

        engine.predict.side_effect = predict
        with (
            patch.object(serving_native.serving, "Engine", return_value=engine),
            ExitStack() as services,
        ):
            with self.assertRaisesRegex(Rejected, "stop_before_container_probe"):
                serving_native.check_http(
                    services, Mock(), ([[0.5] * 6], [0.75]), confirmed, rejected
                )
        self.assertIn("client-admission-accounting", cases)
        self.assertIn("foreign-client-identity-401", cases)

    def test_valid_slow_inference_cannot_hide_cross_client_charge(self):
        engine = Mock()
        generation = threading.Event()
        engine.response_budget.side_effect = lambda: serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        observed = []
        original = serving_access.Access.acquire

        def acquire(access, principal):
            if not observed:
                observed.append(access)
            return original(access, principal)

        calls = []

        def predict(*arguments, **keywords):
            if not calls:
                observed[0].acquire("b" * 32).release()
                calls.append(True)
                time.sleep(1.1)
            return {"predictions": []}

        def confirmed(name, condition):
            if not condition:
                raise Rejected(name)

        engine.predict.side_effect = predict
        config = credentials()
        for client in config["clients"]:
            client.update(requests_per_second=1, burst=1)
        with (
            patch.object(serving_access.Access, "acquire", acquire),
            site(engine, clients=config) as request,
        ):
            body = {
                "schema_version": 1,
                "instances": [{name: 0.5 for name in serving_native.FEATURES}],
            }
            with self.assertRaisesRegex(Rejected, "client-admission-accounting"):
                serving_native.check_clients(request, body, ["a" * 64, "b" * 64], confirmed)

    def test_native_quota_boundary_detects_cross_charge_without_slow_inference_false_failure(self):
        for cross_charge in (False, True):
            with self.subTest(cross_charge=cross_charge):
                engine = Mock()
                generation = threading.Event()
                engine.response_budget.side_effect = lambda: serving.ResponseBudget(
                    generation, time.monotonic() + 10
                )
                engine.predict.side_effect = lambda *args, **kwargs: (
                    time.sleep(1.1),
                    {"predictions": []},
                )[1]
                config = credentials()
                for client in config["clients"]:
                    client.update(requests_per_second=1, burst=1)
                original = serving_access.Access.acquire

                def acquire(access, principal):
                    if cross_charge and principal == "b" * 32:
                        original(access, "a" * 32).release()
                    return original(access, principal)

                def confirmed(name, condition):
                    if not condition:
                        raise Rejected(name)

                with (
                    patch.object(serving_access.Access, "acquire", acquire),
                    site(engine, clients=config) as request,
                ):
                    body = {
                        "schema_version": 1,
                        "instances": [{name: 0.5 for name in serving_native.FEATURES}],
                    }
                    if cross_charge:
                        with self.assertRaisesRegex(Rejected, "independent-client-burst-boundary"):
                            serving_native.check_clients(
                                request, body, ["a" * 64, "b" * 64], confirmed
                            )
                    else:
                        result = serving_native.check_clients(
                            request, body, ["a" * 64, "b" * 64], confirmed
                        )
                        self.assertEqual(result["status"], "pass")

    def test_native_quota_window_lapse_is_inconclusive_not_false_rate_failure(self):
        request = Mock(return_value=(200, {}))
        confirmed = Mock()
        with patch.object(serving_native.time, "monotonic", side_effect=[1.0, 2.1]):
            with self.assertRaisesRegex(Rejected, "client_quota_window_inconclusive"):
                serving_native.check_clients(request, {}, ["a" * 64, "b" * 64], confirmed)
        confirmed.assert_not_called()

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

    def test_real_loopback_two_clients_have_separate_rate_limits(self):
        engine = Mock()
        generation = threading.Event()
        engine.response_budget.side_effect = lambda: serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        engine.check.return_value = {"ready": True}
        config = credentials()
        config["clients"][1].update(requests_per_second=1, burst=1)
        with site(engine, clients=config) as request:
            self.assertEqual(request.admissions(["a" * 64, "b" * 64]), [0, 0, 0])
            for tokens in (["a" * 64, "a" * 64], ["c" * 64]):
                with self.assertRaisesRegex(Rejected, "serving_native_client_unknown"):
                    request.admissions(tokens)
            self.assertEqual(request("/readyz", credential="b" * 64)[0], 200)
            status, result = request("/readyz", credential="b" * 64)
            self.assertEqual((status, result["error"]["code"]), (429, "client_limited"))
            self.assertEqual(request("/readyz")[0], 200)
            self.assertEqual(request("/readyz", credential="")[0], 401)
            time.sleep(1.05)
            self.assertEqual(request("/readyz", credential="b" * 64)[0], 200)


if __name__ == "__main__":
    unittest.main()
