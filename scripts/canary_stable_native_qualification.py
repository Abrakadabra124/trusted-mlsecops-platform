"""Controlled stable-release contracts. No live storage, promoter or worker."""

import os
import time
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import model as onnx_model
from mlsecops import release_bundle, release_policy
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.datasets import FEATURES
from scripts import canary_stable_native as native
from scripts.kube_rollback_native import variant as native_variant


class StableReleaseContracts(unittest.TestCase):
    def test_requires_owned_host_before_provisioning(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), self.assertRaises(Rejected):
            with native.stable_release(
                Path("."), Path(".runtime"), "image", "lab", [[0.5] * len(FEATURES)]
            ):
                self.fail("unexpected serving target")

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.root = Path(__file__).resolve().parents[1]
        self.state = self.root / ".runtime"
        self.image = "sha256:" + "1" * 64
        self.features = [[0.125] * len(FEATURES)]
        self.events = []
        self.receipt_change = {}
        self.reader = stack.enter_context(
            patch.object(native.release_reader, "Reader")
        ).return_value
        self.reader.load.side_effect = lambda: self.loaded
        self.document = stack.enter_context(patch.object(native.release_reader, "document"))

        @contextmanager
        def store(root, state, campaign, suffix, port):
            self.assertEqual((root, state, campaign), (self.root, self.state, "a"))
            self.events.append(("open", suffix, port))
            try:
                yield self.state / ("controlled-" + suffix)
            finally:
                self.events.append(("closed", suffix))

        def promote(root, models, authority, args, public):
            self.assertEqual(
                (root, models, authority),
                (self.root, self.state / "controlled-models", self.state / "controlled-trust"),
            )
            decision = native.release_authorization.verify(**args, clock=int(time.time()))
            policy = release_policy.checked(
                args["policy_envelope"], "promotion-policy", args["trusted_root"]
            )
            manifest = release_bundle.index(
                args["package"]["envelope"], policy["identities"]["publisher"]["public_key"]
            )
            self.model = args["package"]["capsule"]["objects"][
                ("candidates", manifest["materials"]["model"])
            ]
            self.selection = dict(
                proposal_reference=digest(canonical(args["package"]["envelope"])),
                sequence=decision["sequence"],
                subject_sha256=decision["subject_sha256"],
            )
            self.loaded = SimpleNamespace(
                **self.selection,
                expires_at=decision["expires_at"],
                request_sha256=digest(canonical(self.selection)),
                model_sha256=digest(self.model),
                model=self.model,
            )
            self.document.return_value = self.selection.copy()
            return {
                **self.selection,
                "state": "recorded-not-activated",
                "environment": "local-cpu",
                "release_ready": False,
                "request_sha256": self.loaded.request_sha256,
                **self.receipt_change,
            }

        self.hosted = stack.enter_context(
            patch.object(
                native.promotion_entrypoint_native,
                "hosted",
                wraps=native.promotion_entrypoint_native.hosted,
            )
        )
        self.resolve = stack.enter_context(
            patch.object(native, "resolve_image", return_value=self.image)
        )
        self.store = stack.enter_context(patch.object(native, "disposable", side_effect=store))
        self.variant = stack.enter_context(
            patch.object(
                native,
                "variant",
                side_effect=lambda f, image, features: (
                    digest(f.fixture.bundle.materials.fixture.model),
                    [0.625],
                ),
            )
        )
        self.promote = stack.enter_context(
            patch.object(native.promotion_entrypoint_native, "controlled", side_effect=promote)
        )
        for module, fn in (
            (native.promotion_state, "install"),
            (native.promotion_state, "configure"),
            (native.trust_authority, "install"),
            (native.trust_authority, "update"),
        ):
            stack.enter_context(patch.object(module, fn))

    def release(self):
        self.hosted.side_effect = None
        self.hosted.return_value = None
        return native.stable_release(self.root, self.state, self.image, "a", self.features)

    def assert_cleaned(self):
        self.assertEqual(
            self.events,
            [
                ("open", "models", 15444),
                ("open", "trust", 15445),
                ("closed", "trust"),
                ("closed", "models"),
            ],
        )

    def test_controlled_signed_release_and_independent_real_onnx_golden(self):
        self.variant.side_effect = native_variant
        with self.release() as (engine, golden, binding):
            self.assertIsInstance(engine, native.serving.Engine)
            self.assertIs(engine.reader, self.reader)
            create_reader = native.release_reader.Reader.call_args
            self.assertEqual(
                create_reader.args, (self.state / "controlled-models/storage-clients/serving",)
            )
            self.assertEqual(create_reader.kwargs["expected_serving_image"], self.image)
            self.assertEqual(create_reader.kwargs["minimum_sequence"], 1)
            lease = create_reader.kwargs["trust_lease"]
            with patch.object(native.trust_authority, "read") as read:
                lease.reader()
                read.assert_called_once_with(
                    self.state / "controlled-trust/storage-clients/serving", "local-cpu", lease.root
                )
            self.assertIsNone(engine.worker_factory)
            self.assertIsNone(engine.worker)
            self.assertEqual(
                binding,
                {
                    **self.selection,
                    "model_sha256": digest(self.model),
                    "request_sha256": self.loaded.request_sha256,
                },
            )
            self.assertEqual(
                (golden.model, golden.bundle), (binding["model_sha256"], binding["subject_sha256"])
            )
            self.assertEqual(
                decode(golden.body)["instances"],
                [dict(zip(FEATURES, self.features[0], strict=True))],
            )
            runtime, _ = onnx_model.session(self.model)
            self.assertAlmostEqual(
                onnx_model.predict(runtime, self.features)[0], golden.score, delta=1e-6
            )
            self.reader.check.assert_called_once_with(self.loaded)
        self.assertEqual(self.reader.check.call_count, 2)
        self.assertFalse(engine.stopped.is_set())
        self.assert_cleaned()

    def test_expired_signed_fixture_and_mismatched_receipt_never_yield(self):
        real_verify = native.release_authorization.verify

        def expired(**args):
            args["clock"] += 1801
            return real_verify(**args)

        with (
            patch.object(native.release_authorization, "verify", side_effect=expired),
            self.assertRaises(Rejected),
        ):
            with self.release():
                self.fail("expired fixture yielded")
        self.promote.assert_not_called()
        self.assert_cleaned()
        self.events.clear()
        self.receipt_change.update(proposal_reference="0" * 64)
        with self.assertRaisesRegex(Rejected, "canary_stable_receipt"):
            with self.release():
                self.fail("foreign receipt yielded")
        self.reader.load.assert_not_called()
        self.assert_cleaned()

    def test_changed_durable_record_or_head_rejects_after_traffic(self):
        for change in ("request", "proposal", "expiry", "model"):
            self.events.clear()
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(Rejected, "canary_stable_head_changed"),
            ):
                with self.release() as (_, _, binding):
                    if change == "request":
                        binding["request_sha256"] = self.loaded.request_sha256 = "0" * 64
                    elif change == "proposal":
                        self.document.return_value["proposal_reference"] = "0" * 64
                    elif change == "expiry":
                        self.loaded.expires_at += 1
                    else:
                        self.loaded.model = b"changed after traffic"
            self.assert_cleaned()

    def test_failed_traffic_still_checks_head_and_releases_stores(self):
        with self.assertRaisesRegex(RuntimeError, "traffic failed"):
            with self.release():
                raise RuntimeError("traffic failed")
        self.assertEqual(self.reader.check.call_count, 2)
        self.assert_cleaned()

    def test_failed_fixture_cleanup_rejects_after_traffic_and_still_closes_stores(self):
        setup = native.PromotionAdmissionContracts.setUp

        def broken_cleanup():
            raise RuntimeError("fixture cleanup failed")

        def register_failure(fixture):
            setup(fixture)
            fixture.addCleanup(broken_cleanup)

        with (
            patch.object(native.PromotionAdmissionContracts, "setUp", register_failure),
            self.assertRaisesRegex(Rejected, "^canary_stable_fixture_cleanup$"),
        ):
            with self.release():
                self.reader.check.assert_called_once()
        self.assertEqual(self.reader.check.call_count, 2)
        self.assert_cleaned()

    def test_rejects_wrong_input_shape_or_campaign_before_resolving_image(self):
        self.hosted.return_value = None
        for features, campaign in (
            (self.features * 2, "a"),
            ([[0.1]], "a"),
            (self.features, "../other"),
        ):
            with self.subTest(campaign=campaign), self.assertRaises(Rejected):
                with native.stable_release(self.root, self.state, self.image, campaign, features):
                    self.fail("invalid input yielded")
        self.resolve.assert_not_called()
        self.store.assert_not_called()


if __name__ == "__main__":
    unittest.main()
