"""Real signed history for an immutable observer configuration transition."""

import copy
import importlib.util
import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import trust_rotation_qualification as fixtures


class ObserverProfile(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.kube_observer_profile"))
        from mlsecops import kube_observer_profile

        self.subject = kube_observer_profile
        self.fx = fixtures.RotationContracts()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.context = dict(environment="local-cpu", initial_root=self.fx.old_public)
        self.package = self.fx.package()
        documents = [
            dict(version=i + 1, sha256=digest(canonical(envelope)), envelope=envelope)
            for i, envelope in enumerate((self.fx.previous, self.package["document"]))
        ]
        self.history = dict(
            schema_version=1,
            root_public=self.fx.new_public,
            head_version=2,
            head_sha256=documents[-1]["sha256"],
            clock=self.fx.clock,
            documents=documents,
        )

    def created(self):
        return self.subject.advance(
            None, self.context, self.history, self.package, next_root=self.fx.new_public
        )

    def test_current_root_requires_both_signers_and_full_initial_history(self):
        profile = self.created()
        self.assertEqual(self.subject.current_root(profile, self.context), self.fx.new_public)
        self.assertEqual(self.subject.current_root(None, self.context), self.fx.old_public)
        for changed in (
            {**profile, "rotations": []},
            {**profile, "schema_version": True},
            {**profile, "history": {**self.history, "root_public": self.fx.old_public}},
            {**profile, "history": {**self.history, "documents": self.history["documents"][1:]}},
            {**profile, "extra": True},
        ):
            with self.assertRaises(Rejected):
                self.subject.current_root(changed, self.context)
        for part in ("authorization", "acceptance", "document"):
            package = copy.deepcopy(self.package)
            package[part]["signatures"] = []
            with self.subTest(part=part), self.assertRaises(Rejected):
                self.subject.advance(
                    None, self.context, self.history, package, next_root=self.fx.new_public
                )
        with self.assertRaises(Rejected):
            self.subject.advance(
                None, self.context, self.history, self.package, next_root=self.fx.old_public
            )

    def test_retry_keeps_existing_snapshot_and_refuses_changed_past_or_clock_regression(self):
        profile = self.created()
        advanced_clock = {**self.history, "clock": self.history["clock"] + 20}
        self.assertEqual(
            self.subject.advance(
                profile, self.context, advanced_clock, self.package, next_root=self.fx.new_public
            ),
            profile,
        )
        for history in (
            {**self.history, "clock": self.history["clock"] - 1},
            {**self.history, "head_sha256": "f" * 64},
            {**self.history, "documents": []},
        ):
            with self.assertRaises(Rejected):
                self.subject.advance(
                    profile, self.context, history, self.package, next_root=self.fx.new_public
                )

    def test_map_is_bounded_public_immutable_and_content_named(self):
        profile = self.created()
        before = canonical(profile)
        mapping = self.subject.mapping("a" * 32, profile, self.context)
        self.assertTrue(mapping["immutable"])
        self.assertEqual(mapping["metadata"]["namespace"], "ml-serving")
        self.assertEqual(set(mapping["data"]), {"observer.json", "rotation-2.json"})
        config = decode(mapping["data"]["observer.json"].encode())
        self.assertEqual(config["initial_root"], self.fx.old_public)
        self.assertEqual(config["producer_config"], "/security/producer.json")
        self.assertEqual(config["trust_client"], "/client")
        self.assertEqual(
            config["rotations"],
            [
                dict(
                    version=2,
                    next_root=self.fx.new_public,
                    package_file="/observer/rotation-2.json",
                )
            ],
        )
        self.assertEqual(decode(mapping["data"]["rotation-2.json"].encode()), self.package)
        self.assertEqual(canonical(profile), before)
        self.assertLessEqual(len(canonical(mapping["data"])), 128 * 1024)
        self.assertEqual(mapping, self.subject.mapping("a" * 32, profile, self.context))

    def test_second_rotation_preserves_first_and_rejects_reordered_or_changed_proof(self):
        from mlsecops import signing
        from scripts.kube_root_rotation import prepare

        profile = self.created()
        current = dict(
            envelope=self.package["document"],
            root_public=self.fx.new_public,
            environment=self.context["environment"],
            clock=self.fx.clock,
            sha256=self.history["head_sha256"],
        )
        key = self.fx.new_key.with_name("third.pem")
        package = prepare(current, self.fx.new_key, key)
        root = signing.encode64(signing.load_key(key).public_key().public_bytes_raw())
        content = digest(canonical(package["document"]))
        history = {
            **self.history,
            "root_public": root,
            "head_version": 3,
            "head_sha256": content,
            "documents": [
                *self.history["documents"],
                dict(version=3, sha256=content, envelope=package["document"]),
            ],
        }
        advanced = self.subject.advance(profile, self.context, history, package, next_root=root)
        self.assertEqual(advanced["rotations"][0], profile["rotations"][0])
        reversed_profile = {**advanced, "rotations": list(reversed(advanced["rotations"]))}
        with self.assertRaisesRegex(Rejected, "rotation_order"):
            self.subject.verify(reversed_profile, self.context)
        with self.assertRaisesRegex(Rejected, "retry_changed"):
            self.subject.advance(advanced, self.context, history, self.package, next_root=root)

    def test_signed_package_and_serialized_configuration_budgets_fail_closed(self):
        self.fx.following["revoked_artifacts"] = sorted(
            {"b" * 64, *(digest(str(i).encode()) for i in range(1100))}
        )
        self.fx.fixture.payload["revoked_artifacts"] = self.fx.following["revoked_artifacts"]
        self.fx.previous = self.fx.fixture.envelope()
        self.fx.intent["previous_sha256"] = digest(canonical(self.fx.previous))
        package = self.fx.package()
        content = digest(canonical(package["document"]))
        history = {
            **self.history,
            "head_sha256": content,
            "documents": [
                dict(
                    version=1, sha256=self.fx.intent["previous_sha256"], envelope=self.fx.previous
                ),
                dict(version=2, sha256=content, envelope=package["document"]),
            ],
        }
        with self.assertRaisesRegex(Rejected, "configuration_limit"):
            self.subject.advance(None, self.context, history, package, next_root=self.fx.new_public)
        # Independently exercise the serializer's final bound even if a future
        # verifier regression passes an overlarge already-validated structure.
        profile = self.created()
        profile["rotations"][0]["package"] = {"oversized": "a" * self.subject.MAX_CONFIG_BYTES}
        with (
            patch.object(self.subject, "verify"),
            self.assertRaisesRegex(Rejected, "configuration_limit"),
        ):
            self.subject.mapping("a" * 32, profile, self.context)
        with (
            patch.object(self.subject, "verify"),
            self.assertRaisesRegex(Rejected, "rotation_head"),
        ):
            self.subject.advance(
                None,
                self.context,
                {**self.history, "root_public": self.fx.old_public},
                self.package,
                next_root=self.fx.new_public,
            )

    def test_deployment_keeps_old_credentials_and_outbox_but_changes_only_active_config(self):
        profile = self.created()
        deployment = self.subject.deployment(
            "a" * 32, "image@sha256:" + "b" * 64, profile, self.context
        )
        spec = deployment["spec"]["template"]["spec"]
        self.assertEqual(spec["serviceAccountName"], "serving")
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["containers"][0]["command"][-1], "/observer/observer.json")
        self.assertEqual(
            [v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v],
            ["trust-client", "security-trust"],
        )
        self.assertEqual(
            [
                v["persistentVolumeClaim"]["claimName"]
                for v in spec["volumes"]
                if "persistentVolumeClaim" in v
            ],
            ["security-events"],
        )
        self.assertNotIn(b"security_event_provision", canonical(spec))
        names = [v["name"] for v in spec["volumes"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(any(c["name"] == "observer-files" for c in spec["initContainers"]))
        self.assertTrue(
            any(
                m.get("subPath") == "observer" and m.get("readOnly") is True
                for m in spec["containers"][0]["volumeMounts"]
            )
        )


if __name__ == "__main__":
    unittest.main()
