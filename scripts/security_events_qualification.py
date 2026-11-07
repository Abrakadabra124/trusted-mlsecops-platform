"""Real signatures and fixed M23 contracts; not collector or promotion acceptance."""

import copy
import tempfile
import unittest
from pathlib import Path

from mlsecops import security_event_config as config
from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest


class EventContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.keys, self.publics = {}, {}
        for role in (
            "root",
            "receipt",
            "intake",
            "promoter",
            "trust",
            "serving",
            "controller",
            "collector",
            "worker",
        ):
            self.keys[role] = self.directory / (role + ".pem")
            self.publics[role] = signing.create_key(self.keys[role])
        self.policy = "a" * 64
        self.document = {
            "schema_version": 1,
            "policy_sha256": self.policy,
            "issued_at_ms": 1000,
            "expires_at_ms": 1000000,
            "receipt_public": self.publics["receipt"],
            "producers": [
                {
                    "public_key": self.publics[role],
                    "role": role,
                    "epoch": "b" * 32,
                    "heartbeat_required": role == "serving",
                }
                for role in ("intake", "promoter", "trust", "serving", "controller", "collector")
            ],
        }
        self.registry = self.registry_for()

    def registry_for(self, document=None, **options):
        document = copy.deepcopy(self.document if document is None else document)
        return config.Registry(
            signing.sign(document, "security-event-config", self.keys["root"]),
            trusted_root=options.get("root", self.publics["root"]),
            expected_sha256=options.get("pin", digest(canonical(document))),
            clock_ms=options.get("clock", 2000),
        )

    def event(self, kind="artifact.rejected", role="intake", **changes):
        values = {
            "kind": kind,
            "producer_id": digest(signing.decode64(self.publics[role])),
            "epoch": "b" * 32,
            "sequence": 1,
            "occurred_at_ms": 2000,
            "observed_at_ms": 2000,
            "correlation_id": "c" * 32,
            "asset_sha256": "d" * 64,
            "bundle_sha256": None,
            "policy_sha256": self.policy,
            "reason": "integrity",
        }
        values.update(changes)
        return events.create(**values)

    def verify(self, value=None, *, role="intake", clock=2100, kind="security-event"):
        return self.registry.verify(
            signing.sign(value or self.event(), kind, self.keys[role]), clock_ms=clock
        )

    def test_all_seven_types_have_authenticated_distinct_fixed_routes(self):
        cases = (
            ("artifact.rejected", "intake", "integrity"),
            ("promotion.denied", "promoter", "authorization"),
            ("trust.revoked", "trust", "key"),
            ("identity.denied", "serving", "credential"),
            ("inventory.mismatch", "controller", "digest"),
            ("worker.policy_violation", "controller", "output_schema"),
            ("telemetry.gap", "collector", "sequence"),
        )
        routes = set()
        for kind, role, reason in cases:
            value = self.event(kind, role, reason=reason)
            verified = self.verify(value, role=role)
            self.assertEqual(verified.document(), value)
            routes.add(verified.route)
        self.assertEqual(len(routes), 7)

    def test_event_id_is_stable_for_retry_and_changes_with_intent(self):
        first = self.event()
        self.assertEqual(first, self.event())
        self.assertNotEqual(first["event_id"], self.event(sequence=2)["event_id"])
        self.assertNotEqual(first["event_id"], self.event(reason="signature")["event_id"])
        original = self.verify(first)
        changed = original.document()
        changed["reason"] = "PRIVATE-CANARY"
        self.assertEqual(original.document(), first)

    def test_arbitrary_fields_worker_text_and_dynamic_routes_are_rejected(self):
        for key in ("message", "features", "labels", "severity", "route", "token", "stack"):
            value = self.event()
            value[key] = "PRIVATE-CANARY"
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.verify(value)
        for kind in ("PRIVATE-CANARY", "data_drift", "heartbeat", [], None):
            with self.subTest(kind=kind), self.assertRaises(Rejected):
                self.event(kind=kind)

    def test_wrong_action_outcome_reason_or_event_id_never_becomes_trusted(self):
        for key, value in (
            ("action", "allow"),
            ("outcome", "success"),
            ("reason", "PRIVATE-CANARY"),
            ("event_id", "f" * 64),
        ):
            changed = self.event()
            changed[key] = value
            with self.subTest(field=key), self.assertRaises(Rejected):
                self.verify(changed)

    def test_strict_numeric_types_bounds_and_reference_shapes(self):
        for key in ("sequence", "occurred_at_ms", "observed_at_ms"):
            for value in (True, False, 0, -1, 1.5, "1", None, 2**53):
                with self.subTest(key=key, value=value), self.assertRaises(Rejected):
                    self.event(**{key: value})
        for key in ("producer_id", "policy_sha256", "asset_sha256", "epoch", "correlation_id"):
            for value in (True, None, "A" * 64, "../PRIVATE", "f" * 65):
                with self.subTest(key=key), self.assertRaises(Rejected):
                    self.event(**{key: value})
        with self.assertRaises(Rejected):
            self.event(bundle_sha256="bad")
        self.assertEqual(
            self.verify(self.event(bundle_sha256="e" * 64)).document()["bundle_sha256"], "e" * 64
        )

    def test_event_schema_missing_fields_and_non_object_are_rejected(self):
        for key in self.event():
            value = self.event()
            del value[key]
            with self.subTest(key=key), self.assertRaises(Rejected):
                events.checked(value)
        for value in (
            None,
            [],
            "PRIVATE-CANARY",
            {**self.event(), "schema_version": True},
            {**self.event(), "schema_version": 2},
        ):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(Rejected):
                events.checked(value)

    def test_clock_freshness_skew_expiry_and_backward_observation(self):
        self.verify(clock=302000)
        self.verify(clock=1000)
        for clock in (302001, True, 0, -1, 2**53):
            with self.subTest(clock=clock), self.assertRaises(Rejected):
                self.verify(clock=clock)
        with self.assertRaises(Rejected):
            self.verify(self.event(occurred_at_ms=8001, observed_at_ms=8001), clock=3000)
        with self.assertRaises(Rejected):
            self.event(observed_at_ms=1999)
        with self.assertRaises(Rejected):
            self.verify(self.event(occurred_at_ms=999, observed_at_ms=999))

    def test_registered_key_cannot_impersonate_another_producer_or_epoch_or_policy(self):
        for changes in (
            {"producer_id": digest(signing.decode64(self.publics["promoter"]))},
            {"epoch": "f" * 32},
            {"policy_sha256": "f" * 64},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.verify(self.event(**changes))
        with self.assertRaises(Rejected):
            self.verify(role="worker")

    def test_producer_roles_do_not_allow_worker_or_serving_to_claim_revocation(self):
        for role in ("serving", "controller", "promoter", "collector", "intake"):
            with self.subTest(role=role), self.assertRaises(Rejected):
                self.verify(self.event("trust.revoked", role, reason="key"), role=role)
        changed = copy.deepcopy(self.document)
        changed["producers"][0]["role"] = "worker"
        with self.assertRaises(Rejected):
            self.registry_for(changed)

    def test_bad_signature_other_domain_unknown_key_and_noncanonical_payload(self):
        envelope = signing.sign(self.event(), "security-event", self.keys["intake"])
        envelope["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        with self.assertRaises(Rejected):
            self.registry.verify(envelope, clock_ms=2100)
        with self.assertRaises(Rejected):
            self.verify(kind="monitor-alert")
        payload = b" " + canonical(self.event())
        kind = "application/vnd.trusted-mlsecops.security-event.v1+json"
        envelope = {
            "payloadType": kind,
            "payload": signing.encode64(payload),
            "signatures": [
                {
                    "keyid": digest(signing.decode64(self.publics["intake"])),
                    "sig": signing.encode64(
                        signing.load_key(self.keys["intake"]).sign(signing.pae(kind, payload))
                    ),
                }
            ],
        }
        with self.assertRaises(Rejected):
            self.registry.verify(envelope, clock_ms=2100)

    def test_envelope_shapes_size_and_recursion_never_escape_as_unhandled_exception(self):
        valid = signing.sign(self.event(), "security-event", self.keys["intake"])
        variants = [
            None,
            [],
            {},
            {**valid, "payload": "x" * 4097},
            {**valid, "signatures": []},
            {**valid, "signatures": [None]},
            {**valid, "signatures": [{"keyid": [], "sig": "x"}]},
        ]
        cyclic = {}
        cyclic["self"] = cyclic
        variants.append(cyclic)
        for value in variants:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(Rejected):
                self.registry.verify(value, clock_ms=2100)

    def test_config_requires_pinned_root_digest_and_current_validity_on_every_message(self):
        for options in (
            {"root": self.publics["worker"]},
            {"pin": "f" * 64},
            {"clock": 999},
            {"clock": 1000000},
        ):
            with self.subTest(options=options), self.assertRaises(Rejected):
                self.registry_for(**options)
        with self.assertRaises(Rejected):
            self.verify(self.event(occurred_at_ms=999999, observed_at_ms=999999), clock=1000000)

    def test_config_input_mutation_does_not_change_registered_authority(self):
        self.document["producers"][0]["role"] = "trust"
        self.document["policy_sha256"] = "f" * 64
        self.assertEqual(self.verify().document()["policy_sha256"], self.policy)

    def test_config_rejects_duplicate_reused_authority_keys_and_bad_public_encoding(self):
        for fault in ("duplicate", "root", "receipt", "alias", "length", "invalid", "keytype"):
            value = copy.deepcopy(self.document)
            if fault == "duplicate":
                value["producers"].append(value["producers"][0].copy())
            if fault in ("root", "receipt"):
                value["producers"][0]["public_key"] = self.publics[fault]
            if fault == "alias":
                value["producers"][0]["public_key"] = "_" * 43 + "="
            if fault == "length":
                value["producers"][0]["public_key"] = signing.encode64(b"x")
            if fault == "invalid":
                value["producers"][0]["public_key"] = "private"
            if fault == "keytype":
                value["producers"][0]["public_key"] = []
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                self.registry_for(value)

    def test_config_bounded_inventory_exact_schema_and_heartbeat_policy(self):
        for field, value in (
            ("schema_version", True),
            ("schema_version", 2),
            ("producers", []),
            ("producers", [self.document["producers"][0]] * 17),
            ("producers", {}),
            ("issued_at_ms", True),
            ("expires_at_ms", 1000 + 86400001),
            ("policy_sha256", "bad"),
        ):
            changed = {**self.document, field: value}
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.registry_for(changed)
        for field, value in (("heartbeat_required", "yes"), ("epoch", "bad"), ("role", [])):
            changed = copy.deepcopy(self.document)
            changed["producers"][0][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.registry_for(changed)
        for field in self.document:
            changed = copy.deepcopy(self.document)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(Rejected):
                self.registry_for(changed)

    def heartbeat(self, **changes):
        value = {
            "schema_version": 1,
            "producer_id": digest(signing.decode64(self.publics["serving"])),
            "epoch": "b" * 32,
            "sequence": 2,
            "last_event_sequence": 1,
            "observed_at_ms": 2000,
            "policy_sha256": self.policy,
        }
        value.update(changes)
        return value

    def test_signed_heartbeat_is_control_message_and_cannot_become_an_incident(self):
        envelope = signing.sign(self.heartbeat(), "security-heartbeat", self.keys["serving"])
        verified = self.registry.heartbeat(envelope, clock_ms=2100)
        self.assertEqual(verified, self.heartbeat())
        with self.assertRaises(Rejected):
            self.registry.verify(envelope, clock_ms=2100)
        for field, value in (
            ("sequence", 0),
            ("last_event_sequence", -1),
            ("sequence", True),
            ("epoch", "f" * 32),
            ("policy_sha256", "f" * 64),
            ("observed_at_ms", 302001),
            ("schema_version", True),
            ("producer_id", "f" * 64),
            ("raw_payload", "PRIVATE-CANARY"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.registry.heartbeat(
                    signing.sign(
                        self.heartbeat(**{field: value}), "security-heartbeat", self.keys["serving"]
                    ),
                    clock_ms=2100,
                )

    def test_delivery_receipt_uses_separate_authority_and_exact_event_config_route_and_deadline(
        self,
    ):
        event = self.verify()
        receipt = events.delivered(
            event, self.registry.sha256, ingested_at_ms=2100, routed_at_ms=2200, late=False
        )
        envelope = signing.sign(receipt, "security-event-receipt", self.keys["receipt"])
        self.assertEqual(self.registry.receipt(envelope, event), receipt)
        for field, value in (
            ("event_id", "f" * 64),
            ("config_sha256", "f" * 64),
            ("route", "security.trust"),
            ("routed_at_ms", 62101),
            ("routed_at_ms", 2099),
            ("late", 1),
            ("schema_version", True),
        ):
            altered = {**receipt, field: value}
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.registry.receipt(
                    signing.sign(altered, "security-event-receipt", self.keys["receipt"]), event
                )
        with self.assertRaises(Rejected):
            self.registry.receipt(
                signing.sign(receipt, "security-event-receipt", self.keys["intake"]), event
            )

    def test_config_cannot_share_root_receipt_key_or_disable_all_heartbeats(self):
        changed = copy.deepcopy(self.document)
        changed["receipt_public"] = self.publics["root"]
        with self.assertRaises(Rejected):
            self.registry_for(changed)
        changed = copy.deepcopy(self.document)
        for producer in changed["producers"]:
            producer["heartbeat_required"] = False
        with self.assertRaises(Rejected):
            self.registry_for(changed)

    def test_event_wrapper_requires_bounded_canonical_bytes_and_is_immutable(self):
        from dataclasses import FrozenInstanceError

        for content in (None, "private", b"x" * 2049, b" " + canonical(self.event())):
            with self.subTest(content_type=type(content).__name__), self.assertRaises(Rejected):
                events.Event(content)
        event = self.verify()
        with self.assertRaises(FrozenInstanceError):
            event.content = b"{}"
        with self.assertRaises(FrozenInstanceError):
            self.registry.policy_sha256 = "f" * 64
        for kind in ([], None, "data_drift"):
            with self.subTest(kind=kind), self.assertRaises(Rejected):
                self.verify({**self.event(), "kind": kind})

    def test_nested_non_string_envelope_fields_are_rejected_without_recursion(self):
        envelope = signing.sign(self.event(), "security-event", self.keys["intake"])
        deep = []
        for _ in range(1500):
            deep = [deep]
        for field in ("payload", "payloadType"):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.registry.verify({**envelope, field: deep}, clock_ms=2100)
        envelope["signatures"][0]["sig"] = deep
        with self.assertRaises(Rejected):
            self.registry.verify(envelope, clock_ms=2100)

    def test_receipt_cannot_grant_release_or_precede_configuration_and_has_inclusive_deadline(self):
        event = self.verify()
        value = events.delivered(
            event, self.registry.sha256, ingested_at_ms=2100, routed_at_ms=62100, late=True
        )

        def signed(receipt):
            return signing.sign(receipt, "security-event-receipt", self.keys["receipt"])

        self.assertEqual(self.registry.receipt(signed(value), event), value)
        for field, item in (("release_ready", True), ("release_ready", 0), ("ingested_at_ms", 999)):
            receipt = {**value, field: item, "routed_at_ms": 2200}
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.registry.receipt(signed(receipt), event)
        with self.assertRaises(Rejected):
            events.delivered(
                self.event(),
                self.registry.sha256,
                ingested_at_ms=2100,
                routed_at_ms=2200,
                late=False,
            )


if __name__ == "__main__":
    unittest.main()
