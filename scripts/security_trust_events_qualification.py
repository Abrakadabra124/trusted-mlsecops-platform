"""Committed signed trust history -> bounded, idempotent observer events."""

import contextlib
import copy
import io
import unittest
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import security_event_delivery, security_event_ledger, security_event_outbox, signing
from mlsecops import security_trust_events as source
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_events_qualification as event_fixtures
from scripts import trust_rotation_qualification as fixtures


class HostedBoundary(unittest.TestCase):
    def test_native_campaign_refuses_before_infrastructure_on_local_host(self):
        from scripts import security_trust_events_native as native

        with (
            patch.object(native.sys, "platform", "win32"),
            patch.object(native, "disposable") as start,
        ):
            with self.assertRaisesRegex(Rejected, "trust_security_hosted_required"):
                native.qualify()
            start.assert_not_called()


class ProjectionContracts(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.RotationContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.first = self.fx.previous
        self.next_payload = {
            **copy.deepcopy(self.fx.fixture.payload),
            "version": 2,
            "revoked_artifacts": ["b" * 64, "d" * 64],
        }
        self.second = signing.sign(self.next_payload, "trust-policy", self.fx.old_key)

    def history(self, envelopes=None, root=None):
        envelopes = envelopes or [self.first, self.second]
        documents = [
            dict(
                version=i + 1, sha256=digest(canonical(envelope)), envelope=copy.deepcopy(envelope)
            )
            for i, envelope in enumerate(envelopes)
        ]
        return dict(
            schema_version=1,
            root_public=root or self.fx.old_public,
            head_version=len(documents),
            head_sha256=documents[-1]["sha256"],
            clock=self.fx.clock,
            documents=documents,
        )

    def project(self, history=None, **kwargs):
        return source.project(
            history or self.history(),
            environment="local-cpu",
            initial_root=self.fx.old_public,
            **kwargs,
        )

    def test_verified_changes_emit_stable_events_bound_to_committed_document(self):
        events = self.project()
        self.assertEqual([event["reason"] for event in events], ["artifact", "key", "artifact"])
        self.assertEqual(events, self.project())
        self.assertEqual(events[-1]["asset_sha256"], digest(canonical(self.second)))
        self.assertIsNone(events[-1]["bundle_sha256"])
        self.assertEqual(len({event["correlation_id"] for event in events}), 3)

    def test_head_mismatch_missing_version_forgery_and_unrevocation_reject(self):
        variants = []
        for field, value in (
            ("head_version", 1),
            ("head_sha256", "f" * 64),
            ("root_public", self.fx.new_public),
            ("schema_version", True),
        ):
            variants.append({**self.history(), field: value})
        missing = self.history()
        missing["documents"] = missing["documents"][1:]
        variants.append(missing)
        forged = self.history()
        forged["documents"][0]["envelope"]["signatures"] = []
        variants.append(forged)
        for document in variants:
            with self.subTest(type=type(document).__name__), self.assertRaises(Rejected):
                self.project(document)
        removed = {**self.next_payload, "revoked_artifacts": []}
        with self.assertRaises(Rejected):
            self.project(
                self.history(
                    [self.fx.previous, signing.sign(removed, "trust-policy", self.fx.old_key)]
                )
            )

    def test_dual_signed_rotation_requires_explicit_operator_pin_and_complete_binding(self):
        package = self.fx.package()
        history = self.history([self.first, package["document"]], self.fx.new_public)
        rotation = dict(version=2, next_root=self.fx.new_public, package=package)
        with self.assertRaises(Rejected):
            self.project(history)
        events = self.project(history, rotations=[rotation])
        self.assertEqual([event["reason"] for event in events], ["artifact", "key", "key"])
        for changed in (
            dict(rotation, next_root=self.fx.old_public),
            dict(rotation, version=3),
            dict(rotation, package={}),
        ):
            with self.assertRaises(Rejected):
                self.project(history, rotations=[changed])

    def test_expired_history_can_be_observed_without_granting_current_trust(self):
        history = self.history()
        history["clock"] += 90000
        self.assertEqual(self.project(history), self.project())
        history["clock"] = self.fx.fixture.payload["issued_at"] - 1
        with self.assertRaises(Rejected):
            self.project(history)

    def test_policy_change_and_renewal_have_distinct_observer_semantics(self):
        renewal = {**self.next_payload, "version": 3}
        change = {**renewal, "version": 4, "promotion_policy_sha256": "e" * 64}
        events = self.project(
            self.history(
                [
                    self.first,
                    self.second,
                    signing.sign(renewal, "trust-policy", self.fx.old_key),
                    signing.sign(change, "trust-policy", self.fx.old_key),
                ]
            )
        )
        self.assertEqual(
            [event["reason"] for event in events], ["artifact", "key", "artifact", "policy"]
        )

    def test_rotation_package_cannot_substitute_another_committed_document(self):
        package = self.fx.package()
        with self.assertRaisesRegex(Rejected, "trust_security_rotation_document"):
            self.project(rotations=[dict(version=2, next_root=self.fx.new_public, package=package)])

    def test_hard_bounds_duplicates_and_revoked_signer_are_not_silently_skipped(self):
        for rotations in (None, [None] * (source.MAX_ROTATIONS + 1)):
            with self.assertRaises(Rejected):
                self.project(rotations=rotations)
        item = dict(version=2, next_root=self.fx.new_public, package=self.fx.package())
        for rotations in (
            [item, item],
            [dict(item, version=source.MAX_VERSIONS + 1)],
            [dict(item, package={"large": "x" * source.release_policy.MAX_DOCUMENT})],
        ):
            with self.assertRaises(Rejected):
                self.project(rotations=rotations)
        for changed in (
            {**self.history(), "head_version": source.MAX_VERSIONS + 1},
            {**self.history(), "documents": []},
        ):
            with self.assertRaises(Rejected):
                self.project(changed)
        bad = self.history()
        bad["documents"][0]["sha256"] = "f" * 64
        with self.assertRaises(Rejected):
            self.project(bad)
        initial = {
            **self.fx.fixture.payload,
            "revoked_keys": sorted(["c" * 64, digest(signing.decode64(self.fx.old_public))]),
        }
        after = {**initial, "version": 2}
        with self.assertRaisesRegex(Rejected, "revoked_signer"):
            self.project(
                self.history(
                    [
                        signing.sign(initial, "trust-policy", self.fx.old_key),
                        signing.sign(after, "trust-policy", self.fx.old_key),
                    ]
                )
            )
        wrong_version = {**self.next_payload, "version": 3}
        with self.assertRaises(Rejected):
            self.project(
                self.history(
                    [self.first, signing.sign(wrong_version, "trust-policy", self.fx.old_key)]
                )
            )
        mismatched = copy.deepcopy(item)
        mismatched["package"]["document"] = self.second
        with self.assertRaises(Rejected):
            self.project(rotations=[mismatched])


class SourceContracts(unittest.TestCase):
    def setUp(self):
        self.fx = ProjectionContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.ef = event_fixtures.EventContracts("runTest")
        self.ef.setUp()
        self.addCleanup(self.ef.doCleanups)
        self.clock = self.fx.fx.clock * 1000
        self.ef.document.update(issued_at_ms=self.clock - 1000, expires_at_ms=self.clock + 600000)
        self.registry = self.ef.registry_for(clock=self.clock)
        self.box = security_event_outbox.Outbox.empty(
            self.registry,
            security_event_outbox.key_identity(self.ef.keys["trust"]),
            clock_ms=self.clock,
        )
        self.box.snapshot = self.box.document
        self.book = security_event_ledger.Ledger.empty(self.registry, clock_ms=self.clock)
        self.offline = False
        self.sent = 0
        self.client = MagicMock()
        self.client.send.side_effect = self.send
        self.emitter = security_event_delivery.Emitter(
            self.box, self.ef.keys["trust"], self.client, clock=lambda: self.clock
        )

    def send(self, envelope):
        if self.offline:
            raise OSError("PRIVATE-CANARY")
        self.sent += 1
        record = self.book.admit(envelope, clock_ms=self.clock)
        event = self.registry.verify(record["envelope"], clock_ms=self.clock)
        return self.book.route(
            (event.document()["event_id"], self.ef.keys["receipt"]), clock_ms=self.clock
        )["receipt"]

    def sync(self, history=None):
        return source.sync(
            history or self.fx.history(),
            self.emitter,
            environment="local-cpu",
            initial_root=self.fx.fx.old_public,
        )

    def test_operator_rotation_file_is_verified_before_replaying_committed_transition(self):
        package = self.fx.fx.package()
        package_path = self.ef.directory / "rotation.json"
        package_path.write_bytes(canonical(package))
        config_path = self.ef.directory / "observer.json"
        config = dict(
            schema_version=1,
            trust_client=str(self.ef.directory / "client"),
            environment="local-cpu",
            initial_root=self.fx.fx.old_public,
            producer_config=str(self.ef.directory / "producer.json"),
            rotations=[
                dict(version=2, next_root=self.fx.fx.new_public, package_file=str(package_path))
            ],
        )
        config_path.write_bytes(canonical(config))
        history = self.fx.history([self.fx.first, package["document"]], root=self.fx.fx.new_public)
        with (
            patch.object(source.security_event_delivery, "configured", return_value=self.emitter),
            patch.object(source, "read", return_value=history),
        ):
            self.assertEqual(source.configured(str(config_path))["events"], 3)
            before = self.box.snapshot()
            config["rotations"][0]["next_root"] = self.fx.fx.old_public
            config_path.write_bytes(canonical(config))
            with self.assertRaises(Rejected):
                source.configured(str(config_path))
            self.assertEqual(self.box.snapshot(), before)

    def test_outage_then_replay_preserves_original_event_and_receipt(self):
        self.offline = True
        with self.assertRaisesRegex(Rejected, "^trust_security_delivery_unconfirmed$"):
            self.sync()
        original = self.box.snapshot()["records"][0]["envelope"]
        self.assertEqual(len(self.box.pending()), 1)
        self.offline = False
        self.clock += 100
        result = self.sync()
        self.assertEqual(
            (result["events"], result["version"], result["release_ready"]), (3, 2, False)
        )
        self.assertEqual(self.box.snapshot()["records"][0]["envelope"], original)
        before = canonical(self.box.snapshot())
        self.assertEqual(self.sync(), result)
        self.assertEqual(canonical(self.box.snapshot()), before)
        self.assertEqual(self.sent, 3)
        self.assertNotIn(b"PRIVATE-CANARY", before)

    def test_entire_history_and_prior_outbox_are_checked_before_any_delivery(self):
        bad = self.fx.history()
        bad["documents"][-1]["envelope"]["signatures"] = []
        with self.assertRaises(Rejected):
            self.sync(bad)
        self.assertEqual(self.box.snapshot()["records"], [])
        self.sync()
        self.client.send.reset_mock()
        with self.assertRaisesRegex(Rejected, "history_conflicts"):
            self.sync(self.fx.history([self.fx.first]))
        self.client.send.assert_not_called()
        self.box._document["producer_id"] = security_event_outbox.key_identity(
            self.ef.keys["intake"]
        )
        with self.assertRaisesRegex(Rejected, "producer_role"):
            self.sync()

    def rows(self):
        h = self.fx.history()
        return [
            (
                h["root_public"],
                h["head_version"],
                h["head_sha256"],
                h["clock"],
                d["version"],
                d["sha256"],
                canonical(d["envelope"]),
            )
            for d in h["documents"]
        ]

    def test_sql_reader_uses_bounded_single_snapshot_and_read_only_identity(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchall.return_value = self.rows()
        with (
            patch.object(
                source.storage, "connection_parameters", return_value={"user": "ml_serving"}
            ),
            patch.object(source.storage, "connect", return_value=connection),
        ):
            self.assertEqual(source.read("client", "local-cpu"), self.fx.history())
        query, args = connection.execute.call_args.args
        self.assertIn("statement_timestamp()", query)
        self.assertIn("LIMIT %s", query)
        self.assertEqual(args, ("local-cpu", source.MAX_VERSIONS + 1))
        with (
            patch.object(
                source.storage, "connection_parameters", return_value={"user": "ml_promoter"}
            ),
            patch.object(source.storage, "connect") as connect,
            self.assertRaises(Rejected),
        ):
            source.read("client", "local-cpu")
        connect.assert_not_called()

    def test_sql_transport_missing_changed_snapshot_and_invalid_bytes_deny(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        rows = self.rows()
        cases = [
            [],
            rows * 33,
            [rows[0], ("foreign", *rows[1][1:])],
            [(*rows[0][:-1], b"{}")],
            [(*rows[0][:-1], b"")],
            [(*rows[0][:-1], b"x" * (source.release_policy.MAX_DOCUMENT + 1))],
        ]
        with (
            patch.object(
                source.storage, "connection_parameters", return_value={"user": "ml_serving"}
            ),
            patch.object(source.storage, "connect", return_value=connection),
        ):
            for case in cases:
                connection.execute.return_value.fetchall.return_value = case
                with self.subTest(count=len(case)), self.assertRaises(Rejected):
                    source.read("client", "local-cpu")
            connection.execute.side_effect = psycopg.OperationalError("PRIVATE-CANARY")
            with self.assertRaisesRegex(Rejected, "^trust_security_source_unavailable$"):
                source.read("client", "local-cpu")

    def test_configured_observer_and_private_cli_constant_outputs(self):
        path = self.ef.directory / "observer.json"
        value = dict(
            schema_version=1,
            trust_client=str(self.ef.directory / "client"),
            environment="local-cpu",
            initial_root=self.fx.fx.old_public,
            producer_config=str(self.ef.directory / "producer.json"),
            rotations=[],
        )
        path.write_bytes(canonical(value))
        with (
            patch.object(source.security_event_delivery, "configured", return_value=self.emitter),
            patch.object(source, "read", return_value=self.fx.history()),
        ):
            self.assertEqual(source.configured(str(path))["events"], 3)
            value["rotations"] = [None] * (source.MAX_ROTATIONS + 1)
            path.write_bytes(canonical(value))
            with self.assertRaises(Rejected):
                source.configured(str(path))
        result = dict(state="observed", release_ready=False)
        with (
            patch.object(source, "enforce"),
            patch.object(source, "configured", return_value=result),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(source.main(["--config", str(path)]), 0)
        self.assertEqual(out.getvalue(), canonical(result).decode() + "\n")
        for failure, expected in ((RuntimeError("PRIVATE-CANARY"), 1), (KeyboardInterrupt(), 130)):
            with (
                patch.object(source, "enforce"),
                patch.object(source, "configured", side_effect=failure),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(source.main(["--config", str(path)]), expected)
            self.assertEqual(err.getvalue(), "trust_security_rejected\n")


if __name__ == "__main__":
    unittest.main()
