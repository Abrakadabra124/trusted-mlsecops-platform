"""Controlled connection lifecycle and real trust verification; no SQL service."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import psycopg

from mlsecops import serving, trust, trust_authority, trust_session
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.signing import create_key, sign


class TrustSessionContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("connection.json", "ca.crt", "client.crt", "client.key"):
            (self.root / name).write_bytes(name.encode())
        self.options = {"user": "ml_serving", "sslmode": "verify-full"}
        self.connections = []
        self.session = trust_session.Session()
        self.addCleanup(self.session.close)
        self.addCleanup(patch.stopall)
        self.parameters = patch.object(
            trust_session.storage, "connection_parameters", return_value=self.options
        ).start()
        self.connect = patch.object(trust_session.storage, "connect", side_effect=self.new).start()
        self.clock = patch.object(trust_session.time, "monotonic", return_value=0).start()

    def new(self, *args, **kwargs):
        connection = Mock(closed=False, autocommit=False)
        connection.close.side_effect = lambda: setattr(connection, "closed", True)
        self.connections.append(connection)
        return connection

    def use(self):
        with self.session.connection(self.root) as connection:
            return connection

    def test_single_connection_autocommit_reuse_expiry_and_idempotent_close(self):
        first = self.use()
        self.assertTrue(first.autocommit)
        self.assertIs(self.use(), first)
        self.clock.return_value = 4.999
        self.assertIs(self.use(), first)
        self.clock.return_value = 5
        second = self.use()
        self.assertIsNot(first, second)
        self.assertTrue(first.closed)
        self.session.close()
        self.session.close()
        self.assertTrue(second.closed)
        self.assertIsNone(self.session.current)
        with self.assertRaisesRegex(Rejected, "session_closed"):
            self.use()
        self.assertEqual(len(self.connections), 2)

    def test_credential_changes_and_server_closed_connection_reconnect(self):
        previous = self.use()
        for name in ("connection.json", "ca.crt", "client.crt", "client.key"):
            (self.root / name).write_bytes(b"changed")
            current = self.use()
            self.assertIsNot(current, previous)
            self.assertTrue(previous.closed)
            previous = current
        self.options["sslmode"] = "changed-fixture"
        self.assertIsNot(self.use(), previous)
        previous = self.session.current
        previous.closed = True
        self.assertIsNot(self.use(), previous)

    def test_validation_failure_and_query_error_drop_connection_without_hidden_retry(self):
        first = self.use()
        with self.assertRaises(psycopg.OperationalError), self.session.connection(self.root):
            raise psycopg.OperationalError("PRIVATE")
        self.assertTrue(first.closed)
        self.assertEqual(self.connect.call_count, 1)
        second = self.use()
        self.parameters.side_effect = Rejected("storage_client_certificate_changed")
        with self.assertRaisesRegex(Rejected, "certificate_changed"):
            self.use()
        self.assertTrue(second.closed)
        self.parameters.side_effect = None
        self.options["user"] = "ml_trainer"
        with self.assertRaisesRegex(Rejected, "trust_client_identity"):
            self.use()
        self.assertEqual(self.connect.call_count, 2)

    def test_failed_connect_setup_rotation_race_and_close_are_fail_closed(self):
        self.connect.side_effect = Rejected("storage_connection_rejected")
        with self.assertRaisesRegex(Rejected, "connection_rejected"):
            self.use()
        self.connect.side_effect = self.new
        with patch.object(trust_session, "credentials", side_effect=["a", "b"]):
            with self.assertRaisesRegex(Rejected, "credentials_changed"):
                self.use()
        self.assertTrue(self.connections[-1].closed)
        with patch.object(trust_session, "credentials", return_value="a"):
            connection = self.use()
            connection.close.side_effect = None
            with self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"):
                self.session.close()
            self.assertIs(self.session.current, connection)
            connection.close.side_effect = lambda: setattr(connection, "closed", True)
            self.session.close()

    def test_bounded_lock_and_pinned_authority_are_preserved(self):
        with patch.object(self.session, "lock", Mock()) as lock:
            lock.acquire.return_value = False
            with self.assertRaisesRegex(Rejected, "session_busy"):
                self.use()
            lock.acquire.assert_called_once_with(timeout=1)
            lock.release.assert_not_called()
        with self.session.connection(self.root, expected_host="pinned-host"):
            pass
        self.connect.assert_called_once_with(self.root, expected_host="pinned-host")
        self.parameters.assert_called_with(self.root, expected_host="pinned-host")

    def test_authority_read_rejects_changed_role_and_invalid_tls_before_query(self):
        # The connection owner must see validation failures, so a previously
        # opened transport cannot survive failed validation on the next read.
        for reason in ("role", "certificate", "host"):
            with self.subTest(reason=reason):
                self.parameters.side_effect = None
                self.options["user"] = "ml_serving"
                connection = self.use()
                before = self.connect.call_count
                if reason == "role":
                    self.options["user"] = "ml_trainer"
                    code = "trust_client_identity"
                else:
                    code = (
                        "storage_client_certificate_changed"
                        if reason == "certificate"
                        else "storage_client_config_invalid"
                    )
                    self.parameters.side_effect = Rejected(code)
                with self.assertRaisesRegex(Rejected, code):
                    trust_authority.read(
                        self.root, "lab", "unused", connection_factory=self.session.connection
                    )
                connection.execute.assert_not_called()
                self.assertTrue(connection.closed)
                self.assertIsNone(self.session.current)
                self.assertEqual(self.connect.call_count, before)
                self.parameters.side_effect = None
                self.options["user"] = "ml_serving"

    def test_engine_cleanup_closes_reader_even_if_worker_drain_fails(self):
        engine = serving.Engine(Mock(), close_reader=self.session.close)
        first = self.use()
        with patch.object(engine, "drain", side_effect=Rejected("worker_cleanup")):
            with self.assertRaisesRegex(Rejected, "worker_cleanup"):
                engine.close()
        self.assertTrue(first.closed)
        self.assertTrue(engine.stopped.is_set())
        self.assertTrue(engine.generation.is_set())

    def test_every_reused_read_queries_and_validates_new_signed_document(self):
        key = self.root / "signing.pem"
        public = create_key(key)
        payload = {
            "schema_version": 1,
            "environment": "lab",
            "version": 1,
            "promotion_policy_sha256": "a" * 64,
            "issued_at": 100,
            "expires_at": 200,
            "revoked_artifacts": [],
            "revoked_keys": [],
        }
        connection = self.use()
        lease = trust.Lease(
            lambda: trust_authority.read(
                self.root, "lab", public, connection_factory=self.session.connection
            ),
            trusted_root=public,
            environment="lab",
            minimum_version=1,
            wall_clock=lambda: 101,
            monotonic_clock=lambda: 0,
        )
        for version, revoked in ((1, []), (2, ["b" * 64])):
            envelope = sign(
                {**payload, "version": version, "revoked_artifacts": revoked}, "trust-policy", key
            )
            content = canonical(envelope)
            connection.execute.return_value.fetchone.return_value = (
                public,
                version,
                digest(content),
                content,
                101,
            )
            lease.refresh()
            self.assertEqual(lease.payload["revoked_artifacts"], revoked)
            if revoked:
                with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
                    lease.check(policy_sha256="a" * 64, artifacts=["b" * 64], keys=[])
            else:
                lease.check(policy_sha256="a" * 64, artifacts=["b" * 64], keys=[])
        self.assertEqual(connection.execute.call_count, 2)
        self.assertEqual(self.connect.call_count, 1)
        connection.execute.return_value.fetchone.return_value = (public, 2, "0" * 64, content, 101)
        with self.assertRaisesRegex(Rejected, "document_integrity"):
            trust_authority.read(
                self.root, "lab", public, connection_factory=self.session.connection
            )
        self.assertTrue(connection.closed)
        connection = self.use()
        connection.execute.side_effect = psycopg.OperationalError("PRIVATE")
        with self.assertRaisesRegex(Rejected, "trust_service_unavailable"):
            trust_authority.read(
                self.root, "lab", public, connection_factory=self.session.connection
            )
        self.assertTrue(connection.closed)


class SessionFileContracts(unittest.TestCase):
    def test_real_client_file_validation_precedes_query_on_reused_session(self):
        from mlsecops import storage
        from mlsecops.trust_targets import Target
        from scripts.trust_targets_qualification import TrustTargetContracts

        fixture = TrustTargetContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        client = fixture.provision_files(Target.MODEL_REVOCATION) / "storage-clients/serving"
        original = {
            name: (client / name).read_bytes()
            for name in ("connection.json", "ca.crt", "client.key")
        }
        for change in ("role", "host", "certificate", "missing-key", "password-file"):
            with self.subTest(change=change):
                for name, content in original.items():
                    (client / name).write_bytes(content)
                (client / ".no-passwords").unlink(missing_ok=True)
                session = trust_session.Session()
                self.addCleanup(session.close)
                connection = Mock(closed=False)
                connection.close.side_effect = lambda c=connection: setattr(c, "closed", True)
                with patch.object(storage.psycopg, "connect", return_value=connection) as connect:
                    with session.connection(client, expected_host=Target.MODEL_REVOCATION.host):
                        pass
                    self.assertEqual(connect.call_args.kwargs["sslmode"], "verify-full")
                    self.assertEqual(
                        connect.call_args.kwargs["ssl_min_protocol_version"], "TLSv1.3"
                    )
                    if change in {"role", "host"}:
                        settings = read_json(client / "connection.json")
                        settings[change] = "trainer" if change == "role" else Target.PRIMARY.host
                        write_json(client / "connection.json", settings)
                    elif change == "certificate":
                        (client / "ca.crt").write_bytes(b"changed")
                    elif change == "missing-key":
                        (client / "client.key").unlink()
                    else:
                        (client / ".no-passwords").write_bytes(b"forbidden")
                    for _ in range(2):
                        with self.assertRaises((Rejected, OSError)):
                            trust_authority.read(
                                client,
                                "lab",
                                "unused",
                                expected_host=Target.MODEL_REVOCATION.host,
                                connection_factory=session.connection,
                            )
                    connection.execute.assert_not_called()
                    self.assertTrue(connection.closed)
                    self.assertIsNone(session.current)
                    connect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
