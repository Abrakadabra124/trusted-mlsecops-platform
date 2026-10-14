import io
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import storage, trust, trust_authority
from mlsecops.contracts import Rejected, canonical, digest
from scripts import trust_qualification as fixtures


class AuthorityContracts(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TrustContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.envelope = self.fixture.envelope()
        self.content = canonical(self.envelope)
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.execute.return_value.fetchone.return_value = (
            self.fixture.public,
            1,
            digest(self.content),
            self.content,
            int(self.fixture.wall),
        )

    def read(self):
        return trust_authority.read("client", "local-cpu", self.fixture.public)

    def test_real_signed_document_through_controlled_tls_transport(self):
        with (
            patch.object(storage, "connection_parameters", return_value={"user": "ml_serving"}),
            patch.object(storage, "connect", return_value=self.connection),
        ):
            envelope, clock = self.read()
        self.assertEqual(envelope, self.envelope)
        self.assertEqual(clock, self.fixture.wall)
        self.assertEqual(self.connection.execute.call_count, 1)

    def test_wrong_role_or_root_or_missing_document_is_not_valid_policy(self):
        with (
            patch.object(storage, "connection_parameters", return_value={"user": "ml_trainer"}),
            self.assertRaises(Rejected),
        ):
            self.read()
        for row in (None, ("wrong", 1, digest(self.content), self.content, int(self.fixture.wall))):
            self.connection.execute.return_value.fetchone.return_value = row
            with (
                patch.object(storage, "connection_parameters", return_value={"user": "ml_serving"}),
                patch.object(storage, "connect", return_value=self.connection),
                self.assertRaises(Rejected),
            ):
                self.read()

    def test_corrupt_bytes_and_version_mismatch_clear_trust(self):
        for version, reference, content in (
            (2, digest(self.content), self.content),
            (1, "0" * 64, self.content),
            (1, "0" * 64, b"changed"),
        ):
            self.connection.execute.return_value.fetchone.return_value = (
                self.fixture.public,
                version,
                reference,
                content,
                int(self.fixture.wall),
            )
            with (
                patch.object(storage, "connection_parameters", return_value={"user": "ml_serving"}),
                patch.object(storage, "connect", return_value=self.connection),
                self.assertRaises(Rejected),
            ):
                self.read()

    def test_transport_failure_is_redacted_and_does_not_reissue_policy(self):
        with (
            patch.object(storage, "connection_parameters", return_value={"user": "ml_serving"}),
            patch.object(storage, "connect", side_effect=Rejected("storage_connection_rejected")),
            self.assertRaisesRegex(trust.Unavailable, "trust_service_unavailable"),
        ):
            self.read()
        with (
            patch.object(storage, "connection_parameters", return_value={"user": "ml_serving"}),
            patch.object(storage, "connect", side_effect=Rejected("storage_client_config_invalid")),
            self.assertRaisesRegex(Rejected, "storage_client_config_invalid"),
        ):
            self.read()

    def metadata(self, *, empty=False):
        return {
            "environment": "local-cpu",
            "root_public": self.fixture.public,
            "version": None if empty else 1,
            "sha256": None if empty else digest(self.content),
            "envelope": None if empty else self.envelope,
            "clock": int(self.fixture.wall),
        }

    def test_install_requires_known_migration_root_and_dedicated_storage(self):
        checksum = digest(trust_authority.migration_sql().encode())
        expected = f"local-cpu:{self.fixture.public}"
        for responses, error in (
            (["", "", f"1:{checksum}", expected], None),
            (["ml_trust", f"1:{checksum}", expected], None),
            (["ml_trust", "2:changed"], "trust_migration_mismatch"),
            (["ml_trust", f"1:{checksum}", "foreign"], "trust_configuration_conflict"),
        ):
            with (
                patch.object(trust_authority, "validate", return_value={"name": "owned"}),
                patch.object(trust_authority, "admin", side_effect=responses) as admin,
            ):
                if error:
                    with self.assertRaisesRegex(Rejected, error):
                        trust_authority.install("state", "local-cpu", self.fixture.public)
                else:
                    self.assertEqual(
                        trust_authority.install("state", "local-cpu", self.fixture.public), checksum
                    )
                if responses[0] == "":
                    script = admin.call_args_list[1].args[1]
                    self.assertIn("trust_requires_separate_empty_storage", script)
                    self.assertIn("pg_advisory_xact_lock", script)
        with self.assertRaises(Rejected):
            trust_authority.install("state", "local-cpu", "c2hvcnQ=")

    def test_current_validates_primary_bytes_and_migration(self):
        checksum = digest(trust_authority.migration_sql().encode())
        for empty in (True, False):
            value = self.metadata(empty=empty)
            encoded = {**value, "envelope": None if empty else self.content.hex()}
            with (
                patch.object(trust_authority, "validate", return_value={"name": "owned"}),
                patch.object(
                    trust_authority,
                    "admin",
                    side_effect=[f"1:{checksum}", canonical(encoded).decode()],
                ),
            ):
                self.assertEqual(trust_authority.current("state"), ("owned", value))
        with (
            patch.object(trust_authority, "validate", return_value={"name": "owned"}),
            patch.object(trust_authority, "admin", return_value="changed"),
            self.assertRaisesRegex(Rejected, "trust_migration_mismatch"),
        ):
            trust_authority.current("state")
        encoded["sha256"] = "0" * 64
        with (
            patch.object(trust_authority, "validate", return_value={"name": "owned"}),
            patch.object(
                trust_authority, "admin", side_effect=[f"1:{checksum}", canonical(encoded).decode()]
            ),
            self.assertRaisesRegex(Rejected, "trust_document_integrity"),
        ):
            trust_authority.current("state")

    def test_publication_initial_retry_successor_and_readback(self):
        with (
            patch.object(trust_authority, "current", return_value=("owned", self.metadata())),
            patch.object(trust_authority, "admin") as admin,
        ):
            self.assertTrue(trust_authority.publish("state", self.envelope)["reused"])
            admin.assert_not_called()
        for previous in (self.metadata(empty=True), self.metadata()):
            self.fixture.payload["version"] = 1 if previous["version"] is None else 2
            following = self.fixture.envelope()
            reference = digest(canonical(following))
            with (
                patch.object(trust_authority, "current", return_value=("owned", previous)),
                patch.object(trust_authority, "admin", side_effect=["", reference]) as admin,
            ):
                self.assertFalse(trust_authority.publish("state", following)["reused"])
                self.assertIn("trust_update_expired_or_future", admin.call_args_list[0].args[1])
            with (
                patch.object(trust_authority, "current", return_value=("owned", previous)),
                patch.object(trust_authority, "admin", side_effect=["", "wrong"]),
                self.assertRaisesRegex(Rejected, "trust_update_unconfirmed"),
            ):
                trust_authority.publish("state", following)
        with (
            patch.object(
                trust_authority, "current", return_value=("owned", self.metadata(empty=True))
            ),
            self.assertRaisesRegex(Rejected, "trust_initial_version"),
        ):
            trust_authority.publish("state", following)

    def test_update_preserves_revocations_and_signs_with_the_pinned_root(self):
        for previous in (self.metadata(empty=True), self.metadata()):
            with (
                patch.object(trust_authority, "current", return_value=("owned", previous)),
                patch.object(trust_authority, "publish", return_value={"version": 2}) as publish,
            ):
                trust_authority.update(
                    "state",
                    "a" * 64,
                    self.fixture.key,
                    revoked_artifacts=["c" * 64],
                    revoked_keys=["d" * 64],
                )
                payload = trust.validate(
                    publish.call_args.args[1], self.fixture.public, "local-cpu", previous["clock"]
                )
                self.assertEqual(payload["revoked_artifacts"], ["c" * 64])
                self.assertEqual(payload["revoked_keys"], ["d" * 64])

    def test_cli_confirmation_redaction_and_action_routing(self):
        with (
            patch("sys.argv", ["trust_authority", "install", "--state", "private"]),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as outcome,
        ):
            runpy.run_module("mlsecops.trust_authority", run_name="__main__")
        self.assertEqual(outcome.exception.code, 1)
        for arguments in (
            ["install", "--state", "state"],
            ["update", "--state", "state", "--confirm-authority"],
            ["publish", "--state", "state", "--confirm-authority"],
        ):
            output = io.StringIO()
            with redirect_stderr(output):
                self.assertEqual(trust_authority.main(arguments), 1)
            self.assertNotIn("private", output.getvalue())
        for action, target, extra, result in (
            ("install", "install", ["--root-public", self.fixture.public], "a" * 64),
            ("publish", "publish", ["--document", "signed.json"], {"version": 1}),
            ("update", "update", ["--key", "private.pem", "--policy", "a" * 64], {"version": 1}),
            ("show", "current", [], ("owned", self.metadata())),
        ):
            with (
                patch.object(trust_authority, target, return_value=result),
                patch.object(trust_authority, "read_json", return_value=self.envelope),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    trust_authority.main(
                        [action, "--state", "state", "--confirm-authority", *extra]
                    ),
                    0,
                )
        with (
            patch.object(storage, "connection_parameters", return_value={"user": "ml_serving"}),
            patch.object(
                storage, "connect", side_effect=psycopg.OperationalError("private endpoint")
            ),
            self.assertRaisesRegex(trust.Unavailable, "trust_service_unavailable"),
        ):
            self.read()


if __name__ == "__main__":
    unittest.main()
