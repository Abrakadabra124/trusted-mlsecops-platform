import io
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import kube_trust_probe as target
from mlsecops import trust
from mlsecops.contracts import Rejected
from mlsecops.storage_pki import TRUST_HOST
from scripts import trust_qualification as fixtures


class TrustReaderProbeContracts(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TrustContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.envelope = self.fixture.envelope()
        self.policy = self.fixture.payload["promotion_policy_sha256"]
        self.clock = int(self.fixture.wall)
        self.parameters = {"user": "ml_promoter", "host": TRUST_HOST}
        self.enterContext(
            patch.object(target.storage, "connection_parameters", return_value=self.parameters)
        )
        self.read = self.enterContext(
            patch.object(target.trust_authority, "read", return_value=(self.envelope, self.clock))
        )
        self.exists = self.enterContext(patch.object(target.Path, "exists", return_value=False))
        self.enterContext(patch.object(target.socket, "gethostbyname", return_value="10.79.1.2"))
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.execute.side_effect = self.sql
        self.enterContext(patch.object(target.storage, "connect", return_value=self.connection))
        self.connect = self.enterContext(
            patch.object(target.psycopg, "connect", side_effect=self.tls)
        )

    def sql(self, statement):
        if statement.startswith("SELECT ssl"):
            result = MagicMock()
            result.fetchone.return_value = (True, "TLSv1.3")
            return result
        raise psycopg.errors.InsufficientPrivilege("private SQL detail")

    def tls(self, **parameters):
        if parameters["host"] == "wrong.invalid":
            reason = "does not match host name"
        elif parameters.get("sslcert") == "":
            reason = "requires a valid client certificate"
        elif parameters.get("sslmode") == "disable":
            reason = "pg_hba.conf rejects connection"
        else:
            reason = "certificate authentication failed"
        raise psycopg.OperationalError(reason)

    def probe(self, **kwargs):
        return target.probe("promoter", self.fixture.public, self.policy, 1, [], **kwargs)

    def test_real_signed_policy_and_all_expected_denials(self):
        result = self.probe()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(result["cases"]), 16)
        self.assertFalse(result["release_ready"])
        self.parameters["user"] = "ml_serving"
        self.assertEqual(
            target.probe("serving", self.fixture.public, self.policy, 1, [])["role"], "serving"
        )

    def test_identity_policy_mount_and_transport_changes_are_not_pass(self):
        for changes, code in (
            ({"user": "ml_publisher"}, "identity"),
            ({"host": "other"}, "identity"),
        ):
            with (
                patch.object(
                    target.storage,
                    "connection_parameters",
                    return_value={**self.parameters, **changes},
                ),
                self.assertRaisesRegex(Rejected, "trust_probe_" + code),
            ):
                self.probe()
        with self.assertRaisesRegex(Rejected, "policy_mismatch"):
            target.probe("promoter", self.fixture.public, self.policy, 2, [])
        self.exists.return_value = True
        with self.assertRaisesRegex(Rejected, "forbidden_mount"):
            self.probe()
        self.exists.return_value = False
        self.connection.execute.side_effect = None
        self.connection.execute.return_value.fetchone.return_value = (True, "TLSv1.2")
        with self.assertRaisesRegex(Rejected, "trust_probe_tls"):
            self.probe()

    def test_sql_and_tls_wrong_failures_or_unexpected_success_are_rejected(self):
        original = self.sql
        for error, code in (
            (psycopg.OperationalError("other"), "wrong_sql_denial"),
            (None, "sql_bypass"),
        ):

            def changed(statement):
                if statement.startswith("SELECT ssl"):
                    return original(statement)
                if error is not None:
                    raise error
                return MagicMock()

            self.connection.execute.side_effect = changed
            with self.assertRaisesRegex(Rejected, code):
                self.probe()
        self.connection.execute.side_effect = self.sql
        self.connect.side_effect = psycopg.OperationalError("wrong cause")
        with self.assertRaisesRegex(Rejected, "wrong_tls_denial"):
            self.probe()
        self.connect.side_effect = None
        with self.assertRaisesRegex(Rejected, "tls_bypass"):
            self.probe()
        self.connect.side_effect = self.tls
        self.read.side_effect = [(self.envelope, self.clock), ({}, self.clock)]
        with self.assertRaisesRegex(Rejected, "policy_changed"):
            self.probe()

    def test_outage_requires_real_unavailability_and_cli_never_exposes_error_detail(self):
        with self.assertRaisesRegex(Rejected, "outage_not_observed"):
            self.probe(unavailable=True)
        self.read.side_effect = trust.Unavailable("private endpoint")
        self.assertEqual(self.probe(unavailable=True)["cases"], ["authority-outage-unavailable"])
        self.read.side_effect = Rejected("not an outage")
        with self.assertRaisesRegex(Rejected, "not an outage"):
            self.probe(unavailable=True)
        arguments = [
            "--role",
            "promoter",
            "--root",
            self.fixture.public,
            "--policy",
            self.policy,
            "--version",
            "1",
        ]
        with (
            patch.object(target, "enforce_privacy"),
            patch.object(target, "probe", return_value={"status": "pass"}),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(target.main(arguments), 0)
        for error, code in ((Rejected("private endpoint"), 1), (KeyboardInterrupt(), 130)):
            output = io.StringIO()
            with (
                patch.object(target, "enforce_privacy"),
                patch.object(target, "probe", side_effect=error),
                redirect_stderr(output),
            ):
                self.assertEqual(target.main(arguments), code)
            self.assertEqual(output.getvalue(), "trust_probe_rejected\n")
        with (
            patch("sys.argv", ["trust-probe"]),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as outcome,
        ):
            runpy.run_module("mlsecops.kube_trust_probe", run_name="__main__")
        self.assertEqual(outcome.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
