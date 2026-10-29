import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import kube_trust_isolation as probe
from mlsecops.contracts import Rejected
from mlsecops.trust_targets import Target


class TrustIsolationContracts(unittest.TestCase):
    def exercise(
        self,
        *,
        bypass_sql=False,
        sqlstate=True,
        tls_error="certificate verify failed",
        bypass_tls=False,
        tls=(True, "TLSv1.3"),
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "ca.crt"
            root.write_bytes(b"public CA")
            for target in Target:
                connection = MagicMock()

                def execute(statement):
                    if statement.startswith("SELECT ssl"):
                        return MagicMock(fetchone=lambda: tls)
                    if not bypass_sql:
                        raise (
                            psycopg.errors.InsufficientPrivilege("private")
                            if sqlstate
                            else psycopg.OperationalError("private")
                        )

                connection.execute.side_effect = execute
                context = MagicMock(__enter__=lambda self: connection)
                count = 0

                def connect(**params):
                    nonlocal count
                    count += 1
                    if count == 1 or bypass_tls:
                        return context
                    raise psycopg.OperationalError(tls_error)

                def check(label, actual, wanted):
                    if type(actual) is not type(wanted) or actual != wanted:
                        raise Rejected(label)

                with (
                    patch.object(
                        probe.storage,
                        "connection_parameters",
                        return_value={
                            "host": target.host,
                            "user": "ml_serving",
                            "sslrootcert": str(root),
                        },
                    ),
                    patch.object(probe.psycopg, "connect", side_effect=connect),
                ):
                    result = probe.verify(target, check)
                    self.assertEqual(result["target"], target.value)
                    self.assertTrue(result["cross_ca_denied"])
                    self.assertEqual(count, 2)

    def test_two_distinct_scopes_verify_tls_and_sql_denial(self):
        self.exercise()

    def test_network_failure_or_wrong_tls_does_not_prove_ca_isolation(self):
        for values in (
            {"tls_error": "timeout PRIVATE"},
            {"bypass_tls": True},
            {"tls": (True, "TLSv1.2")},
        ):
            with self.subTest(values=values), self.assertRaises(Rejected):
                self.exercise(**values)

    def test_sql_access_or_wrong_error_cannot_pass(self):
        for values in ({"bypass_sql": True}, {"sqlstate": False}):
            with self.subTest(values=values), self.assertRaises(Rejected):
                self.exercise(**values)


if __name__ == "__main__":
    unittest.main()
