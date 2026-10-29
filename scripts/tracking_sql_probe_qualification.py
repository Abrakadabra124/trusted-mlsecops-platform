"""Security probe invariants under all interpreter optimization levels; fake SQL only."""

import ast
import io
import json
import socket
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psycopg

from scripts import tracking_sql_probe as probe


class SQLProbeContracts(unittest.TestCase):
    def execute(
        self,
        optimization,
        *,
        wrong_identity=False,
        flags=None,
        bypass=False,
        dead_control=False,
        main=False,
    ):
        class Database:
            def __init__(self, role):
                self.role = role

            def __enter__(self):
                return self

            def __exit__(self, *error):
                pass

            def execute(self, statement):
                if "pg_stat_ssl" in statement:
                    row = (
                        ("foreign", "foreign", "TLSv1.2")
                        if wrong_identity
                        else (self.role, self.role, "TLSv1.3")
                    )
                elif statement == "SELECT 1":
                    row = (0,) if dead_control else (1,)
                else:
                    row = (False, False, False, False) if flags is None else flags
                return SimpleNamespace(fetchone=lambda: row)

        def connect(**values):
            role = values["user"]
            baseline = (
                values["host"] == "tracking-pg"
                and values["dbname"] == role
                and values["sslmode"] == "verify-full"
                and values["sslrootcert"] == "/config/ca.crt"
                and values["sslcert"] == f"/config/{role}.crt"
                and values["sslkey"] == f"/config/{role}.key"
            )
            if not baseline and not bypass:
                raise psycopg.OperationalError("synthetic denial")
            return Database(role)

        with (
            patch.object(psycopg, "connect", side_effect=connect),
            patch.object(socket, "gethostbyname", return_value="127.0.0.1"),
        ):
            if optimization is None:
                return probe.qualify()
            tree = ast.parse(Path(probe.__file__).read_text(encoding="utf-8"))
            if main:
                namespace = {"__name__": "__main__"}
                exec(compile(tree, probe.__file__, "exec", optimize=optimization), namespace)
                return None
            functions = [
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "qualify"
            ]
            self.assertEqual(len(functions), 1)
            namespace = {"psycopg": psycopg, "socket": socket}
            exec(
                compile(
                    ast.Module(body=functions, type_ignores=[]),
                    probe.__file__,
                    "exec",
                    optimize=optimization,
                ),
                namespace,
            )
            return namespace["qualify"]()

    def test_valid_tls_roles_and_denied_variants_pass_in_all_modes(self):
        for optimization in (None, 0, 1, 2):
            with self.subTest(optimization=optimization):
                report = self.execute(optimization)
                self.assertEqual(report["status"], "pass")
                self.assertEqual(report["checks"], 16)
                self.assertEqual(len(set(report["cases"])), 16)

    def test_bad_identity_or_privileges_never_become_positive_cases(self):
        for optimization in (None, 0, 1, 2):
            for kwargs, reason in (
                ({"wrong_identity": True}, "role_database_or_tls_changed"),
                ({"flags": (True, True, True, True)}, "database_role_escalated"),
                ({"flags": (0, 0, 0, 0)}, "database_role_escalated"),
            ):
                with (
                    self.subTest(optimization=optimization, kwargs=kwargs),
                    self.assertRaisesRegex(AssertionError, reason),
                ):
                    self.execute(optimization, **kwargs)

    def test_negative_bypass_or_dead_control_never_passes(self):
        for optimization in (None, 0, 1, 2):
            for kwargs, reason in (
                ({"bypass": True}, "database_boundary_bypass"),
                ({"dead_control": True}, "database_positive_control_failed"),
            ):
                with (
                    self.subTest(optimization=optimization, kwargs=kwargs),
                    self.assertRaisesRegex(AssertionError, reason),
                ):
                    self.execute(optimization, **kwargs)

    def test_cli_still_reports_failure_and_nonzero_exit_when_optimized(self):
        for optimization in (0, 1, 2):
            with (
                self.subTest(optimization=optimization),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                with self.assertRaises(SystemExit) as error:
                    self.execute(optimization, wrong_identity=True, main=True)
                self.assertEqual(error.exception.code, 1)
                self.assertEqual(
                    json.loads(output.getvalue()), {"status": "fail", "reason": "AssertionError"}
                )
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.execute(optimization, main=True)
                self.assertEqual(json.loads(output.getvalue())["checks"], 16)


if __name__ == "__main__":
    unittest.main()
