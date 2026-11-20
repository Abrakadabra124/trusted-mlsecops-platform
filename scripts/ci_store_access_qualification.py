"""Read-only access preflight for the actual private store; no live credentials."""

import io
import os
import runpy
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import ci_store_access as access
from scripts.ci_private_assets_qualification import StoreAPI


class StoreAccessTests(unittest.TestCase):
    def setUp(self):
        self.api = StoreAPI()

    def test_each_preflight_reads_the_private_repo_and_ref_without_mutation(self):
        for role in ("reader", "publisher"):
            self.assertIsNone(access.check(self.api, role))
        self.assertEqual(self.api.mutations, [])
        self.assertFalse(self.api.downloads)

    def test_unknown_role_or_repository_refuses_before_any_mutation(self):
        with self.assertRaises(Rejected):
            access.check(None, "admin")
        self.api.repo["private"] = False
        with self.assertRaises(Rejected):
            access.check(self.api, "publisher")
        self.assertEqual(self.api.mutations, [])

    def test_only_fine_grained_credentials_reach_the_designated_client(self):
        for value in ("", "example", "gho_example", "ghp_example", "ghs_example"):
            with (
                patch.dict(os.environ, {"CANDIDATE_ACCESS_TOKEN": value}, clear=True),
                patch.object(access, "Client") as client,
            ):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(access.main(["reader"]), 1)
                client.assert_not_called()
                self.assertNotIn("CANDIDATE_ACCESS_TOKEN", os.environ)

    def test_cli_output_contains_only_public_status(self):
        for role, error, expected in (
            ("reader", False, 0),
            ("publisher", True, 1),
            ("other", False, 1),
        ):
            out = io.StringIO()
            with (
                patch.dict(
                    os.environ, {"CANDIDATE_ACCESS_TOKEN": "github_pat_public_fixture"}, clear=True
                ),
                patch.object(access, "Client", return_value=self.api),
                redirect_stdout(out),
                redirect_stderr(out),
            ):
                self.api.repo["private"] = not error
                self.assertEqual(access.main([role]), expected)
                self.assertNotIn("CANDIDATE_ACCESS_TOKEN", os.environ)
            self.assertEqual(
                out.getvalue().strip(),
                "private_access_readback=pass"
                if not expected
                else "private_access_readback=refused",
            )
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(io.StringIO()):
            self.assertEqual(access.main([]), 1)

    def test_command_line_without_secret_refuses(self):
        out = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(sys, "argv", ["ci_store_access", "reader"]),
            patch.dict(sys.modules),
            redirect_stdout(out),
            self.assertRaises(SystemExit) as failure,
        ):
            sys.modules.pop("scripts.ci_store_access", None)
            runpy.run_module("scripts.ci_store_access", run_name="__main__")
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(out.getvalue().strip(), "private_access_readback=refused")
