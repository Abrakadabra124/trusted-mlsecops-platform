import os
import unittest
from contextlib import contextmanager
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected
from scripts import serving_core_qualification as core
from scripts import serving_native
from scripts.audit_export_probe import exercise


class ExportSiteContracts(unittest.TestCase):
    def test_hook_runs_after_http_and_journal_close_before_temporary_cleanup(self):
        order, paths = [], []
        journal = Mock()
        journal.close.side_effect = lambda: order.append("journal-close")

        @contextmanager
        def site(*arguments, **options):
            try:
                yield Mock()
            finally:
                order.append("http-stop")

        def export(path):
            self.assertTrue(path.is_dir())
            paths.append(path)
            order.append("export")

        with (
            patch.object(serving_native, "_site", site),
            patch.object(serving_native.serving_audit, "Journal", return_value=journal),
        ):
            with serving_native.site(Mock(), audit_export=export):
                order.append("body")
        self.assertEqual(order, ["body", "http-stop", "journal-close", "export"])
        self.assertFalse(paths[0].exists())

    def test_body_shutdown_or_close_failure_never_calls_export(self):
        for fault in ("body", "stop", "close"):
            journal, export = Mock(), Mock()
            if fault == "close":
                journal.close.side_effect = Rejected("close")

            @contextmanager
            def site(*arguments, **options):
                try:
                    yield Mock()
                finally:
                    if fault == "stop":
                        raise Rejected("stop")

            with (
                patch.object(serving_native, "_site", site),
                patch.object(serving_native.serving_audit, "Journal", return_value=journal),
            ):
                with self.assertRaises(Rejected):
                    with serving_native.site(Mock(), audit_export=export):
                        if fault == "body":
                            raise Rejected("body")
            export.assert_not_called()

    def test_external_journal_does_not_give_fixture_export_ownership(self):
        with patch.object(serving_native, "_site") as site:
            with self.assertRaises(Rejected):
                with serving_native.site(Mock(), audit=Mock(), audit_export=Mock()):
                    self.fail("unowned journal accepted")
            site.assert_not_called()

    def test_export_failure_propagates_and_temporary_directory_is_removed(self):
        paths = []

        @contextmanager
        def site(*arguments, **options):
            yield Mock()

        def export(path):
            paths.append(path)
            raise Rejected("export failed")

        with (
            patch.object(serving_native, "_site", site),
            patch.object(serving_native.serving_audit, "Journal"),
        ):
            with self.assertRaises(Rejected):
                with serving_native.site(Mock(), audit_export=export):
                    pass
        self.assertFalse(paths[0].exists())

    @unittest.skipUnless(os.name == "posix", "native closed-spool CLI requires Linux")
    def test_real_loopback_request_is_exported_only_after_owned_journal_close(self):
        fixture = core.ServingCoreContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        result = {}

        def export(path):
            self.assertIsNone(fixture.engine.worker)
            self.assertFalse((path / ".lease").exists())
            result.update(exercise(path))

        with serving_native.site(fixture.engine, audit_export=export) as request:
            self.assertEqual(request("/readyz")[0], 200)
            self.assertEqual(result, {})
        self.assertEqual(result["requests"], {"completed": 1, "aborted": 0, "unresolved": 0})
        self.assertEqual(result["routes"], {"predict": 0, "ready": 1})


if __name__ == "__main__":
    unittest.main()
