import asyncio
import io
import unittest
from contextlib import redirect_stderr
from types import SimpleNamespace
from unittest.mock import Mock

from mlsecops import serving_startup as startup
from mlsecops.contracts import Rejected, canonical


class StartupDiagnosticsContracts(unittest.TestCase):
    def test_http_lifespan_diagnostics_require_explicit_opt_in(self):
        from mlsecops import serving_http

        for enabled in (False, True):
            engine = Mock(startup_failure=startup.record("reader", None, RuntimeError("SECRET")))
            engine.activate.side_effect = Rejected("PRIVATE-TOKEN")
            app = serving_http.create_app(engine, "a" * 64, startup_diagnostics=enabled)

            async def exercise():
                async with app.router.lifespan_context(app):
                    pass

            with redirect_stderr(io.StringIO()) as output:
                asyncio.run(exercise())
            text = output.getvalue()
            self.assertNotIn("PRIVATE", text)
            self.assertNotIn("SECRET", text)
            if enabled:
                self.assertIsNotNone(startup.validated(text.encode()))
            else:
                self.assertEqual(text, "")
            engine.close.assert_called_once()

    def test_only_finite_codes_are_serialized(self):
        value = startup.record("reader", None, Rejected("serving_head_missing"))
        self.assertEqual(startup.validated(canonical(value)), value)
        self.assertEqual(startup.content(SimpleNamespace(startup_failure=value)), canonical(value))
        for nested in (([], []), ("PRIVATE", "TOKEN"), None):
            value = startup.record(
                "PRIVATE-TOKEN", SimpleNamespace(startup_failure=nested), RuntimeError("PASSWORD")
            )
            self.assertEqual(
                value,
                {
                    "event": "serving-startup-refused",
                    "phase": "unknown",
                    "worker_phase": "none",
                    "cause": "unknown",
                },
            )

    def test_private_or_malformed_outputs_cannot_be_exported_as_diagnostic(self):
        valid = startup.record(
            "worker-start",
            SimpleNamespace(startup_failure=("load", "serving_exchange_rejected")),
            RuntimeError(),
        )
        for content in (
            b"SECRET",
            b"x" * 513,
            canonical({**valid, "extra": "PRIVATE"}),
            canonical({**valid, "cause": "PRIVATE"}),
            canonical({**valid, "phase": []}),
            canonical({**valid, "worker_phase": []}),
            b"[]",
            b"null",
            canonical(valid) + b"\nPRIVATE",
        ):
            self.assertIsNone(startup.validated(content))
        for value in (object(), {"token": "PRIVATE"}):
            content = startup.content(SimpleNamespace(startup_failure=value))
            self.assertNotIn(b"PRIVATE", content)
            self.assertEqual(startup.validated(content)["phase"], "unknown")


if __name__ == "__main__":
    unittest.main()
