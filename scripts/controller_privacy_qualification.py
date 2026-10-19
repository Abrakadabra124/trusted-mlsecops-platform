import io
import sys
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest.mock import patch

from mlsecops import controller, controller_probe, intake_probe, serving_http, worker_transport
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.intake_denial import RecordedDenial

ENTRYPOINTS = (
    (controller, ["--request", "private-request"], "execute", "controller_rejected\n"),
    (controller_probe, ["--role", "publisher"], "probe", "controller_probe_rejected\n"),
    (intake_probe, ["--request", "private-request"], "qualify", None),
    (
        serving_http,
        ["--config", "private-config"],
        "configured",
        "serving_configuration_rejected\n",
    ),
    (
        worker_transport,
        ["--request-file", "private-request"],
        "capture",
        "worker_transport_rejected\n",
    ),
)


class EntrypointPrivacyContracts(unittest.TestCase):
    def test_cancellation_has_no_private_traceback(self):
        for module, arguments, operation, diagnostic in ENTRYPOINTS:
            result = self.invoke(
                module, arguments, operation, operation_error=KeyboardInterrupt("private-cancel")
            )
            self.assertEqual(result[0], 130)
            self.assertNotIn("private-cancel", result[1] + result[2])
            self.assertNotIn("Traceback", result[1] + result[2])
            if module is worker_transport:
                self.assertEqual(result[2], "worker_transport_cancelled\n")
            elif diagnostic is not None:
                self.assertEqual(result[2], diagnostic)

    def test_positive_controls_and_recorded_denials(self):
        for module, arguments, operation, _diagnostic in ENTRYPOINTS[:-1]:
            result = self.invoke(module, arguments, operation)
            self.assertEqual(result[0], 0)
            self.assertEqual(result[2], "")
            result[3].assert_called_once_with()
            result[5].assert_called_once()
        for status in ("fail", "inconclusive"):
            result = self.invoke(
                controller,
                ["--request", "private-request"],
                "execute",
                operation_error=RecordedDenial("1" * 64, status),
            )
            self.assertEqual(
                result[:3],
                (
                    1,
                    canonical(
                        {
                            "status": status,
                            "decision": "deny-evaluation",
                            "denial_reference": "1" * 64,
                            "release_ready": False,
                        }
                    ).decode()
                    + "\n",
                    "",
                ),
            )

    def test_transport_success_invalid_envelope_and_serialization_limit(self):
        envelope = {
            "schema_version": 1,
            "output": {},
            "diagnostics": {
                "bytes": 0,
                "gpu_discovery_warning": False,
                "raw_output_retained": False,
            },
        }
        for mode in ("valid", "invalid", "limit"):
            output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
            with (
                patch("sys.argv", ["transport", "--request-file", "private-request"]),
                patch.object(worker_transport, "enforce_privacy"),
                patch.object(
                    worker_transport, "capture", return_value={} if mode == "invalid" else envelope
                ),
                patch.object(worker_transport, "MAX_OUTPUT", 1 if mode == "limit" else 4096),
                redirect_stdout(output),
                redirect_stderr(io.StringIO()) as diagnostic,
            ):
                code = worker_transport.main()
            content = output.buffer.getvalue()
            if mode == "valid":
                self.assertEqual(code, 0)
                self.assertEqual(decode(content), envelope)
                self.assertEqual(diagnostic.getvalue(), "")
            else:
                self.assertEqual(
                    (code, content, diagnostic.getvalue()), (1, b"", "worker_transport_rejected\n")
                )
            output.close()

    def invoke(self, module, arguments, operation, *, guard_error=None, operation_error=None):
        output, diagnostic = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(sys, "argv", ["controlled", *arguments]))
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(diagnostic))
            server = stack.enter_context(patch.object(serving_http, "run_server"))
            guard = stack.enter_context(
                patch.object(module, "enforce_privacy", side_effect=guard_error)
            )
            read = stack.enter_context(
                patch.object(module, "read_json", create=True, return_value={})
            )
            action = stack.enter_context(
                patch.object(module, operation, side_effect=operation_error, return_value={})
            )
            code = module.main()
        return code, output.getvalue(), diagnostic.getvalue(), guard, read, action, server

    def check_rejection(self, result, diagnostic):
        code, output, errors, *_ = result
        self.assertEqual(code, 1)
        if diagnostic is None:
            self.assertEqual(
                output,
                '{"reason":"kube_intake_probe_incomplete","release_ready":false,"status":"fail"}\n',
            )
            self.assertEqual(errors, "")
        else:
            self.assertEqual(output, "")
            self.assertEqual(errors, diagnostic)

    def test_guard_failure_prevents_private_reads_actions_and_server_start(self):
        for module, arguments, operation, diagnostic in ENTRYPOINTS:
            with self.subTest(module=module.__name__):
                result = self.invoke(
                    module, arguments, operation, guard_error=Rejected("private-policy-canary")
                )
                self.check_rejection(result, diagnostic)
                result[3].assert_called_once_with()
                result[4].assert_not_called()
                result[5].assert_not_called()
                result[6].assert_not_called()

    def test_invalid_arguments_never_echo_values_or_traceback(self):
        for module, arguments, operation, diagnostic in ENTRYPOINTS:
            with self.subTest(module=module.__name__):
                result = self.invoke(module, [*arguments, "--private-canary"], operation)
                self.check_rejection(result, diagnostic)
                result[4].assert_not_called()
                result[5].assert_not_called()

    def test_runtime_errors_are_constant(self):
        for module, arguments, operation, diagnostic in ENTRYPOINTS:
            for failure in (
                RuntimeError("private-password-canary"),
                Rejected("kube_intake_private_canary"),
            ):
                with self.subTest(module=module.__name__, failure=type(failure).__name__):
                    result = self.invoke(module, arguments, operation, operation_error=failure)
                    self.check_rejection(result, diagnostic)
                    result[3].assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
