import contextlib
import copy
import io
import ssl
import tempfile
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from mlsecops.contracts import Rejected, canonical
from scripts import tracking_doctor


def qualify():
    cases = []
    observed = {role: {"State": {"Running": True}} for role in ("pg", "server")}
    with tempfile.TemporaryDirectory(prefix="tracking-doctor-") as directory:
        state = Path(directory)
        missing = state / "missing"
        result = tracking_doctor.diagnose(missing)
        if result["status"] != "inconclusive" or missing.exists():
            raise Rejected("doctor_missing_state_not_read_only_inconclusive")
        cases.append("real-missing-state-not-created")
        (state / "configuration.json").write_bytes(b"{invalid")
        if tracking_doctor.diagnose(state)["status"] != "fail":
            raise Rejected("doctor_malformed_json_accepted")
        cases.append("real-malformed-json-denied")
        for name, stage, error, status in (
            ("missing-state", "read_json", FileNotFoundError("secret"), "inconclusive"),
            ("invalid-json", "read_json", Rejected("secret"), "fail"),
            ("tampered-state", "validate", Rejected("secret"), "fail"),
            ("invalid-state-shape", "validate", TypeError("secret"), "fail"),
            ("missing-field", "validate", KeyError("secret"), "fail"),
            ("invalid-certificate", "validate", ValueError("secret"), "fail"),
            (
                "docker-unavailable",
                "verify",
                Rejected("storage_docker_unavailable"),
                "inconclusive",
            ),
            ("partial-bootstrap", "verify", FileNotFoundError("secret"), "inconclusive"),
            (
                "foreign-resource",
                "verify",
                Rejected("tracking_service_foreign_resource:secret"),
                "fail",
            ),
            (
                "policy-drift",
                "verify",
                Rejected("tracking_service_container_policy_changed:secret"),
                "fail",
            ),
            ("malformed-receipt", "verify", KeyError("secret"), "fail"),
            ("tls-untrusted", "probe_https", ssl.SSLError("secret"), "inconclusive"),
            (
                "transport-unavailable",
                "probe_https",
                urllib.error.URLError("secret"),
                "inconclusive",
            ),
            ("redirect-denied", "probe_https", Rejected("tracking_redirect_denied:secret"), "fail"),
        ):
            with (
                patch.object(tracking_doctor, "read_json", return_value={"port": 15445}),
                patch.object(tracking_doctor, "validate"),
                patch.object(tracking_doctor, "verify", return_value=observed),
                patch.object(tracking_doctor, "probe_https") as health,
            ):
                with patch.object(tracking_doctor, stage, side_effect=error):
                    result = tracking_doctor.diagnose(state)
                if result["status"] != status or result["release_ready"]:
                    raise Rejected("doctor_failure_misclassified:" + name)
                if "secret" in canonical(result).decode():
                    raise Rejected("doctor_exception_leaked:" + name)
                if stage != "probe_https":
                    health.assert_not_called()
            cases.append(name)
        for stopped in (None, "pg", "server"):
            current = copy.deepcopy(observed)
            if stopped:
                current[stopped]["State"]["Running"] = False
            with (
                patch.object(tracking_doctor, "read_json", return_value={"port": 15445}),
                patch.object(tracking_doctor, "validate"),
                patch.object(tracking_doctor, "verify", return_value=current),
                patch.object(tracking_doctor, "probe_https") as health,
            ):
                result = tracking_doctor.diagnose(state)
                if result["status"] != ("fail" if stopped else "pass"):
                    raise Rejected("doctor_running_state_ignored")
                if stopped:
                    health.assert_not_called()
                else:
                    health.assert_called_once_with(state, {"port": 15445})
            cases.append("stopped-" + stopped if stopped else "healthy")
        for name, status, body, rejected in (
            ("bounded-health", 200, b"OK", False),
            ("bad-http-status", 503, b"secret", True),
            ("oversize-health", 200, b"x" * 65, True),
        ):
            response = MagicMock()
            response.status = status
            response.read.return_value = body
            response.__enter__.return_value = response
            with patch.object(tracking_doctor, "Client") as client:
                client.return_value.opener.open.return_value = response
                try:
                    tracking_doctor.probe_https(state, {"port": 15445})
                except Rejected:
                    if not rejected:
                        raise
                else:
                    if rejected:
                        raise Rejected("doctor_invalid_health_accepted")
                response.read.assert_called_once_with(65)
                client.assert_called_once_with("https://127.0.0.1:15445", state / "ca.crt")
                request = client.return_value.opener.open.call_args.args[0]
                if (
                    request.get_method() != "GET"
                    or request.full_url != "https://127.0.0.1:15445/health"
                ):
                    raise Rejected("doctor_health_not_read_only")
            cases.append(name)
        with patch.object(tracking_doctor, "Client") as client:
            client.return_value.opener.open.side_effect = urllib.error.HTTPError(
                "https://127.0.0.1:15445/health", 503, "secret", {}, None
            )
            try:
                tracking_doctor.probe_https(state, {"port": 15445})
            except Rejected as error:
                if str(error) != "tracking_health_response_invalid":
                    raise Rejected("doctor_http_error_leaked") from error
            else:
                raise Rejected("doctor_http_error_accepted")
        cases.append("http-exception-sanitized")
        for status, expected in (("pass", 0), ("fail", 1), ("inconclusive", 2)):
            with (
                patch.object(tracking_doctor, "diagnose", return_value={"status": status}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                if tracking_doctor.main() != expected:
                    raise Rejected("doctor_exit_code_invalid")
            cases.append("exit-" + status)
    return {"status": "pass", "scope": "controlled-doctor-contracts", "checks": len(cases)}


if __name__ == "__main__":
    print(canonical(qualify()).decode())
