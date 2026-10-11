import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical
from scripts.tracking_client import Client, NoRedirect, publish, read_back
from scripts.tracking_config import initialize


def qualify():
    cases = []

    def rejected(name, operation):
        try:
            operation()
        except Rejected:
            cases.append(name)
        else:
            raise Rejected("tracking_client_bypass:" + name)

    with tempfile.TemporaryDirectory(prefix="tracking-client-") as directory:
        state = Path(directory)
        initialize(state, "sha256:" + "a" * 64, 15445)
        for endpoint in (
            "http://127.0.0.1:15445",
            "https://remote.invalid",
            "https://user@localhost",
            "https://localhost/path",
            "https://localhost?query=1",
            "https://localhost#fragment",
        ):
            rejected("endpoint-" + str(len(cases)), lambda: Client(endpoint, state / "ca.crt"))
        client = Client(
            "https://127.0.0.1:15445", state / "ca.crt", "publisher", "disposable-test-value"
        )
        with patch.object(client.opener, "open") as request:
            for path in (
                "//foreign.invalid/api/",
                "/api/../private",
                "/api/run#fragment",
                "https://remote.invalid/api/",
            ):
                rejected("path-" + str(len(cases)), lambda: client.request("GET", path))
            rejected(
                "oversized-input", lambda: client.request("PUT", "/api/test", content=b"x" * 65537)
            )
            if request.called:
                raise Rejected("tracking_bad_input_reached_network")
        rejected(
            "no-redirect",
            lambda: NoRedirect().redirect_request(
                None, None, 302, "", {}, "https://foreign.invalid"
            ),
        )
        for name, status, body in (
            ("wrong-status", 500, b"private diagnostic"),
            ("oversized-response", 200, b"x" * (1024 * 1024 + 1)),
        ):
            response = Mock(status=status)
            response.read.return_value = body
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            with patch.object(client.opener, "open", return_value=response):
                rejected(name, lambda: client.request("GET", "/api/test"))
    record = {
        "source_run_id": "a" * 32,
        "params": {"input_digest": "b" * 64},
        "metrics": {"auprc": 0.9},
    }
    for name, run_id, uri in (
        ("invalid-run-id", "invalid", "mlflow-artifacts:/1/run/artifacts"),
        ("external-artifact", "a" * 32, "https://foreign.invalid/model"),
        ("artifact-authority", "a" * 32, "mlflow-artifacts://foreign.invalid/run"),
        ("artifact-parent", "a" * 32, "mlflow-artifacts:/../run"),
    ):
        client = Mock()
        client.request.return_value = canonical(
            {"run": {"info": {"run_id": run_id, "artifact_uri": uri}}}
        )
        rejected(name, lambda: publish(client, "1", record))
        if client.request.call_count != 1:
            raise Rejected("tracking_bad_artifact_reached_write")
    client = Mock()
    client.request.side_effect = [
        canonical({"run": {"data": {"params": [], "metrics": []}}}),
        b"tamper",
    ]
    rejected(
        "read-back-mismatch",
        lambda: read_back(
            client,
            {"run_id": "a" * 32, "artifact_path": "/api/artifact", "record_digest": "a" * 64},
            record,
        ),
    )
    return {"status": "pass", "scope": "tracking-client-negative-contracts", "checks": len(cases)}


if __name__ == "__main__":
    print(canonical(qualify()).decode())
