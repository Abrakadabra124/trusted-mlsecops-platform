import shutil
import ssl
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, atomic_write, canonical
from mlsecops.controller_api import HOST, MAX_JSON, Client


def qualify(state):
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"controller_api_qualification_failed:{name}")
        cases.append({"id": f"api-contract:{name}", "status": "pass"})

    def rejected(name, action, reason):
        try:
            action()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected(f"controller_api_wrong_rejection:{name}:{error}") from error
            confirmed(name, True)
        else:
            confirmed(name, False)

    client = Client("publisher")
    with patch.object(
        Client, "exchange", side_effect=AssertionError("Invalid request reached network")
    ):
        for name, action, reason in (
            ("unknown-role", lambda: Client("approver"), "controller_api_role_invalid"),
            ("role-type", lambda: Client([]), "controller_api_role_invalid"),
            (
                "secret-resource",
                lambda: client.request("secrets"),
                "controller_api_resource_invalid",
            ),
            (
                "traversal",
                lambda: client.request("jobs", "../../secrets"),
                "controller_api_identifier_invalid",
            ),
            (
                "query-in-name",
                lambda: client.request("jobs", "name?namespace=ml-control"),
                "controller_api_identifier_invalid",
            ),
            (
                "patch",
                lambda: client.request("jobs", method="PATCH", value={}),
                "controller_api_method_invalid",
            ),
            (
                "empty-post",
                lambda: client.request("jobs", method="POST"),
                "controller_api_method_invalid",
            ),
            ("get-body", lambda: client.request("pods", value={}), "controller_api_method_invalid"),
            (
                "delete-collection",
                lambda: client.request("jobs", method="DELETE"),
                "controller_api_name_invalid",
            ),
            (
                "post-named",
                lambda: client.request("jobs", "worker", method="POST", value={}),
                "controller_api_name_invalid",
            ),
            ("logs-unnamed", lambda: client.request("logs"), "controller_api_log_request_invalid"),
            (
                "wrong-selector",
                lambda: client.request("jobs", job="worker-name"),
                "controller_api_selector_invalid",
            ),
            (
                "request-size",
                lambda: client.request("configmaps", method="POST", value={"data": "x" * MAX_JSON}),
                "controller_api_request_limit",
            ),
        ):
            rejected(name, action, reason)
    with patch.object(Client, "exchange", return_value=b"{}") as exchange:
        client.request("pods", job="controller-worker-test")
        confirmed(
            "fixed-namespace-and-encoded-selector",
            exchange.call_args.args[1]
            == "/api/v1/namespaces/ml-train/pods?labelSelector=job-name%3Dcontroller-worker-test",
        )
        client.request(
            "jobs",
            "controller-worker-test",
            method="DELETE",
            value={"preconditions": {"uid": "owned"}},
        )
        confirmed(
            "delete-uid-preserved",
            exchange.call_args.args[2] == canonical({"preconditions": {"uid": "owned"}}),
        )

    class Response:
        def __init__(self, status, content):
            self.status = status
            self.content = content
            self.offset = 0

        def read1(self, limit):
            content = self.content[self.offset : self.offset + limit]
            self.offset += len(content)
            return content

    with tempfile.TemporaryDirectory(dir=state) as temporary:
        directory = Path(temporary)
        shutil.copyfile(Path(state) / "kubernetes-storage/storage-pki/ca.crt", directory / "ca.crt")
        atomic_write(directory / "token", b"header.payload.signature")
        client = Client("publisher", directory)

        def connection(response):
            return SimpleNamespace(
                request=Mock(), getresponse=Mock(return_value=response), close=Mock(), sock=None
            )

        for name, status, content, reason in (
            ("redirect", 302, b"", "controller_api_status:302:Unexpected"),
            ("forbidden", 403, b'{"reason":"Forbidden"}', "controller_api_status:403:Forbidden"),
            (
                "untrusted-error-text",
                503,
                b'{"reason":"secret-content-must-not-be-forwarded"}',
                "controller_api_status:503:Unexpected",
            ),
            ("oversized-response", 200, b"x" * (MAX_JSON + 1), "controller_api_response_limit"),
            ("duplicate-json", 200, b'{"kind":1,"kind":2}', "invalid_json"),
            ("invalid-json", 200, b"not-json", "invalid_json"),
        ):
            transport = connection(Response(status, content))
            with patch(
                "mlsecops.controller_api.http.client.HTTPSConnection", return_value=transport
            ):
                rejected(name, lambda: client.request("pods"), reason)
            confirmed(f"{name}:closed", transport.close.call_count == 1)
        transport = connection(Response(200, b'{"kind":"PodList","items":[]}'))
        with patch(
            "mlsecops.controller_api.http.client.HTTPSConnection", return_value=transport
        ) as constructor:
            confirmed("json-roundtrip", client.request("pods") == {"kind": "PodList", "items": []})
            context = constructor.call_args.kwargs["context"]
            confirmed(
                "fixed-host-verified-tls13",
                constructor.call_args.args == (HOST, 443)
                and context.check_hostname
                and context.verify_mode == ssl.CERT_REQUIRED
                and context.minimum_version == ssl.TLSVersion.TLSv1_3,
            )
            atomic_write(directory / "token", b"rotated.payload.signature")
            transport.getresponse.return_value = Response(200, b"{}")
            client.request("pods")
            confirmed(
                "token-reread",
                transport.request.call_args.kwargs["headers"]["Authorization"]
                == "Bearer rotated.payload.signature",
            )
        for name, error, reason in (
            ("tls-failure", ssl.SSLError("fixture"), "controller_api_tls_failure"),
            ("socket-timeout", TimeoutError("fixture"), "controller_api_transport_failure"),
        ):
            transport = connection(None)
            transport.getresponse.side_effect = error
            with patch(
                "mlsecops.controller_api.http.client.HTTPSConnection", return_value=transport
            ):
                rejected(name, lambda: client.request("pods"), reason)
            confirmed(f"{name}:closed", transport.close.call_count == 1)
        transport = connection(Response(200, b"{}"))
        with (
            patch("mlsecops.controller_api.http.client.HTTPSConnection", return_value=transport),
            patch("mlsecops.controller_api.time.monotonic", side_effect=[0, 31]),
        ):
            rejected(
                "body-deadline", lambda: client.request("pods"), "controller_api_body_deadline"
            )
        for name, token in (
            ("malformed-token", b"bad\r\nheader"),
            ("oversized-token", b"a" * 16385),
        ):
            atomic_write(directory / "token", token)
            rejected(name, lambda: client.request("pods"), "controller_api_token_invalid")
    return cases
