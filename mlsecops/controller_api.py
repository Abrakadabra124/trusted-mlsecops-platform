import http.client
import re
import ssl
import time
from pathlib import Path
from urllib.parse import urlencode

from mlsecops.contracts import Rejected, canonical, decode

HOST = "kubernetes.default.svc"
TARGETS = {"publisher": ("ml-train", "trainer"), "scorer": ("ml-eval", "evaluator")}
MAX_JSON = 1024 * 1024
MAX_LOG = 16 * 1024 * 1024


class APIError(Rejected):
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason
        super().__init__(f"controller_api_status:{status}:{reason}")


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]", value):
        raise Rejected("controller_api_identifier_invalid")
    return value


class Client:
    def __init__(self, role, credentials=Path("/api")):
        if not isinstance(role, str) or role not in TARGETS:
            raise Rejected("controller_api_role_invalid")
        self.namespace = TARGETS[role][0]
        self.credentials = Path(credentials)

    def request(self, resource, name=None, method="GET", value=None, job=None):
        if resource not in {"jobs", "configmaps", "pods", "logs"}:
            raise Rejected("controller_api_resource_invalid")
        allowed = {"GET"} if resource in {"pods", "logs"} else {"GET", "POST", "DELETE"}
        if (
            method not in allowed
            or (method == "POST" and value is None)
            or (method == "GET" and value is not None)
        ):
            raise Rejected("controller_api_method_invalid")
        if (method == "POST" and name is not None) or (method == "DELETE" and name is None):
            raise Rejected("controller_api_name_invalid")
        prefix = "/apis/batch/v1" if resource == "jobs" else "/api/v1"
        collection = "pods" if resource == "logs" else resource
        path = f"{prefix}/namespaces/{self.namespace}/{collection}"
        if name is not None:
            path += "/" + identifier(name)
        if resource == "logs":
            if name is None or job is not None:
                raise Rejected("controller_api_log_request_invalid")
            path += "/log?" + urlencode({"container": "worker", "limitBytes": MAX_LOG + 1})
        elif job is not None:
            if resource != "pods" or name is not None:
                raise Rejected("controller_api_selector_invalid")
            path += "?" + urlencode({"labelSelector": f"job-name={identifier(job)}"})
        content = canonical(value) if value is not None else None
        if content is not None and len(content) > MAX_JSON:
            raise Rejected("controller_api_request_limit")
        limit = MAX_LOG if resource == "logs" else MAX_JSON
        output = self.exchange(method, path, content, limit)
        return output if resource == "logs" else decode(output, limit)

    def exchange(self, method, path, content, limit):
        try:
            with (self.credentials / "token").open("rb") as source:
                token = source.read(16385).strip()
            if len(token) > 16384 or not re.fullmatch(
                rb"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token
            ):
                raise Rejected("controller_api_token_invalid")
            context = ssl.create_default_context(cafile=str(self.credentials / "ca.crt"))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            connection = http.client.HTTPSConnection(HOST, 443, timeout=20, context=context)
            try:
                connection.request(
                    method,
                    path,
                    body=content,
                    headers={
                        "Authorization": "Bearer " + token.decode("ascii"),
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                response = connection.getresponse()
                output = bytearray()
                deadline = time.monotonic() + 30
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Rejected("controller_api_body_deadline")
                    if connection.sock is not None:
                        connection.sock.settimeout(min(20, remaining))
                    chunk = response.read1(min(65536, limit + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > limit:
                        raise Rejected("controller_api_response_limit")
                expected = {"GET": {200}, "POST": {201}, "DELETE": {200, 202}}[method]
                if response.status not in expected:
                    reason = "Unexpected"
                    try:
                        document = decode(output, limit)
                        if isinstance(document, dict) and document.get("reason") in {
                            "Forbidden",
                            "Unauthorized",
                            "NotFound",
                            "AlreadyExists",
                            "Invalid",
                        }:
                            reason = document["reason"]
                    except Rejected:
                        pass
                    raise APIError(response.status, reason)
                return bytes(output)
            finally:
                connection.close()
        except ssl.SSLError as error:
            raise Rejected("controller_api_tls_failure") from error
        except (OSError, http.client.HTTPException) as error:
            raise Rejected("controller_api_transport_failure") from error
