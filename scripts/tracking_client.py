import base64
import re
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode, urlsplit

from mlsecops.contracts import Rejected, canonical, decode, digest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise Rejected("tracking_redirect_denied")


class Client:
    def __init__(self, endpoint, ca, role=None, password=None):
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in ("127.0.0.1", "localhost")
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise Rejected("tracking_endpoint_not_local_https")
        self.endpoint = endpoint
        self.authorization = (
            base64.b64encode(f"{role}:{password}".encode()).decode() if role else None
        )
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
            NoRedirect(),
        )

    def request(self, method, path, value=None, *, content=None, expected=200):
        if not path.startswith("/api/") or path.startswith("//") or "#" in path or ".." in path:
            raise Rejected("tracking_api_path_invalid")
        headers = {"Content-Type": "application/json"}
        if self.authorization:
            headers["Authorization"] = "Basic " + self.authorization
        if value is not None:
            content = canonical(value)
        if content is not None and len(content) > 65536:
            raise Rejected("tracking_request_too_large")
        request = urllib.request.Request(
            self.endpoint + path, data=content, method=method, headers=headers
        )
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(1024 * 1024 + 1)
            if response.status != expected or len(body) > 1024 * 1024:
                raise Rejected(
                    f"tracking_response_invalid:expected-{expected}:actual-{response.status}"
                )
            return body


def configure_access(client, credentials, experiment_name):
    for role in ("publisher", "reader", "foreign"):
        try:
            client.request("GET", "/api/2.0/mlflow/users/get?" + urlencode({"username": role}))
        except Rejected:
            client.request(
                "POST",
                "/api/2.0/mlflow/users/create",
                {"username": role, "password": credentials[role]},
            )
    experiment = decode(
        client.request("POST", "/api/2.0/mlflow/experiments/create", {"name": experiment_name})
    )["experiment_id"]
    for role, permission in (("publisher", "EDIT"), ("reader", "READ")):
        client.request(
            "POST",
            "/api/3.0/mlflow/users/permissions/grant",
            {
                "username": role,
                "resource_type": "experiment",
                "resource_id": experiment,
                "permission": permission,
            },
        )
    return experiment


def publish(client, experiment, record):
    run = decode(
        client.request(
            "POST",
            "/api/2.0/mlflow/runs/create",
            {
                "experiment_id": experiment,
                "tags": [{"key": "source_run_id", "value": record["source_run_id"]}],
            },
        )
    )["run"]["info"]
    run_id = run["run_id"]
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise Rejected("tracking_returned_run_identity_invalid")
    uri = urlsplit(run["artifact_uri"])
    if (
        uri.scheme != "mlflow-artifacts"
        or uri.netloc
        or ".." in uri.path
        or uri.query
        or uri.fragment
    ):
        raise Rejected("tracking_artifact_origin_invalid")
    client.request(
        "POST",
        "/api/2.0/mlflow/runs/log-batch",
        {
            "run_id": run_id,
            "params": [{"key": key, "value": value} for key, value in record["params"].items()],
            "metrics": [
                {"key": key, "value": value, "timestamp": int(time.time() * 1000), "step": 0}
                for key, value in record["metrics"].items()
            ],
        },
    )
    path = "/api/2.0/mlflow-artifacts/artifacts/" + quote(
        uri.path.lstrip("/") + "/run-materials.json", safe="/"
    )
    client.request("PUT", path, content=canonical(record))
    return {"run_id": run_id, "artifact_path": path, "record_digest": digest(canonical(record))}


def read_back(client, receipt, record):
    observed = decode(
        client.request(
            "GET", "/api/2.0/mlflow/runs/get?" + urlencode({"run_id": receipt["run_id"]})
        )
    )["run"]["data"]
    artifact = client.request("GET", receipt["artifact_path"])
    if (
        {item["key"]: item["value"] for item in observed["params"]} != record["params"]
        or {item["key"]: item["value"] for item in observed["metrics"]} != record["metrics"]
        or artifact != canonical(record)
        or digest(artifact) != receipt["record_digest"]
    ):
        raise Rejected("tracking_read_back_mismatch")
