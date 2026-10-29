"""Native integration of the ordinary serving CLI, with synthetic inputs only."""

import copy
import http.client
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mlsecops import kube_serving_runtime
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, read_json, write_json
from mlsecops.controller_api import APIError, Client
from mlsecops.controller_worker import remove
from mlsecops.datasets import FEATURES
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce


def qualify(config, expected):
    client = Client("serving")
    cases = []

    def check(label, condition):
        if not condition:
            raise Rejected("kube_serving_probe:" + label)
        cases.append(label)

    check("initial-worker-absence", not client.request("pods")["items"])
    # Real admission must reject altered commands, credentials and privilege.
    for field in ("command", "credential", "privilege"):
        document = kube_serving_runtime.document(config["kubernetes_worker"], secrets.token_hex(16))
        spec = document["spec"]["template"]["spec"]
        if field == "command":
            spec["containers"][0]["command"] = ["python", "-c", "pass"]
        elif field == "credential":
            spec["volumes"].append({"name": "api", "secret": {"secretName": "private"}})
        else:
            spec["containers"][0]["securityContext"]["privileged"] = True
        try:
            created = client.request("jobs", method="POST", value=document)
        except APIError as error:
            check("admission-denies-" + field, error.status in {403, 422})
        else:
            remove(client, "jobs", document["metadata"]["name"], created["metadata"]["uid"])
            check("admission-denies-" + field, False)
    for resource in ("secrets", "serviceaccounts"):
        try:
            client.exchange("GET", f"/api/v1/namespaces/ml-serve/{resource}", None, 1024)
        except APIError as error:
            check("RBAC-denies-" + resource, error.status == 403)
        else:
            check("RBAC-denies-" + resource, False)

    with tempfile.TemporaryDirectory(prefix="serving-probe-", dir="/tmp") as temporary:
        directory = Path(temporary)
        token = secrets.token_hex(32)
        token_path = directory / "token"
        token_path.write_text(token, encoding="ascii")
        token_path.chmod(0o600)
        config = copy.deepcopy(config)
        config.update(token_file=str(token_path), audit_directory=str(directory / "audit"))
        config_path = directory / "config.json"
        write_json(config_path, config)
        output = directory / "service-output"
        with output.open("wb") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "mlsecops.serving_http", "--config", str(config_path)],
                stdout=log,
                stderr=log,
                start_new_session=True,
            )

        def request(path, body=None, authorized=True):
            connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=12)
            try:
                connection.request(
                    "POST" if body is not None else "GET",
                    path,
                    body=body,
                    headers={"Authorization": "Bearer " + token} if authorized else {},
                )
                response = connection.getresponse()
                return response.status, decode(response.read(65537), 65536)
            finally:
                connection.close()

        max_error = None
        try:
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    check("service-process-alive", False)
                try:
                    if request("/livez")[0] == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.25)
            else:
                check("startup-deadline", False)
            body = canonical(
                {
                    "schema_version": 1,
                    "instances": [
                        dict(zip(FEATURES, row, strict=True)) for row in expected["features"]
                    ],
                }
            )
            ready = request("/readyz")
            if expected["ready"]:
                check(
                    "ordinary-CLI-ready-after-verified-load",
                    ready[0] == 200 and ready[1]["ready"] is True,
                )
                pods = client.request("pods")["items"]
                check("one-persistent-worker", len(pods) == 1)
                worker = pods[0]
                replies = [request("/v1/predict", body) for _ in range(3)]
                check("three-HTTP-predictions", all(code == 200 for code, _ in replies))
                for _, reply in replies:
                    check(
                        "response-model-and-bundle-binding",
                        reply["model_sha256"] == expected["model"]
                        and reply["bundle_sha256"] == expected["bundle"],
                    )
                max_error = max(
                    abs(row["score"] - score)
                    for _, reply in replies
                    for row, score in zip(reply["predictions"], expected["scores"], strict=True)
                )
                check("ONNX-golden-parity", max_error <= 1e-6)
                check(
                    "same-worker-UID-across-requests",
                    client.request("pods")["items"][0]["metadata"]["uid"]
                    == worker["metadata"]["uid"],
                )
                check("unauthenticated-401", request("/v1/predict", body, False)[0] == 401)
                check("malformed-422", request("/v1/predict", b"{}")[0] == 422)
                check("oversized-413", request("/v1/predict", b"x" * 65537)[0] == 413)
                owner = worker["metadata"]["ownerReferences"][0]
                remove(client, "jobs", worker["metadata"]["labels"]["job-name"], owner["uid"])
                deadline = time.monotonic() + 15
                while client.request("pods")["items"] and time.monotonic() < deadline:
                    time.sleep(0.25)
                check("stopped-worker-503", request("/v1/predict", body)[0] == 503)
            else:
                check("unapproved-or-revoked-ready-503", ready[0] == 503)
                check("unapproved-or-revoked-predict-503", request("/v1/predict", body)[0] == 503)
                check("refused-before-worker-start", not client.request("pods")["items"])
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
                raise Rejected("kube_serving_shutdown_deadline") from None
        check("ordinary-CLI-clean-shutdown", process.returncode == 0)
        check("worker-cleanup-confirmed", not client.request("pods")["items"])
        check("service-output-empty", bounded_read(output, 65536) == b"")
        check("audit-journal-created", (directory / "audit").is_dir())
    return {"status": "pass", "cases": cases, "max_golden_error": max_error, "release_ready": False}


def main():
    try:
        enforce()
        parser = Arguments(prog="kubernetes-serving-probe")
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path, required=True)
        options = parser.parse_args()
        report = qualify(read_json(options.config), read_json(options.request))
        print(canonical(report).decode())
        return 0
    except Exception as error:
        reason = (
            str(error)
            if isinstance(error, Rejected) and str(error).startswith("kube_serving_probe:")
            else "kubernetes_serving_probe_rejected"
        )
        print(reason, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
