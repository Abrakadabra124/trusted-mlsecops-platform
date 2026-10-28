import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import mlflow
import requests
from mlflow.server import get_app_client

BASE = "http://127.0.0.1:5000"


class ProbeFailure(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def qualify(records):
    if mlflow.__version__ != "3.17.2" or not isinstance(records, list) or len(records) != 3:
        raise ProbeFailure("tracking_probe_input_or_version_invalid")
    passwords = {
        name: secrets.token_urlsafe(32) for name in ("admin", "publisher", "reader", "foreign")
    }
    cases = []
    session = requests.Session()
    session.trust_env = False

    def request(name, role, method, path, expected=200, **kwargs):
        response = session.request(
            method,
            BASE + path,
            auth=(role, passwords[role]) if role else None,
            timeout=10,
            allow_redirects=False,
            **kwargs,
        )
        if response.status_code != expected:
            raise ProbeFailure(f"{name}:expected-{expected}:actual-{response.status_code}")
        cases.append({"id": name, "status": "pass", "http_status": response.status_code})
        return response

    with tempfile.TemporaryDirectory(prefix="tracking-probe-") as directory:
        state = Path(directory)
        configuration = state / "auth.ini"
        configuration.write_text(
            "[mlflow]\ndefault_permission = NO_PERMISSIONS\n"
            f"database_uri = sqlite:///{state}/auth.db\n"
            "admin_username = admin\n"
            "authorization_function = mlflow.server.auth:authenticate_request_basic_auth\n",
            encoding="utf-8",
        )
        environment = {
            **os.environ,
            "MLFLOW_AUTH_CONFIG_PATH": str(configuration),
            "MLFLOW_AUTH_ADMIN_PASSWORD": passwords["admin"],
            "MLFLOW_FLASK_SERVER_SECRET_KEY": secrets.token_urlsafe(48),
            "MLFLOW_DISABLE_TELEMETRY": "true",
            "MLFLOW_ENABLE_REMOTE_ASSISTANT": "false",
            "MLFLOW_ENABLE_ASSISTANT_SANDBOX": "false",
        }
        arguments = [
            sys.executable,
            "-m",
            "mlflow",
            "server",
            "--app-name",
            "basic-auth",
            "--backend-store-uri",
            f"sqlite:///{state}/metadata.db",
            "--artifacts-destination",
            str(state / "artifacts"),
            "--host",
            "127.0.0.1",
            "--port",
            "5000",
            "--workers",
            "1",
            "--allowed-hosts",
            "127.0.0.1:5000",
        ]
        with (state / "server.log").open("wb") as log:

            def start():
                process = subprocess.Popen(
                    arguments,
                    env=environment,
                    stdout=log,
                    stderr=log,
                    start_new_session=True,
                )
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        if session.get(BASE + "/health", timeout=1).status_code == 200:
                            return process
                    except requests.RequestException:
                        pass
                    time.sleep(0.25)
                stop(process)
                raise ProbeFailure("tracking_server_not_ready")

            process = start()
            try:
                os.environ["MLFLOW_TRACKING_USERNAME"] = "admin"
                os.environ["MLFLOW_TRACKING_PASSWORD"] = passwords["admin"]
                auth = get_app_client("basic-auth", tracking_uri=BASE)
                for name in ("publisher", "reader", "foreign"):
                    auth.create_user(username=name, password=passwords[name])
                experiment = request(
                    "admin-create-experiment",
                    "admin",
                    "POST",
                    "/api/2.0/mlflow/experiments/create",
                    json={"name": "synthetic-release-risk"},
                ).json()["experiment_id"]
                for role, permission in (("publisher", "EDIT"), ("reader", "READ")):
                    auth.grant_user_permission(role, "experiment", experiment, permission)
                request(
                    "anonymous-experiment-denied",
                    None,
                    "GET",
                    "/api/2.0/mlflow/experiments/get",
                    401,
                    params={"experiment_id": experiment},
                )
                request(
                    "foreign-experiment-denied",
                    "foreign",
                    "GET",
                    "/api/2.0/mlflow/experiments/get",
                    403,
                    params={"experiment_id": experiment},
                )
                request(
                    "reader-create-run-denied",
                    "reader",
                    "POST",
                    "/api/2.0/mlflow/runs/create",
                    403,
                    json={"experiment_id": experiment},
                )
                tracked = []
                for index, record in enumerate(records):
                    run = request(
                        f"publisher-create-run-{index}",
                        "publisher",
                        "POST",
                        "/api/2.0/mlflow/runs/create",
                        json={
                            "experiment_id": experiment,
                            "tags": [{"key": "source_run_id", "value": record["source_run_id"]}],
                        },
                    ).json()["run"]
                    run_id = run["info"]["run_id"]
                    request(
                        f"publisher-log-materials-{index}",
                        "publisher",
                        "POST",
                        "/api/2.0/mlflow/runs/log-batch",
                        json={
                            "run_id": run_id,
                            "params": [
                                {"key": key, "value": value}
                                for key, value in record["params"].items()
                            ],
                            "metrics": [
                                {
                                    "key": key,
                                    "value": value,
                                    "timestamp": int(time.time() * 1000),
                                    "step": 0,
                                }
                                for key, value in record["metrics"].items()
                            ],
                        },
                    )
                    uri = urlsplit(run["info"]["artifact_uri"])
                    if uri.scheme != "mlflow-artifacts" or uri.netloc or ".." in uri.path:
                        raise ProbeFailure("tracking_artifact_origin_invalid")
                    path = "/api/2.0/mlflow-artifacts/artifacts/" + quote(
                        uri.path.lstrip("/") + "/run-materials.json", safe="/"
                    )
                    content = canonical(record)
                    request(f"publisher-upload-{index}", "publisher", "PUT", path, data=content)
                    downloaded = request(f"reader-artifact-{index}", "reader", "GET", path).content
                    if downloaded != content:
                        raise ProbeFailure("tracking_artifact_content_changed")
                    for role, expected in ((None, 401), ("foreign", 403)):
                        request(f"artifact-denied-{role}-{index}", role, "GET", path, expected)
                        request(
                            f"artifact-write-denied-{role}-{index}",
                            role,
                            "PUT",
                            path,
                            expected,
                            data=b"tamper",
                        )
                    request(
                        f"reader-write-denied-{index}", "reader", "PUT", path, 403, data=b"tamper"
                    )
                    request(
                        f"foreign-run-denied-{index}",
                        "foreign",
                        "GET",
                        "/api/2.0/mlflow/runs/get",
                        403,
                        params={"run_id": run_id},
                    )
                    request(
                        f"reader-log-denied-{index}",
                        "reader",
                        "POST",
                        "/api/2.0/mlflow/runs/log-batch",
                        403,
                        json={
                            "run_id": run_id,
                            "params": [{"key": "input_digest", "value": "tamper"}],
                        },
                    )
                    request(
                        f"publisher-input-overwrite-denied-{index}",
                        "publisher",
                        "POST",
                        "/api/2.0/mlflow/runs/log-parameter",
                        400,
                        json={"run_id": run_id, "key": "input_digest", "value": "tamper"},
                    )
                    request(
                        f"publisher-delete-denied-{index}",
                        "publisher",
                        "POST",
                        "/api/2.0/mlflow/runs/delete",
                        403,
                        json={"run_id": run_id},
                    )
                    tracked.append((run_id, path, content, record))
                if len({entry[0] for entry in tracked}) != 3:
                    raise ProbeFailure("tracking_runs_reused")
                request(
                    "publisher-self-admin-denied",
                    "publisher",
                    "PATCH",
                    "/api/2.0/mlflow/users/update-admin",
                    403,
                    json={"username": "publisher", "is_admin": True},
                )
                stop(process)
                process = start()
                for index, (run_id, path, content, record) in enumerate(tracked):
                    observed = request(
                        f"restart-run-{index}",
                        "reader",
                        "GET",
                        "/api/2.0/mlflow/runs/get",
                        params={"run_id": run_id},
                    ).json()["run"]["data"]
                    if (
                        {item["key"]: item["value"] for item in observed["params"]}
                        != record["params"]
                        or {item["key"]: item["value"] for item in observed["metrics"]}
                        != record["metrics"]
                        or request(f"restart-artifact-{index}", "reader", "GET", path).content
                        != content
                    ):
                        raise ProbeFailure("tracking_restart_binding_changed")
                    request(f"restart-foreign-denied-{index}", "foreign", "GET", path, 403)
                return {
                    "status": "pass",
                    "release_ready": False,
                    "scope": "mlflow-offline-auth-sqlite-spike-not-T08-M06",
                    "version": mlflow.__version__,
                    "checks": len(cases),
                    "cases": cases,
                    "tracking_run_ids": [entry[0] for entry in tracked],
                    "record_digests": [hashlib.sha256(entry[2]).hexdigest() for entry in tracked],
                }
            finally:
                stop(process)
                session.close()


if __name__ == "__main__":
    try:
        content = sys.stdin.buffer.read(65537)
        if len(content) > 65536:
            raise ProbeFailure("tracking_input_limit")
        print(canonical(qualify(json.loads(content))).decode())
    except Exception as error:
        print(
            canonical(
                {
                    "status": "fail",
                    "release_ready": False,
                    "reason": str(error)
                    if isinstance(error, ProbeFailure)
                    else type(error).__name__,
                }
            ).decode()
        )
        raise SystemExit(2)
