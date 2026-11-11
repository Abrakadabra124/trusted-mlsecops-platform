"""Real HTTP -> owned child -> durable identity events on hosted Linux.

The engine is deliberately unready: this qualifies auth/audit, not inference.
"""

import argparse
import http.client
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from uvicorn.config import STARTUP_FAILURE

from mlsecops import (
    security_event_delivery,
    security_event_outbox,
    security_identity_http,
    serving_http,
)
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, require_fields
from mlsecops.inventory import command, source_fingerprint
from mlsecops.process_privacy import enforce
from scripts import security_event_audit_fixture


def hosted():
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("identity_source_hosted_required")


class UnreadyEngine:
    def activate(self):
        raise Rejected("controlled_unready_engine")

    def response_budget(self):
        raise Rejected("controlled_unready_engine")

    def close(self):
        pass


def serve(path, port):
    hosted()
    enforce()
    config = decode(bounded_read(path, 16384), 16384)
    require_fields(config, ("identity_file", "token_file", "operator_file"))
    identity = security_identity_http.configured(config["identity_file"])
    app = serving_http.create_app(
        UnreadyEngine(),
        bounded_read(config["token_file"], 64).decode(),
        metrics_token=bounded_read(config["operator_file"], 64).decode(),
        identity_audit=identity,
    )
    try:
        try:
            serving_http.run_server(
                app,
                host="127.0.0.1",
                port=port,
                access_log=False,
                proxy_headers=False,
                server_header=False,
                log_level="warning",
                timeout_keep_alive=1,
                limit_concurrency=16,
            )
        except KeyboardInterrupt:
            # Uvicorn reraises SIGINT after lifespan shutdown. The fixture
            # still verifies lifecycle status and child cleanup below.
            pass
        except SystemExit as failure:
            if failure.code != STARTUP_FAILURE:
                raise
            raise Rejected("identity_fixture_startup_failed") from None
        if app.lifecycle_failed:
            raise Rejected("identity_fixture_lifecycle_failed")
    finally:
        if not identity.closed or identity.child is not None or identity.pending is not None:
            raise Rejected("identity_fixture_cleanup_unconfirmed")
        print("identity_fixture_cleanup_pass", flush=True)


def qualify():
    hosted()
    root = Path(__file__).resolve().parents[1]
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("identity_source_dirty")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    cases, durations = [], []

    def check(name, condition):
        if not condition:
            raise Rejected("identity_source_case:" + name)
        cases.append(name)

    with security_event_audit_fixture.live() as fx:
        producer = decode(fx.audit_config.read_bytes())
        key = fx.fx.keys["serving"]
        producer.update(
            schema_version=1,
            producer_key_file=str(key),
            state_directory=str(fx.directory / "serving-outbox"),
        )
        producer["state_sha256"] = security_event_outbox.initialize(
            producer["state_directory"],
            fx.registry,
            security_event_outbox.key_identity(key),
            clock_ms=fx.now(),
        )
        fx.write("identity-producer.json", canonical(producer))
        producer_path = str(fx.directory / "identity-producer.json")
        service = digest(b"controlled-unready-http-service-for-identity-audit")
        fx.write(
            "identity-source.json",
            canonical(
                dict(schema_version=1, producer_config=producer_path, service_sha256=service)
            ),
        )
        token, operator = secrets.token_hex(32), secrets.token_hex(32)
        fx.write("service.token", token.encode())
        fx.write("metrics.token", operator.encode())
        fx.write(
            "http-fixture.json",
            canonical(
                dict(
                    identity_file=str(fx.directory / "identity-source.json"),
                    token_file=str(fx.directory / "service.token"),
                    operator_file=str(fx.directory / "metrics.token"),
                )
            ),
        )
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = None

        def records():
            return security_event_delivery.configured(producer_path).store.snapshot()["records"]

        def request(path, credential=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
            headers = {} if credential is None else {"Authorization": "Bearer " + credential}
            body = b"PRIVATE-CANARY" if path == "/v1/predict" else None
            started = time.monotonic()
            try:
                connection.request(
                    "POST" if body is not None else "GET", path, body=body, headers=headers
                )
                response = connection.getresponse()
                content = response.read(65537)
                check(
                    "bounded-private-http-output",
                    len(content) <= 65536
                    and b"PRIVATE-CANARY" not in content
                    and token.encode() not in content
                    and operator.encode() not in content,
                )
                durations.append(time.monotonic() - started)
                return response.status, content
            finally:
                connection.close()

        def closed_port():
            with socket.socket() as sock:
                sock.settimeout(1)
                return sock.connect_ex(("127.0.0.1", port)) != 0

        def stop():
            nonlocal process
            if process is None:
                return
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            try:
                code = process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise Rejected("identity_http_graceful_cleanup_failed") from None
            port_closed = closed_port()
            if code != 0 or not port_closed:
                print(canonical(dict(identity_http_exit=code, port_closed=port_closed)).decode())
            check("owned-http-exit-and-port-closed", code == 0 and port_closed)
            process = None

        private_log = fx.directory / "identity-http-private.log"
        with private_log.open("wb") as output:

            def start(*, expect_failure=False):
                nonlocal process
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-W",
                        "error",
                        "-m",
                        "scripts.security_identity_events_native",
                        "--serve",
                        "--config",
                        str(fx.directory / "http-fixture.json"),
                        "--port",
                        str(port),
                    ],
                    cwd=root,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    env={**os.environ, "PYTHONUTF8": "1"},
                )
                if expect_failure:
                    code = process.wait(timeout=12)
                    check("pending-outage-denies-server-startup", code == 1 and closed_port())
                    process = None
                    return
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise Rejected("identity_http_startup_failed")
                    try:
                        if request("/livez")[0] == 200:
                            return
                    except (OSError, http.client.HTTPException):
                        pass
                    time.sleep(0.05)
                raise Rejected("identity_http_startup_deadline")

            try:
                start()
                check("startup-probe-creates-no-denial", records() == [])
                expected_reasons, correlations = [], []
                for path, supplied, reason in (
                    ("/v1/predict", None, "credential"),
                    ("/readyz", "PRIVATE-CANARY", "credential"),
                    ("/v1/predict", operator, "role"),
                    ("/metrics", token, "role"),
                    ("/metrics", None, "credential"),
                ):
                    status, content = request(path, supplied)
                    check("actual-http-identity-denied-after-delivery", status == 401)
                    correlations.append(decode(content)["request_id"])
                    expected_reasons.append(reason)
                before = records()
                check(
                    "valid-metrics-does-not-emit-identity-denial",
                    request("/metrics", operator)[0] == 200 and records() == before,
                )
                fx.stop()
                status, content = request("/v1/predict")
                check(
                    "audit-outage-denies-with-503",
                    status == 503
                    and decode(content)["error"]["code"] == "security_audit_unavailable",
                )
                correlations.append(decode(content)["request_id"])
                expected_reasons.append("credential")
                pending = records()[-1]
                check(
                    "offline-event-retained-before-child-exit",
                    len(records()) == 6 and pending["receipt"] is None,
                )
                check(
                    "liveness-and-operator-remain-available",
                    request("/livez")[0] == 200 and request("/metrics", operator)[0] == 200,
                )
                stop()
                start(expect_failure=True)
                check("failed-startup-keeps-original-pending", records()[-1] == pending)
                fx.start()
                start()
                check(
                    "startup-probe-delivers-original-event",
                    len(records()) == 6
                    and records()[-1]["envelope"] == pending["envelope"]
                    and records()[-1]["receipt"] is not None,
                )
                check(
                    "operator-retry-is-idempotent",
                    security_event_delivery.configured(producer_path).retry() == 0,
                )
                for index, record in enumerate(records()):
                    event = fx.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
                    fx.registry.receipt(record["receipt"], event)
                    value = event.document()
                    check(
                        "signed-identity-subject-and-route-" + str(index + 1),
                        value["kind"] == "identity.denied"
                        and value["reason"] == expected_reasons[index]
                        and value["correlation_id"] == correlations[index]
                        and value["asset_sha256"] == service
                        and value["bundle_sha256"] is None
                        and event.route == "security.identity",
                    )
                check(
                    "credentials-and-input-absent-from-outbox",
                    b"PRIVATE-CANARY" not in canonical(records())
                    and token.encode() not in canonical(records())
                    and operator.encode() not in canonical(records()),
                )
            except Exception as failure:
                reason = str(failure)
                safe_reason = (
                    reason
                    if isinstance(failure, Rejected)
                    and reason.startswith(("identity_source_case:", "identity_http_"))
                    else "identity_native_rejected"
                )
                log = bounded_read(private_log, 65536)
                print(
                    canonical(
                        dict(
                            identity_failure=safe_reason,
                            completed_assertions=len(cases),
                            cleanup_markers=log.count(b"identity_fixture_cleanup_pass"),
                            startup_rejected=b"Application startup failed" in log,
                            lifecycle_rejected=b"identity_fixture_lifecycle_failed" in log,
                            cleanup_rejected=b"identity_fixture_cleanup_unconfirmed" in log,
                        )
                    ).decode()
                )
                raise
            finally:
                stop()
        log = bounded_read(private_log, 65536)
        check(
            "all-three-server-lifecycles-reaped-their-children",
            log.count(b"identity_fixture_cleanup_pass") == 3,
        )
        check(
            "no-credentials-in-private-server-log",
            token.encode() not in log
            and operator.encode() not in log
            and b"PRIVATE-CANARY" not in log,
        )
    check("collector-and-private-files-cleaned", fx.process is None and not fx.directory.exists())
    check(
        "source-unchanged",
        source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return dict(
        status="pass",
        source=revision,
        fingerprint=fingerprint,
        cases=cases,
        max_http_seconds=max(durations),
        release_ready=False,
        scope="actual-http-and-identity-child-with-controlled-unready-engine-not-M13-M14-M23",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--config")
    parser.add_argument("--port", type=int)
    arguments = parser.parse_args()
    try:
        if arguments.serve:
            serve(arguments.config, arguments.port)
        else:
            print(canonical(qualify()).decode())
    except Exception as failure:
        reason = str(failure)
        if (
            arguments.serve
            or not isinstance(failure, Rejected)
            or not reason.startswith(
                (
                    "identity_source_case:",
                    "identity_http_",
                    "identity_source_dirty",
                    "identity_source_hosted",
                )
            )
        ):
            reason = "identity_native_rejected"
        print(reason, file=sys.stderr)
        raise SystemExit(1) from None
