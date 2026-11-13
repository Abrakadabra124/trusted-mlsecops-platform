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
import traceback
from pathlib import Path

from uvicorn.config import STARTUP_FAILURE

from mlsecops import (
    security_event_delivery,
    security_event_outbox,
    security_event_store,
    security_identity_http,
    serving_http,
)
from mlsecops import (
    security_identity_evidence as evidence,
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


def readback(reader):
    deadline = time.monotonic() + 2
    while True:
        try:
            return reader()
        except Rejected as failure:
            if str(failure) not in (
                "artifact_unavailable",
                "security_store_unavailable",
                "security_store_busy",
            ):
                raise
            if time.monotonic() >= deadline:
                raise Rejected("identity_readback_unavailable") from None
            time.sleep(0.02)


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
        if (
            not identity.closed
            or identity.child is not None
            or identity.pending is not None
            or identity.ticker is not None
        ):
            raise Rejected("identity_fixture_cleanup_unconfirmed")
        print("identity_fixture_cleanup_pass", flush=True)


def qualify():
    hosted()
    root = Path(__file__).resolve().parents[1]
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("identity_source_dirty")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    materials = evidence.method_materials(root)
    cases, durations = [], []
    snapshots, observations, http_exits = {}, [], []

    def check(name, condition):
        if not condition:
            raise Rejected("identity_source_case:" + name)
        cases.append(name)

    with security_event_audit_fixture.live(initial_heartbeat=False) as fx:
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
        collector_config = decode((fx.directory / "collector.json").read_bytes())
        collector_store = security_event_store.Store(
            collector_config["state_directory"], collector_config["state_sha256"], fx.registry
        )
        # Owner-pinned public authority only; config paths, keys and tokens stay in the fixture.
        authority = dict(
            envelope=decode(bounded_read(producer["registry_file"], 65536)),
            root=producer["registry_root"],
            pin=producer["registry_sha256"],
            clock_ms=fx.now(),
        )
        expected = dict(
            source=revision,
            fingerprint=fingerprint,
            method_materials=materials,
            registry_root=authority["root"],
            registry_sha256=authority["pin"],
        )
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
            return readback(
                lambda: security_event_delivery.configured(producer_path).store.snapshot()
            )["records"]

        def snapshot(phase):
            snapshots[phase] = evidence.capture(
                lambda: readback(
                    lambda: security_event_delivery.configured(producer_path).store.snapshot()
                ),
                lambda: readback(collector_store.snapshot),
                fx.now,
            )

        def heartbeat():
            document = readback(
                lambda: security_event_delivery.configured(producer_path).store.snapshot()
            )
            envelope = document["heartbeat"]
            return envelope, fx.registry.heartbeat(envelope, clock_ms=fx.now())

        def collector_heartbeat():
            streams = readback(collector_store.snapshot)["telemetry"]["streams"]
            return next(
                stream["heartbeat"]
                for stream in streams
                if stream["producer_id"] == security_event_outbox.key_identity(key)
            )

        def request(path, credential=None, *, case):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
            headers = {} if credential is None else {"Authorization": "Bearer " + credential}
            body = b"PRIVATE-CANARY" if path == "/v1/predict" else None
            started = time.monotonic()
            started_at_ms = fx.now()
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
                elapsed = time.monotonic() - started
                durations.append(elapsed)
                observations.append(
                    evidence.observation(
                        case,
                        path,
                        response.status,
                        content,
                        started_at_ms=started_at_ms,
                        completed_at_ms=fx.now(),
                        elapsed_seconds=elapsed,
                    )
                )
                return response.status, content
            finally:
                connection.close()

        def closed_port(target=port):
            with socket.socket() as sock:
                sock.settimeout(1)
                return sock.connect_ex(("127.0.0.1", target)) != 0

        def stop(phase="stopped"):
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
            http_exits.append(dict(phase=phase, exit_code=code, port_closed=port_closed))
            process = None

        private_log = fx.directory / "identity-http-private.log"
        with private_log.open("wb") as output:

            def start(*, expect_failure=False, phase="startup"):
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
                    port_closed = closed_port()
                    check("pending-outage-denies-server-startup", code == 1 and port_closed)
                    http_exits.append(
                        dict(phase="failed-startup", exit_code=code, port_closed=port_closed)
                    )
                    process = None
                    return
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise Rejected("identity_http_startup_failed")
                    try:
                        if request("/livez", case=phase)[0] == 200:
                            return
                    except (OSError, http.client.HTTPException):
                        pass
                    time.sleep(0.05)
                raise Rejected("identity_http_startup_deadline")

            try:
                start()
                check("startup-probe-creates-no-denial", records() == [])
                first_envelope, first_heartbeat = heartbeat()
                check(
                    "startup-actual-producer-heartbeat",
                    first_heartbeat["sequence"] == 1
                    and first_heartbeat["last_event_sequence"] == 0
                    and collector_heartbeat()["envelope"] == first_envelope,
                )
                check(
                    "live-producer-allows-fresh-audit-challenge",
                    fx.audit.check("a" * 64)["healthy"] is True,
                )
                snapshot("startup")
                expected_reasons, correlations = [], []
                for path, supplied, reason, case in (
                    ("/v1/predict", None, "credential", "predict-missing"),
                    ("/readyz", "PRIVATE-CANARY", "credential", "ready-invalid"),
                    ("/v1/predict", operator, "role", "predict-role"),
                    ("/metrics", token, "role", "metrics-role"),
                    ("/metrics", None, "credential", "metrics-missing"),
                ):
                    status, content = request(path, supplied, case=case)
                    check("actual-http-identity-denied-after-delivery", status == 401)
                    correlations.append(decode(content)["request_id"])
                    expected_reasons.append(reason)
                before = records()
                check(
                    "valid-metrics-does-not-emit-identity-denial",
                    request("/metrics", operator, case="metrics-authorized")[0] == 200
                    and records() == before,
                )
                outage_process = fx.process
                fx.stop()
                outage_exit_code, outage_port_closed = (
                    outage_process.returncode,
                    closed_port(fx.port),
                )
                status, content = request("/v1/predict", case="outage-denial")
                check(
                    "audit-outage-denies-with-503",
                    status == 503
                    and decode(content)["error"]["code"] == "security_audit_unavailable",
                )
                correlations.append(decode(content)["request_id"])
                expected_reasons.append("credential")
                pending = records()[-1]
                before_restart = heartbeat()[1]
                check(
                    "offline-event-retained-before-child-exit",
                    len(records()) == 6 and pending["receipt"] is None,
                )
                snapshot("outage")
                check(
                    "liveness-and-operator-remain-available",
                    request("/livez", case="outage-live")[0] == 200
                    and request("/metrics", operator, case="outage-metrics")[0] == 200,
                )
                stop("outage")
                start(expect_failure=True)
                check("failed-startup-keeps-original-pending", records()[-1] == pending)
                snapshot("failed-startup")
                fx.start()
                start(phase="recovered")
                check(
                    "startup-probe-delivers-original-event",
                    len(records()) == 6
                    and records()[-1]["envelope"] == pending["envelope"]
                    and records()[-1]["receipt"] is not None,
                )
                after_restart = heartbeat()[1]
                check(
                    "restart-retains-heartbeat-counter-and-complete-head",
                    after_restart["sequence"] > before_restart["sequence"]
                    and after_restart["last_event_sequence"] == 6,
                )
                snapshot("recovered")
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
                first_envelope, first_heartbeat = heartbeat()
                deadline = time.monotonic() + 40
                periodic = first_heartbeat
                while (
                    time.monotonic() < deadline
                    and periodic["sequence"] == first_heartbeat["sequence"]
                ):
                    time.sleep(0.2)
                    try:
                        _, periodic = heartbeat()
                    except Rejected as failure:
                        if str(failure) not in (
                            "security_store_unavailable",
                            "security_store_busy",
                        ):
                            raise
                heartbeat_interval = (
                    periodic["observed_at_ms"] - first_heartbeat["observed_at_ms"]
                ) / 1000
                check(
                    "actual-thirty-second-owned-scheduler",
                    periodic["sequence"] == first_heartbeat["sequence"] + 1
                    and 30 <= heartbeat_interval <= 40,
                )
                # Producer persists before send; wait for independent collector
                # readback, never mistake the allocated counter for delivery.
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        received = collector_heartbeat()
                        if (
                            fx.registry.heartbeat(
                                received["envelope"], clock_ms=received["ingested_at_ms"]
                            )["sequence"]
                            == first_heartbeat["sequence"] + 1
                        ):
                            break
                    except Rejected as failure:
                        if str(failure) not in (
                            "security_store_unavailable",
                            "security_store_busy",
                        ):
                            raise
                    time.sleep(0.05)
                check(
                    "periodic-heartbeat-reached-collector",
                    collector_heartbeat()["envelope"] == heartbeat()[0],
                )
                snapshot("periodic")
            except Exception as failure:
                reason = str(failure)
                safe_reason = (
                    reason
                    if isinstance(failure, Rejected)
                    and reason.startswith(("identity_source_case:", "identity_http_"))
                    else "identity_native_rejected"
                )
                log = bounded_read(private_log, 65536)
                sites = [
                    frame.lineno
                    for frame in traceback.extract_tb(failure.__traceback__)
                    if Path(frame.filename).resolve() == Path(__file__).resolve()
                ]
                print(
                    canonical(
                        dict(
                            identity_failure=safe_reason,
                            failure_type=type(failure).__name__,
                            fixture_lines=sites[-4:],
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
        last_envelope, last_heartbeat = heartbeat()
        gap_began = time.monotonic() - (fx.now() - last_heartbeat["observed_at_ms"]) / 1000
        notice = None
        while time.monotonic() - gap_began <= 120:
            offset = 0
            incidents = []
            while offset is not None:
                status, page = fx.exchange("GET", "/incidents/" + str(offset))
                if status != 200:
                    raise Rejected("identity_source_case:incident_readback_unavailable")
                incidents.extend(page["incidents"])
                for record in page["incidents"]:
                    event = fx.registry.verify(
                        record["envelope"], clock_ms=record["ingested_at_ms"]
                    )
                    if (
                        event.document()["kind"] == "telemetry.gap"
                        and event.document()["reason"] == "heartbeat"
                    ):
                        fx.registry.receipt(record["receipt"], event)
                        notice = record
                offset = page["next_offset"]
            if notice is not None:
                break
            time.sleep(0.5)
        stopped_notice_seconds = time.monotonic() - gap_began
        gap_observed_at_ms = fx.now()
        check(
            "actual-stopped-producer-gap-within-120s",
            notice is not None and 90 <= stopped_notice_seconds <= 120,
        )
        health_status = fx.exchange("GET", "/health")[0]
        check(
            "stopped-owner-cannot-keep-sending-heartbeats",
            heartbeat()[0] == last_envelope and health_status == 503,
        )
        try:
            fx.audit.check("a" * 64)
        except Rejected:
            check("missing-producer-denies-fresh-promotion-audit", True)
        else:
            raise Rejected("identity_source_case:missing_producer_allowed_audit")
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
        # Stop the final collector before taking the immutable terminal snapshots;
        # fixture files still exist here. The context manager deletes them on exit.
        collector_process = fx.process
        fx.stop()
        collector_exit_code, collector_port_closed = (
            collector_process.returncode,
            closed_port(fx.port),
        )
        snapshot("stopped")
        authority["clock_ms"] = snapshots["stopped"]["captured_at_ms"]
        delivery = dict(
            registry=authority,
            outboxes=[snapshots["stopped"]["outbox"]],
            collector=snapshots["stopped"]["collector"],
            incidents=incidents,
        )
        cleanup = dict(
            http_exits=http_exits,
            child_cleanup_markers=log.count(b"identity_fixture_cleanup_pass"),
            collector_exit_code=collector_exit_code,
            collector_port_closed=collector_port_closed,
            outage_exit_code=outage_exit_code,
            outage_port_closed=outage_port_closed,
            http_owner_reaped=process is None,
            collector_owner_reaped=fx.process is None,
            captured_at_ms=snapshots["stopped"]["captured_at_ms"],
        )
    check("collector-and-private-files-cleaned", fx.process is None and not fx.directory.exists())
    cleanup.update(fixture_removed=not fx.directory.exists(), confirmed_at_ms=fx.now())
    check(
        "source-unchanged",
        source_fingerprint(root) == fingerprint
        and evidence.method_materials(root) == materials
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    summary = dict(
        status="pass",
        source=revision,
        fingerprint=fingerprint,
        cases=cases,
        max_http_seconds=max(durations),
        heartbeat_interval_seconds=heartbeat_interval,
        stopped_producer_notice_seconds=stopped_notice_seconds,
        release_ready=False,
        scope="actual-http-and-identity-child-with-controlled-unready-engine-not-M13-M14-M23",
    )
    packet = dict(
        schema_version=1,
        source=revision,
        fingerprint=fingerprint,
        method=evidence.SCOPE,
        method_materials=materials,
        service_sha256=service,
        delivery=delivery,
        snapshots=snapshots,
        http=observations,
        cleanup=cleanup,
        summary=summary,
        gap=dict(
            observed_at_ms=gap_observed_at_ms,
            elapsed_seconds=stopped_notice_seconds,
            health_status=health_status,
        ),
    )
    return evidence.retain(root, packet, expected=expected)


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
