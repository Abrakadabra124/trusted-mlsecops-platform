"""Actual candidate HTTP stays observed while the hosted operator faults audit."""

import asyncio
import dataclasses
import secrets
import time
from contextlib import ExitStack
from pathlib import Path

from mlsecops import (
    load_monitoring,
    security_identity_http,
    security_outage_packet,
    serving,
    serving_http,
    trust_session,
)
from mlsecops.contracts import Rejected, canonical, decode, read_json
from mlsecops.controller_api import Client
from mlsecops.datasets import FEATURES
from mlsecops.kube_candidate_probe import candidate
from mlsecops.kube_serving_runtime import Worker
from mlsecops.load_golden import Golden
from mlsecops.load_probe import listen
from mlsecops.monitoring_probe import request
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce
from mlsecops.security_outage_exchange import DIRECTORY, Channel


def capture(runtime):
    async def observed():
        return decode(
            canonical(
                {
                    "state": runtime.snapshot(),
                    "windows": [
                        {"document": closed.document(), "predictions": closed.predictions}
                        for closed, _labels in runtime._windows.values()
                    ],
                }
            )
        )

    operation = observed()
    try:
        future = asyncio.run_coroutine_threadsafe(operation, runtime.task.get_loop())
    except BaseException:
        operation.close()
        raise
    try:
        return future.result(timeout=3)
    except BaseException:
        future.cancel()
        raise


def cycle(port, token, operator, runtime, expected, phase):
    observation_started = time.time_ns() // 1000000
    # One independent golden row and999 frozen validation rows per complete window.
    rows = [expected["features"][0], *[r["features"] for r in expected["monitoring"]["rows"][:999]]]
    if len(rows) != 1000:
        raise Rejected("security_green_validation_rows")
    http = []
    for start in range(0, 1000, 100):
        features = rows[start : start + 100]
        response = request(
            port,
            token,
            "/v1/predict",
            {
                "schema_version": 1,
                "instances": [dict(zip(FEATURES, row, strict=True)) for row in features],
            },
        )
        http.append({"features": features, "response": response})
        time.sleep(0.2)
    deadline = time.monotonic() + 10
    while True:
        captured = capture(runtime)
        state = captured["state"]
        if state["faults"]:
            raise Rejected("security_green_monitor_failed")
        if not state["pending_windows"] and captured["windows"]:
            window = captured["windows"][-1]
            break
        if time.monotonic() >= deadline:
            raise Rejected("security_green_monitor_timeout")
        time.sleep(0.05)
    observed = request(port, operator, "/monitoring")
    return {
        "phase": phase,
        **window,
        "http": http,
        "monitor": {name: observed[name] for name in security_outage_packet.GREEN_FIELDS},
        "observed_at_ms": time.time_ns() // 1000000,
        "observation_started_at_ms": observation_started,
    }


def campaign(port, token, operator, runtime, expected, channel):
    windows = []

    def observe(phase):
        if len(windows) >= 128:
            raise Rejected("security_green_window_capacity")
        windows.append(cycle(port, token, operator, runtime, expected, phase))

    def transition(phase, observation_phase):
        channel.begin(phase, {})
        while True:
            observe(observation_phase)
            result = channel.poll()
            if result is not None:
                return result

    transition("ready", "ready")
    observe("ready")  # A full baseline window after the operator's health check.
    transition("outage", "ready")
    observe("outage")  # Fault is confirmed before this full fresh window.
    transition("attempt", "outage")
    observe("attempt")  # Refusal confirmed; fault is still installed.
    transition("recover", "attempt")
    observe("recover")
    return windows


def qualify(config, expected):
    client = Client("serving")
    if client.request("pods")["items"]:
        raise Rejected("security_green_initial_worker")
    DIRECTORY.mkdir(mode=0o700)
    channel = Channel(DIRECTORY, config["expected_campaign"])
    golden = Golden.from_expected(expected)
    session = trust_session.Session()
    engine = None
    resources = ExitStack()
    try:
        engine = serving.Engine(
            candidate(config, connection_factory=session.connection),
            worker_factory=lambda model, image: Worker(model, image, config["kubernetes_worker"]),
            close_reader=session.close,
        )
        monitor = resources.enter_context(
            load_monitoring.session(
                DIRECTORY / "monitor", expected, config["expected_campaign"], listen
            )
        )
        token, operator = secrets.token_hex(32), secrets.token_hex(32)
        (DIRECTORY / "audit").mkdir(mode=0o700)
        app = serving_http.create_app(
            engine,
            token,
            metrics_token=operator,
            monitor=monitor.runtime,
            audit_path=DIRECTORY / "audit",
            identity_audit=security_identity_http.configured("/security/identity-audit.json"),
        )
        with listen(app) as port:
            if (
                engine.check()
                != {"ready": True, "model_sha256": golden.model, "bundle_sha256": golden.bundle}
                or engine.loaded.permit_sha256 != config["expected_permit"]
                or engine.loaded.release_ready is not False
            ):
                raise Rejected("security_green_candidate_binding")
            trace = engine.audit_context
            packet = {
                "schema_version": 1,
                "campaign": config["expected_campaign"],
                "context": dataclasses.asdict(trace),
                "windows": campaign(port, token, operator, monitor.runtime, expected, channel),
            }
            summary = security_outage_packet.verify(
                packet,
                reference=monitor.reference,
                context=trace,
                golden=golden,
                campaign=config["expected_campaign"],
            )
    finally:
        try:
            resources.close()
        finally:
            if engine is None:
                session.close()
            else:
                engine.close()
    if client.request("pods")["items"]:
        raise Rejected("security_green_worker_cleanup")
    channel.begin("finish", {"packet": packet, "summary": summary})
    while (ack := channel.poll()) is None:
        time.sleep(0.1)
    if ack != {"packet_sha256": summary["packet_sha256"]}:
        raise Rejected("security_green_finish_binding")
    return {**summary, "worker_cleanup_verified": True}


def main():
    try:
        enforce()
        parser = Arguments(prog="candidate-security-outage-probe")
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path, required=True)
        options = parser.parse_args()
        print(canonical(qualify(read_json(options.config), read_json(options.request))).decode())
        return 0
    except Exception:
        print(
            canonical(
                {"status": "fail", "release_ready": False, "code": "security_green_probe_rejected"}
            ).decode()
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
