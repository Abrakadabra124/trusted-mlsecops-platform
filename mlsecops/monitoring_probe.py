"""Private M15 campaign using real serving HTTP and signed loopback receipts."""

import asyncio
import dataclasses
import http.client
import secrets
import tempfile
import time
from pathlib import Path

from mlsecops import (
    monitoring_config,
    monitoring_packet,
    monitoring_state,
    security_identity_http,
    serving,
    serving_http,
    signing,
    trust_session,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json, write_json
from mlsecops.controller_api import Client
from mlsecops.datasets import FEATURES
from mlsecops.kube_candidate_probe import candidate
from mlsecops.kube_serving_runtime import Worker
from mlsecops.load_exchange import DIRECTORY, send
from mlsecops.load_probe import listen
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce
from mlsecops.release_policy import checked

FAILURES = frozenset(
    {
        "monitor_probe_http_status",
        "monitor_probe_windows_incomplete",
        "monitor_probe_quality_incomplete",
        "monitor_probe_negative_support_insufficient",
        "monitor_probe_operator_state",
        "monitor_probe_initial_worker",
        "monitor_probe_shutdown_unconfirmed",
        "monitor_probe_worker_cleanup_unconfirmed",
        "monitor_probe_operator_ack",
        "monitor_packet_drift_profile",
        "monitor_packet_quality_profile",
        "monitor_packet_receipt_binding",
        "load_server_lifespan",
        "load_server_startup",
        "serving_cleanup_unconfirmed",
        "audit_shutdown_pending",
        "unknown",
    }
)


def request(port, token, path, document=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request(
            "GET" if document is None else "POST",
            path,
            body=None if document is None else canonical(document),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        content = decode(response.read(262145), 262144)
        if response.status != 200:
            raise Rejected("monitor_probe_http_status")
        return content
    finally:
        connection.close()


def campaign(port, token, operator, runtime, rows, label_key):
    observations = []
    for window in range(12):
        for batch in range(10):
            features = (
                [row["features"] for row in rows[batch * 100 : (batch + 1) * 100]]
                if window < 10
                else [[0.99] * len(FEATURES) for _ in range(100)]
            )
            response = request(
                port,
                token,
                "/v1/predict",
                {
                    "schema_version": 1,
                    "instances": [dict(zip(FEATURES, row, strict=True)) for row in features],
                },
            )
            observations.append({"features": features, "response": response})
            time.sleep(0.055)  # Respect the unchanged20RPS client quota.

    # Read private evidence on its owning loop, never concurrent dictionary access.
    async def capture():
        return decode(
            canonical(
                {
                    "windows": [
                        {"document": closed.document(), "predictions": closed.predictions}
                        for closed, _labels in runtime._windows.values()
                    ],
                    "receipts": list(runtime._receipts),
                    "state": runtime.snapshot(),
                }
            )
        )

    def snapshot():
        return asyncio.run_coroutine_threadsafe(capture(), runtime.task.get_loop()).result(
            timeout=5
        )

    deadline = time.monotonic() + 10
    while True:
        captured = snapshot()
        if (
            captured["state"]["windows_evaluated"] == 12
            and captured["state"]["alerts_delivered"] == 2
        ):
            break
        if time.monotonic() >= deadline or captured["state"]["faults"]:
            raise Rejected("monitor_probe_windows_incomplete")
        time.sleep(0.1)
    selected = captured["windows"][9]
    identifiers = [identifier for identifier, positive in selected["predictions"] if not positive][
        :200
    ]
    if len(identifiers) != 200:
        raise Rejected("monitor_probe_negative_support_insufficient")
    issued = time.time_ns() // 1000000
    envelope = signing.sign(
        {
            "schema_version": 1,
            "reference_sha256": runtime._reference_sha256,
            "window_sha256": digest(canonical(selected["document"])),
            "issued_at_ms": issued,
            "expires_at_ms": issued + 60000,
            "labels": [{"observation_id": key, "label": 1} for key in identifiers],
        },
        "monitor-labels",
        label_key,
    )
    labels = []
    for _ in range(2):
        response = request(port, operator, "/monitoring/labels", envelope)
        labels.append(
            {
                "envelope": envelope,
                "response": response,
                "accepted_at_ms": time.time_ns() // 1000000,
            }
        )
    deadline = time.monotonic() + 10
    while True:
        captured = snapshot()
        if captured["state"]["alerts_delivered"] == 3:
            break
        if time.monotonic() >= deadline or captured["state"]["faults"]:
            raise Rejected("monitor_probe_quality_incomplete")
        time.sleep(0.1)
    status = request(port, operator, "/monitoring")
    if (
        status["release_ready"] is not False
        or status["observations"] != 12000
        or not status["healthy"]
    ):
        raise Rejected("monitor_probe_operator_state")
    return {
        "schema_version": 1,
        "windows": captured["windows"],
        "http": observations,
        "labels": labels,
        "receipts": captured["receipts"],
    }


def qualify(config, expected):
    client = Client("serving")
    if client.request("pods")["items"]:
        raise Rejected("monitor_probe_initial_worker")
    supplied = expected["monitoring"]
    reference = checked(supplied["reference"], "monitor-reference", supplied["reference_public"])
    with tempfile.TemporaryDirectory(prefix="monitor-") as temporary:
        root = Path(temporary)
        producer, sink_key, label_key = (
            root / (name + ".pem") for name in ("producer", "sink", "label")
        )
        producer_public, sink_public, label_public = (
            signing.create_key(path) for path in (producer, sink_key, label_key)
        )
        epoch = config["expected_campaign"]
        reference_sha = digest(canonical(reference))
        state_directory = str(root / "epochs")
        state_sha256 = monitoring_state.initialize(state_directory)
        write_json(root / "reference.json", supplied["reference"])
        write_json(
            root / "sink.json",
            {
                "schema_version": 1,
                "reference_sha256": reference_sha,
                "producer_public": producer_public,
                "receipt_key_file": str(sink_key),
                "port": 8910,
                "epoch": epoch,
                "state_directory": state_directory,
                "state_sha256": state_sha256,
            },
        )
        sink_app, _unused_port = monitoring_config.sink(str(root / "sink.json"))
        session = trust_session.Session()
        try:
            engine = serving.Engine(
                candidate(config, connection_factory=session.connection),
                worker_factory=lambda model, image: Worker(
                    model, image, config["kubernetes_worker"]
                ),
                close_reader=session.close,
            )
        except BaseException:
            session.close()
            raise
        try:
            with listen(sink_app) as sink_port:
                write_json(
                    root / "producer.json",
                    {
                        "schema_version": 1,
                        "reference_file": str(root / "reference.json"),
                        "reference_sha256": reference_sha,
                        "reference_public": supplied["reference_public"],
                        "producer_key_file": str(producer),
                        "sink_public": sink_public,
                        "label_public": label_public,
                        "sink_port": sink_port,
                        "epoch": epoch,
                        "state_directory": state_directory,
                        "state_sha256": state_sha256,
                    },
                )
                runtime = monitoring_config.producer(str(root / "producer.json"))
                token, operator = secrets.token_hex(32), secrets.token_hex(32)
                (root / "audit").mkdir(mode=0o700)
                app = serving_http.create_app(
                    engine,
                    token,
                    metrics_token=operator,
                    monitor=runtime,
                    audit_path=root / "audit",
                    identity_audit=security_identity_http.configured(
                        "/security/identity-audit.json"
                    ),
                )
                with listen(app) as port:
                    packet = campaign(port, token, operator, runtime, supplied["rows"], label_key)
                    summary = monitoring_packet.verify(
                        packet,
                        reference=reference,
                        reference_sha256=reference_sha,
                        context=engine.audit_context,
                        sink_public=sink_public,
                        label_public=label_public,
                        epoch=epoch,
                    )
                    context = dataclasses.asdict(engine.audit_context)
                # The lifecycle has closed monitor and serving worker before retaining the packet.
                if runtime.task is None or not runtime.task.done() or runtime.snapshot()["faults"]:
                    raise Rejected("monitor_probe_shutdown_unconfirmed")
        finally:
            engine.close()
        if client.request("pods")["items"]:
            raise Rejected("monitor_probe_worker_cleanup_unconfirmed")
        DIRECTORY.mkdir(mode=0o700, exist_ok=True)
        acknowledgement = send(
            DIRECTORY,
            "finish",
            epoch,
            {
                "packet": packet,
                "summary": summary,
                "context": context,
                "sink_public": sink_public,
                "label_public": label_public,
            },
        )
        if acknowledgement != {"packet_sha256": summary["packet_sha256"]}:
            raise Rejected("monitor_probe_operator_ack")
    return {
        **summary,
        "scope": "actual-candidate-monitoring-observation",
        "worker_cleanup_verified": True,
        "model_sha256": reference["model_sha256"],
        "subject_sha256": reference["bundle_sha256"],
    }


def location(failure):
    """Only this public module's call site, never exception text or stack locals."""
    line, frame = 0, failure.__traceback__
    while frame is not None:
        if frame.tb_frame.f_code.co_filename == __file__:
            line = frame.tb_lineno
        frame = frame.tb_next
    kind = type(failure).__name__
    return {
        "exception": kind
        if kind in {"Rejected", "KeyError", "TypeError", "ValueError", "OSError", "AttributeError"}
        else "other",
        "source_file": "mlsecops/monitoring_probe.py" if line else "unknown",
        "source_line": line,
    }


def main():
    try:
        enforce()
        parser = Arguments(prog="candidate-monitoring-probe")
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path, required=True)
        options = parser.parse_args()
        print(
            canonical(qualify(read_json(options.config), read_json(options.request))).decode(),
            flush=True,
        )
        return 0
    except Exception as failure:
        cause = (
            str(failure)
            if isinstance(failure, Rejected) and str(failure) in FAILURES
            else "unknown"
        )
        print(
            canonical(
                {
                    "status": "fail",
                    "release_ready": False,
                    "code": "monitor_probe_rejected",
                    "cause": cause,
                    "location": location(failure),
                }
            ).decode(),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
