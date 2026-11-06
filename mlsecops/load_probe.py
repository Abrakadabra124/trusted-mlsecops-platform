"""Disposable M14 candidate benchmark, never an approved-release entrypoint."""

import asyncio
import secrets
import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import uvicorn

from mlsecops import load_diagnostics, load_measurement, serving, serving_http
from mlsecops.contracts import Rejected, canonical, digest, read_json
from mlsecops.controller_api import Client
from mlsecops.kube_candidate_probe import candidate
from mlsecops.kube_serving_runtime import Worker
from mlsecops.load_exchange import DIRECTORY, send
from mlsecops.load_golden import Golden
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce
from mlsecops.serving_access import Access

PHASE = "startup"


def credentials():
    return {
        "schema_version": 1,
        "clients": [
            {
                "principal_id": secrets.token_hex(16),
                "token": secrets.token_hex(32),
                "requests_per_second": 20,
                "burst": 40,
                "max_in_flight": 4,
            }
            for _ in range(10)
        ],
    }


@contextmanager
def listen(app):
    listener = socket.socket()
    server = thread = None
    started = False
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                lifespan="on",
                access_log=False,
                log_config=None,
                log_level="critical",
                proxy_headers=False,
                server_header=False,
                timeout_keep_alive=1,
            )
        )
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        started = True
        deadline = time.monotonic() + 100
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= deadline:
                raise Rejected("load_server_startup")
            time.sleep(0.05)
        yield port
    finally:
        if server is not None:
            server.should_exit = True
        if started:
            thread.join(timeout=60)
        listener.close()
        if started and thread.is_alive():
            raise Rejected("load_server_shutdown")


async def exercise(port, tokens, golden):
    limited = load_diagnostics.reasons()
    phase = "normal"

    async def request(index):
        status, body = await load_measurement.request(port, tokens[index % 10], golden.body)
        if status == 429:
            limited[phase][load_diagnostics.reason(body)] += 1
        return status, body

    observation = await load_measurement.collect(request, golden.valid)
    # A separate bounded burst; never included in normal-load percentiles.
    phase = "overload"
    started = time.monotonic_ns()
    replies = await asyncio.gather(*(request(i) for i in range(40)), return_exceptions=True)
    elapsed = time.monotonic_ns() - started
    correct = denials = errors = 0
    for value in replies:
        if isinstance(value, tuple) and value[0] == 200 and golden.valid(value[1]):
            correct += 1
        elif isinstance(value, tuple) and value[0] == 429:
            denials += 1
        else:
            errors += 1
    await asyncio.sleep(2)
    phase = "recovery"
    try:
        status, response = await request(0)
        recovered = status == 200 and golden.valid(response)
    except Exception:
        recovered = False
    overload = {
        "attempts": 40,
        "correct": correct,
        "limited": denials,
        "errors": errors,
        "elapsed_ns": elapsed,
        "recovered": recovered,
        "profile_met": denials > 0 and errors == 0 and recovered and elapsed <= 3_000_000_000,
    }
    return observation, overload, limited


def qualify(config, expected):
    global PHASE
    DIRECTORY.mkdir(mode=0o700)
    golden = Golden.from_expected(expected)
    client = Client("serving")
    if client.request("pods")["items"]:
        raise Rejected("load_initial_worker_present")
    clients = credentials()
    tokens = [row["token"] for row in clients["clients"]]
    engine = serving.Engine(
        candidate(config),
        worker_factory=lambda model, image: Worker(model, image, config["kubernetes_worker"]),
    )
    try:
        PHASE = "activate"
        (DIRECTORY / "audit").mkdir(mode=0o700)
        app = serving_http.create_app(
            engine,
            clients=Access(clients),
            audit_path=DIRECTORY / "audit",
            startup_diagnostics=True,
        )
        with listen(app) as port:
            identity = engine.check()
            if (
                identity
                != {"ready": True, "model_sha256": golden.model, "bundle_sha256": golden.bundle}
                or engine.loaded.permit_sha256 != config["expected_permit"]
                or engine.loaded.release_ready is not False
            ):
                raise Rejected("load_candidate_binding")
            status, response = asyncio.run(load_measurement.request(port, tokens[0], golden.body))
            if status != 200 or not golden.valid(response):
                raise Rejected("load_initial_prediction")
            worker = engine.worker
            PHASE = "start"
            send(
                DIRECTORY,
                "start",
                config["expected_campaign"],
                {
                    "session": worker.binding["session_id"],
                    "job": worker.name,
                    "job_uid": worker.job_uid,
                    "pod_uid": worker.pod_uid,
                    "golden": golden.binding(),
                },
            )
            PHASE = "measure"
            timings = load_diagnostics.Timings()
            with timings.instrument(engine):
                observation, overload, limited = asyncio.run(exercise(port, tokens, golden))
            diagnostics = load_diagnostics.result(timings, limited)
            summary = load_measurement.summarize(
                **{key: observation[key] for key in ("records", "elapsed_ns", "exhausted")}
            )
            PHASE = "finish"
            receipt = send(
                DIRECTORY,
                "finish",
                config["expected_campaign"],
                {
                    "observation": observation,
                    "summary": summary,
                    "overload": overload,
                    "golden": golden.binding(),
                    "diagnostics": diagnostics,
                },
            )
            if receipt.get("summary_sha256") != digest(canonical(summary)) or receipt.get(
                "diagnostics_sha256"
            ) != digest(canonical(diagnostics)):
                raise Rejected("load_operator_summary_changed")
    finally:
        # Also covers failed thread creation before the application's lifespan.
        engine.close()
    PHASE = "cleanup"
    if client.request("pods")["items"]:
        raise Rejected("load_worker_cleanup_unconfirmed")
    return {
        "status": "pass",
        "scope": "actual-candidate-load-observation",
        "release_ready": False,
        "full_M14": "inconclusive",
        "model_sha256": golden.model,
        "subject_sha256": golden.bundle,
        "golden": golden.binding(),
        "measurement": summary,
        "overload": overload,
        "diagnostics": diagnostics,
        "operator": receipt,
        "worker_cleanup_verified": True,
        "profile_met": summary["profile_met"] and overload["profile_met"],
    }


def main():
    try:
        enforce()
        parser = Arguments(prog="candidate-load-probe")
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path, required=True)
        arguments = parser.parse_args()
        print(
            canonical(qualify(read_json(arguments.config), read_json(arguments.request))).decode()
        )
        return 0
    except Exception:
        print(
            canonical(
                {
                    "status": "fail",
                    "release_ready": False,
                    "code": "load_probe_rejected",
                    "phase": PHASE,
                }
            ).decode()
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
