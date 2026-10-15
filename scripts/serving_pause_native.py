import threading
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from psycopg.pq import TransactionStatus

from mlsecops import storage, storage_bootstrap
from mlsecops.contracts import Rejected, canonical, write_json
from mlsecops.inventory import command
from scripts.serving_outage_native import response_valid


class PausedQuery:
    def __init__(self, client, owned, state=None):
        self.client, self.owned = Path(client).resolve(), owned
        self.state = state
        self.original = storage.connect
        self.local = threading.local()
        self.entered, self.finished = threading.Event(), threading.Event()
        self.attempted = False
        self.guard = threading.Lock()
        self.closed = False
        self.connection = None

    def active(self):
        return (
            self.connection is not None
            and self.connection.info.transaction_status == TransactionStatus.ACTIVE
        )

    def run(self, operation, *arguments, **keywords):
        self.local.selected = True
        try:
            return operation(*arguments, **keywords)
        finally:
            self.local.selected = False

    def execute(self, *arguments, **keywords):
        self.entered.set()
        try:
            return self.connection.execute(*arguments, **keywords)
        finally:
            self.finished.set()

    @contextmanager
    def connect(self, client):
        selected = (
            Path(client).resolve() == self.client
            and getattr(self.local, "selected", False)
            and not self.attempted
        )
        try:
            with self.original(client) as connection:
                if selected:
                    with self.guard:
                        if self.closed:
                            raise Rejected("pause_injection_closed")
                        if storage_bootstrap.validate(self.state) != self.owned:
                            raise Rejected("pause_authority_identity_changed")
                        self.attempted = True
                        command(["docker", "pause", self.owned["container_id"]], timeout=10)
                        if (
                            command(
                                [
                                    "docker",
                                    "inspect",
                                    "--format",
                                    "{{.State.Paused}}",
                                    self.owned["container_id"],
                                ]
                            )
                            != "true"
                        ):
                            raise Rejected("pause_authority_not_paused")
                        self.connection = connection
                yield self if selected else connection
        finally:
            if selected:
                self.finished.set()

    def restore(self, state):
        with self.guard:
            self.closed = True
            if not self.attempted:
                return
            if storage_bootstrap.validate(state) != self.owned:
                raise Rejected("pause_authority_identity_changed")
            command(["docker", "unpause", self.owned["container_id"]], timeout=10)
            if (
                command(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Paused}}",
                        self.owned["container_id"],
                    ]
                )
                != "false"
            ):
                raise Rejected("pause_authority_recovery_unconfirmed")


@contextmanager
def injection(state, port, client):
    owned = storage_bootstrap.validate(state)
    if owned.get("port") != port:
        raise Rejected("pause_authority_port_changed")
    probe = PausedQuery(client, owned, state)
    try:
        with patch.object(storage, "connect", probe.connect):
            yield probe
    finally:
        probe.restore(state)


def exercise(engine, request, body, *, authority, port, client, expected, output, confirmed):
    identity = {key: engine.identity()[key] for key in ("model_sha256", "bundle_sha256")}
    old_worker = engine.worker.container
    status, result = request("/v1/predict", body)
    confirmed(
        "paused-query-baseline-golden",
        response_valid(status, result, identity, expected) and status == 200,
    )
    anchor = engine.reader.trust.observation()
    trace = {
        "schema_version": 1,
        "status": "inconclusive",
        "release_ready": False,
        "last_verified": anchor,
    }
    write_json(output, trace)
    try:
        with injection(authority, port, client) as probe:
            original = engine.predict
            with patch.object(
                engine, "predict", lambda *args, **kwargs: probe.run(original, *args, **kwargs)
            ):
                started_wall, started = time.time(), time.monotonic()
                status, result = request("/v1/predict", body)
                finished, finished_wall = time.monotonic(), time.time()
            trace["denial"] = {
                "started_wall": started_wall,
                "finished_wall": finished_wall,
                "started_monotonic": started,
                "finished_monotonic": finished,
                "http_status": status,
                "response_valid": response_valid(status, result, identity, expected),
                "connected_read_entered": probe.entered.is_set(),
                "libpq_query_active_at_denial": probe.active(),
                "read_finished_at_denial": probe.finished.is_set(),
                "generation_fenced": engine.generation.is_set(),
            }
            write_json(output, trace)
            confirmed(
                "paused-established-query-HTTP-denial-before-completion",
                status == 503
                and trace["denial"]["response_valid"]
                and probe.entered.is_set()
                and trace["denial"]["libpq_query_active_at_denial"] is True
                and not probe.finished.is_set()
                and engine.generation.is_set()
                and finished - started <= 10.25
                and finished <= anchor["deadline"]
                and finished - anchor["monotonic"] <= 60,
            )
            confirmed("paused-query-fenced-readiness", request("/readyz")[0] == 503)
        if not probe.finished.wait(15) or not engine.lock.acquire(timeout=15):
            raise Rejected("pause_read_completion_unconfirmed")
        engine.lock.release()
        engine.drain()
        confirmed(
            "paused-query-owned-worker-cleaned",
            engine.worker is None
            and not command(
                ["docker", "container", "ls", "--all", "--quiet", "--filter", f"id={old_worker}"]
            ),
        )
        confirmed("late-trust-read-cannot-reactivate", request("/v1/predict", body)[0] == 503)
        engine.activate()
        status, result = request("/v1/predict", body)
        restored = engine.reader.trust.observation()
        confirmed(
            "paused-query-explicit-fresh-recovery",
            status == 200
            and response_valid(status, result, identity, expected)
            and restored["sequence"] > anchor["sequence"]
            and engine.worker.container != old_worker,
        )
        trace.update(status="pass", recovery_verified=restored)
    finally:
        write_json(output, trace)
        print(canonical({"http_paused_query": trace}).decode(), flush=True)
    return trace
