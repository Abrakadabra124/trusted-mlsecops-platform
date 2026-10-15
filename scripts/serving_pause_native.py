import math
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from psycopg.pq import TransactionStatus

from mlsecops import storage, storage_bootstrap
from mlsecops.contracts import Rejected, canonical, require_fields, write_json
from mlsecops.inventory import command
from scripts.serving_outage_native import number, response_valid


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
        self.observed = None
        self.stop_observer = threading.Event()

    def observe(self):
        while not self.stop_observer.wait(0.005):
            try:
                if self.active():
                    self.observed = {"wall": time.time(), "monotonic": time.monotonic()}
                    return
            except Exception:
                return

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
    observer = threading.Thread(target=probe.observe, daemon=True)
    try:
        observer.start()
        with patch.object(storage, "connect", probe.connect):
            yield probe
    finally:
        probe.stop_observer.set()
        if observer.ident is not None:
            observer.join(timeout=1)
        probe.restore(state)
        if observer.is_alive():
            raise Rejected("pause_observer_shutdown_unconfirmed")


def active_before_denial(observed, started, finished):
    return (
        isinstance(observed, dict)
        and set(observed) == {"wall", "monotonic"}
        and all(type(value) in (int, float) and math.isfinite(value) for value in observed.values())
        and started <= observed["monotonic"] <= finished
    )


def expiry_window(anchor, expires_at, receipt, started):
    require_fields(
        anchor, ("version", "document_sha256", "sequence", "wall", "monotonic", "deadline")
    )
    require_fields(receipt, ("version", "document_sha256", "reused"))
    storage.object_id(receipt["document_sha256"])
    for field in ("wall", "monotonic", "deadline"):
        number(anchor[field])
    number(started)
    if (
        type(expires_at) is not int
        or type(receipt["version"]) is not int
        or receipt["version"] < 1
        or receipt["reused"] is not False
        or any(anchor[field] != receipt[field] for field in ("version", "document_sha256"))
    ):
        raise Rejected("pause_expiry_policy_binding")
    expiry_monotonic = anchor["monotonic"] + expires_at - anchor["wall"]
    if (
        started < anchor["monotonic"]
        or not 0.5 < anchor["deadline"] - started <= 8
        or not anchor["deadline"] <= expiry_monotonic <= started + 10
    ):
        raise Rejected("pause_expiry_window")
    return expiry_monotonic


def exercise(
    engine,
    request,
    body,
    *,
    authority,
    port,
    client,
    expected,
    output,
    confirmed,
    expiry_receipt=None,
    renew=None,
):
    if expiry_receipt is not None and not callable(renew):
        raise Rejected("pause_expiry_renewal_required")
    near_expiry = expiry_receipt is not None
    if near_expiry:
        confirm = confirmed

        def confirmed(name, condition):
            confirm("near-expiry-" + name, condition)

    trace = {
        "schema_version": 1,
        "status": "inconclusive",
        "release_ready": False,
        "profile": "signed-policy-expiry" if near_expiry else "request-deadline",
    }
    if near_expiry:
        trace["expected_trust"] = expiry_receipt
    write_json(output, trace)
    try:
        identity = {key: engine.identity()[key] for key in ("model_sha256", "bundle_sha256")}
        old_worker = engine.worker.container
        status, result = request("/v1/predict", body)
        confirmed(
            "paused-query-baseline-golden",
            response_valid(status, result, identity, expected) and status == 200,
        )
        if near_expiry:
            with engine.reader.trust.lock:
                anchor = engine.reader.trust.observation()
                expires_at = engine.reader.trust.payload["expires_at"]
        else:
            anchor = engine.reader.trust.observation()
        trace["last_verified"] = anchor
        with injection(authority, port, client) as probe:
            original = engine.predict
            with patch.object(
                engine, "predict", lambda *args, **kwargs: probe.run(original, *args, **kwargs)
            ):
                started_wall, started = time.time(), time.monotonic()
                if near_expiry:
                    expiry_monotonic = expiry_window(anchor, expires_at, expiry_receipt, started)
                    trace.update(
                        policy_expires_at=expires_at,
                        policy_expiry_monotonic=expiry_monotonic,
                        expected_trust=expiry_receipt,
                        approval_deadline=engine.admission.deadline,
                    )
                    confirmed(
                        "short-policy-limits-before-approval",
                        engine.admission.deadline > expiry_monotonic,
                    )
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
                "active_observed": probe.observed,
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
                and active_before_denial(trace["denial"]["active_observed"], started, finished)
                and not probe.finished.is_set()
                and engine.generation.is_set()
                and finished - started <= 10.25
                and finished < anchor["deadline"]
                and finished - anchor["monotonic"] <= 60,
            )
            confirmed("paused-query-fenced-readiness", request("/readyz")[0] == 503)
            if near_expiry:
                confirmed("client-denial-before-signed-expiry", finished_wall < expires_at)
                remaining = max(0, expiry_monotonic + 0.05 - time.monotonic())
                if remaining > 10:
                    raise Rejected("pause_expiry_wait_bound")
                time.sleep(remaining)
                started_wall, started = time.time(), time.monotonic()
                status, result = request("/v1/predict", body)
                trace["post_expiry"] = {
                    "started_wall": started_wall,
                    "started_monotonic": started,
                    "finished_wall": time.time(),
                    "finished_monotonic": time.monotonic(),
                    "http_status": status,
                    "response_valid": response_valid(status, result, identity, expected),
                    "query_active": probe.active(),
                    "query_finished": probe.finished.is_set(),
                }
                confirmed(
                    "paused-query-post-expiry-denial",
                    status == 503
                    and trace["post_expiry"]["response_valid"]
                    and started_wall >= expires_at
                    and started >= expiry_monotonic
                    and trace["post_expiry"]["query_active"] is True
                    and not probe.finished.is_set(),
                )
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
        if near_expiry:
            renewed = renew()
            require_fields(renewed, ("version", "document_sha256", "reused"))
            storage.object_id(renewed["document_sha256"])
            if (
                type(renewed["version"]) is not int
                or renewed["version"] != expiry_receipt["version"] + 1
                or renewed["document_sha256"] == expiry_receipt["document_sha256"]
                or renewed["reused"] is not False
            ):
                raise Rejected("pause_expiry_renewal_unconfirmed")
            trace["renewal_receipt"] = renewed
            confirmed(
                "renewed-trust-still-requires-activation", request("/v1/predict", body)[0] == 503
            )
        engine.activate()
        status, result = request("/v1/predict", body)
        restored = engine.reader.trust.observation()
        confirmed(
            "paused-query-explicit-fresh-recovery",
            status == 200
            and response_valid(status, result, identity, expected)
            and restored["sequence"] > anchor["sequence"]
            and (
                not near_expiry
                or (
                    all(
                        restored[field] == renewed[field]
                        for field in ("version", "document_sha256")
                    )
                    and restored["monotonic"] > expiry_monotonic
                )
            )
            and engine.worker.container != old_worker,
        )
        trace.update(status="pass", recovery_verified=restored)
    finally:
        write_json(output, trace)
        key = "http_expiring_query" if near_expiry else "http_paused_query"
        print(canonical({key: trace}).decode(), flush=True)
    return trace
