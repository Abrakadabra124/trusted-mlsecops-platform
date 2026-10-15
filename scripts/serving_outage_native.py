import math
import time
from contextlib import ExitStack, contextmanager

from mlsecops import serving, storage_bootstrap, trust
from mlsecops.contracts import Rejected, canonical, require_fields, write_json
from mlsecops.inventory import command
from mlsecops.storage import object_id
from scripts.serving_native import site


class ObservedLease(trust.Lease):
    def __init__(self, *arguments, **keywords):
        super().__init__(*arguments, **keywords)
        self.observed = None
        self.sequence = 0

    def refresh(self):
        with self.lock:
            result = super().refresh()
            wall, monotonic = self.sample()
            self.sequence += 1
            self.observed = {
                **result,
                "sequence": self.sequence,
                "wall": wall,
                "monotonic": monotonic,
                "deadline": self.deadline,
            }
            return result

    def observation(self):
        with self.lock:
            if self.observed is None:
                raise Rejected("outage_no_verified_read")
            return dict(self.observed)


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise Rejected("outage_invalid_time")
    return value


def assess(anchor, records):
    require_fields(
        anchor, ("version", "document_sha256", "sequence", "wall", "monotonic", "deadline")
    )
    object_id(anchor["document_sha256"])
    for field in ("version", "sequence"):
        if type(anchor[field]) is not int or anchor[field] < 1:
            raise Rejected("outage_invalid_anchor")
    for field in ("wall", "monotonic", "deadline"):
        number(anchor[field])
    if not anchor["monotonic"] < anchor["deadline"] <= anchor["monotonic"] + 60:
        raise Rejected("outage_invalid_anchor")
    if not isinstance(records, list) or not 1 <= len(records) <= 512:
        raise Rejected("outage_trace_bound")
    failures = set()
    first_denial = None
    last_success = None
    previous = anchor["monotonic"]
    post_deadline_denial = False
    denials = 0
    for record in records:
        require_fields(
            record,
            (
                "started_wall",
                "finished_wall",
                "started_monotonic",
                "finished_monotonic",
                "http_status",
                "response_valid",
                "trust_sequence",
                "lease_deadline",
            ),
        )
        for field in (
            "started_wall",
            "finished_wall",
            "started_monotonic",
            "finished_monotonic",
            "lease_deadline",
        ):
            number(record[field])
        start, end = record["started_monotonic"], record["finished_monotonic"]
        if start < previous or end < start or record["finished_wall"] < record["started_wall"]:
            raise Rejected("outage_trace_order")
        if any(
            abs(
                record[phase + "_wall"]
                - anchor["wall"]
                - (record[phase + "_monotonic"] - anchor["monotonic"])
            )
            > 2
            for phase in ("started", "finished")
        ):
            raise Rejected("outage_clock_divergence")
        previous = end
        if (
            type(record["http_status"]) is not int
            or type(record["response_valid"]) is not bool
            or type(record["trust_sequence"]) is not int
        ):
            raise Rejected("outage_trace_types")
        if (
            record["trust_sequence"] != anchor["sequence"]
            or record["lease_deadline"] != anchor["deadline"]
        ):
            failures.add("trust_refreshed_or_lease_changed_during_outage")
        if not record["response_valid"]:
            failures.add("http_response_invalid")
        if record["http_status"] == 200:
            if end >= anchor["deadline"] or first_denial is not None:
                failures.add("ml_response_after_deadline_or_denial")
            last_success = end
        elif record["http_status"] == 503:
            denials += 1
            if first_denial is None:
                first_denial = end
            if start >= anchor["deadline"]:
                post_deadline_denial = True
        else:
            failures.add("unexpected_http_status")
    if last_success is None or denials < 2 or not post_deadline_denial:
        failures.add("missing_outage_phase")
    delay = None if first_denial is None else first_denial - anchor["monotonic"]
    if delay is not None and delay > 60:
        failures.add("first_http_503_exceeds_60_seconds")
    return {
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "fail" if failures else "pass",
        "release_ready": False,
        "observations": len(records),
        "first_503_seconds": delay,
        "last_200_seconds": None if last_success is None else last_success - anchor["monotonic"],
        "failures": sorted(failures),
    }


def response_valid(status, result, identity, expected):
    if not isinstance(result, dict):
        return False
    if status == 503:
        return (
            set(result) == {"schema_version", "request_id", "error"}
            and result["schema_version"] == 1
            and result["error"] == {"code": "model_unavailable"}
        )
    if status != 200 or any(result.get(field) != value for field, value in identity.items()):
        return False
    predictions = result.get("predictions")
    if not isinstance(predictions, list) or len(predictions) != len(expected):
        return False
    return all(
        isinstance(item, dict)
        and item.get("decision") == "score"
        and type(item.get("score")) in (int, float)
        and math.isfinite(item["score"])
        and abs(item["score"] - score) <= 1e-5
        for item, score in zip(predictions, expected, strict=True)
    )


@contextmanager
def stopped_authority(state, port):
    owned = storage_bootstrap.validate(state)
    if owned.get("port") != port:
        raise Rejected("outage_authority_port_changed")
    try:
        command(["docker", "stop", "--time", "1", owned["container_id"]], timeout=15)
        running = command(
            ["docker", "inspect", "--format", "{{.State.Running}}", owned["container_id"]]
        )
        if running != "false":
            raise Rejected("outage_authority_not_stopped")
        yield
    finally:
        if storage_bootstrap.validate(state) != owned:
            raise Rejected("outage_authority_identity_changed")
        command(["docker", "start", owned["container_id"]])
        deadline = time.monotonic() + 30
        while True:
            try:
                if (
                    storage_bootstrap.admin(
                        owned["container_id"], "SELECT 1;", "postgres", timeout=5
                    )
                    == "1"
                ):
                    break
            except Rejected:
                pass
            if time.monotonic() >= deadline:
                raise Rejected("outage_authority_recovery_unconfirmed")
            time.sleep(0.1)
        if storage_bootstrap.validate(state) != owned:
            raise Rejected("outage_authority_identity_changed")


def exercise(
    engine, request, body, *, authority, port, reader_factory, expected, output, confirmed
):
    identity = {key: engine.identity()[key] for key in ("model_sha256", "bundle_sha256")}
    lease = engine.reader.trust
    old_worker = engine.worker.container
    trace = {
        "schema_version": 1,
        "status": "inconclusive",
        "release_ready": False,
        "identity": identity,
        "records": [],
    }
    write_json(output, trace)
    try:
        with stopped_authority_after_read(engine, authority, port) as anchor:
            trace["last_verified"] = anchor
            with site(serving.Engine(reader_factory())) as cold:
                confirmed("trust-outage-cold-start-not-ready", cold("/readyz")[0] == 503)
                confirmed("trust-outage-cold-start-no-ML", cold("/v1/predict", body)[0] == 503)
            deadline = anchor["monotonic"] + 65
            denials = 0
            while len(trace["records"]) < 512 and time.monotonic() < deadline:
                started_wall, started = time.time(), time.monotonic()
                status, result = request("/v1/predict", body)
                ended, finished_wall = time.monotonic(), time.time()
                with lease.lock:
                    observed = lease.observation()
                    current_deadline = lease.deadline
                trace["records"].append(
                    {
                        "started_wall": started_wall,
                        "finished_wall": finished_wall,
                        "started_monotonic": started,
                        "finished_monotonic": ended,
                        "http_status": status,
                        "response_valid": response_valid(status, result, identity, expected),
                        "trust_sequence": observed["sequence"],
                        "lease_deadline": current_deadline,
                    }
                )
                denials += status == 503
                if denials >= 2 and status == 503 and started >= anchor["deadline"]:
                    break
                remaining = anchor["deadline"] - time.monotonic()
                time.sleep(2 if remaining > 2.1 else 0.005)
            trace["assessment"] = assess(anchor, trace["records"])
            write_json(output, trace)
            confirmed("trust-outage-expired-readiness-503", request("/readyz")[0] == 503)
            engine.drain()
            confirmed(
                "trust-outage-owned-worker-cleaned",
                engine.worker is None
                and not command(
                    [
                        "docker",
                        "container",
                        "ls",
                        "--all",
                        "--quiet",
                        "--filter",
                        f"id={old_worker}",
                    ]
                ),
            )
        confirmed("trust-restart-no-implicit-activation", request("/v1/predict", body)[0] == 503)
        engine.activate()
        status, result = request("/v1/predict", body)
        restored = lease.observation()
        confirmed(
            "trust-recovery-fresh-read-and-golden",
            status == 200
            and response_valid(status, result, identity, expected)
            and restored["sequence"] > anchor["sequence"]
            and restored["monotonic"] > anchor["deadline"]
            and engine.worker.container != old_worker,
        )
        trace["recovery_verified"] = restored
        trace["status"] = trace["assessment"]["status"]
    finally:
        write_json(output, trace)
        print(canonical({"http_trust_outage": trace}).decode(), flush=True)
    confirmed("trust-outage-HTTP-deadline-and-no-extension", trace["status"] == "pass")
    return trace


@contextmanager
def stopped_authority_after_read(engine, authority, port):
    with ExitStack() as services:
        with engine.lock:
            previous = engine.reader.trust.observation()
            engine.reader.check(engine.loaded)
            anchor = engine.reader.trust.observation()
            if anchor["sequence"] <= previous["sequence"]:
                raise Rejected("outage_fresh_read_required")
            services.enter_context(stopped_authority(authority, port))
        yield anchor
