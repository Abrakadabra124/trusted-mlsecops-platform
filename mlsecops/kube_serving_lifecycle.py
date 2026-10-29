"""Synthetic hosted fault probe around an unmodified ordinary serving process."""

import math
import signal
import socket
import time
from contextlib import ExitStack
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, read_json
from mlsecops.storage_pki import TRUST_HOST

DIRECTORY = Path("/tmp")
FAULTS = {"outage", "blackhole", "policy-change", "revocation", "key-revocation"}
CHECKS = {
    "trust-fault-kind",
    "trust-fault-initial-prediction",
    "trust-fault-response-contract",
    "trust-fault-no-late-ML",
    "trust-fault-first-503-within-60s",
    "trust-fault-complete-trace",
    "trust-fault-readiness-503",
    "no-automatic-reactivation",
    "trust-fault-clock-order",
    "trust-blackhole-TCP-blocked",
    "trust-blackhole-TCP-restored",
}


def tcp_state(address, *, blocked):
    """Require an actual connect timeout; a refused socket is not a blackhole."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            connection = socket.create_connection((address, 5432), timeout=1)
        except TimeoutError:
            if blocked:
                return True
        except OSError:
            pass
        else:
            connection.close()
            if not blocked:
                return True
        time.sleep(0.1)
    return False


def checkpoint(phase, fault):
    marker = {"phase": phase, "fault": fault}
    print(canonical({"event": "trust-fault", **marker}).decode(), flush=True)
    path = DIRECTORY / ("mlsecops-trust-" + phase + ".json")
    deadline = time.monotonic() + 90
    while not path.exists():
        if time.monotonic() >= deadline:
            raise Rejected("kube_serving_lifecycle_coordination_deadline")
        time.sleep(0.1)
    if path.is_symlink() or read_json(path) != marker:
        raise Rejected("kube_serving_lifecycle_coordination_binding")


def valid(status, reply, expected):
    if not isinstance(reply, dict):
        return False
    if status == 503:
        return (
            set(reply) == {"schema_version", "request_id", "error"}
            and reply["schema_version"] == 1
            and reply["error"] == {"code": "model_unavailable"}
        )
    if (
        status != 200
        or reply.get("model_sha256") != expected["model"]
        or reply.get("bundle_sha256") != expected["bundle"]
    ):
        return False
    predictions = reply.get("predictions")
    return (
        isinstance(predictions, list)
        and len(predictions) == len(expected["scores"])
        and all(
            isinstance(row, dict)
            and row.get("decision") == "score"
            and type(row.get("score")) in (int, float)
            and math.isfinite(row["score"])
            and 0 <= row["score"] <= 1
            and abs(row["score"] - score) <= 1e-6
            for row, score in zip(predictions, expected["scores"], strict=True)
        )
    )


def exercise(process, request, body, expected, check, *, pause=None, on_denied=lambda: None):
    fault = expected["fault"]
    check("trust-fault-kind", fault in FAULTS)
    # Resolve before injection; DNS remains outside the targeted drop rule.
    address = socket.gethostbyname(TRUST_HOST) if fault == "blackhole" else None
    # A successful ordinary request performs fresh trust reads. Its start is a
    # lower bound on the final successful read, not an invented exact timestamp.
    anchor_wall, anchor = time.time(), time.monotonic()
    status, reply = request("/v1/predict", body)
    check("trust-fault-initial-prediction", status == 200 and valid(status, reply, expected))
    # Quiesce refresh during fault injection: owned child signal by default,
    # or the actual candidate Engine lock when HTTP runs in this process.
    with ExitStack() as suspended:
        if fault in {"outage", "blackhole"}:
            if pause is None:
                process.send_signal(signal.SIGSTOP)
                suspended.callback(process.send_signal, signal.SIGCONT)
            else:
                suspended.enter_context(pause())
        checkpoint("ready", fault)
        if fault == "blackhole":
            check("trust-blackhole-TCP-blocked", tcp_state(address, blocked=True))
    records, first_denial, successes, denials = [], None, 0, 0
    previous = anchor
    while len(records) < 512 and time.monotonic() < anchor + 65:
        start, wall = time.monotonic(), time.time()
        status, reply = request("/v1/predict", body)
        end, end_wall = time.monotonic(), time.time()
        check(
            "trust-fault-clock-order",
            previous <= start <= end
            and wall <= end_wall
            and abs((end_wall - anchor_wall) - (end - anchor)) <= 2,
        )
        previous = end
        check("trust-fault-response-contract", valid(status, reply, expected))
        records.append(
            {"start_seconds": start - anchor, "end_seconds": end - anchor, "http_status": status}
        )
        if status == 200:
            successes += 1
            check("trust-fault-no-late-ML", first_denial is None and end < anchor + 60)
        else:
            denials += 1
            if first_denial is None:
                first_denial = end - anchor
            check("trust-fault-first-503-within-60s", first_denial <= 60)
        if denials >= 2 and (fault not in {"outage", "blackhole"} or start >= anchor + 60):
            break
        remaining = anchor + 60 - time.monotonic()
        time.sleep(2 if remaining > 2.1 else 0.05)
    check("trust-fault-complete-trace", denials >= 2 and (fault != "outage" or successes > 0))
    check("trust-fault-readiness-503", request("/readyz")[0] == 503)
    on_denied()
    checkpoint("denied", fault)
    if fault == "blackhole":
        check("trust-blackhole-TCP-restored", tcp_state(address, blocked=False))
    # The parent has now restored availability / a fresh compatible policy.
    # A revoked model stays revoked; a fenced generation never silently reloads.
    check(
        "no-automatic-reactivation",
        request("/readyz")[0] == 503
        and all(request("/v1/predict", body)[0] == 503 for _ in range(2)),
    )
    return {
        "fault": fault,
        "first_503_seconds": first_denial,
        "observations": len(records),
        "anchor": "successful-request-start-lower-bound-on-last-trust-read",
        "trace": records,
    }
