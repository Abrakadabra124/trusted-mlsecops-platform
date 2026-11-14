"""One bounded T19 traffic stage on two caller-owned loopback listeners."""

import re
import time

from mlsecops import load_measurement
from mlsecops.contracts import Rejected, digest
from mlsecops.load_golden import Golden

STAGES = (0, 10, 50, 100)
MAX_REQUESTS = 1000
DIGEST = re.compile(r"[0-9a-f]{64}")


def _check_endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 2:
        raise Rejected("canary_endpoint")
    port, token = endpoint
    if (
        type(port) is not int
        or not 1 <= port <= 65535
        or type(token) is not str
        or not DIGEST.fullmatch(token)
    ):
        raise Rejected("canary_endpoint")


def _prediction(golden, reply, tokens):
    # Golden enforces the complete serving contract, including score tolerance.
    # For a binding mismatch, preserve only a well-formed observed prediction.
    if type(reply) is not dict:
        return "mismatch", None
    model, bundle = reply.get("model_sha256"), reply.get("bundle_sha256")
    if model in tokens or bundle in tokens:
        return "mismatch", None
    matches = golden.valid(reply)
    if not matches:
        predictions = reply.get("predictions")
        if (
            type(predictions) is not list
            or len(predictions) != 1
            or type(predictions[0]) is not dict
        ):
            return "mismatch", None
        try:
            observed = Golden(golden.body, model, bundle, predictions[0].get("score"))
        except (Rejected, OverflowError):
            return "mismatch", None
        if not observed.valid(reply):
            return "mismatch", None
    return "ok" if matches else "mismatch", {
        "model_sha256": model,
        "bundle_sha256": bundle,
        "risk_score": reply["predictions"][0]["score"],
        "request_id": reply["request_id"],
    }


async def run_stage(percent, *, stable, candidate, stable_golden, candidate_golden, requests=100):
    """Send one stage and return observations for an independent rollout evaluator.

    The caller supplies verified Goldens and owned (port, token) tuples and drives
    STAGES in order. One closed-loop client sends exactly one request per index.
    Row times are absolute monotonic nanoseconds on the sender host. Status zero
    denotes an exchange that returned no decoded HTTP response.
    """
    if (
        type(percent) is not int
        or percent not in STAGES
        or type(requests) is not int
        or not 100 <= requests <= MAX_REQUESTS
        or requests % 10
    ):
        raise Rejected("canary_stage")
    _check_endpoint(stable)
    _check_endpoint(candidate)
    if (
        stable[0] == candidate[0]
        or type(stable_golden) is not Golden
        or type(candidate_golden) is not Golden
        or stable_golden.body != candidate_golden.body
        or stable_golden.bundle == candidate_golden.bundle
    ):
        raise Rejected("canary_targets")

    rows = []
    tokens = (stable[1], candidate[1])
    for index in range(requests):
        # The cumulative candidate count after n requests is floor(n * percent / 100).
        if (index + 1) * percent // 100 > index * percent // 100:
            target, endpoint, golden = "candidate", candidate, candidate_golden
        else:
            target, endpoint, golden = "stable", stable, stable_golden
        projected = None
        start = time.monotonic_ns()
        try:
            status, reply = await load_measurement.request(*endpoint, golden.body)
        except TimeoutError:
            status, outcome = 0, "timeout"
        except Exception:
            status, outcome = 0, "transport"
        end = time.monotonic_ns()
        if status == 200:
            outcome, projected = _prediction(golden, reply, tokens)
        elif status:
            outcome = "http_error"
        rows.append(
            dict(
                index=index,
                target=target,
                start_ns=start,
                end_ns=end,
                status=status,
                outcome=outcome,
                response=projected,
            )
        )
    return dict(
        schema_version=1,
        candidate_percent=percent,
        payload_sha256=digest(stable_golden.body),
        rows=rows,
    )
