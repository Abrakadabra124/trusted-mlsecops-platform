"""Replay bounded T19 stage observations before changing the candidate traffic share."""

import re

from mlsecops.canary_probe import MAX_REQUESTS, STAGES
from mlsecops.contracts import Rejected, digest, require_fields
from mlsecops.load_golden import Golden
from mlsecops.load_measurement import distribution


def require(condition):
    if not condition:
        raise Rejected("canary_evidence_invalid")


def check_response(row, golden, seen):
    status, outcome, response = row["status"], row["outcome"], row["response"]
    require(type(status) is int)
    if status == 0:
        require(outcome in ("timeout", "transport") and response is None)
        return
    if status != 200:
        require(100 <= status <= 599 and outcome == "http_error" and response is None)
        return
    if response is None:
        require(outcome == "mismatch")
        return
    require_fields(response, ("request_id", "risk_score", "model_sha256", "bundle_sha256"))
    identifier = response["request_id"]
    require(
        type(identifier) is str
        and re.fullmatch("[0-9a-f]{32}", identifier)
        and identifier not in seen
    )
    seen.add(identifier)
    # A projected response is retained only for a structurally valid reply.
    # Recheck its observed subject, model and score against the independent golden.
    observed = Golden(
        golden.body, response["model_sha256"], response["bundle_sha256"], response["risk_score"]
    )
    full = dict(
        schema_version=1,
        request_id=identifier,
        model_sha256=observed.model,
        bundle_sha256=observed.bundle,
        predictions=[dict(decision="score", reason=None, score=observed.score)],
    )
    require(outcome == ("ok" if golden.valid(full) else "mismatch"))


def summarize(stage, percent, goldens, seen, previous_end, baseline):
    require_fields(stage, ("schema_version", "candidate_percent", "payload_sha256", "rows"))
    rows = stage["rows"]
    require(
        type(stage["schema_version"]) is int
        and stage["schema_version"] == 1
        and type(stage["candidate_percent"]) is int
        and stage["candidate_percent"] == percent
        and stage["payload_sha256"] == digest(goldens["stable"].body)
        and type(rows) is list
        and 100 <= len(rows) <= MAX_REQUESTS
        and len(rows) % 10 == 0
    )
    delays, valid_delays = [], []
    mismatches = candidate_attempts = 0
    for index, row in enumerate(rows):
        require_fields(
            row, ("index", "target", "start_ns", "end_ns", "status", "outcome", "response")
        )
        target = "candidate" if (index + 1) * percent // 100 > index * percent // 100 else "stable"
        start, end = row["start_ns"], row["end_ns"]
        require(
            type(row["index"]) is int
            and row["index"] == index
            and row["target"] == target
            and type(start) is int
            and type(end) is int
            and previous_end <= start <= end < 2**63
        )
        check_response(row, goldens[target], seen)
        previous_end = end
        delays.append((end - start) / 1_000_000)
        candidate_attempts += target == "candidate"
        mismatches += row["outcome"] == "mismatch"
        if row["outcome"] == "ok":
            valid_delays.append(delays[-1])
    attempts, valid = len(rows), len(valid_delays)
    errors = attempts - valid
    all_latency, ok_latency = distribution(delays), distribution(valid_delays)
    checks = {
        "valid_observations": valid >= 100,
        "golden_responses": mismatches == 0,
        "latency": all(
            item is not None and item["p95"] <= 200 and item["p99"] <= 500
            for item in (all_latency, ok_latency)
        ),
        # Compare exact fractions, including the boundary at one percentage point.
        "error_delta": baseline is None
        or 100 * (errors * baseline["attempts"] - baseline["errors"] * attempts)
        <= attempts * baseline["attempts"],
    }
    return dict(
        candidate_percent=percent,
        attempts=attempts,
        valid=valid,
        errors=errors,
        candidate_attempts=candidate_attempts,
        p95_ms=all_latency["p95"],
        p99_ms=all_latency["p99"],
        checks=checks,
        passed=all(checks.values()),
    ), previous_end


def evaluate(stages, *, stable_golden, candidate_golden):
    """A failed stage holds traffic. Evidence of advancement after a hold is invalid."""
    require(type(stages) is list and 1 <= len(stages) <= len(STAGES))
    require(
        type(stable_golden) is Golden
        and type(candidate_golden) is Golden
        and stable_golden.body == candidate_golden.body
        and stable_golden.bundle != candidate_golden.bundle
    )
    goldens = dict(stable=stable_golden, candidate=candidate_golden)
    reports, seen = [], set()
    previous_end = 0
    for percent, stage in zip(STAGES, stages, strict=False):
        require(not reports or reports[-1]["passed"])
        baseline = reports[0] if reports else None
        report, previous_end = summarize(stage, percent, goldens, seen, previous_end, baseline)
        reports.append(report)
    decision = "hold"
    if reports[-1]["passed"]:
        decision = "complete" if len(reports) == len(STAGES) else "advance"
    return dict(stages=reports, decision=decision)
