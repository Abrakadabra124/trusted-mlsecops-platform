"""Drive synthetic traffic on two already-authorized targets, stopping on the first hold."""

from pathlib import Path
from uuid import uuid4

from mlsecops import canary_evaluation, canary_probe
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    safe_child,
    write_json,
)

MAX_BYTES = 4 * 1024 * 1024


def replay(path, expected_sha256, *, stable_golden, candidate_golden):
    raw = bounded_read(path, MAX_BYTES)
    if digest(raw) != expected_sha256:
        raise Rejected("canary_capture_changed")
    stages = decode(raw, MAX_BYTES)
    result = canary_evaluation.evaluate(
        stages, stable_golden=stable_golden, candidate_golden=candidate_golden
    )
    if result["decision"] == "advance":
        raise Rejected("canary_capture_incomplete")
    return result


async def run(state, *, stable, candidate, stable_golden, candidate_golden, requests=200):
    """Endpoints belong to the caller. This probe neither promotes nor revokes a release."""
    reference = dict(stable_golden=stable_golden, candidate_golden=candidate_golden)
    campaign = uuid4().hex
    directory = safe_child(Path(state), "evidence/canary-" + campaign)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    stages = []
    for percent in canary_probe.STAGES:
        stages.append(
            await canary_probe.run_stage(
                percent, stable=stable, candidate=candidate, requests=requests, **reference
            )
        )
        result = canary_evaluation.evaluate(stages, **reference)
        if result["decision"] == "hold":
            break
    path = directory / "traffic.json"
    # The owner pins observations before the readback, including write_json's trailing LF.
    pin = digest(canonical(stages) + b"\n")
    write_json(path, stages)
    verified = replay(path, pin, **reference)
    if verified != result:
        raise Rejected("canary_replay_changed")
    return dict(
        schema_version=1,
        scope="two-endpoint-synthetic-traffic",
        campaign=campaign,
        primary_sha256=pin,
        stable=stable_golden.binding(),
        candidate=candidate_golden.binding(),
        release_ready=False,
        **verified,
    )
