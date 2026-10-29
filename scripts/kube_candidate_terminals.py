"""Two irreversible revocations on independent, pre-existing authority states."""

from mlsecops.contracts import Rejected, canonical
from mlsecops.trust_targets import Target
from scripts.kube_authority_pair import capture, isolation, transition
from scripts.kube_candidate_faults import exercise as faults
from scripts.kube_promotion_snapshot import read as snapshot
from scripts.kube_serving_native import invoke


def exercise(state, profile, config, expected, *, base_probe, key, revoked_key, expires_at):
    public, policy = config["permit_public"], config["expected_permit"]
    before = capture(state, public, policy)
    isolation(base_probe, before, Target.PRIMARY)
    if any(
        expected["model"] in row["revoked_artifacts"] or revoked_key in row["revoked_keys"]
        for row in before.values()
    ):
        raise Rejected("candidate_terminal_baseline_revoked")
    journal = snapshot(state)
    alternate = {**config, "trust_target": Target.MODEL_REVOCATION.value}
    model = faults(
        state,
        profile,
        alternate,
        expected,
        key=key,
        policy=policy,
        revoked_key=revoked_key,
        faults=("revocation",),
        expires_at=expires_at,
        target=Target.MODEL_REVOCATION,
    )["revocation"]
    after_model = capture(state, public, policy)
    transition(before, after_model, Target.MODEL_REVOCATION, "revoked_artifacts", expected["model"])
    isolation(model["probe"], before, Target.MODEL_REVOCATION)
    publisher = faults(
        state,
        profile,
        config,
        expected,
        key=key,
        policy=policy,
        revoked_key=revoked_key,
        faults=("key-revocation",),
        expires_at=expires_at,
    )["key-revocation"]
    after_key = capture(state, public, policy)
    transition(after_model, after_key, Target.PRIMARY, "revoked_keys", revoked_key)
    cold = {}
    for target in Target:
        selected = config if target is Target.PRIMARY else alternate
        report = invoke(
            state,
            profile,
            selected,
            {**expected, "cold_only": True},
            candidate_probe=True,
            trust_target=target,
        )
        label = "cold-key-revocation" if target is Target.PRIMARY else "cold-model-revocation"
        cause = "trust_key_revoked" if target is Target.PRIMARY else "trust_artifact_revoked"
        if (
            report.get("status") != "pass"
            or report.get("release_ready") is not False
            or report.get("scope") != "candidate-cold-revocation"
            or report.get("authority_target") != target.value
            or report.get("model_sha256") != expected["model"]
            or report.get("subject_sha256") != expected["bundle"]
            or canonical(report.get("cases"))
            != canonical(
                [
                    {"id": "initial-worker-absence", "status": "pass", "actual": 0, "expected": 0},
                    {"id": label, "status": "pass", "actual": cause, "expected": cause},
                    {"id": "cold-worker-absence", "status": "pass", "actual": 0, "expected": 0},
                ]
            )
        ):
            raise Rejected("candidate_terminal_cold_binding")
        cold[target.value] = report
    if capture(state, public, policy) != after_key or snapshot(state) != journal:
        raise Rejected("candidate_terminal_readback_changed")
    return {
        "model": model,
        "key": publisher,
        "states": {"before": before, "after_model": after_model, "after_key": after_key},
        "cold": cold,
    }
