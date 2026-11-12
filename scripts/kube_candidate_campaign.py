"""Eight post-root candidate Jobs inside one explicit serving ownership transfer."""

from mlsecops.contracts import Rejected
from scripts import kube_owned_probe as ownership
from scripts import kube_serving_native as probes
from scripts.kube_candidate_faults import NONTERMINAL
from scripts.kube_candidate_faults import exercise as exercise_faults
from scripts.kube_candidate_terminals import exercise as exercise_terminals
from scripts.kube_promotion_snapshot import read as snapshot
from scripts.kube_trust_native import hosted


def qualify(state, profile, config, expected, *, key, revoked_key, expires_at, base_snapshot):
    hosted()

    def observe():
        # Every call still creates a separate Job with fresh audit/preflight and
        # independently confirmed cleanup. Root/observer/peer rotation is over.
        result = probes.invoke(state, profile, config, expected, candidate_probe=True)
        if (
            result.get("status") != "pass"
            or result.get("release_ready") is not False
            or result.get("model_sha256") != expected["model"]
            or result.get("subject_sha256") != expected["bundle"]
            or result.get("authority_target") != "primary"
        ):
            raise Rejected("candidate_inference_binding_changed")
        if snapshot(state) != base_snapshot:
            raise Rejected("candidate_inference_promotion_state_changed")
        faults = exercise_faults(
            state,
            profile,
            config,
            expected,
            key=key,
            policy=config["expected_permit"],
            revoked_key=revoked_key,
            faults=NONTERMINAL,
            expires_at=expires_at,
            probe=probes.invoke,
        )
        terminals = exercise_terminals(
            state,
            profile,
            config,
            expected,
            base_probe=result,
            key=key,
            revoked_key=revoked_key,
            expires_at=expires_at,
            probe=probes.invoke,
        )
        return {"native": result, "faults": faults, "terminals": terminals}

    # Fault scopes unwind before run catches the error and attempts owner return.
    # An unsuccessful Job remains failed even after a successful return.
    return ownership.run(state, profile, observe)
