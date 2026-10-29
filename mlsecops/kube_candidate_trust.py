"""Actual-candidate faults with cold denial and explicit recovery verification."""

from mlsecops import kube_serving_lifecycle as lifecycle
from mlsecops import trust
from mlsecops.contracts import Rejected

NONTERMINAL = ("outage", "blackhole", "policy-change")


def exercise(reader_factory, request, body, expected, check, *, pause=None):
    fault = expected.get("fault")
    if fault not in (*NONTERMINAL, "key-revocation", "revocation"):
        raise Rejected("candidate_trust_fault")
    if fault in {"outage", "blackhole"} and pause is None:
        raise Rejected("candidate_trust_pause_required")

    def cold_denial():
        try:
            reader_factory().load()
        except Rejected as error:
            correct = (
                isinstance(error, trust.Unavailable) and str(error) == "trust_service_unavailable"
                if fault in {"outage", "blackhole"}
                else str(error) == "trust_policy_changed"
            )
            check("cold-reader-" + fault, correct, True)
        else:
            check("cold-reader-" + fault, False, True)

    trace = lifecycle.exercise(
        None,
        request,
        body,
        expected,
        lambda label, condition: check(label, condition, True),
        pause=pause,
        on_denied=cold_denial if fault in NONTERMINAL else lambda: None,
    )
    if fault in NONTERMINAL:
        loaded = reader_factory().load()
        check("restored-cold-reader-model", loaded.model_sha256, expected["model"])
        check("restored-cold-reader-subject", loaded.subject_sha256, expected["bundle"])
        return trace
    label = (
        "cold-reader-key-revocation"
        if fault == "key-revocation"
        else "cold-reader-model-revocation"
    )
    cause = "trust_key_revoked" if fault == "key-revocation" else "trust_artifact_revoked"
    try:
        reader_factory().load()
    except Rejected as error:
        check(label, str(error) == cause, True)
    else:
        check(label, False, True)
    return trace
