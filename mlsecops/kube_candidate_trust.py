"""Actual-candidate key revocation, separate from controlled model revocation."""

from mlsecops import kube_serving_lifecycle as lifecycle
from mlsecops.contracts import Rejected


def exercise(reader_factory, request, body, expected, check):
    if expected.get("fault") != "key-revocation":
        raise Rejected("candidate_trust_fault")
    trace = lifecycle.exercise(
        None, request, body, expected, lambda label, condition: check(label, condition, True)
    )
    try:
        reader_factory().load()
    except Rejected as error:
        check("cold-reader-key-revocation", str(error) == "trust_key_revoked", True)
    else:
        check("cold-reader-key-revocation", False, True)
    return trace
