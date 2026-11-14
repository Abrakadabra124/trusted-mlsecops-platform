"""Reconcile two private HTTP journals with the client's ordered rollout observations."""

from collections import Counter

from mlsecops import audit_export
from mlsecops.contracts import Rejected, decode


def reconcile(content, rows, extra, *, subject, model, authority, pre_admission_denial=False):
    """extra holds all HTTP observations after the last stage, including the fault."""
    summary = audit_export.project([content])
    if summary["status"] != "pass" or summary["requests"]["aborted"]:
        raise Rejected("canary_journal_incomplete")
    completed = {}
    for line in content.splitlines():
        event = decode(line)["event"]
        if event["route"] != "predict":
            raise Rejected("canary_journal_route")
        if event["stage"] != "response_completed":
            continue
        if event["status"] == 200:
            ctx = event["context"]
            if (ctx["model_sha256"], ctx["bundle_sha256"]) != (model, subject) or any(
                ctx.get(field) != value for field, value in authority.items()
            ):
                raise Rejected("canary_journal_authority")
        completed[event["request_id"]] = event["status"]
    expected = {}
    errors = Counter()
    for row in rows:
        if row["status"] == 0:
            # No client response can be paired with a completed server request.
            raise Rejected("canary_journal_transport_unconfirmed")
        if row["status"] != 200:
            errors[row["status"]] += 1
            continue
        identifier = row["response"]["request_id"]
        if identifier in expected:
            raise Rejected("canary_journal_duplicate")
        expected[identifier] = 200
    for sample in extra:
        identifier = sample["reply"]["request_id"]
        if identifier in expected:
            raise Rejected("canary_journal_duplicate")
        expected[identifier] = sample["status"]
    # A fenced Engine may reject the terminal probe before Access.acquire and
    # before an audit reservation. The dedicated client's counters prove this path.
    if pre_admission_denial:
        last = extra[-1]
        if (
            authority.get("kind") != "candidate-qualification"
            or last["status"] != 503
            or last["reply"]["request_id"] in completed
        ):
            raise Rejected("canary_journal_admission_conflict")
        expected.pop(last["reply"]["request_id"])
    for identifier, status in expected.items():
        if completed.pop(identifier, None) != status:
            raise Rejected("canary_journal_exchange")
    if errors != Counter(completed.values()):
        raise Rejected("canary_journal_inventory")
    return summary["requests"]["completed"]
