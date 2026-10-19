import re
from dataclasses import asdict

from mlsecops import audit_lineage, serving_context
from mlsecops.contracts import Rejected

FIELDS = {"schema_version", "request_id", "principal_id", "route", "stage", "status", "context"}
STAGES = {
    "request_started",
    "response_intended",
    "response_started",
    "response_completed",
    "aborted",
}


def checked(value):
    if (
        type(value) is not dict
        or value.keys() != FIELDS
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or any(
            type(value[key]) is not str or re.fullmatch(r"[a-f0-9]{32}", value[key]) is None
            for key in ("request_id", "principal_id")
        )
        or type(value["route"]) is not str
        or value["route"] not in {"predict", "ready"}
        or type(value["stage"]) is not str
        or value["stage"] not in STAGES
    ):
        raise Rejected("audit_event_invalid")
    status, stage, context = value["status"], value["stage"], value["context"]
    if (
        status is not None
        and (type(status) is not int or not 200 <= status <= 599)
        or stage == "request_started"
        and status is not None
        or stage not in {"request_started", "aborted"}
        and status is None
    ):
        raise Rejected("audit_event_invalid")
    if status == 200:
        context = checked_context(context)
    elif context is not None:
        raise Rejected("audit_event_invalid")
    return {**value, "context": context}


def checked_context(value):
    if (
        type(value) is not dict
        or type(value.get("schema_version")) is not int
        or value["schema_version"] not in (1, 2)
        or value.get("release_ready") is not False
    ):
        raise Rejected("audit_event_invalid")
    kind = value.get("kind")
    if kind == "release-selection":
        context_type = serving_context.ReleaseContext
        references = {"selection_sha256", "bundle_sha256", "model_sha256"}
        if value["schema_version"] == 2:
            context_type = serving_context.ReleaseTrace
            references |= {"authorization_sha256", "assurance_sha256", "approval_sha256"}
    elif kind == "candidate-qualification":
        context_type = serving_context.QualificationContext
        references = {"permit_sha256", "proposal_sha256", "bundle_sha256", "model_sha256"}
        if value["schema_version"] == 2:
            context_type = serving_context.QualificationTrace
    else:
        raise Rejected("audit_event_invalid")
    lineage_fields = {"lineage"} if value["schema_version"] == 2 else set()
    if value.keys() != references | lineage_fields | {"schema_version", "kind", "release_ready"}:
        raise Rejected("audit_event_invalid")
    try:
        arguments = {key: value[key] for key in references}
        if lineage_fields:
            arguments["lineage"] = audit_lineage.checked(value["lineage"])
        context = context_type(**arguments)
    except Rejected:
        raise Rejected("audit_event_invalid") from None
    return asdict(context)
