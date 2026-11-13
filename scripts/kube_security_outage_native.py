"""Fresh actual-candidate green ML during an owned audit outage; not full M23."""

import math
import sys
import traceback
from pathlib import Path

from mlsecops import audit_lineage, kube_storage, promotion_state, security_outage_packet
from mlsecops import security_events as events
from mlsecops.cluster import request_failure
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.load_golden import Golden
from mlsecops.security_outage_exchange import PHASES
from mlsecops.serving_context import QualificationTrace
from mlsecops.trust_acceptance import materials
from scripts.kube_candidate_native import qualify
from scripts.kube_load_native import failure_site
from scripts.kube_privacy_diagnostic import validated
from scripts.kube_security_outage_operator import MAX_RECOVERY, owner_authority, verify_recovery
from scripts.kube_serving_native import prepare
from scripts.kube_trust_native import hosted

PUBLIC = "evidence/kubernetes-security-outage-public.json"
PRIVATE = "evidence/kubernetes-security-outage-private.json"


def ownership_return(value):
    """Replay the parent's terminal ownership contract, not a live health claim."""
    events.shape(
        value,
        (
            "transfer",
            "observation",
            "heartbeat_before",
            "heartbeat_after",
            "return_seconds",
            "identity_events_delivered",
            "outbox_retained",
            "release_ready",
        ),
    )
    transfer = value["transfer"]
    events.shape(transfer, ("before", "after", "release_ready"))
    for name in ("before", "after"):
        if type(transfer[name]) is not str or not 1 <= len(transfer[name]) <= 128:
            raise Rejected("security_outage_ownership_uid")
    before = events.integer(value["heartbeat_before"])
    after = events.integer(value["heartbeat_after"])
    events.integer(value["identity_events_delivered"], 0)
    seconds = value["return_seconds"]
    if (
        transfer["before"] == transfer["after"]
        or transfer["release_ready"] is not False
        or value["release_ready"] is not False
        or value["outbox_retained"] is not True
        or value["observation"] is not None
        or after <= before
        or type(seconds) not in (int, float)
        or not math.isfinite(seconds)
        or not 0 <= seconds <= 120
    ):
        raise Rejected("security_outage_ownership_return")


def reverify(root, state):
    public = read_json(state / PUBLIC)
    events.shape(
        public,
        (
            "schema_version",
            "status",
            "scope",
            "source",
            "method_materials",
            "primary_sha256",
            "retained_sha256",
            "release_ready",
            "full_M23",
            *(("observation",) if "observation" in public else ()),
        ),
    )
    events.version(public["schema_version"])
    if (
        public["status"] != "pass"
        or public["scope"] != "actual-candidate-ML-and-monitoring-during-audit-outage"
        or public["release_ready"] is not False
        or public["full_M23"] != "inconclusive"
    ):
        raise Rejected("security_outage_public_status")
    content = bounded_read(state / PRIVATE, security_outage_packet.MAX_PACKET)
    if digest(content) != public["primary_sha256"]:
        raise Rejected("security_outage_primary_changed")
    result = decode(content, security_outage_packet.MAX_PACKET)
    events.version(result.get("schema_version"))
    if (
        result.get("status") != "pass"
        or result.get("scope") != "actual-candidate-kubernetes-inference"
    ):
        raise Rejected("security_outage_private_status")
    ownership_return(result.get("native", {}).get("ownership_return"))
    source = public["source"]
    if (
        result["source"] != source
        or result["source_dirty"] is not False
        or source["source_revision"] != command(["git", "-C", str(root), "rev-parse", "HEAD"])
        or source["source_fingerprint"] != source_fingerprint(root)
        or public["method_materials"] != materials(root)
        or result["release_ready"] is not False
        or result["full_M23"] != "inconclusive"
    ):
        raise Rejected("security_outage_source_changed")
    campaign = result["security_campaign_id"]
    directory = safe_child(state, "evidence/security-outage/" + campaign)
    records = {}
    for name in ("binding.json", "packet.json", "operator.json"):
        raw = bounded_read(directory / name, security_outage_packet.MAX_PACKET)
        if digest(raw) != public["retained_sha256"][name]:
            raise Rejected("security_outage_retained_changed")
        records[name] = decode(raw, security_outage_packet.MAX_PACKET)
    binding, operator = records["binding.json"], records["operator.json"]
    context = binding["context"]
    trace = QualificationTrace(
        *(
            context[name]
            for name in ("permit_sha256", "proposal_sha256", "bundle_sha256", "model_sha256")
        ),
        audit_lineage.checked(context["lineage"]),
    )
    golden = binding["golden"]
    summary = security_outage_packet.verify(
        records["packet.json"],
        reference=binding["reference"],
        context=trace,
        golden=Golden(golden["body"].encode(), golden["model"], golden["bundle"], golden["score"]),
        campaign=campaign,
    )
    security_outage_packet.verify_timeline(records["packet.json"], operator["timeline"])
    if (
        trace.permit_sha256 != result["qualification_permit_sha256"]
        or trace.proposal_sha256 != result["proposal_reference"]
        or trace.bundle_sha256 != result["subject_sha256"]
        or trace.model_sha256 != result["model_sha256"]
        or trace.lineage.source_fingerprint != source["source_fingerprint"]
        or trace.lineage.source_revision != source["source_revision"]
        or binding["campaign"] != campaign
        or operator["campaign"] != campaign
        or operator["phases"] != list(PHASES)
        or set(operator["requests"]) != set(PHASES)
        or set(operator["results"]) != set(PHASES)
        or binding["summary"] != summary
        or result["native"]["operator_retained_reverified"] != summary
        or canonical({key: result["native"].get(key) for key in summary}) != canonical(summary)
        or result["native"]["worker_cleanup_verified"] is not True
        or result["native"]["audit_boundary"] != binding["boundary"]
        or canonical(result["native"]["recovery"]) != canonical(binding["recovery"])
        or result["base_snapshot_sha256"] != binding["base_snapshot_sha256"]
        or binding["packet_hash"] != public["retained_sha256"]["packet.json"]
    ):
        raise Rejected("security_outage_binding_changed")
    for phase in PHASES:
        payload = (
            {"packet": records["packet.json"], "summary": summary} if phase == "finish" else {}
        )
        expected = digest(canonical({"phase": phase, "campaign": campaign, "payload": payload}))
        ack = {"packet_sha256": summary["packet_sha256"]} if phase == "finish" else {}
        if operator["requests"][phase] != expected or operator["results"][phase] != ack:
            raise Rejected("security_outage_exchange_changed")
    boundary, recovery = binding["boundary"], binding["recovery"]
    retained = decode(bounded_read(directory / "recovery.json", MAX_RECOVERY), MAX_RECOVERY)
    if canonical(retained) != canonical(recovery):
        raise Rejected("security_outage_recovery_changed")
    verify_recovery(
        boundary, retained, owner_authority(state, source=source), timeline=operator["timeline"]
    )
    observation = {**summary, "retained_primary_reverified": True, "full_M23": "inconclusive"}
    if "observation" in public and canonical(public["observation"]) != canonical(observation):
        raise Rejected("security_outage_public_observation_changed")
    return observation


def run(root, state):
    hosted()
    destination = state / PUBLIC
    write_json(destination, {"status": "inconclusive", "release_ready": False})
    promotion_state.install(state, backend=kube_storage.binding)
    prepared = prepare(root, state, "trusted-mlsecops:dev")
    result = qualify(
        root,
        state,
        "trusted-mlsecops:dev",
        security=True,
        prepared=(prepared["profile"], prepared["actual"]),
    )
    write_json(state / PRIVATE, result)
    directory = safe_child(state, "evidence/security-outage/" + result["security_campaign_id"])
    public = {
        "schema_version": 1,
        "status": "pass",
        "scope": "actual-candidate-ML-and-monitoring-during-audit-outage",
        "source": result["source"],
        "method_materials": materials(root),
        "primary_sha256": digest(bounded_read(state / PRIVATE, security_outage_packet.MAX_PACKET)),
        "retained_sha256": {
            name: digest(bounded_read(directory / name, security_outage_packet.MAX_PACKET))
            for name in ("binding.json", "packet.json", "operator.json")
        },
        "release_ready": False,
        "full_M23": "inconclusive",
    }
    write_json(destination, public)
    try:
        public["observation"] = reverify(root, state)
    except BaseException:
        write_json(
            destination, {"status": "fail", "release_ready": False, "full_M23": "inconclusive"}
        )
        raise
    write_json(destination, public)
    return public


def failure_report(error):
    root = Path(__file__).resolve().parents[1]
    callers = []
    for frame in traceback.extract_tb(error.__traceback__):
        path = Path(frame.filename).resolve()
        if path.parent.parent == root:
            site = validated(
                dict(
                    source_file=path.relative_to(root).as_posix(),
                    source_line=frame.lineno,
                    exception="other",
                )
            )
            if site is not None:
                callers.append(site)
    return dict(
        status="fail",
        release_ready=False,
        full_M23="inconclusive",
        code="security_outage_native_rejected",
        site=failure_site(error),
        request=request_failure(error),
        callers=callers[-12:],
    )


def main():
    try:
        if sys.argv[1:] not in ([], ["--reverify"]):
            raise Rejected("security_outage_arguments")
        root, state = Path.cwd(), Path(".runtime").resolve()
        result = reverify(root, state) if sys.argv[1:] else run(root, state)
        print(canonical(result).decode(), flush=True)
        return 0
    except Exception as error:
        print(canonical(failure_report(error)).decode(), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
