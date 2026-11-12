"""Fresh actual-candidate green ML during an owned audit outage; not full M23."""

import sys
from pathlib import Path

from mlsecops import audit_lineage, kube_storage, promotion_state, security_outage_packet
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
from scripts.kube_serving_native import prepare
from scripts.kube_trust_native import hosted

PUBLIC = "evidence/kubernetes-security-outage-public.json"
PRIVATE = "evidence/kubernetes-security-outage-private.json"


def reverify(root, state):
    public = read_json(state / PUBLIC)
    content = bounded_read(state / PRIVATE, security_outage_packet.MAX_PACKET)
    if digest(content) != public["primary_sha256"]:
        raise Rejected("security_outage_primary_changed")
    result = decode(content, security_outage_packet.MAX_PACKET)
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
        or any(result["native"].get(key) != value for key, value in summary.items())
        or result["native"]["worker_cleanup_verified"] is not True
        or result["native"]["audit_boundary"] != binding["boundary"]
        or result["native"]["recovery"] != binding["recovery"]
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
    pending = boundary["pending"]
    received = recovery["original_denial"]
    if (
        boundary["status"] != "pass"
        or boundary["release_ready"] is not False
        or boundary["scope"] != "controlled-authorization-and-trust-real-sql-audit-boundary"
        or type(boundary["audit_checks"]) is not int
        or boundary["audit_checks"] != 1
        or type(boundary["audit_denials"]) is not int
        or boundary["audit_denials"] != 1
        or boundary["audit_check_error"] != "promotion_audit_unavailable"
        or boundary["promotion_error"] != "promotion_denial_audit_unconfirmed"
        or pending["reason"] != "audit_unavailable"
        or pending["receipt"] is not None
        or received["id"] != pending["event_id"]
        or received["envelope"] != pending["envelope_sha256"]
        or received["kind"] != pending["kind"]
        or received["kind"] != "promotion.denied"
        or received["receipt"] is None
        or recovery["fault_removed"] is not True
        or recovery["SQL_and_CAS_unchanged"] is not True
    ):
        raise Rejected("security_outage_refusal_or_recovery_changed")
    return {**summary, "retained_primary_reverified": True, "full_M23": "inconclusive"}


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


def main():
    try:
        if sys.argv[1:] not in ([], ["--reverify"]):
            raise Rejected("security_outage_arguments")
        root, state = Path.cwd(), Path(".runtime").resolve()
        result = reverify(root, state) if sys.argv[1:] else run(root, state)
        print(canonical(result).decode(), flush=True)
        return 0
    except Exception as error:
        print(
            canonical(
                {
                    "status": "fail",
                    "release_ready": False,
                    "full_M23": "inconclusive",
                    "code": "security_outage_native_rejected",
                    "site": failure_site(error),
                }
            ).decode(),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
