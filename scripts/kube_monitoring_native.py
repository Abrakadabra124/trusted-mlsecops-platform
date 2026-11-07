"""Hosted actual-candidate monitoring observation; full M15 is deliberately open."""

import sys
from pathlib import Path

from mlsecops import audit_lineage, kube_storage, monitoring_packet, promotion_state
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
from mlsecops.serving_context import QualificationTrace
from scripts import feedback_native
from scripts.kube_candidate_native import qualify
from scripts.kube_load_native import failure_site
from scripts.kube_serving_native import prepare
from scripts.kube_trust_native import hosted


def reverify(state):
    public = read_json(state / "evidence/kubernetes-monitoring-public.json")
    directory = safe_child(state, "evidence/monitoring/" + public["campaign"])
    content = bounded_read(directory / "binding.json")
    if digest(content) != public["binding_sha256"]:
        raise Rejected("monitor_binding_changed")
    binding = decode(content)
    context = binding["context"]
    trace = QualificationTrace(
        *(
            context[name]
            for name in ("permit_sha256", "proposal_sha256", "bundle_sha256", "model_sha256")
        ),
        audit_lineage.checked(context["lineage"]),
    )
    # Independently read primary records after disposal; no infrastructure client.
    content = bounded_read(directory / "packet.json", 32 * 1024 * 1024)
    if digest(content) != binding["packet_hash"]:
        raise Rejected("monitor_packet_changed")
    payload = decode(content, 32 * 1024 * 1024)
    if payload["context"] != context or binding["campaign"] != public["campaign"]:
        raise Rejected("monitor_context_changed")
    result = monitoring_packet.verify(
        payload["packet"],
        reference=binding["reference"],
        reference_sha256=digest(canonical(binding["reference"])),
        context=trace,
        sink_public=payload["sink_public"],
        label_public=payload["label_public"],
        epoch=public["campaign"],
    )
    if (
        result != binding["summary"]
        or result != payload["summary"]
        or result != public["native"]["operator_retained_reverified"]
    ):
        raise Rejected("monitor_public_summary_changed")
    feedback = feedback_native.reverify(
        state, public["campaign"], public["feedback_quarantine"], payload["packet"]
    )
    return {
        "status": "pass",
        "post_cleanup_reverified": True,
        **result,
        "feedback_quarantine": feedback,
    }


def run(root, state):
    hosted()
    destination = state / "evidence/kubernetes-monitoring-public.json"
    write_json(destination, {"status": "inconclusive", "release_ready": False})
    promotion_state.install(state, backend=kube_storage.binding)
    prepared = prepare(root, state, "trusted-mlsecops:dev")
    result = qualify(
        root,
        state,
        "trusted-mlsecops:dev",
        monitoring=True,
        prepared=(prepared["profile"], prepared["actual"]),
    )
    result["feedback_quarantine"] = feedback_native.qualify(state, result)
    write_json(state / "evidence/kubernetes-monitoring-private.json", result)
    directory = safe_child(state, "evidence/monitoring/" + result["monitoring_campaign_id"])
    public = {
        name: result[name]
        for name in (
            "source",
            "source_dirty",
            "started_at",
            "finished_at",
            "candidate_reference",
            "proposal_reference",
            "model_sha256",
            "subject_sha256",
            "qualification_permit_sha256",
            "full_M15",
            "release_ready",
            "native",
            "feedback_quarantine",
        )
    }
    public.update(
        schema_version=1,
        scope="actual-candidate-monitoring-observation",
        status="pass",
        campaign=result["monitoring_campaign_id"],
        binding_sha256=digest(bounded_read(directory / "binding.json")),
    )
    write_json(destination, public)
    try:
        reverify(state)
    except BaseException:
        write_json(
            destination, {"status": "fail", "release_ready": False, "full_M15": "inconclusive"}
        )
        raise
    return public


def main():
    try:
        hosted()
        state = Path(".runtime").resolve()
        if sys.argv[1:] not in ([], ["--reverify"]):
            raise Rejected("monitor_native_arguments")
        result = reverify(state) if sys.argv[1:] else run(Path.cwd(), state)
        print(canonical(result).decode(), flush=True)
        return 0
    except Exception as failure:
        print(
            canonical(
                {
                    "status": "fail",
                    "release_ready": False,
                    "full_M15": "inconclusive",
                    "code": "monitor_native_rejected",
                    "site": failure_site(failure),
                }
            ).decode(),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
