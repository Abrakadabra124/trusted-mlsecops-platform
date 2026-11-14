"""Reopen the original M10 decision and its signed denial receipts with storage offline."""

from mlsecops import final_evidence as evidence
from mlsecops.contracts import canonical, decode, digest, now, safe_child
from scripts import promotion_gate_native as promotion


def unchanged_denial(record, reason):
    evidence.same(record["reason"], reason, "promotion-denial-reason")
    evidence.same(
        record["cli"], {"status": "rejected", "release_ready": False}, "promotion-denial-cli"
    )
    for field in ("after_parent", "after"):
        evidence.same(record[field], record["before"], "promotion-denial-history")


def verify_refusal(record, proposal):
    unchanged_denial(record, "release_assurance_required")
    evidence.same(record["request"]["proposal_reference"], proposal, "promotion-denial-proposal")
    evidence.same(record["before"]["events"], [], "promotion-initial-events")
    evidence.same(
        record["before"]["head"],
        dict(environment=promotion.ENV, sequence=0, request_sha256=None, release_ready=False),
        "promotion-initial-state",
    )
    promotion.check_audit(
        record["audit"],
        registry_root=record["registry_root"],
        registry_pin=record["registry_pin"],
        proposal=proposal,
        windows=record["windows"],
    )


def verify(state, values, freeze, keys, pin):
    report = evidence.published_report(state, "M10", pin)
    refs = report["artifact_hashes"]
    evidence.same(
        sorted(refs), ["actual_proposal_report", "promotion_primary"], "promotion-artifacts"
    )
    evidence.same(
        refs["actual_proposal_report"], freeze["evidence/release-native.json"], "promotion-source"
    )
    raw = evidence.pinned(
        safe_child(state, "evidence/M10-promotion-primary.json"), refs["promotion_primary"]
    )
    packet = decode(raw)
    control = packet["controlled"]
    outcomes = {
        "actual-signed-proposal": values["release_subject"],
        "actual-candidate-denied": "release_assurance_required",
        "actual-signed-denials-delivered": 2,
        "actual-durable-sequence": 0,
        **{"controlled-" + k: v for k, v in promotion.NEGATIVES.items()},
        "controlled-recorded-sequence": 1,
        "controlled-repeat-same-request": control["first"]["request_sha256"],
    }
    evidence.check_gate(
        "M10", report, values, evidence.timestamp(now()), digest(canonical(sorted(outcomes)))
    )
    evidence.same({c["id"]: c["actual"] for c in report["cases"]}, outcomes, "promotion-cases")
    evidence.subset(
        packet,
        dict(
            schema_version=1,
            scope=promotion.SCOPE,
            source={k: values[k] for k in ("source_revision", "source_fingerprint", "image_id")},
            input_files=freeze,
            actual_policy_root=keys["trust"],
        ),
        "promotion-frozen-materials",
    )
    verify_refusal(packet["actual"], values["proposal_reference"])
    evidence.same(
        sorted(control["negatives"]), sorted(promotion.NEGATIVES), "promotion-control-inventory"
    )
    for case, reason in promotion.NEGATIVES.items():
        unchanged_denial(control["negatives"][case], reason)
    promotion.check_transition(
        *(
            control[k]
            for k in (
                "request",
                "subject",
                "before",
                "first",
                "committed",
                "retry",
                "repeated",
                "selection",
                "proof",
            )
        )
    )
    evidence.same(
        report["metrics"],
        dict(
            checks=len(outcomes),
            actual_release_authorization="inconclusive",
            actual_sequence=0,
            controlled_sequence=1,
            controlled_negative_cases=len(promotion.NEGATIVES),
        ),
        "promotion-metrics",
    )
    for content in (
        raw,
        evidence.pinned(
            safe_child(state, "evidence/release-native.json"), refs["actual_proposal_report"]
        ),
    ):
        evidence.retain(state, content)
    evidence.primary("M10", report, lambda ref: evidence.blob(state, ref), values)
