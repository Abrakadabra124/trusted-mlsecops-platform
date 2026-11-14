"""Join frozen delivery inputs to ordinary M11 observations without issuing a new proposal."""

from mlsecops import signing, trust_gate
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, safe_child
from mlsecops.storage import object_id
from scripts.serving_output_native import verified_materials


def pinned(path, expected):
    raw = bounded_read(path)
    if digest(raw) != object_id(expected):
        raise Rejected("M11_frozen_file_pin")
    return decode(raw)


def clean_campaign(state):
    # M12/M13 and M11 have mutable authority/serving state. A new campaign
    # requires a freshly owned Kubernetes store and its own local markers.
    for name in (
        "kubernetes-trust",
        "kubernetes-trust-model",
        "kubernetes-security",
        "kubernetes-serving-service",
    ):
        if safe_child(state, name).exists():
            raise Rejected("M11_fresh_cluster_required")


def freeze(root, state, source, proposal_pin, demo_pin):
    report = pinned(safe_child(state, "evidence/release-native.json"), proposal_pin)
    demo = pinned(safe_child(state, "storage-demo.json"), demo_pin)
    context, verified, package, publisher = verified_materials(root, state, source)
    reference = context["evaluation_reference"]
    evaluation = package["capsule"]["objects"][("evaluations", reference)]
    signed = signing.verify(decode(evaluation), "stored-evaluation", context["trust"]["evaluator"])
    trust_gate.require(
        digest(evaluation) == reference
        and canonical(signed) == canonical(demo["evaluation"])
        and reference == demo["evaluation_reference"]
        and context["candidate_reference"]
        == demo["candidate"]["candidate_reference"]
        == signed["candidate_reference"]
        and verified["subject_sha256"] == report["subject_sha256"]
        and digest(verified["model"])
        == report["model_sha256"]
        == demo["candidate"]["metadata"]["model_digest"]
        and report["source"] == source
        and digest(canonical(package["envelope"])) == report["proposal_reference"]
        and verified["manifest"]["release_id"] == report["campaign_id"]
    )
    return dict(
        context=context,
        publisher_public=publisher,
        source=source,
        candidate_reference=context["candidate_reference"],
        evaluation_reference=reference,
        proposal_reference=report["proposal_reference"],
        subject_sha256=verified["subject_sha256"],
        model_sha256=digest(verified["model"]),
        proposal_issued_at=verified["manifest"]["issued_at"],
        proposal_expires_at=verified["manifest"]["expires_at"],
        input_files={
            "evidence/release-native.json": proposal_pin,
            "storage-demo.json": demo_pin,
            **{
                name: digest(bounded_read(safe_child(state, name)))
                for name in ("trusted-keys.json", "storage-trust.json")
            },
        },
    )


def retained(state, native, binding):
    actual = native["actual_inference"]
    campaign = actual["qualification_campaign_id"]
    if (
        not isinstance(campaign, str)
        or len(campaign) != 32
        or any(c not in "0123456789abcdef" for c in campaign)
    ):
        raise Rejected("M11_campaign_id")
    directory = safe_child(state, "candidate-inference/" + campaign)
    config = pinned(directory / "config.json", actual["artifact_hashes"]["config.json"])
    probe = pinned(directory / "probe.json", actual["artifact_hashes"]["probe.json"])
    trust_gate.require(canonical(probe) == canonical(actual["native"]))
    for name, pin in binding["input_files"].items():
        pinned(safe_child(state, name), pin)
    return trust_gate.delivery(native, binding, config)


def check_pins(proposal_pin, demo_pin):
    if (proposal_pin is None) != (demo_pin is None):
        raise Rejected("M11_frozen_pins_required")
    if proposal_pin is not None:
        object_id(proposal_pin)
        object_id(demo_pin)
