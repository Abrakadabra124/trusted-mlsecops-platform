"""Recover the original evaluated proposal from the serving role on the new storage."""

import math
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import release_authorization, release_bundle, storage
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
)
from mlsecops.security_events import hexadecimal
from mlsecops.storage_bootstrap import inspect, validate
from scripts.candidate_serving_reader import bind_proposal
from scripts.kube_trust_native import hosted
from scripts.serving_output_native import source


def verify(root, origin, target, image, *, proposal_pin, keys_pin, demo_pin):
    hosted()
    old, new = validate(origin), validate(target)
    if (
        any(
            old[k] == new[k]
            for k in ("workspace_id", "container_id", "network_id", "volume", "port")
        )
        or inspect("container", old["container_id"])["State"]["Running"] is not False
        or inspect("container", new["container_id"])["State"]["Running"] is not True
    ):
        raise Rejected("recovered_proposal_storage_identity")
    public = read_json(safe_child(target, "recovered-public-keys.json"))
    demo = bounded_read(safe_child(origin, "storage-demo.json"))
    raw = bounded_read(safe_child(origin, "evidence/release-native.json"))
    if (
        digest(canonical(public)) != keys_pin
        or digest(raw) != proposal_pin
        or digest(demo) != demo_pin
    ):
        raise Rejected("recovered_proposal_pin")
    demo, report = decode(demo), decode(raw)
    policy = read_json(root / "policies/local-cpu.json")
    trust = dict(
        curator=public["curator"],
        evaluator=public["evaluator"],
        source_approval_digest=demo["dataset"]["source_approval_digest"],
    )
    image_source = source(root, image)
    clock = math.ceil(time.time())
    # load() reconnects per object. Keep its verified credentials private and
    # fixed for the entire read, including libpq's later opens of TLS files.
    exported = safe_child(target, "storage-clients/serving")
    if (exported / ".no-passwords").exists():
        raise Rejected("recovered_proposal_serving_client")
    with TemporaryDirectory() as temporary:
        client = Path(temporary).resolve()
        for name in ("connection.json", "client.crt", "client.key", "ca.crt"):
            atomic_write(client / name, bounded_read(safe_child(exported, name), 4096))
        params, files = storage.connection_materials(client)
        if (
            (params["host"], params["port"], params["user"])
            != ("127.0.0.1", new["port"], "ml_serving")
            or any(
                files[name]
                != digest(bounded_read(safe_child(target, "storage-pki/" + owned), 4096))
                for name, owned in (
                    ("ca.crt", "ca.crt"),
                    ("client.crt", "ml_serving.crt"),
                    ("client.key", "ml_serving.key"),
                )
            )
            or validate(target) != new
        ):
            raise Rejected("recovered_proposal_serving_client")
        package = release_bundle.load(
            client, report["proposal_reference"], publisher_public=public["approver"]
        )
    context, checked = bind_proposal(
        report,
        package,
        policy=policy,
        source_trust=trust,
        publisher_public=public["approver"],
        expected=image_source,
        clock=clock,
    )
    if (
        context["candidate_reference"] != demo["candidate"]["candidate_reference"]
        or context["evaluation_reference"] != demo["evaluation_reference"]
        or digest(checked["model"]) != demo["candidate"]["metadata"]["model_digest"]
    ):
        raise Rejected("recovered_proposal_wrong_candidate")
    campaign = hexadecimal(report["campaign_id"], 32)
    policy_envelope = read_json(
        safe_child(origin, f"release-proposals/{campaign}/policy-envelope.json")
    )
    try:
        release_authorization.verify(
            package=package,
            policy_envelope=policy_envelope,
            assurance_envelope=None,
            approval_envelope=None,
            reports={},
            context=context,
            trusted_root=public["trust"],
            expected_policy=report["policy_sha256"],
            expected_serving_image=image_source["image_id"],
            clock=clock,
        )
    except Rejected as refusal:
        if str(refusal) != "release_assurance_required":
            raise
    else:
        raise Rejected("recovered_proposal_unapproved_admission")
    return dict(
        candidate_reference=context["candidate_reference"],
        evaluation_reference=context["evaluation_reference"],
        model_sha256=digest(checked["model"]),
        subject_sha256=checked["subject_sha256"],
        proposal_reference=report["proposal_reference"],
        target_workspace=new["workspace_id"],
        status="verified-proposal-requires-assurance",
        release_ready=False,
    )
