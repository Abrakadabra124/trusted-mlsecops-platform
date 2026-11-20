"""Prepare private phase-specific packets from one original hosted producer proposal."""

import os

from mlsecops import ci_transfer, storage, storage_bootstrap
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, safe_child, write_json
from scripts import ci_candidate_transfer as bridge
from scripts import ci_upstream_transfer as upstream
from scripts import ci_validation_transfer as validation
from scripts import frozen_candidate_transfer as transfer
from scripts import m18_delivery_freeze, release_native
from scripts.kube_trust_native import hosted
from scripts.serving_output_native import source

IMAGE = "trusted-mlsecops:dev"
CLAIM = "ci-campaign-proposal-claim"


def run_owner():
    if os.environ["GITHUB_REPOSITORY"] != ci_transfer.REPOSITORY:
        raise Rejected("ci_campaign_repository")
    return dict(
        repository=ci_transfer.REPOSITORY,
        run_id=int(os.environ["GITHUB_RUN_ID"]),
        run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
        producer_job=os.environ["GITHUB_JOB"],
    )


def put(state, relative, value):
    path = safe_child(state, relative)
    write_json(path, value)
    raw = canonical(value) + b"\n"
    if bounded_read(path) != raw:
        raise Rejected("ci_campaign_write_readback")
    return digest(raw)


def require_unproposed(producer):
    for name in (transfer.delivery.PROPOSAL, transfer.RECEIPT, CLAIM):
        if safe_child(producer, name).exists():
            raise Rejected("ci_campaign_already_proposed")
    proposals = safe_child(producer, "release-proposals")
    if proposals.exists() and any(proposals.iterdir()):
        raise Rejected("ci_campaign_already_proposed")


def freeze_original(root, producer, original, owner_run, progress):
    require_unproposed(producer)
    # A failed qualifier may have published to storage before writing any file.
    # Keep the exclusive claim even after failure or process interruption.
    try:
        safe_child(producer, CLAIM).mkdir(mode=0o700)
    except FileExistsError:
        raise Rejected("ci_campaign_already_proposed") from None
    progress["stage"] = "proposal"
    proposal = release_native.qualify(root, producer, IMAGE)
    pin = put(producer, transfer.delivery.PROPOSAL, proposal)
    if not (
        proposal["status"] == "pass"
        and proposal["source"] == original
        and proposal["source_dirty"] is False
    ):
        raise Rejected("ci_campaign_proposal")
    progress["stage"] = "freeze"
    freeze = {
        name: digest(bounded_read(safe_child(producer, name)))
        for name in transfer.delivery.FILES
        if name != transfer.delivery.PROPOSAL
    }
    freeze[transfer.delivery.PROPOSAL] = pin
    freeze_pin = m18_delivery_freeze.capture(root, producer, freeze, original["source_revision"])
    index = transfer.delivery.pinned(safe_child(producer, transfer.RECEIPT), freeze_pin)
    values, _, _ = transfer.delivery.frozen(root, producer, index)
    expected = {field: values[field] for field in transfer.IDENTITY}
    if {k: expected[k] for k in transfer.delivery.SOURCE} != original:
        raise Rejected("ci_campaign_frozen_source")
    return dict(freeze_pin=freeze_pin, freeze=freeze, expected=expected, run_owner=owner_run)


def seal_serving(root, producer, owner, key):
    reports = {
        gate: digest(bounded_read(safe_child(producer, "evidence/" + gate + ".json")))
        for gate in upstream.GATES
    }
    args = dict(**owner, key=key, phase="M13")
    candidate = bridge.seal(root, producer, **args)
    receipts = upstream.seal(root, producer, reports=reports, **args)
    values, _ = bridge._fresh(root, producer, owner)
    descriptor = validation._descriptor(producer, values)
    content = storage.get(
        safe_child(producer, "storage-clients/publisher"), "validation", descriptor["sha256"]
    )
    packet = validation.retain(root, producer, content, **owner)
    return reports, dict(
        candidate=candidate,
        upstream=receipts,
        validation=validation.seal(root, producer, packet, **args),
    )


def prepare(root, producer, *, key):
    """Return private owner, original report pins and sealed packets to the trusted caller."""
    hosted()
    if type(key) is not bytes or len(key) != 32:
        raise Rejected("ci_campaign_key")
    original, owner_run = source(root, IMAGE), run_owner()
    storage_bootstrap.validate(producer)
    owner = freeze_original(root, producer, original, owner_run, {})
    shared = bridge.seal(root, producer, key=key, **owner, phase="M11-M12")
    reports, serving = seal_serving(root, producer, owner, key)
    candidate = serving["candidate"]
    if (shared["manifest_sha256"], shared["context"]["payload_sha256"]) != (
        candidate["manifest_sha256"],
        candidate["context"]["payload_sha256"],
    ):
        raise Rejected("ci_campaign_archive_changed")
    sealed = {
        "candidate-shared": shared,
        "candidate-serving": candidate,
        "upstream-serving": serving["upstream"],
        "validation-serving": serving["validation"],
    }
    if source(root, IMAGE) != original:
        raise Rejected("ci_campaign_source_changed")
    values, current = bridge._fresh(root, producer, owner)
    for packet in sealed.values():
        bridge._window(packet["context"], values, current)
    return dict(owner=owner, reports=reports, sealed=sealed)
