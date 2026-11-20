"""Produce a single candidate from the prepared hosted source, then hand it to the private store."""

from mlsecops import storage_bootstrap
from mlsecops.contracts import Rejected, canonical
from scripts import ci_campaign_control as control
from scripts import ci_campaign_guard as guard
from scripts import ci_campaign_handoff as handoff
from scripts import ci_campaign_producer as producer
from scripts import ci_candidate_transfer as bridge
from scripts import ci_producer_cluster as cluster_owner
from scripts import m17_recovery_native as recovery
from scripts import shared_serving_receipt as receipt


def publish_original(root, state, *, api, source_api, key, run_owner, source, checkpoint):
    """Return the verification key and a private cleanup receipt only after readback.

    source_api reads public run metadata. Only the private store receives api.
    The caller owns durable private checkpointing and cleanup on every exit.
    """
    if type(key) is not bytes or len(key) != 32 or not callable(checkpoint):
        raise Rejected("campaign_producer_inputs")

    def authorize():
        guard.authorize(
            root, source_api=source_api, job="producer", run_owner=run_owner, source=source
        )

    authorize()
    marker = storage_bootstrap.validate(state)
    cluster_owner.cleanup(state)
    prepared = producer.prepare(root, state, key=key)
    owner = prepared["owner"]
    if (
        canonical(owner["run_owner"]) != canonical(run_owner)
        or {k: owner["expected"][k] for k in source} != source
    ):
        raise Rejected("campaign_frozen_identity")
    recovery.stop_owned(state)
    if storage_bootstrap.validate(state) != marker:
        raise Rejected("campaign_producer_storage_changed")
    offline = receipt.offline_pin(state)
    origin = {k: marker[k] for k in ("workspace_id", "container_id")} | {"offline_pin": offline}
    authorize()
    result = handoff.publish(
        api,
        key=key,
        owner=owner,
        reports=prepared["reports"],
        packets=prepared["sealed"],
        origin=origin,
        checkpoint=checkpoint,
    )
    if receipt.offline_pin(state) != offline:
        raise Rejected("campaign_producer_readback")
    authorize()
    values, current = bridge._fresh(root, state, owner)
    for name in control.PHASES:
        context = prepared["sealed"][name]["context"]
        bridge._window(context, values, current)
        if context["expires_at"] - current < 600:
            raise Rejected("campaign_producer_remaining_window")
    return result
