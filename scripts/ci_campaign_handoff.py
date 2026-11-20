"""Materialize an original producer's encrypted packets for one fresh consumer."""

from contextlib import ExitStack, contextmanager

from mlsecops.contracts import Rejected, canonical, digest
from scripts import ci_campaign_control as control
from scripts import ci_private_assets as store
from scripts import ci_upstream_transfer as upstream
from scripts import consumer_candidate_state

JOBS = {
    "shared": ("candidate-shared",),
    "serving": ("candidate-serving", "upstream-serving", "validation-serving"),
}


def publish(api, *, owner, reports, origin, packets, key, checkpoint):
    """Publish five private assets, forwarding an owned cleanup journal after each mutation."""
    if not callable(checkpoint):
        raise Rejected("campaign_checkpoint_missing")
    issuer = None

    def remember(receipt):
        checkpoint({"storage": receipt, "issuer": issuer.copy() if issuer is not None else None})

    def seal_control(receipt):
        nonlocal issuer
        blob, public = control.issue(
            owner=owner, origin=origin, reports=reports, packets=packets, storage=receipt, key=key
        )
        issuer = dict(
            public=public, control_sha256=digest(blob), storage_sha256=digest(canonical(receipt))
        )
        # Persist verification authority before the irreversible network upload.
        remember(receipt)
        return blob

    expected = owner["run_owner"] | {"source_revision": owner["expected"]["source_revision"]}
    receipt = store.publish(
        api,
        expected,
        {k: v["envelope"] for k, v in packets.items()},
        seal_control,
        checkpoint=remember,
    )
    if issuer is None:
        raise Rejected("campaign_control_missing")
    return issuer["public"], receipt


@contextmanager
def open_consumer(root, *, job, api, trust_key_path, key, trusted_public, run_owner, source):
    """The caller supplies a bounded private reader and independent producer job outputs."""
    if type(job) is not str or job not in JOBS:
        raise Rejected("campaign_consumer_job")
    control.binding(run_owner, source)
    expected = run_owner | {"source_revision": source["source_revision"]}
    record = control.read(
        store.fetch_control(api, expected),
        key=key,
        trusted_public=trusted_public,
        run_owner=run_owner,
        source=source,
    )
    names = JOBS[job]
    packets = {}
    for name in names:
        raw = store.fetch(api, expected, record["storage"], name)
        packets[name] = control.attach(record, name, raw)
    owner = record["owner"]
    first = packets[names[0]]
    phase = control.PHASES[names[0]]
    with ExitStack() as cleanup:
        state, prepared = cleanup.enter_context(
            consumer_candidate_state.materialize(
                root,
                first["envelope"],
                key=key,
                trust_key_path=trust_key_path,
                **owner,
                phase=phase,
                expected_context=first["context"],
                ciphertext_pin=first["ciphertext_sha256"],
                manifest_pin=first["manifest_sha256"],
            )
        )
        if prepared["workspace_id"] == record["origin"]["workspace_id"]:
            raise Rejected("campaign_consumer_workspace")
        if job == "serving":
            packet = packets["upstream-serving"]
            view, attached = cleanup.enter_context(
                upstream.materialize(
                    root,
                    state,
                    packet["envelope"],
                    key=key,
                    **owner,
                    reports=record["reports"],
                    phase=phase,
                    expected_context=packet["context"],
                    ciphertext_pin=packet["ciphertext_sha256"],
                    workspace_id=prepared["workspace_id"],
                )
            )
            if view != state or attached["reports"] != record["reports"]:
                raise Rejected("campaign_consumer_upstream")
        # The serving driver imports the signed validation split into its own SQL.
        # Caller must clean owned runtime resources before leaving this scope.
        yield state, prepared, record, packets
