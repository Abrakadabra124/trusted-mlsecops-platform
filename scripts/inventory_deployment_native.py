"""T25 capture on the hosted runner owning the evaluated candidate and disposable stores."""

import uuid
from pathlib import Path

from mlsecops import inventory_gate as gate
from mlsecops.contracts import canonical, digest
from scripts import canary_rollback_native, inventory_fleet_native, inventory_promotion_native
from scripts import canary_rollout_native as rollout


def capture(root, state, *, full=True):
    before = gate.inputs(root, state)
    if full:
        campaign = uuid.uuid4().hex
        fleet = inventory_fleet_native.capture(root, state, before[0], before[2], campaign)
        record = rollout.traffic(root, state, inventory=True, campaign=campaign)
        record["fleet"] = fleet
    else:
        record = rollout.traffic(root, state, inventory=True)
    traffic = record["traffic"]
    graph, snapshot, ancestor = gate.materialize(root, state, record, before[2])
    if full:
        graph, snapshot, ancestor, _, _ = gate.full_graph(
            root, state, record, before[0], before[2], ancestor
        )
    faults = gate.refusals(graph, snapshot, ancestor)
    proofs = {}

    def check_head(models, authority, fixture, args, public):
        proofs.update(
            inventory_promotion_native.capture(models, authority, fixture, args, public, faults)
        )

    durable = canary_rollback_native.drill(
        root,
        state,
        rollout.IMAGE,
        traffic["campaign"],
        rollout.probe_features(traffic),
        revoke_datasets=True,
        check_inventory_head=check_head,
    )
    owner, marker, files = gate.inputs(root, state)
    gate.require((owner, marker, files) == before)
    return dict(
        schema_version=2 if full else 1,
        storage_sha256=digest(canonical(marker)),
        graph=graph,
        snapshot=snapshot,
        durable=durable,
        denials=proofs,
        **record,
    )


def main(root):
    state = root / ".runtime"
    try:
        rollout.publish_pin(state, gate.PACKET, capture(root, state))
    except Exception as error:
        print(canonical(dict(status="fail", site=rollout.failure_site(error))).decode(), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(__file__).resolve().parents[1]))
