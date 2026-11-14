"""T25 capture on the hosted runner owning the evaluated candidate and disposable stores."""

from pathlib import Path

from mlsecops import inventory_gate as gate
from mlsecops.contracts import canonical, digest
from scripts import canary_rollback_native, inventory_promotion_native
from scripts import canary_rollout_native as rollout


def capture(root, state):
    before = gate.inputs(root, state)
    record = rollout.traffic(root, state, inventory=True)
    traffic = record["traffic"]
    graph, snapshot, ancestor = gate.materialize(root, state, record, before[2])
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
        schema_version=1,
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
