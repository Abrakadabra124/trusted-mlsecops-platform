"""Private producer cluster witness; hosted-only start/cleanup, no SQL ownership."""

import sys
import traceback
from pathlib import Path

from mlsecops import cluster, controller_bootstrap, kube_storage, storage_pki
from mlsecops.contracts import Rejected, atomic_write, bounded_read, canonical, safe_child
from scripts import ci_consumer_native as driver
from scripts import ci_consumer_recovery as recovery

WITNESS = "producer-cluster-witness"


def need(value):
    if not value:
        raise Rejected("ci_producer_cluster_rejected")


def start(root, producer):
    original = driver.source(root, driver.IMAGE)
    owner = driver.run_owner()
    storage_pki.workspace_id(producer)
    workspace = bounded_read(safe_child(producer, "workspace.json"))
    state = safe_child(producer, WITNESS)
    state.mkdir(mode=0o700, exist_ok=False)
    # Exact original workspace only: never initialize another authority or keys.
    atomic_write(safe_child(state, "workspace.json"), workspace)
    witness = recovery.Recovery.begin(state, owner, original)
    witness.arm_cluster()
    try:
        cluster.bootstrap(producer)
    finally:
        # kind --retain may leave a node before cluster.json or Kubernetes readiness.
        witness.observe_cluster(producer)
    kube_storage.bootstrap(producer)
    controller_bootstrap.bootstrap(root, producer, driver.IMAGE)


def cleanup(producer):
    state = safe_child(producer, WITNESS)
    need(
        bounded_read(safe_child(state, "workspace.json"))
        == bounded_read(safe_child(producer, "workspace.json"))
    )
    witness = recovery.Recovery(state)
    need(canonical(witness.record["run_owner"]) == canonical(driver.run_owner()))
    need(witness.record["sql"] is None)
    result = witness.cleanup()
    need(canonical(result) == canonical({"sql": True, "cluster": True}))


def execute(root, action):
    valid = action in ("start", "cleanup")
    summary = dict(
        stage=action if valid else "arguments",
        status="fail",
        cleanup_counts=dict(required=1, verified=0),
    )
    if not valid:
        return summary
    try:
        producer = safe_child(root, ".runtime")
        with driver.private_output(producer, "producer-cluster-" + action):
            try:
                driver.hosted()
                if action == "start":
                    start(root, producer)
                else:
                    cleanup(producer)
            except BaseException:
                traceback.print_exc()
                return summary
        # Log flushing/restoration must also succeed before returning pass.
        summary["status"] = "pass"
        summary["cleanup_counts"]["verified"] = int(action == "cleanup")
    except BaseException:
        pass
    return summary


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    action = arguments[0] if len(arguments) == 1 else None
    summary = execute(Path(__file__).resolve().parents[1], action)
    print(canonical(summary).decode())
    return int(summary["status"] != "pass")


if __name__ == "__main__":
    sys.exit(main())
