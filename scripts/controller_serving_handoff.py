"""Replace the disposable training cluster, preserving the authoritative host SQL."""

import os
import time
from pathlib import Path

from mlsecops import (
    cluster,
    kube_storage,
    kube_storage_migration,
    release_bundle,
    signing,
    storage_bootstrap,
    storage_pipeline,
    storage_restore,
    storage_schema,
)
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_qualification import probe
from mlsecops.kube_worker import load_image
from scripts.candidate_serving_reader import bind_proposal
from scripts.controller_delivery import reconcile
from scripts.kube_trust_native import hosted


def host_snapshot(root, state, demo_pin, proposal_pin, keys_pin):
    demo = decode(read_pinned(state / "storage-demo.json", demo_pin))
    proposal = decode(read_pinned(state / "evidence/release-native.json", proposal_pin))
    public = read_json(state / "trusted-keys.json")
    trust = read_json(state / "storage-trust.json")
    if (
        digest(canonical(public)) != keys_pin
        or any(trust[k] != public[k] for k in ("curator", "evaluator"))
        or any(
            signing.encode64(
                signing.load_key(state / "keys" / (role + ".pem")).public_key().public_bytes_raw()
            )
            != public[role]
            for role in signing.ROLES
        )
    ):
        raise Rejected("serving_handoff_owner_keys")
    policy = read_json(root / "policies/local-cpu.json")
    client = state / "storage-clients/promoter"
    package = release_bundle.load(
        client, proposal["proposal_reference"], publisher_public=public["approver"]
    )
    context, verified = bind_proposal(
        proposal,
        package,
        policy=policy,
        source_trust=trust,
        publisher_public=public["approver"],
        clock=int(time.time()),
        expected=dict(
            source_revision=os.environ["GITHUB_SHA"],
            source_fingerprint=source_fingerprint(root),
            image_id=demo["candidate"]["metadata"]["image_id"],
        ),
    )
    if (
        context["candidate_reference"] != demo["candidate"]["candidate_reference"]
        or context["evaluation_reference"] != demo["evaluation_reference"]
        or digest(verified["model"]) != demo["candidate"]["metadata"]["model_digest"]
        or storage_pipeline.read_evaluation(
            client, context["evaluation_reference"], context["candidate_reference"], policy, trust
        )
        != demo["evaluation"]
    ):
        raise Rejected("serving_handoff_signed_subject")
    owner = storage_bootstrap.validate(state)
    return dict(
        owner=owner,
        ledger=storage_restore.ledger(owner["name"]),
        demo=demo_pin,
        proposal=proposal_pin,
        keys=keys_pin,
        keys_file=digest(bounded_read(state / "trusted-keys.json")),
        trust_file=digest(bounded_read(state / "storage-trust.json")),
        candidate=context["candidate_reference"],
        evaluation=context["evaluation_reference"],
    )


def preserved_history(state, owner, original, current):
    # Both ledgers already verified sha256(payload) for every row. A superset on
    # the host must also retain the original timestamp of every historical object.
    for table in storage_schema.TABLES:
        if original[table] == current[table]:
            continue
        if original[table]["rows"] > current[table]["rows"]:
            raise Rejected("serving_handoff_history_missing")
        query = f"SELECT coalesce(jsonb_object_agg(sha256,extract(epoch FROM created_at)::text),'{{}}') FROM ml.{table};"
        previous = decode(kube_storage.admin(state, query))
        present = decode(storage_bootstrap.admin(owner["name"], query))
        if len(previous) != original[table]["rows"] or any(
            present.get(k) != v for k, v in previous.items()
        ):
            raise Rejected("serving_handoff_history_missing")


def owned_node(state):
    marker = cluster.validate_cluster(state)
    node = storage_bootstrap.inspect("container", cluster.NODE)
    labels = node["Config"]["Labels"]
    if (
        command(["kind", "get", "nodes", "--name", cluster.NAME]).splitlines() != [cluster.NODE]
        or node["Name"] != "/" + cluster.NODE
        or labels.get("io.x-k8s.kind.cluster") != cluster.NAME
        or labels.get("io.x-k8s.kind.role") != "control-plane"
    ):
        raise Rejected("serving_handoff_kind_ownership")
    volumes = [m["Name"] for m in node["Mounts"] if m["Type"] == "volume"]
    if any(
        command(["docker", "ps", "-aq", "--no-trunc", "--filter", "volume=" + volume]).splitlines()
        != [node["Id"]]
        for volume in volumes
    ):
        raise Rejected("serving_handoff_shared_node_volume")
    return {"container": node["Id"], "namespace": marker["namespace_uid"], "volumes": volumes}


def replace(root, state, *, demo_pin, proposal_pin, keys_pin):
    hosted()
    if (
        state != (root / ".runtime").resolve()
        or root != Path(os.environ["GITHUB_WORKSPACE"]).resolve()
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != os.environ["GITHUB_SHA"]
        or command(["git", "-C", str(root), "status", "--porcelain"])
    ):
        raise Rejected("serving_handoff_workspace")
    reports = reconcile(
        state,
        demo_pin=demo_pin,
        proposal_pin=proposal_pin,
        keys_pin=keys_pin,
        revision=os.environ["GITHUB_SHA"],
    )
    before = host_snapshot(root, state, demo_pin, proposal_pin, keys_pin)
    owner = before["owner"]
    old = owned_node(state)
    private = kube_storage.validate(state)
    signed = signing.verify(
        read_json(state / "evidence/controller-history-transfer.json"),
        "controller-history-transfer",
        read_json(state / "trusted-keys.json")["trust"],
    )
    if (
        signed["workspace"] != owner["workspace_id"]
        or signed["host_container"] != owner["container_id"]
        or signed["volume_uid"] != private["volume_uid"]
        or signed["after"] != kube_storage_migration.ledger(state)
        or kube_storage_migration.connection_limit(state) != 0
    ):
        raise Rejected("serving_handoff_training_storage")
    preserved_history(state, owner, signed["after"], before["ledger"])
    tag, image = load_image(state, "trusted-mlsecops:dev")
    denied = probe(state, tag, image, "ml-serving", "serving", "maintenance")
    if denied != {"status": "pass", "role": "serving", "result": "database-maintenance-denied"}:
        raise Rejected("serving_handoff_fence_control")
    retired = safe_child(state, "retired-training-cluster")
    markers = [
        safe_child(state, name)
        for name in ("cluster.json", "kubeconfig", "kubernetes-storage", "controllers")
    ]
    if (
        retired.exists()
        or not all(path.exists() for path in markers)
        or any(
            (state / name).exists()
            for name in ("serving/resources.json", "kubernetes-trust/resources.json")
        )
    ):
        raise Rejected("serving_handoff_requires_original_training_cluster")
    retired.mkdir(mode=0o700)
    if owned_node(state) != old:
        raise Rejected("serving_handoff_training_node_changed")
    cleanup_config = retired / "teardown-kubeconfig"
    atomic_write(cleanup_config, bounded_read(state / "kubeconfig"))
    command(
        ["kind", "delete", "cluster", "--name", cluster.NAME, "--kubeconfig", str(cleanup_config)],
        timeout=120,
    )
    if (
        cluster.NAME in command(["kind", "get", "clusters"]).splitlines()
        or old["container"] in command(["docker", "ps", "-aq", "--no-trunc"]).splitlines()
        or set(old["volumes"])
        & set(command(["docker", "volume", "ls", "--format", "{{.Name}}"]).splitlines())
    ):
        raise Rejected("serving_handoff_training_node_survived")
    for path in markers:
        path.rename(retired / path.name)
    cluster.bootstrap(state)
    kube_storage.bootstrap(state)
    new = owned_node(state)
    fresh = kube_storage.validate(state)
    empty = kube_storage_migration.ledger(state)
    if (
        new["container"] == old["container"]
        or new["namespace"] == old["namespace"]
        or fresh["volume_uid"] == private["volume_uid"]
        or fresh["pod_uid"] == private["pod_uid"]
        or any(row["rows"] for row in empty.values())
        or kube_storage_migration.connection_limit(state) != -1
    ):
        raise Rejected("serving_handoff_private_sql_not_fresh")
    tag, image = load_image(state, "trusted-mlsecops:dev")
    access = probe(state, tag, image, "ml-serving", "serving", "sql")
    required = {
        "serving:authenticated-role",
        "serving:tls-1.3",
        "serving:read-releases",
        "serving:read-candidates",
    }
    if (
        access["status"] != "pass"
        or access["role"] != "serving"
        or not required.issubset(
            {case["id"] for case in access["cases"] if case["status"] == "pass"}
        )
        or kube_storage_migration.ledger(state) != empty
    ):
        raise Rejected("serving_handoff_serving_readback")
    if host_snapshot(root, state, demo_pin, proposal_pin, keys_pin) != before:
        raise Rejected("serving_handoff_host_changed")
    report = dict(
        status="pass",
        release_ready=False,
        host_container=owner["container_id"],
        candidate=before["candidate"],
        evaluation=before["evaluation"],
        proposal_packet=proposal_pin,
        demo_packet=demo_pin,
        keys=keys_pin,
        old_cluster=old,
        new_cluster=new,
        old_volume=private["volume_uid"],
        new_volume=fresh["volume_uid"],
        serving_role_checks=access["count"],
        host_ledger=digest(canonical(before["ledger"])),
        reports=reports,
    )
    write_json(state / "evidence/controller-serving-handoff.json", report)
    return report


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    print(
        canonical(
            replace(
                root,
                root / ".runtime",
                demo_pin=os.environ["M17_DEMO_SHA256"],
                proposal_pin=os.environ["M17_PROPOSAL_SHA256"],
                keys_pin=os.environ["M17_KEYS_SHA256"],
            )
        ).decode()
    )
