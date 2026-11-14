"""M19 acceptance for the observed qualification inventory and dataset revocation."""

import copy
import os
from datetime import UTC, datetime, timedelta

from mlsecops import asset_graph, canary_native_evidence, release_bundle, storage_bootstrap
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
)
from mlsecops.security_events import hexadecimal
from scripts import (
    asset_graph_fixture,
    canary_rollback_native,
    canary_rollout_native,
    inventory_promotion_native,
)
from scripts.candidate_lineage_native import KNOWN_OWNERS

PACKET = "evidence/M19-inventory-private.json"
SCOPE = "evaluated-candidate-dataset-to-qualification-deployment"
OWNER_FILES = {
    "M19_PROPOSAL_SHA256": "evidence/release-native.json",
    "M19_KEYS_SHA256": "trusted-keys.json",
    "M19_DEMO_SHA256": "storage-demo.json",
}


def require(condition):
    if not condition:
        raise Rejected("M19_inventory_binding")


def reference(asset):
    return {key: asset[key] for key in ("asset_id", "sha256")}


def deployment(source, binding, report, policy, *, observation, publisher, worker_id=None):
    """Extend the authenticated candidate graph with its proposal and one observed activation."""
    envelope = source["proposal"]
    require_fields(
        observation,
        ("permit_sha256", "subject_sha256", "model_sha256", "image_id", "evaluation_policy_sha256"),
    )
    manifest = release_bundle.index(envelope, publisher)
    projection = source["projection"]
    materials = manifest["materials"]
    require(
        observation["image_id"] == manifest["serving_image"]
        and digest(canonical(envelope))
        == report["proposal_reference"]
        == binding["proposal_reference"]
        and digest(canonical(manifest)) == report["subject_sha256"] == binding["subject_sha256"]
        and digest(canonical(projection)) == materials["asset_projection"]
        and digest(canonical(policy)) == materials["evaluation_policy"]
        and manifest["environment"] == policy["environment"] == "local-cpu"
        and manifest["source_commit"] == report["source"]["source_revision"]
        and manifest["training_image"] == manifest["serving_image"] == report["source"]["image_id"]
        and projection["bindings"]["dataset_reference"] == materials["dataset_manifest"]
        and projection["bindings"]["candidate_reference"] == binding["candidate_reference"]
        and projection["bindings"]["evaluation_reference"]
        == materials["evaluation_report"]
        == binding["evaluation_reference"]
    )
    graph = copy.deepcopy(projection["graph"])
    nodes = {a["kind"]: a for a in graph["assets"]}
    require(
        len(graph["assets"]) == len(nodes) == 5
        and nodes["model"]["sha256"] == materials["model"] == report["model_sha256"]
        and nodes["run"]["sha256"] == materials["provenance"]
        and nodes["runtime"]["sha256"] == manifest["serving_image"].removeprefix("sha256:")
        and nodes["policy"]["sha256"] == materials["evaluation_policy"]
        and nodes["dataset"]["sha256"] == materials["split_manifest"] != materials["model"]
    )
    permit = hexadecimal(binding["permit_sha256"])
    require(observation["permit_sha256"] == permit)
    identifier = permit if worker_id is None else hexadecimal(worker_id)
    release = dict(
        asset_id="release-" + binding["subject_sha256"],
        kind="release",
        sha256=binding["subject_sha256"],
        owner=manifest["owner"],
        environment=manifest["environment"],
        dependencies=[reference(nodes[k]) for k in ("model", "runtime", "policy")],
    )
    endpoint = dict(
        asset_id="deployment-" + identifier,
        kind="deployment",
        sha256=identifier,
        owner="platform-owner",
        environment=manifest["environment"],
        dependencies=[reference(release)],
    )
    graph["assets"].extend((release, endpoint))
    row = dict(
        asset_id=endpoint["asset_id"],
        sha256=identifier,
        release_sha256=observation["subject_sha256"],
        model_sha256=observation["model_sha256"],
        runtime_sha256=observation["image_id"].removeprefix("sha256:"),
        policy_sha256=observation["evaluation_policy_sha256"],
    )
    snapshot = dict(
        schema_version=1,
        environment=manifest["environment"],
        graph_sha256=digest(canonical(graph)),
        deployments=[row],
    )
    ancestor = reference(nodes["dataset"])
    impacts(graph, snapshot, ancestor)
    return graph, snapshot, ancestor


def impacts(graph, snapshot, ancestor):
    return asset_graph.assess(graph, KNOWN_OWNERS, "local-cpu", snapshot, [ancestor])


def fault_inputs(graph, snapshot, ancestor):
    affected = impacts(graph, snapshot, ancestor)["blocked_deployments"][0]
    for reason in ("owner", "dangling", "cycle", "digest"):
        changed, observed = copy.deepcopy((graph, snapshot))
        root = next(a for a in changed["assets"] if a["asset_id"] == ancestor["asset_id"])
        endpoint = next(a for a in changed["assets"] if a["asset_id"] == affected)
        if reason == "owner":
            root["owner"] = "unknown-owner"
        elif reason == "dangling":
            endpoint["dependencies"][0]["asset_id"] = "missing-release"
        elif reason == "cycle":
            root["dependencies"] = [reference(endpoint)]
        else:
            model = observed["deployments"][0]["model_sha256"]
            observed["deployments"][0]["model_sha256"] = digest(model.encode())
        # Keep graph/snapshot hashes consistent: each rejection must come from the semantic fault.
        observed["graph_sha256"] = digest(canonical(changed))
        yield reason, changed, observed


def refusals(graph, snapshot, ancestor):
    reasons = {}
    for reason, changed, observed in fault_inputs(graph, snapshot, ancestor):
        try:
            impacts(changed, observed, ancestor)
        except asset_graph.InventoryMismatch as error:
            require(error.reason == reason)
            reasons[reason] = dict(
                reason=str(error),
                graph=digest(canonical(changed)),
                snapshot=digest(canonical(observed)),
            )
        else:
            raise Rejected("M19_negative_accepted")
    return reasons


def fixture_impact():
    graph, snapshot, revoked = asset_graph_fixture.fixture()
    result = impacts(graph, snapshot, revoked[0])
    expected = sorted(
        [
            "dataset-a",
            "deployment-a-canary",
            "deployment-a-primary",
            "deployment-a-rollback",
            *(
                kind + "-" + role
                for kind in ("run", "model", "release")
                for role in ("a-current", "a-previous")
            ),
        ]
    )
    require(
        result["asset_count"] == 17
        and result["impacted_assets"] == expected
        and result["blocked_deployments"]
        == ["deployment-a-canary", "deployment-a-primary", "deployment-a-rollback"]
        and result["unaffected_deployments"] == ["deployment-b"]
    )
    return dict(
        expected=expected,
        actual=result["impacted_assets"],
        blocked=result["blocked_deployments"],
        unaffected=result["unaffected_deployments"],
    )


def inputs(root, state):
    require(state.resolve() == safe_child(root, ".runtime") and not state.is_symlink())
    delivery = any(k in os.environ for k in ("M19_TRUST_SHA256", "M19_WORKSPACE_ID"))
    additional = ("M19_TRUST_SHA256", "M19_WORKSPACE_ID", "GITHUB_SHA") if delivery else ()
    if not all(
        os.environ.get(k)
        for k in (*OWNER_FILES, *additional, "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    ):
        raise FileNotFoundError("M19 owner pins unavailable")
    canary_rollout_native.hosted()
    marker = storage_bootstrap.validate(state)
    owner = canary_rollout_native.capture_inputs(root, "M19_PROPOSAL_SHA256")
    files, raw_pins = {}, {}
    paths = {**OWNER_FILES, **({"M19_TRUST_SHA256": "storage-trust.json"} if delivery else {})}
    for variable, path in paths.items():
        content = bounded_read(safe_child(state, path))
        files[path] = decode(content)
        raw_pins[path] = digest(content)
        measured = (
            digest(canonical(files[path]))
            if delivery and variable == "M19_KEYS_SHA256"
            else raw_pins[path]
        )
        require(measured == hexadecimal(os.environ[variable]))
    if delivery:
        require(
            marker["workspace_id"] == hexadecimal(os.environ["M19_WORKSPACE_ID"], 32)
            and owner["source"]["source_revision"] == hexadecimal(os.environ["GITHUB_SHA"], 40)
        )
        files["delivery"] = dict(
            schema_version=1,
            owner=owner,
            workspace_id=marker["workspace_id"],
            storage_sha256=digest(canonical(marker)),
            files=raw_pins,
        )
    return owner, marker, files


def materialize(root, state, record, files):
    read = canary_native_evidence.read_pinned
    traffic = record["traffic"]
    directory = safe_child(state, "evidence/canary-native-" + hexadecimal(traffic["campaign"], 32))
    src = decode(
        read(safe_child(directory, "inventory-source.json"), record["inventory_source_sha256"])
    )
    require_fields(src, ("projection", "proposal"))
    report = files["evidence/release-native.json"]
    keys = files["trusted-keys.json"]
    demo = files["storage-demo.json"]
    policy = read_json(root / "policies/local-cpu.json")
    graph, snapshot, ancestor = deployment(
        src,
        traffic["candidate"],
        report,
        policy,
        observation=record["observation"],
        publisher=keys["approver"],
    )
    require(
        ancestor["sha256"] == demo["candidate"]["metadata"]["dataset_id"]
        and ancestor["sha256"] == demo["dataset"]["dataset_id"]
        and src["projection"]["bindings"]["dataset_reference"]
        == demo["dataset"]["dataset_reference"]
    )
    return graph, snapshot, ancestor


def full_graph(root, state, record, owner, files, ancestor):
    from mlsecops import inventory_fleet
    from scripts.inventory_fleet_native import pinned

    traffic = record["traffic"]
    result = inventory_fleet.replay(
        state,
        record["fleet"],
        inputs=pinned(state),
        files=files,
        owner=owner,
        campaign=traffic["campaign"],
        policy=read_json(root / "policies/local-cpu.json"),
        features=canary_rollout_native.probe_features(traffic),
    )
    require(result[2] == ancestor)
    return result


def qualify(root, state):
    if not os.environ.get("M19_PRIMARY_SHA256") or not safe_child(state, PACKET).is_file():
        raise FileNotFoundError("M19 capture unavailable")
    owner, marker, files = inputs(root, state)
    require(
        storage_bootstrap.inspect("container", marker["container_id"])["State"]["Running"] is False
    )
    pin = hexadecimal(os.environ["M19_PRIMARY_SHA256"])
    record = decode(canary_native_evidence.read_pinned(safe_child(state, PACKET), pin))
    require(isinstance(record, dict))
    full = record.get("schema_version") == 2
    require_fields(
        record,
        (
            "schema_version",
            "storage_sha256",
            "traffic",
            "observation",
            "reader_refusal",
            "inventory_source_sha256",
            "graph",
            "snapshot",
            "durable",
            "denials",
            *(("fleet",) if full else ()),
        ),
    )
    require(
        type(record["schema_version"]) is int
        and record["schema_version"] in (1, 2)
        and record["storage_sha256"] == digest(canonical(marker))
        and record["reader_refusal"] == "trust_artifact_revoked"
    )
    traffic = record["traffic"]
    graph, snapshot, ancestor = materialize(root, state, record, files)
    replay = canary_native_evidence.replay(
        state, traffic, **owner, revoked_dataset=ancestor["sha256"]
    )
    impact = impacts(graph, snapshot, ancestor)
    expected = sorted(
        a["asset_id"]
        for a in graph["assets"]
        if a["kind"] in ("dataset", "run", "model", "release", "deployment")
    )
    require(
        len(expected) == 5
        and impact["impacted_assets"] == expected
        and impact["blocked_deployments"] == [snapshot["deployments"][0]["asset_id"]]
    )
    if full:
        graph, snapshot, ancestor, expected, denial_times = full_graph(
            root, state, record, owner, files, ancestor
        )
        impact = impacts(graph, snapshot, ancestor)
    require(canonical((graph, snapshot)) == canonical((record["graph"], record["snapshot"])))
    fault = traffic["recovery"]
    denied_ns = fault["candidate"][-1]["end_ns"] - fault["start_ns"]
    require(
        0
        <= denied_ns
        <= read_json(root / "policies/local-cpu.json")["trust_lease_seconds"] * 1_000_000_000
    )
    negative = refusals(graph, snapshot, ancestor)
    durable = record["durable"]
    require(
        durable["campaign"] == traffic["campaign"]
        and durable["image"] == traffic["candidate"]["image_id"]
        and durable["features"] == canary_rollout_native.probe_features(traffic)
    )
    control = canary_rollback_native.replay(durable, revoke_datasets=True)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    start_us = (datetime.fromisoformat(traffic["finished_at"]) - epoch) // timedelta(microseconds=1)
    require(durable["events"]["initial_trust"]["start"]["wall_ns"] >= start_us * 1000)
    if full:
        fleet = record["fleet"]
        slice_start = (datetime.fromisoformat(traffic["started_at"]) - epoch) // timedelta(
            microseconds=1
        )
        require(fleet["finished"]["wall_ns"] // 1000 <= slice_start)
    denials = inventory_promotion_native.replay(record["denials"], negative, durable)
    fixture = fixture_impact()
    names = [
        "candidate-deployment-graph",
        "signed-dataset-revocation-to-http-503",
        "exact-fixture-rollback-and-independent-branch",
        "controlled-revoked-dataset-rollback-denied",
        "controlled-independent-branch-serves",
        *("promotion-rejected-" + r for r in negative),
    ]
    if full:
        names.extend(
            (
                "four-live-workers-shared-runtime-and-policy",
                "previous-version-served-before-current",
                "exact-observed-ancestor-closure",
                "three-descendants-denied-within-lease",
                "independent-worker-serves-after-all-denials",
            )
        )
    cases = [dict(id="M19-" + name, status="pass", expected=True, actual=True) for name in names]
    return dict(
        status="pass" if full else "inconclusive",
        cases=cases,
        source_dirty=False,
        started_at=(
            epoch
            + timedelta(
                microseconds=fleet["deployments"]["previous"]["history"]["wall_start_ns"] // 1000
            )
        ).isoformat()
        if full
        else traffic["started_at"],
        checks=len(cases),
        metrics=dict(
            expected=expected,
            actual=impact["impacted_assets"],
            blocked=impact["blocked_deployments"],
            fixture=fixture,
            refusals=negative,
            evaluated_candidate_graph=graph,
            deployment_snapshot=snapshot,
            controlled_rollback_denial=control["rejected_rollback_event"],
            controlled_promotion_denials=denials,
            dataset_denial_ns=denied_ns,
            traffic_requests=replay["requests"],
            **(
                dict(
                    unaffected=impact["unaffected_deployments"],
                    fleet_denial_ns=denial_times,
                    deployment_roles={
                        r: "deployment-" + o["container"] for r, o in fleet["deployments"].items()
                    },
                )
                if full
                else {}
            ),
        ),
        artifact_hashes=dict(
            primary=pin,
            proposal=owner["proposal_pin"],
            methods=owner["methods"],
            storage_marker=record["storage_sha256"],
            graph=impact["graph_sha256"],
            snapshot=impact["snapshot_sha256"],
            inventory_source=record["inventory_source_sha256"],
            traffic_rows=replay["primary_traffic_sha256"],
            candidate_journal=traffic["journals"]["candidate"],
            stable_journal=traffic["journals"]["stable"],
            candidate_source=traffic["candidate"]["source_evidence_sha256"],
            controlled_rollback=digest(canonical(durable)),
            promotion_denials=digest(canonical(record["denials"])),
            demo=hexadecimal(os.environ["M19_DEMO_SHA256"]),
            public_keys=hexadecimal(os.environ["M19_KEYS_SHA256"]),
            **(
                dict(
                    proposal_packet=owner["proposal_pin"],
                    source_trust=files["delivery"]["files"]["storage-trust.json"],
                    delivery_source=digest(canonical(files["delivery"])),
                )
                if "delivery" in files
                else {}
            ),
            **(
                dict(
                    fleet_inputs=hexadecimal(os.environ["M19_FLEET_INPUTS_SHA256"]),
                    fleet=digest(canonical(fleet)),
                    **{r + "_fleet_journal": o["journal"] for r, o in fleet["deployments"].items()},
                )
                if full
                else {}
            ),
        ),
        input_digests=dict(
            **owner["source"],
            candidate_reference=replay["candidate"],
            qualified_model=replay["model"],
            dataset=ancestor["sha256"],
            qualified_subject=replay["release_subject"],
            **(
                dict(
                    release_subject=replay["release_subject"],
                    model=replay["model"],
                    evaluation_reference=traffic["candidate"]["evaluation_reference"],
                    proposal_reference=traffic["candidate"]["proposal_reference"],
                    image_id=traffic["candidate"]["image_id"],
                    qualified_candidate_subject=replay["release_subject"],
                    qualified_candidate_model=replay["model"],
                )
                if full
                else {}
            ),
        ),
        limitations=[
            "Four observed loopback qualification deployments in one disposable synthetic lab. All three evaluated proposals remain unapproved.",
            "Durable promotion and rollback rejection use separately approved controlled releases.",
        ]
        if full
        else [
            "One evaluated qualification deployment observed. The four-deployment inventory is a structural fixture.",
            "Rollback, independent service and durable promotion refusals use separately approved controlled releases. The evaluated candidate has no approved selection or deployed rollback history.",
        ],
    )
