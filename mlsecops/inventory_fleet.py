"""Offline reconciliation of four co-resident qualification deployments and a shared revocation."""

from collections import Counter
from dataclasses import asdict

from mlsecops import audit_lineage, canary_journal, release_bundle, release_policy, signing, trust
from mlsecops import inventory_gate as gate
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.candidate_serving_reader import FLEET_KIND, KIND, fleet_policy
from mlsecops.contracts import canonical, decode, digest, require_fields, safe_child
from mlsecops.load_golden import Golden
from mlsecops.security_events import hexadecimal

ROLES = {
    "previous": "previous",
    "primary": "current",
    "canary": "current",
    "independent": "independent",
}
SCOPE = "four-observed-qualification-deployments-under-shared-dataset-revocation"
NS = 10**9
require = gate.require


def sha(value):
    return digest(canonical(value))


def stamp(value):
    require(type(value) is int and 0 < value < 2**63)
    return value


def reconcile(branches, observations):
    """Union the signed graph paths by identity, requiring every live worker to be distinct."""
    require_fields(branches, ROLES)
    require_fields(observations, ROLES)
    assets, rows, roots, expected, blocked = {}, [], {}, set(), []
    for role, (branch, snapshot, root) in branches.items():
        ob = observations[role]
        worker = hexadecimal(ob["container"])
        hexadecimal(ob["session"], 32)
        require(type(ob["port"]) is int and 1 <= ob["port"] <= 65535)
        (row,) = snapshot["deployments"]
        require(row["asset_id"] == "deployment-" + worker and row["sha256"] == worker)
        rows.append(row)
        roots[role] = root
        for node in branch["assets"]:
            require(assets.setdefault(node["asset_id"], node) == node)
            if role != "independent" and node["kind"] not in ("runtime", "policy"):
                expected.add(node["asset_id"])
        if role != "independent":
            blocked.append(row["asset_id"])
    for key in ("port", "session", "container"):
        require(len({ob[key] for ob in observations.values()}) == 4)
    require(roots["previous"] == roots["primary"] == roots["canary"] != roots["independent"])
    counts = dict(dataset=2, model=3, run=3, release=3, deployment=4, runtime=1, policy=1)
    require(Counter(a["kind"] for a in assets.values()) == counts)
    for kind, count in counts.items():
        require(len({a["sha256"] for a in assets.values() if a["kind"] == kind}) == count)
    graph = dict(schema_version=1, assets=[assets[k] for k in sorted(assets)])
    snapshot = dict(
        schema_version=1,
        environment="local-cpu",
        graph_sha256=sha(graph),
        deployments=sorted(rows, key=lambda row: row["asset_id"]),
    )
    ancestor = roots["primary"]
    result = gate.impacts(graph, snapshot, ancestor)
    require(
        len(expected) == 10
        and result["impacted_assets"] == sorted(expected)
        and result["blocked_deployments"] == sorted(blocked)
        and result["unaffected_deployments"]
        == ["deployment-" + observations["independent"]["container"]]
    )
    return graph, snapshot, ancestor, sorted(expected)


def source(item, report, keys, qualification_root, campaign, owner_source, policy, clock, label):
    require_fields(item, ("proposal", "projection", "lineage_envelope", "permit", "golden"))
    manifest = release_bundle.index(item["proposal"], keys["approver"])
    materials = manifest["materials"]
    projection = item["projection"]
    pins = projection["bindings"]
    require(
        report["source"] == {**owner_source, "image_id": manifest["serving_image"]}
        and report["status"] == "pass"
        and report["source_dirty"] is False
        and report["release_ready"] is False
        and type(manifest["sequence"]) is int
        and manifest["sequence"] == (2 if label == "current" else 1)
        and manifest["release_id"] == report["campaign_id"]
        and sha(manifest) == report["subject_sha256"]
        and sha(item["proposal"]) == report["proposal_reference"]
        and materials["model"] == report["model_sha256"]
        and sha(projection) == materials["asset_projection"]
        and sha(item["lineage_envelope"]) == pins["lineage_object"]
    )
    release_policy.window(manifest, clock)
    lineage = signing.verify(item["lineage_envelope"], "data-lineage", keys["curator"])
    require(
        sha(lineage) == pins["lineage_id"]
        and lineage["dataset_id"] == materials["split_manifest"]
        and lineage["policy_digest"] == sha(policy)
    )
    trace = audit_lineage.Lineage(
        owner_source["source_revision"],
        owner_source["source_fingerprint"],
        lineage["source_sha256"],
        pins["source_approval_digest"],
        materials["dataset_manifest"],
        pins["lineage_object"],
        materials["provenance"],
        materials["evaluation_report"],
    )
    permit = release_policy.checked(item["permit"], KIND, qualification_root)
    fixed = dict(
        schema_version=1,
        purpose=KIND,
        campaign_id=campaign,
        environment="local-cpu",
        proposal_sha256=report["proposal_reference"],
        subject_sha256=report["subject_sha256"],
        model_sha256=report["model_sha256"],
        **report["source"],
    )
    require_fields(permit, (*fixed, "issued_at", "expires_at"))
    require(canonical({k: permit[k] for k in fixed}) == canonical(fixed))
    release_policy.window(permit, clock, maximum=600)
    binding = {
        **fixed,
        "proposal_reference": fixed["proposal_sha256"],
        "permit_sha256": sha(permit),
        "candidate_reference": pins["candidate_reference"],
        "evaluation_reference": pins["evaluation_reference"],
    }
    require_fields(item["golden"], ("features", "scores"))
    golden = Golden.from_expected(
        {**item["golden"], "bundle": fixed["subject_sha256"], "model": fixed["model_sha256"]}
    )
    return binding, asdict(trace), golden


def probes(role, ob, golden, trace, binding, directory, start, committed, finished, lease):
    require_fields(
        ob,
        (
            "port",
            "container",
            "session",
            "loaded",
            "attestation",
            "activation_ns",
            "healthy",
            "after",
            "admissions",
            "reader_result",
            "trust_readback",
            "journal",
            "history",
        ),
    )
    affected = role != "independent"
    prior = [ob["history"]] if role == "previous" else []
    require(role == "previous" or ob["history"] is None)
    require(ob["reader_result"] == ("trust_artifact_revoked" if affected else "trust-version-2"))
    samples = [*prior, ob["healthy"], ob["after"]]
    cursor = stamp(ob["activation_ns"])
    exchanges = {}
    for i, sample in enumerate(samples):
        require_fields(
            sample, ("status", "reply", "start_ns", "end_ns", "wall_start_ns", "wall_end_ns")
        )
        require(cursor <= stamp(sample["start_ns"]) <= stamp(sample["end_ns"]))
        cursor = sample["end_ns"]
        require(stamp(sample["wall_start_ns"]) <= stamp(sample["wall_end_ns"]))
        reply = sample["reply"]
        identifier = hexadecimal(reply["request_id"], 32)
        require(identifier not in exchanges)
        exchanges[identifier] = sample
        if i < len(samples) - 1:
            require(
                sample["end_ns"] <= start["mono_ns"] and sample["wall_end_ns"] <= start["wall_ns"]
            )
        else:
            require(
                committed["mono_ns"]
                <= sample["start_ns"]
                <= sample["end_ns"]
                <= finished["mono_ns"]
                and committed["wall_ns"]
                <= sample["wall_start_ns"]
                <= sample["wall_end_ns"]
                <= finished["wall_ns"]
            )
        if affected and i == len(samples) - 1:
            require_fields(reply, ("schema_version", "request_id", "error"))
            require(
                sample["status"] == 503
                and type(reply["schema_version"]) is int
                and reply["schema_version"] == 1
                and reply["error"] == {"code": "model_unavailable"}
                and cursor - start["mono_ns"] <= lease
                and sample["wall_end_ns"] - start["wall_ns"] <= lease
            )
        else:
            require(sample["status"] == 200 and golden.valid(reply))
    before, after = ob["admissions"]
    require(
        type(before) is int
        and type(after) is int
        and before == len(samples) - 1
        and (after - before in (0, 1) if affected else after - before == 1)
    )
    journal = read_pinned(safe_child(directory, role + ".jsonl"), ob["journal"])
    canary_journal.reconcile(
        journal,
        [],
        samples,
        subject=golden.bundle,
        model=golden.model,
        authority=dict(
            kind="candidate-qualification",
            schema_version=2,
            release_ready=False,
            permit_sha256=binding["permit_sha256"],
            proposal_sha256=binding["proposal_reference"],
            lineage=trace,
        ),
        pre_admission_denial=after == before,
    )
    for raw in journal.splitlines():
        entry = decode(raw)
        event = entry["event"]
        if event["stage"] == "response_intended":
            sample = exchanges[event["request_id"]]
            require(sample["wall_start_ns"] <= entry["recorded_at_ns"] <= sample["wall_end_ns"])
    return cursor - start["mono_ns"]


def replay(state, fleet, *, inputs, files, owner, campaign, policy, features):
    require_fields(
        fleet,
        (
            "campaign",
            "owner",
            "sources",
            "roster",
            "deployments",
            "before",
            "after",
            "start",
            "committed",
            "finished",
        ),
    )
    require_fields(inputs, ("qualification_root", "reports"))
    require_fields(inputs["reports"], set(ROLES.values()))
    require_fields(fleet["sources"], set(ROLES.values()))
    observations = fleet["deployments"]
    require_fields(observations, ROLES)
    require(fleet["campaign"] == hexadecimal(campaign, 32) and fleet["owner"] == owner)
    keys = files["trusted-keys.json"]
    root = inputs["qualification_root"]
    require(signing.decode64(root) not in {signing.decode64(v) for v in keys.values()})
    reports = inputs["reports"]
    require(reports["current"] == files["evidence/release-native.json"])
    directory = safe_child(state, "evidence/M19-fleet-" + campaign)
    start, committed, finished = (fleet[k] for k in ("start", "committed", "finished"))
    for t in (start, committed, finished):
        require_fields(t, ("mono_ns", "wall_ns"))
        for v in t.values():
            stamp(v)
    for k in start:
        require(start[k] <= committed[k] <= finished[k])
    clock = finished["wall_ns"] // NS
    before, after = [
        trust.validate(fleet[k], root, "local-cpu", clock) for k in ("before", "after")
    ]
    trust.successor(before, after)
    require(
        before["version"] == 1
        and before["revoked_artifacts"] == before["revoked_keys"] == after["revoked_keys"] == []
        and start["wall_ns"] // NS <= after["issued_at"] <= committed["wall_ns"] // NS
    )
    branches, denials, seen = {}, {}, set()
    source_bytes = {}
    roster = release_policy.checked(fleet["roster"], FLEET_KIND, root)
    for role, label in ROLES.items():
        item = fleet["sources"][label]
        binding, trace, golden = source(
            item, reports[label], keys, root, campaign, owner["source"], policy, clock, label
        )
        source_bytes[label] = trace["source_sha256"]
        require(
            item["golden"]["features"] == features
            and roster["permits"][label] == binding["permit_sha256"]
        )
        authority = fleet_policy(fleet["roster"], root, campaign, binding["permit_sha256"])
        require(before["promotion_policy_sha256"] == after["promotion_policy_sha256"] == authority)
        ob = observations[role]
        actual = release_policy.checked(ob["attestation"], "inventory-running-worker", root)
        require(
            canonical(ob["trust_readback"])
            == canonical(dict(version=after["version"], document_sha256=sha(fleet["after"])))
        )
        require(
            canonical(actual)
            == canonical(
                dict(
                    campaign=campaign,
                    role=role,
                    owner=owner,
                    **{k: ob[k] for k in ("port", "container", "session", "loaded")},
                )
            )
        )
        require(before["issued_at"] <= (ob["history"] or ob["healthy"])["wall_start_ns"] // NS)
        branches[role] = gate.deployment(
            item,
            binding,
            reports[label],
            policy,
            observation=ob["loaded"],
            publisher=keys["approver"],
            worker_id=ob["container"],
        )
        elapsed = probes(
            role,
            ob,
            golden,
            trace,
            binding,
            directory,
            start,
            committed,
            finished,
            policy["trust_lease_seconds"] * NS,
        )
        if role != "independent":
            denials[role] = elapsed
        for sample in (ob["history"], ob["healthy"], ob["after"]):
            if sample is not None:
                request = sample["reply"]["request_id"]
                require(request not in seen)
                seen.add(request)
    history = observations["previous"]["history"]
    require(source_bytes["previous"] == source_bytes["current"] != source_bytes["independent"])
    require(
        history["end_ns"] <= min(observations[k]["activation_ns"] for k in ("primary", "canary"))
        and max(o["activation_ns"] for o in observations.values())
        <= min(o["healthy"]["start_ns"] for o in observations.values())
        and observations["independent"]["after"]["start_ns"]
        >= max(observations[k]["after"]["end_ns"] for k in denials)
    )
    graph, snapshot, ancestor, expected = reconcile(branches, observations)
    require(after["revoked_artifacts"] == [ancestor["sha256"]])
    return graph, snapshot, ancestor, expected, denials
