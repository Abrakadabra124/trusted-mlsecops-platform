"""One hosted M13/M14/M15 campaign with private capture and post-cleanup replay."""

from mlsecops import (
    audit_evidence,
    audit_snapshot,
    cluster,
    final_evidence,
    kube_storage,
    privacy_gate,
    release_policy,
    storage_bootstrap,
)
from mlsecops import (
    performance_delivery as delivery,
)
from mlsecops.contracts import canonical, decode, digest, safe_child
from mlsecops.inventory import command
from mlsecops.storage import object_id

GATES = ("M02", "M03", "M07", "M13", "M14", "M15")
MARKERS = (
    "cluster.json",
    "kubeconfig",
    "controllers",
    "serving",
    "kubernetes-storage",
    "kubernetes-trust",
    "kubernetes-trust-model",
    "kubernetes-security",
    "kubernetes-serving-service",
)


def identity(state, source_pin):
    owner = delivery.pinned(state / "storage.json", source_pin)
    delivery.require(storage_bootstrap.validate(state) == owner)
    current = cluster.validate_cluster(state)
    delivery.require(current["workspace_id"] == owner["workspace_id"])
    storage = kube_storage.validate(state)
    return dict(
        namespace=digest(canonical(current["namespace_uid"])),
        volume=digest(canonical(storage["volume_uid"])),
    )


def transition(state, retired, source_pin):
    before = identity(state, source_pin)
    command(
        [
            "kind",
            "delete",
            "cluster",
            "--name",
            cluster.NAME,
            "--kubeconfig",
            str(state / "kubeconfig"),
        ],
        timeout=180,
    )
    delivery.require(cluster.NAME not in command(["kind", "get", "clusters"]).splitlines())
    retired.mkdir(mode=0o700)
    for name in MARKERS:
        marker = safe_child(state, name)
        if marker.exists():
            marker.rename(retired / name)
    cluster.bootstrap(state)
    kube_storage.bootstrap(state)
    after = identity(state, source_pin)
    delivery.require(all(after[k] != before[k] for k in before))
    return dict(before=before, after=after, source_sql=source_pin)


def chain(steps, source_pin):
    first, second = steps
    delivery.require(first["source_sql"] == second["source_sql"] == object_id(source_pin))
    delivery.require(first["after"] == second["before"])
    nodes = [first["before"], first["after"], second["after"]]
    for key in ("namespace", "volume"):
        delivery.require(len({object_id(n[key]) for n in nodes}) == 3)
    return nodes


def bind_report(gate, report, values):
    final_evidence.subset(
        report,
        dict(
            gate=gate,
            status="pass",
            exit_code=0,
            source_dirty=False,
            source_revision=values["source_revision"],
        ),
        "campaign-header",
    )
    delivery.require(report.get("release_ready", False) is False)
    inputs = {k: values[k] for k in ("source_fingerprint", *final_evidence.BINDINGS[gate].split())}
    final_evidence.subset(report["input_digests"], inputs, "campaign-inputs")
    final_evidence.check_cases(gate, report["cases"])


def privacy(root, state, report, admission_pin, index, values, keys):
    directory = state / "evidence"
    admission = delivery.pinned(directory / "privacy-gate-private.json", admission_pin)
    value = delivery.pinned(
        directory / "kubernetes-privacy-private.json", admission["private_observation"]
    )
    delivery.signed_inputs(root, state, "M13", index, value)
    artifacts = report["artifact_hashes"]
    final_evidence.subset(
        artifacts,
        dict(
            proposal_packet=index["freeze"][delivery.PROPOSAL],
            frozen_demo=index["freeze"][delivery.DEMO],
        ),
        "privacy-owner",
    )
    metrics = privacy_gate.reconcile(
        value,
        value["source"],
        started=report["started_at"],
        finished=report["finished_at"],
        methods=artifacts["method_materials"],
    )
    final_evidence.same(
        report["metrics"], dict(checks=len(report["cases"]), **metrics), "privacy-metrics"
    )
    # Recover the expected audit context from the same authenticated dataset and run.
    # The signed frozen package was read and verified offline by signed_inputs.
    dataset = release_policy.checked(
        decode(final_evidence.blob(state, values["dataset_reference"])),
        "stored-dataset",
        keys["curator"],
    )
    demo = delivery.pinned(state / delivery.DEMO, index["freeze"][delivery.DEMO])
    lineage = dict(
        source_revision=values["source_revision"],
        source_fingerprint=values["source_fingerprint"],
        source_sha256=values["source"],
        dataset_sha256=values["dataset_reference"],
        evaluation_sha256=values["evaluation_reference"],
        lineage_sha256=dataset["lineage_object"],
        run_sha256=digest(canonical(demo["candidate"]["metadata"])),
        source_approval_sha256=demo["dataset"]["source_approval_digest"],
    )
    expected = dict(
        schema_version=2,
        kind="candidate-qualification",
        release_ready=False,
        proposal_sha256=values["proposal_reference"],
        model_sha256=values["model"],
        bundle_sha256=values["release_subject"],
        permit_sha256=value["qualification_permit_sha256"],
        lineage=lineage,
    )
    epoch = privacy_gate.campaign(value["privacy_campaign_id"])
    raw = audit_snapshot.load_packet(
        safe_child(state, "evidence/privacy/" + epoch + "/audit-evidence")
    )
    audit = audit_evidence.verify(
        raw, binding=dict(campaign_id=epoch, source=value["source"]), expected_context=expected
    )
    final_evidence.same(audit, value["native"]["audit"], "privacy-audit")
    final_evidence.same(
        privacy_gate.retained_windows(state, value),
        admission["retained_packets"],
        "privacy-windows",
    )
    return value["qualification_permit_sha256"]


def replay(root, state, *, pins, reports, admissions, transitions, source_pin, revision):
    delivery.pinned(state / "storage.json", source_pin)
    nodes = chain(transitions, source_pin)
    public = {g: final_evidence.published_report(state, g, reports[g]) for g in GATES}
    proofs = [
        delivery.replay(
            root, state, g, pins=pins, report_pin=reports[g], admission_pin=admissions[g]
        )
        for g in ("M14", "M15")
    ]
    index = delivery.pinned(state / "evidence/M14-frozen-private.json", admissions["M14"])["index"]
    final_evidence.clean(root, revision, index["source_fingerprint"])
    values, keys, _ = delivery.frozen(root, state, index)
    delivery.require(values["source_revision"] == revision)
    for gate, report in public.items():
        bind_report(gate, report, values)
    permit = privacy(root, state, public["M13"], admissions["M13"], index, values, keys)
    times = [
        final_evidence.timestamp(public[g][k])
        for g in ("M13", "M14", "M15")
        for k in ("started_at", "finished_at")
    ]
    delivery.require(times == sorted(times))
    delivery.require(
        len(
            {permit, *(p["report"]["input_digests"]["qualification_permit_sha256"] for p in proofs)}
        )
        == 3
    )
    return dict(
        scope="shared-source-M02-M03-M07-M13-M14-M15",
        release_ready=False,
        source_sql_sha256=source_pin,
        clusters=nodes,
        source_files=pins,
        reports=reports,
        **{k: values[k] for k in (*delivery.SOURCE, *delivery.IDENTITY, "dataset_reference")},
    ), [
        dict(gate=g, status="pass", release_ready=False, report_sha256=reports[g], report=public[g])
        for g in GATES
    ]
