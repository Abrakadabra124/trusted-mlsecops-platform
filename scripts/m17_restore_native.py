"""Hosted M17 SQL and evaluated-model recovery component. replay() is offline."""

from datetime import datetime, timedelta
from pathlib import Path
from time import monotonic_ns

from mlsecops import (
    sandbox,
    storage,
    storage_backup,
    storage_bootstrap,
    storage_dataset,
    storage_pipeline,
    storage_restore,
)
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
)
from mlsecops.prediction_protocol import PredictionBatch, validate_scores
from mlsecops.storage import object_id
from scripts.promotion_entrypoint_native import hosted
from scripts.r1_walkthrough import stop_owned

ROWS = 1000
IDENTITY = ("workspace_id", "container_id", "volume", "network_id", "port")


def require(condition, reason):
    if not condition:
        raise Rejected("m17_restore_" + reason)


def _readback(state, port, demo, policy, trust, image):
    publisher = safe_child(state, "storage-clients/publisher")
    promoter = safe_child(state, "storage-clients/promoter")
    for client in (publisher, promoter):
        params = storage.connection_parameters(client)
        require(
            (params["host"], params["port"], params["user"])
            == ("127.0.0.1", port, "ml_" + client.name),
            "client_endpoint",
        )
    reference = demo["candidate"]["candidate_reference"]
    evaluation_ref = demo["evaluation_reference"]
    record, meta, model = storage_pipeline.load_candidate(publisher, reference, policy)
    bound = storage_pipeline.read_evaluation(promoter, evaluation_ref, reference, policy, trust)
    dataset = demo["dataset"]
    splits, _, statement = storage_dataset.read_dataset(
        publisher,
        record["dataset_reference"],
        policy,
        trust["curator"],
        trust["source_approval_digest"],
        ("validation",),
    )
    require(
        digest(canonical(record)) == reference
        and meta == demo["candidate"]["metadata"]
        and digest(model) == record["model_object"] == meta["model_digest"]
        and meta["image_id"] == image
        and bound == demo["evaluation"]
        and bound["candidate_reference"] == reference
        and bound["dataset_reference"]
        == record["dataset_reference"]
        == dataset["dataset_reference"]
        and bound["lineage_id"]
        == meta["lineage_id"]
        == statement["lineage_id"]
        == dataset["lineage_id"]
        and meta["dataset_id"] == statement["dataset_id"] == dataset["dataset_id"]
        and statement["source_approval_digest"] == dataset["source_approval_digest"],
        "subject",
    )
    features = [row["features"] for row in splits["validation"][:ROWS]]
    require(len(features) == ROWS, "golden_rows")
    saved = decode(storage.get(publisher, "candidates", record["scores_object"]))
    require(
        digest(canonical(saved))
        == record["scores_object"]
        == meta["validation_probability_digest"],
        "evaluated_scores",
    )
    evaluated = validate_scores(saved, len(splits["validation"]))
    batch = PredictionBatch(model, features)
    output, execution = sandbox.run_worker(image, batch.request)
    scores, _, proof = batch.consume(output)
    require(execution["image_id"] == image, "worker_image")
    require(
        float(abs(scores - evaluated[:ROWS]).max()) <= policy["repeat_tolerance"], "golden_parity"
    )
    return dict(
        prediction_receipt=proof,
        dataset_reference=record["dataset_reference"],
        candidate_reference=reference,
        evaluation_reference=evaluation_ref,
        model_sha256=proof["model_digest"],
        image_id=image,
        features_sha256=digest(canonical(features)),
        evaluated_scores=saved,
        scores=scores.tolist(),
    )


def replay(packet, *, backup_pin, demo_pin, public, policy):
    """Recheck externally pinned capture bytes before calling; no clock or live dependencies."""
    require(type(packet["schema_version"]) is int and packet["schema_version"] == 1, "schema")
    start, finish = (datetime.fromisoformat(packet[k]) for k in ("started_at", "finished_at"))
    require(start.utcoffset() is not None and finish.utcoffset() is not None, "wall_clock")
    statement = storage_backup.verify_manifest(packet["manifest"], public, policy, moment=start)
    require(digest(canonical(statement)) == object_id(backup_pin), "backup_pin")
    require("recovery_point_at" in statement, "unmeasured_snapshot")
    point = datetime.fromisoformat(statement["recovery_point_at"])
    rpo = start - point
    require(timedelta(0) <= rpo <= timedelta(days=1), "rpo")
    first, last = (packet[k] for k in ("start_ns", "finish_ns"))
    require(
        type(first) is int
        and type(last) is int
        and 0 <= first < last
        and last - first <= 900_000_000_000,
        "rto",
    )
    require(timedelta(0) < finish - start <= timedelta(minutes=15), "wall_clock")

    source, target, receipt = (packet[k] for k in ("source", "target", "receipt"))
    require(
        set(source) == set(target) == set(IDENTITY)
        and all(source[k] != target[k] for k in IDENTITY),
        "independence",
    )
    imported = datetime.fromisoformat(receipt["restored_at"])
    require(
        receipt["backup_id"] == backup_pin
        and receipt["reused"] is False
        and receipt["source_workspace"] == source["workspace_id"] == statement["source_workspace"]
        and receipt["target_workspace"] == target["workspace_id"]
        and receipt["container_id"] == target["container_id"]
        and receipt["port"] == target["port"]
        and receipt["schema_version"] == statement["schema_version"]
        and receipt["tables"] == statement["tables"]
        and receipt.get("promotion") == statement.get("promotion")
        and receipt["release_ready"] is False
        and receipt["status"] == "storage-restored-not-release-ready"
        and imported.utcoffset() is not None
        and start <= imported <= finish,
        "receipt",
    )
    raw = packet["storage_demo"].encode("utf-8")
    require(digest(raw) == object_id(demo_pin), "demo_pin")
    demo = decode(raw)
    meta = demo["candidate"]["metadata"]
    expected = dict(
        dataset_reference=demo["dataset"]["dataset_reference"],
        candidate_reference=demo["candidate"]["candidate_reference"],
        evaluation_reference=demo["evaluation_reference"],
        model_sha256=meta["model_digest"],
        image_id=meta["image_id"],
        features_sha256=object_id(packet["original"]["features_sha256"]),
    )
    # The training-time reference predates both executions and is bound by
    # the caller's original demo pin. Compare both runs with it as well as each other.
    saved = packet["original"]["evaluated_scores"]
    require(digest(canonical(saved)) == meta["validation_probability_digest"], "evaluated_scores")
    reference_scores = validate_scores(saved, len(saved))[:ROWS]
    require(len(reference_scores) == ROWS, "golden_rows")
    scores = []
    for name in ("original", "restored"):
        observation = packet[name]
        require(
            {
                k: v
                for k, v in observation.items()
                if k not in ("scores", "evaluated_scores", "prediction_receipt")
            }
            == expected
            and canonical(observation["evaluated_scores"]) == canonical(saved),
            "readback",
        )
        proof = observation["prediction_receipt"]
        require(
            proof["schema_version"] == 2
            and proof["model_digest"] == expected["model_sha256"]
            and proof["rows"] == ROWS,
            "prediction_receipt",
        )
        for field in ("request_digest", "response_digest"):
            object_id(proof[field])
        scores.append(validate_scores(observation["scores"], ROWS))
    require(
        packet["original"]["prediction_receipt"]["request_digest"]
        != packet["restored"]["prediction_receipt"]["request_digest"],
        "golden_replay",
    )
    error = max(
        float(abs(a - b).max())
        for a, b in (
            (scores[0], scores[1]),
            (reference_scores, scores[0]),
            (reference_scores, scores[1]),
        )
    )
    require(error <= policy["repeat_tolerance"], "golden_parity")
    return dict(
        scope="source-offline-sql-evaluated-candidate",
        release_ready=False,
        backup_id=backup_pin,
        **expected,
        golden_rows=ROWS,
        max_error=error,
        rto_seconds=(last - first) / 1e9,
        wall_elapsed_seconds=(finish - start).total_seconds(),
        rpo_seconds=rpo.total_seconds(),
    )


def capture(
    root,
    state,
    target,
    image,
    *,
    demo_pin,
    keys_pin,
    port=15440,
    include_promotion=False,
    backup_pin=None,
):
    """Stop the owned source, leave restored target available and return private primary evidence."""
    hosted()
    root, state, target = Path(root), Path(state), Path(target)
    require(
        not target.exists() and not target.is_symlink() and not target.parent.is_symlink(),
        "fresh_target",
    )
    demo_raw = bounded_read(safe_child(state, "storage-demo.json"))
    require(digest(demo_raw) == object_id(demo_pin), "demo_pin")
    demo = decode(demo_raw)
    policy = read_json(root / "policies/local-cpu.json")
    public = storage_backup.trusted_keys(read_json(safe_child(state, "trusted-keys.json")))
    require(digest(canonical(public)) == object_id(keys_pin), "key_pin")
    trust = read_json(safe_child(state, "storage-trust.json"))
    require(
        all(trust[k] == public[k] for k in ("curator", "evaluator"))
        and trust["source_approval_digest"] == demo["dataset"]["source_approval_digest"],
        "source_trust",
    )
    source = storage_bootstrap.validate(state)
    require(type(port) is int and 1024 <= port <= 65535 and source["port"] != port, "target_port")
    image = sandbox.resolve_image(image)
    original = _readback(state, source["port"], demo, policy, trust, image)
    if backup_pin is None:
        backup = storage_backup.create(
            root, state, include_promotion=include_promotion, recovery_point=True
        )
        pin = object_id(backup["backup_id"])
    else:
        pin = object_id(backup_pin)
    directory = safe_child(state, "backups/" + pin)
    # Independently verify existing archive bytes before taking the source offline.
    statement, archive = storage_backup.read_backup(directory, public, policy)
    del archive
    manifest = read_json(directory / "manifest.json")
    require(
        digest(canonical(statement)) == pin
        and storage_backup.verify_manifest(manifest, public, policy) == statement
        and statement["source_workspace"] == source["workspace_id"]
        and "recovery_point_at" in statement
        and (backup_pin is None or statement["schema_version"] == 2),
        "backup_pin",
    )
    require(
        storage_bootstrap.validate(state) == source and not target.exists(), "preflight_changed"
    )

    started_at, start_ns = now(), monotonic_ns()
    stop_owned(state)
    receipt = storage_restore.restore(root, directory, target, public, port, expected_backup_id=pin)
    dest = storage_bootstrap.validate(target)
    require(not receipt["reused"] and all(dest[k] != source[k] for k in IDENTITY), "independence")
    target_keys = storage_backup.trusted_keys(read_json(target / "trusted-keys.json"))
    require(
        set(target_keys.values()).isdisjoint(public.values())
        and read_json(target / "recovered-public-keys.json") == public,
        "target_trust",
    )
    restored = _readback(target, dest["port"], demo, policy, trust, image)
    require(original["features_sha256"] == restored["features_sha256"], "readback")
    require(
        max(abs(a - b) for a, b in zip(original["scores"], restored["scores"], strict=True))
        <= policy["repeat_tolerance"],
        "golden_parity",
    )
    require(
        storage_restore.ledger(dest["name"]) == receipt["tables"]
        and read_json(target / "recovery.json")
        == {k: v for k, v in receipt.items() if k != "reused"},
        "target_readback",
    )
    require(
        storage_bootstrap.validate(state) == source
        and storage_bootstrap.inspect("container", source["container_id"])["State"]["Running"]
        is False,
        "source_online_or_changed",
    )
    finish_ns, finished_at = monotonic_ns(), now()
    packet = dict(
        schema_version=1,
        manifest=manifest,
        receipt=receipt,
        storage_demo=demo_raw.decode("utf-8"),
        source={k: source[k] for k in IDENTITY},
        target={k: dest[k] for k in IDENTITY},
        original=original,
        restored=restored,
        started_at=started_at,
        finished_at=finished_at,
        start_ns=start_ns,
        finish_ns=finish_ns,
    )
    replay(packet, backup_pin=pin, demo_pin=demo_pin, public=public, policy=policy)
    return packet
