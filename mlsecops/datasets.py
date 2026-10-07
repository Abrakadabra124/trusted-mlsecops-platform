from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.signing import sign, verify

FEATURES = (
    "change_size",
    "failed_checks",
    "dependency_changes",
    "test_coverage",
    "change_entropy",
    "prior_failure_rate",
)


def generate(seed=24017, rows=20000):
    if type(seed) is not int or type(rows) is not int or not 100 <= rows <= 20000:
        raise Rejected("invalid_generator_parameters")
    generator = np.random.default_rng(seed)
    features = np.round(generator.uniform(0, 1, (rows, len(FEATURES))), 6)
    logits = (features - 0.5) @ np.array([9, 4, 5, -5, 2, 6], dtype=float) - 1.0
    probabilities = 1.0 / (1.0 + np.exp(-logits))
    labels = generator.binomial(1, probabilities)
    return [
        {"entity_id": int(index), "features": values.tolist(), "label": int(label)}
        for index, (values, label) in enumerate(zip(features, labels, strict=True))
    ]


def validate_rows(records, expected=None):
    if not isinstance(records, list) or not records or len(records) > 20000:
        raise Rejected("invalid_row_count")
    if expected is not None and len(records) != expected:
        raise Rejected("unexpected_row_count")
    identifiers = set()
    for record in records:
        require_fields(record, ("entity_id", "features", "label"))
        identifier = record["entity_id"]
        if type(identifier) is not int or identifier < 0 or identifier in identifiers:
            raise Rejected("invalid_or_duplicate_entity")
        identifiers.add(identifier)
        if type(record["label"]) is not int or record["label"] not in (0, 1):
            raise Rejected("invalid_label")
        validate_features([record["features"]], max_rows=1)
    return identifiers


def validate_features(features, max_rows=20000):
    if not isinstance(features, list) or not 1 <= len(features) <= max_rows:
        raise Rejected("invalid_batch_size")
    for row in features:
        if not isinstance(row, list) or len(row) != len(FEATURES):
            raise Rejected("invalid_feature_shape")
        if any(type(value) not in (int, float) or not np.isfinite(value) for value in row):
            raise Rejected("invalid_feature_type")
        if any(not 0.0 <= value <= 1.0 for value in row):
            raise Rejected("feature_out_of_domain")
    return np.asarray(features, dtype=np.float32)


def arrays(records):
    validate_rows(records)
    return validate_features([record["features"] for record in records]), np.array(
        [record["label"] for record in records], dtype=np.int64
    )


def validate_approval(approval, policy):
    require_fields(approval, ("schema_version", "source", "purpose", "expires_at", "owner"))
    if (
        approval["schema_version"] != 1
        or approval["source"] != policy["source"]
        or approval["purpose"] != "synthetic-lab"
        or approval["owner"] != "lab-curator"
    ):
        raise Rejected("unknown_source_approval")
    try:
        expires = datetime.fromisoformat(approval["expires_at"])
    except (TypeError, ValueError) as error:
        raise Rejected("invalid_source_expiry") from error
    if expires.tzinfo is None or expires <= datetime.now(UTC):
        raise Rejected("expired_source_approval")


def prepare(state, policy):
    state = Path(state)
    public = read_json(state / "trusted-keys.json")
    approval_path = state / "source-approval.json"
    if not approval_path.exists():
        approval = {
            "schema_version": 1,
            "source": policy["source"],
            "purpose": "synthetic-lab",
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            "owner": "lab-curator",
        }
        write_json(approval_path, sign(approval, "source", state / "keys/curator.pem"))
    approval = verify(read_json(approval_path), "source", public["curator"])
    validate_approval(approval, policy)
    rows = generate(policy["data_seed"], policy["rows"])
    validate_rows(rows, policy["rows"])
    sizes = policy["split_counts"]
    if sizes != [14000, 3000, 3000] or sum(sizes) != len(rows):
        raise Rejected("unsupported_split_policy")
    splits = dict(
        zip(
            ("train", "validation", "holdout"),
            np.split(np.array(rows, dtype=object), [14000, 17000]),
            strict=True,
        )
    )
    split_bytes = {name: canonical(values.tolist()) for name, values in splits.items()}
    manifest = {
        "schema_version": 1,
        "source": policy["source"],
        "seed": policy["data_seed"],
        "policy_digest": digest(canonical(policy)),
        "features": list(FEATURES),
        "source_approval_digest": digest(canonical(approval)),
        "objects": {
            f"{name}.json": {"sha256": digest(content), "bytes": len(content), "rows": sizes[index]}
            for index, (name, content) in enumerate(split_bytes.items())
        },
    }
    identifier = digest(canonical(manifest))
    destination = safe_child(state / "approved", identifier)
    if destination.exists():
        verify_dataset(state, identifier, policy)
        return identifier
    quarantine = safe_child(state / "quarantine", identifier)
    quarantine.mkdir(parents=True, exist_ok=True)
    for name, content in split_bytes.items():
        path = quarantine / f"{name}.json"
        with path.open("wb") as output:
            output.write(content)
    write_json(quarantine / "manifest.json", sign(manifest, "dataset", state / "keys/curator.pem"))
    quarantine.rename(destination)
    verify_dataset(state, identifier, policy)
    return identifier


def verify_dataset(state, identifier, policy):
    state = Path(state)
    if (
        not isinstance(identifier, str)
        or len(identifier) != 64
        or any(character not in "0123456789abcdef" for character in identifier)
    ):
        raise Rejected("invalid_dataset_id")
    location = safe_child(state / "approved", identifier)
    public = read_json(state / "trusted-keys.json")
    manifest = verify(read_json(location / "manifest.json"), "dataset", public["curator"])
    require_fields(
        manifest,
        (
            "schema_version",
            "source",
            "seed",
            "policy_digest",
            "features",
            "source_approval_digest",
            "objects",
        ),
    )
    if digest(canonical(manifest)) != identifier or manifest["policy_digest"] != digest(
        canonical(policy)
    ):
        raise Rejected("dataset_manifest_mismatch")
    approval = verify(read_json(state / "source-approval.json"), "source", public["curator"])
    validate_approval(approval, policy)
    if manifest["source_approval_digest"] != digest(canonical(approval)):
        raise Rejected("source_version_mismatch")
    if set(manifest["objects"]) != {"train.json", "validation.json", "holdout.json"}:
        raise Rejected("unexpected_dataset_objects")
    all_identifiers = set()
    result = {}
    for name, metadata in manifest["objects"].items():
        require_fields(metadata, ("sha256", "bytes", "rows"))
        path = safe_child(location, name)
        content = bounded_read(path)
        if len(content) != metadata["bytes"] or digest(content) != metadata["sha256"]:
            raise Rejected("dataset_content_mismatch")
        records = decode(content)
        identifiers = validate_rows(records, metadata["rows"])
        if all_identifiers.intersection(identifiers):
            raise Rejected("cross_split_leakage")
        all_identifiers.update(identifiers)
        result[name.removesuffix(".json")] = records
    return result, manifest
