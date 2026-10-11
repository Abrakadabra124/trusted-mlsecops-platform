import argparse
import sys
from contextlib import suppress
from pathlib import Path
from unittest.mock import patch

from psycopg import sql

from mlsecops import asset_graph, candidate_lineage, storage
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import resolve_image
from mlsecops.storage_bootstrap import validate

OWNERS = {
    "dataset": "data-owner",
    "run": "ml-owner",
    "model": "ml-owner",
    "runtime": "platform-owner",
    "policy": "platform-owner",
}
KNOWN_OWNERS = ["data-owner", "ml-owner", "platform-owner"]


def metadata_snapshot(state):
    result = {}
    for role, tables in (
        ("publisher", ("manifests", "lineage")),
        ("promoter", ("candidates", "evaluations")),
    ):
        with storage.connect(safe_child(state, f"storage-clients/{role}")) as connection:
            if connection.execute("SELECT current_user").fetchone() != (f"ml_{role}",):
                raise Rejected("inventory_native_sql_identity_mismatch")
            for table in tables:
                rows = connection.execute(
                    sql.SQL("SELECT sha256 FROM {} ORDER BY sha256 LIMIT 2001").format(
                        sql.Identifier("ml", table)
                    )
                ).fetchall()
                if len(rows) > 2000:
                    raise Rejected("inventory_native_fixture_too_large")
                result[table] = {"objects": len(rows), "digest": digest(canonical(rows))}
    return result


def qualify(root, state, image):
    marker = validate(state)
    policy = read_json(root / "policies/local-cpu.json")
    trust_path = safe_child(state, "storage-trust.json")
    demo_path = safe_child(state, "storage-demo.json")
    trust, demo = read_json(trust_path), read_json(demo_path)
    files = {path: digest(bounded_read(path)) for path in (trust_path, demo_path)}
    expected = {
        "image_id": resolve_image(image),
        "source_fingerprint": source_fingerprint(root),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
    }
    metadata_client = safe_child(state, "storage-clients/publisher")
    review_client = safe_child(state, "storage-clients/promoter")
    arguments = dict(
        candidate_reference=demo["candidate"]["candidate_reference"],
        evaluation_reference=demo["evaluation_reference"],
        policy=policy,
        trust=trust,
        expected=expected,
        owners=OWNERS,
        known_owners=KNOWN_OWNERS,
    )
    before = metadata_snapshot(state)
    reads = set()
    original_get = storage.get

    def observed_get(client, table, reference):
        reads.add((Path(client).name, table))
        return original_get(client, table, reference)

    with patch.object(storage, "get", side_effect=observed_get):
        projection = candidate_lineage.collect(metadata_client, review_client, **arguments)
    if reads != {
        ("publisher", "manifests"),
        ("publisher", "lineage"),
        ("promoter", "candidates"),
        ("promoter", "evaluations"),
    }:
        raise Rejected("inventory_native_unexpected_reads")
    cases = ["real-signed-candidate-lineage", "actual-metadata-only-reads"]
    graph = projection["graph"]
    dataset = next(asset for asset in graph["assets"] if asset["kind"] == "dataset")
    snapshot = {
        "schema_version": 1,
        "environment": policy["environment"],
        "graph_sha256": digest(canonical(graph)),
        "deployments": [],
    }
    impact = asset_graph.assess(
        graph,
        KNOWN_OWNERS,
        policy["environment"],
        snapshot,
        [{"asset_id": dataset["asset_id"], "sha256": dataset["sha256"]}],
    )
    expected_impact = sorted(
        asset["asset_id"]
        for asset in graph["assets"]
        if asset["kind"] in ("dataset", "run", "model")
    )
    if impact["impacted_assets"] != expected_impact:
        raise Rejected("inventory_native_impact_mismatch")
    cases.append("dataset-revocation-has-exact-three-node-impact")

    def rejected(name, operation, reason):
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected("inventory_native_wrong_rejection") from None
            cases.append(name)
        else:
            raise Rejected("inventory_native_negative_bypass")

    for name, changes, reason in (
        ("missing-candidate", {"candidate_reference": "0" * 64}, "storage_object_missing"),
        ("missing-evaluation", {"evaluation_reference": "0" * 64}, "storage_object_missing"),
        (
            "wrong-build-source",
            {"expected": {**expected, "source_revision": "0" * 40}},
            "inventory_candidate_build_binding",
        ),
        (
            "unknown-owner",
            {"owners": {**OWNERS, "dataset": "unknown-owner"}},
            "inventory_unknown_owner",
        ),
    ):
        rejected(
            name,
            lambda changes=changes: candidate_lineage.collect(
                metadata_client, review_client, **{**arguments, **changes}
            ),
            reason,
        )
    holdout = demo["evaluation"]["report"]["holdout_digest"]
    for role, client in (("publisher", metadata_client), ("promoter", review_client)):
        rejected(
            f"{role}-holdout-denied-by-sql",
            lambda client=client: storage.get(client, "holdout", holdout),
            "storage_read_rejected:42501",
        )
    after = metadata_snapshot(state)
    if before != after:
        raise Rejected("inventory_native_sql_changed")
    cases.append("sql-metadata-and-budget-ledger-unchanged")
    if (
        source_fingerprint(root) != expected["source_fingerprint"]
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != expected["source_revision"]
        or resolve_image(image) != expected["image_id"]
        or any(digest(bounded_read(path)) != original for path, original in files.items())
        or validate(state)["container_id"] != marker["container_id"]
    ):
        raise Rejected("inventory_native_inputs_changed")
    return {
        "schema_version": 1,
        "scope": "candidate-lineage-native-not-full-M19",
        "status": "pass",
        "full_M19": "inconclusive",
        "release_ready": False,
        "observed_at": now(),
        "cases": cases,
        "source": expected,
        "runner_digest": digest(bounded_read(Path(__file__))),
        "projection": projection,
        "impact": impact,
        "metadata_snapshot": after,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Read-only candidate lineage qualification against an existing SQL demo"
    )
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    output = None
    try:
        output = safe_child(arguments.state, "evidence/candidate-lineage-native.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        report = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        write_json(output, report)
        print(
            canonical(
                {
                    "scope": report["scope"],
                    "status": report["status"],
                    "cases": len(report["cases"]),
                    "full_M19": report["full_M19"],
                    "release_ready": False,
                }
            ).decode()
        )
        return 0
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "release_ready": False})
        print(
            "Candidate lineage qualification rejected; inspect scoped inputs privately",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
