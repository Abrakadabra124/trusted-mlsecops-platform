import argparse
import sys
from contextlib import suppress
from pathlib import Path

from mlsecops import material_bundle, storage
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
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS, metadata_snapshot


def release_snapshot(client):
    with storage.connect(client) as connection:
        if connection.execute("SELECT current_user").fetchone() != ("ml_serving",):
            raise Rejected("bundle_native_sql_identity_mismatch")
        rows = connection.execute(
            "SELECT sha256 FROM ml.releases ORDER BY sha256 LIMIT 2001"
        ).fetchall()
        if len(rows) > 2000:
            raise Rejected("bundle_native_fixture_too_large")
        return {row[0] for row in rows}


def qualify(root, state, image):
    marker = validate(state)
    policy = read_json(root / "policies/local-cpu.json")
    paths = [
        safe_child(state, name)
        for name in ("storage-trust.json", "storage-demo.json", "trusted-keys.json")
    ]
    files = {path: digest(bounded_read(path)) for path in paths}
    trust, demo, public = (read_json(path) for path in paths)
    expected = {
        "image_id": resolve_image(image),
        "source_fingerprint": source_fingerprint(root),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
    }
    context = {
        "candidate_reference": demo["candidate"]["candidate_reference"],
        "evaluation_reference": demo["evaluation_reference"],
        "policy": policy,
        "trust": trust,
        "expected": expected,
        "owners": OWNERS,
        "known_owners": KNOWN_OWNERS,
    }
    clients = {
        role: safe_child(state, f"storage-clients/{role}")
        for role in ("publisher", "promoter", "serving")
    }
    arguments = {"context": context, "signer_public": public["approver"]}
    signing = {**arguments, "signing_key": safe_child(state, "keys/approver.pem")}
    before = metadata_snapshot(state)
    releases_before = release_snapshot(clients["serving"])
    bundle = material_bundle.create(clients["publisher"], clients["promoter"], **signing)
    verified = material_bundle.verify_bundle(bundle, **arguments)
    cases = ["closed-signed-materials"]
    repeated = material_bundle.create(clients["publisher"], clients["promoter"], **signing)
    if bundle != repeated:
        raise Rejected("bundle_native_nondeterministic_index")
    cases.append("deterministic-envelope")
    reference = material_bundle.publish(clients["promoter"], bundle, **arguments)
    published = release_snapshot(clients["serving"])
    if (
        material_bundle.publish(clients["promoter"], repeated, **arguments) != reference
        or release_snapshot(clients["serving"]) != published
    ):
        raise Rejected("bundle_native_idempotency_failed")
    cases.append("idempotent-sql-publication")
    observed = material_bundle.read(clients["serving"], reference, **arguments)
    if observed != verified:
        raise Rejected("bundle_native_readback_mismatch")
    cases.append("serving-reads-same-verified-bytes")

    def rejected(name, operation, reason):
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected("bundle_native_negative_wrong_reason") from None
            cases.append(name)
        else:
            raise Rejected("bundle_native_negative_bypass")

    wrong_context = {**context, "expected": {**expected, "source_revision": "0" * 40}}
    rejected(
        "wrong-external-source",
        lambda: material_bundle.read(
            clients["serving"], reference, context=wrong_context, signer_public=public["approver"]
        ),
        "inventory_candidate_build_binding",
    )
    model = verified["model"]
    model_key = ("candidates", digest(model))
    corrupted = {**bundle, "objects": {**bundle["objects"], model_key: b"tampered"}}
    rejected(
        "tampered-model",
        lambda: material_bundle.verify_bundle(corrupted, **arguments),
        "bundle_material_integrity_failed",
    )
    for table in ("manifests", "candidates", "holdout"):
        rejected(
            f"serving-{table}-denied-by-sql",
            lambda table=table: storage.get(clients["serving"], table, "0" * 64),
            "storage_read_rejected:42501",
        )
    rejected(
        "serving-write-denied-by-sql",
        lambda: storage.put(clients["serving"], "releases", b"denied-write-probe"),
        "storage_write_rejected:42501",
    )
    after = metadata_snapshot(state)
    if before != after:
        raise Rejected("bundle_native_metadata_changed")
    cases.append("source-metadata-and-budget-unchanged")
    if release_snapshot(clients["serving"]) != releases_before | {
        key[1] for key in bundle["objects"]
    } | {reference}:
        raise Rejected("bundle_native_release_set_mismatch")
    cases.append("exact-release-object-set")
    if (
        source_fingerprint(root) != expected["source_fingerprint"]
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != expected["source_revision"]
        or resolve_image(image) != expected["image_id"]
        or any(digest(bounded_read(path)) != original for path, original in files.items())
        or validate(state)["container_id"] != marker["container_id"]
    ):
        raise Rejected("bundle_native_inputs_changed")
    return {
        "schema_version": 1,
        "scope": "candidate-material-bundle-not-full-M10",
        "status": "pass",
        "full_M10": "inconclusive",
        "release_ready": False,
        "observed_at": now(),
        "source": expected,
        "cases": cases,
        "bundle_reference": reference,
        "objects": len(bundle["objects"]),
        "model_sha256": digest(model),
        "projection_sha256": digest(canonical(verified["projection"])),
        "runner_digest": digest(bounded_read(Path(__file__))),
        "metadata_snapshot": after,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Publish unapproved candidate materials to owned lab SQL and verify serving-role readback"
    )
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    output = None
    try:
        output = safe_child(arguments.state, "evidence/material-bundle-native.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        report = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        write_json(output, report)
        summary = {key: report[key] for key in ("scope", "status", "full_M10", "bundle_reference")}
        print(
            canonical({**summary, "cases": len(report["cases"]), "release_ready": False}).decode()
        )
        return 0
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "release_ready": False})
        print(
            "Material bundle qualification rejected; inspect scoped evidence locally",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
