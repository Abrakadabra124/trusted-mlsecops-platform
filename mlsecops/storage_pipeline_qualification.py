import argparse
import copy
import sys
from pathlib import Path
from unittest.mock import patch

from mlsecops import storage, storage_dataset, storage_pipeline
from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json, write_json
from mlsecops.signing import decode64, encode64, sign, verify
from mlsecops.storage_bootstrap import admin, validate


def qualify(root, state, image):
    root, state = Path(root), Path(state)
    marker = validate(state)
    reads, cases, temporary_objects = [], [], []
    original_get = storage.get

    def tracked_get(client, table, identifier):
        reads.append((Path(client).name, table))
        return original_get(client, table, identifier)

    def confirmed(identifier, condition):
        if not condition:
            raise Rejected(f"storage_pipeline_qualification_failed:{identifier}")
        cases.append({"id": identifier, "status": "pass", "expected": True, "actual": True})

    def rejected(identifier, operation, reason=None):
        try:
            operation()
        except Rejected as error:
            if reason and str(error) != reason:
                raise Rejected(f"storage_pipeline_wrong_rejection:{identifier}") from None
            cases.append(
                {"id": identifier, "status": "pass", "expected": "reject", "actual": str(error)}
            )
        else:
            raise Rejected(f"storage_pipeline_qualification_bypass:{identifier}")

    def fixture(role, table, content):
        client = state / "storage-clients" / role
        identifier = digest(content)
        try:
            storage.get(client, table, identifier)
        except Rejected as error:
            if str(error) != "storage_object_missing":
                raise
            storage.put(client, table, content)
            temporary_objects.append((table, identifier, content))
        return identifier

    with patch("mlsecops.storage.get", tracked_get):
        result = storage_pipeline.demo(root, state, image)
    policy = read_json(root / "policies/local-cpu.json")
    trust = read_json(state / "storage-trust.json")
    publisher, scorer = state / "storage-clients/publisher", state / "storage-clients/scorer"
    dataset_ref = result["dataset"]["dataset_reference"]
    candidate_ref = result["candidate"]["candidate_reference"]
    report = result["evaluation"]["report"]
    for role, allowed in (
        ("publisher", {"manifests", "lineage", "train", "validation", "candidates"}),
        ("scorer", {"manifests", "lineage", "holdout", "candidates", "evaluations"}),
    ):
        observed = {table for identity, table in reads if identity == role}
        confirmed(f"{role}:actual-read-scope", observed == allowed)
    confirmed("training-quality", report["quality_component"] == "pass" and report["rows"] == 3000)
    confirmed("release-remains-unapproved", report["release_status"] == "unapproved")
    confirmed(
        "signed-report-binds-candidate",
        verify(
            decode(storage.get(scorer, "evaluations", result["evaluation_reference"])),
            "stored-evaluation",
            trust["evaluator"],
        )
        == result["evaluation"]
        and result["evaluation"]["candidate_reference"] == candidate_ref,
    )

    def dataset(
        client=publisher,
        reference=dataset_ref,
        public=None,
        approval=None,
        selected=("train", "validation"),
    ):
        return storage_dataset.read_dataset(
            client,
            reference,
            policy,
            public or trust["curator"],
            approval or trust["source_approval_digest"],
            selected,
        )

    try:
        rejected("missing-dataset", lambda: dataset(reference="0" * 64), "storage_object_missing")
        rejected("wrong-curator", lambda: dataset(public=trust["evaluator"]))
        rejected(
            "stale-source",
            lambda: dataset(approval="0" * 64),
            "storage_dataset_policy_or_source_stale",
        )
        rejected(
            "publisher-holdout",
            lambda: dataset(selected=("holdout",)),
            "storage_read_rejected:42501",
        )
        rejected(
            "scorer-train",
            lambda: dataset(client=scorer, selected=("train",)),
            "storage_read_rejected:42501",
        )
        rejected(
            "serving-training-material",
            lambda: dataset(client=state / "storage-clients/serving"),
            "storage_read_rejected:42501",
        )
        rejected(
            "split-path-traversal",
            lambda: dataset(selected=("../holdout",)),
            "storage_split_selection_invalid",
        )
        rejected(
            "split-invalid-type", lambda: dataset(selected=([],)), "storage_split_selection_invalid"
        )
        for role, table in (
            ("ingestor", "train"),
            ("publisher", "holdout"),
            ("scorer", "candidates"),
            ("publisher", "evaluations"),
        ):
            rejected(
                f"{role}:{table}:write-denied",
                lambda role=role, table=table: storage.put(
                    state / "storage-clients" / role, table, b"unauthorized"
                ),
                "storage_write_rejected:42501",
            )
        original = decode(storage.get(publisher, "manifests", dataset_ref))
        tampered = copy.deepcopy(original)
        payload = decode(decode64(tampered["payload"]))
        payload["policy_digest"] = "0" * 64
        tampered["payload"] = encode64(canonical(payload))
        bad_reference = fixture("curator", "manifests", canonical(tampered))
        rejected("unsigned-index-mutation", lambda: dataset(reference=bad_reference))
        payload = verify(original, "stored-dataset", trust["curator"])
        for field in ("dataset_id", "lineage_id", "quarantine_object"):
            altered = {**payload, field: "0" * 64}
            bad_reference = fixture(
                "curator",
                "manifests",
                canonical(sign(altered, "stored-dataset", state / "keys/curator.pem")),
            )
            rejected(
                f"wrong-binding:{field}",
                lambda reference=bad_reference: dataset(reference=reference),
            )
        record, metadata, model = storage_pipeline.load_candidate(scorer, candidate_ref, policy)
        bad_model = fixture("publisher", "candidates", model[:-1] + bytes([model[-1] ^ 1]))
        bad_reference = fixture(
            "publisher", "candidates", canonical({**record, "model_object": bad_model})
        )
        rejected(
            "model-single-byte-mutation",
            lambda: storage_pipeline.load_candidate(scorer, bad_reference, policy),
            "stored_candidate_material_mismatch",
        )
        for field, value in (
            ("dataset_id", "0" * 64),
            ("image_id", "latest"),
            ("validation_parity_max_error", True),
        ):
            altered = {**metadata, field: value}
            bad_metadata = fixture("publisher", "candidates", canonical(altered))
            bad_reference = fixture(
                "publisher", "candidates", canonical({**record, "metadata_object": bad_metadata})
            )

            def forbidden_executor(*arguments):
                raise AssertionError("Invalid candidate reached prediction execution")

            rejected(
                f"candidate-metadata:{field}",
                lambda reference=bad_reference: storage_pipeline.evaluate(
                    scorer,
                    reference,
                    policy,
                    image,
                    trust,
                    state / "keys/evaluator.pem",
                    forbidden_executor,
                ),
            )
        confirmed(
            "original-candidate-still-readable",
            storage_pipeline.load_candidate(scorer, candidate_ref, policy)[2] == model,
        )
    finally:
        for table, identifier, content in temporary_objects:
            admin(
                marker["name"],
                f"DELETE FROM ml.{table} WHERE sha256 = '{identifier}' AND payload = decode('{content.hex()}', 'hex');",
            )
    return {
        "schema_version": 1,
        "observed_at": now(),
        "scope": "storage-pipeline-component",
        "status": "pass",
        "checks": len(cases),
        "cases": cases,
        "dataset_reference": dataset_ref,
        "candidate_reference": candidate_ref,
        "evaluation_reference": result["evaluation_reference"],
        "auprc": report["auprc"],
        "parity_max_error": report["validation_parity_max_error"],
        "role_read_tables": {
            role: sorted({table for identity, table in reads if identity == role})
            for role in ("publisher", "scorer")
        },
        "limitations": result["limitations"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    destination = arguments.state / "evidence/storage-pipeline-qualification.json"
    try:
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        write_json(destination, result)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        write_json(destination, {"status": "fail", "observed_at": now(), "reason": str(error)})
        print(f"Storage pipeline qualification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
