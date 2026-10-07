import subprocess
import uuid
from pathlib import Path

from mlsecops import storage_dataset
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.data_source import prepare_versioned, reproduce, verify_source
from mlsecops.sandbox import resolve_image
from mlsecops.storage_bootstrap import validate
from mlsecops.storage_pipeline_qualification import qualify as qualify_pipeline
from mlsecops.storage_qualification import qualify as qualify_storage
from mlsecops.worker_transport import capture, unwrap


def filesystem_fixtures(image):
    identifier = resolve_image(image)
    name = f"tml-integrity-{uuid.uuid4().hex}"
    try:
        output, diagnostics = unwrap(
            capture(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    name,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--user",
                    "65532:65532",
                    "--pids-limit",
                    "32",
                    "--cpus",
                    "2",
                    "--memory",
                    "1g",
                    "--memory-swap",
                    "1g",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=64m",
                    "--log-driver",
                    "none",
                    identifier,
                    "python",
                    "-m",
                    "mlsecops.dataset_integrity",
                ],
                timeout=120,
            )
        )
    finally:
        subprocess.run(
            ["docker", "rm", "--force", name], capture_output=True, timeout=30, check=False
        )
    return output, {
        "image_id": identifier,
        "diagnostic_bytes": diagnostics["bytes"],
        "network": "none",
    }


def qualify(root, state, image="trusted-mlsecops:dev"):
    root, state = Path(root).resolve(), Path(state).resolve()
    validate(state)
    policy = read_json(root / "policies/local-cpu.json")
    filesystem, execution = filesystem_fixtures(image)
    if (
        filesystem.get("status") != "pass"
        or filesystem.get("scope") != "M03-filesystem-fixtures"
        or filesystem.get("platform") != "Linux"
        or filesystem.get("policy_digest") != digest(canonical(policy))
        or not filesystem.get("hashes_before")
        or filesystem.get("hashes_before") != filesystem.get("hashes_after")
    ):
        raise Rejected("integrity_filesystem_evidence_invalid")
    reproduce(root, state)
    prepared = prepare_versioned(root, state)
    dataset = storage_dataset.publish(state, prepared["dataset_id"], prepared["lineage_id"], policy)

    def snapshot():
        splits, manifest, statement = storage_dataset.read_dataset(
            state / "storage-clients/curator",
            dataset["dataset_reference"],
            policy,
            read_json(state / "trusted-keys.json")["curator"],
            dataset["source_approval_digest"],
            storage_dataset.SPLITS,
        )
        content = canonical([row for name in storage_dataset.SPLITS for row in splits[name]])
        if digest(content) != filesystem["source_sha256"]:
            raise Rejected("integrity_sql_source_mismatch")
        return {
            **{name: digest(canonical(rows)) for name, rows in splits.items()},
            "manifest": digest(canonical(manifest)),
            "index": dataset["dataset_reference"],
            "lineage": statement["lineage_object"],
            "approval": statement["approval_object"],
        }

    before = snapshot()
    storage = qualify_storage(state)
    pipeline = qualify_pipeline(root, state, image)
    after = snapshot()
    if before != after or pipeline["dataset_reference"] != dataset["dataset_reference"]:
        raise Rejected("integrity_approved_sql_dataset_changed")
    source, lock_digest = verify_source(root, state)
    if filesystem["source_sha256"] != digest(source):
        raise Rejected("integrity_source_profile_mismatch")
    cases = [
        {
            "id": "integration:approved-sql-hashes-unchanged",
            "status": "pass",
            "expected": before,
            "actual": after,
        },
        {
            "id": "integration:idempotent-sql-publication",
            "status": "pass",
            "expected": dataset["dataset_reference"],
            "actual": pipeline["dataset_reference"],
        },
    ]
    artifacts = {}
    for label, evidence in (
        ("filesystem", filesystem),
        ("storage", storage),
        ("pipeline", pipeline),
    ):
        if evidence.get("status") != "pass" or not evidence.get("cases"):
            raise Rejected(f"integrity_component_incomplete:{label}")
        identifiers = set()
        for case in evidence["cases"]:
            if (
                case.get("status") != "pass"
                or not isinstance(case.get("id"), str)
                or case["id"] in identifiers
            ):
                raise Rejected(f"integrity_component_case_invalid:{label}")
            identifiers.add(case["id"])
            cases.append({**case, "id": f"{label}:{case['id']}"})
        content = canonical(evidence) + b"\n"
        write_json(state / f"evidence/M03-{label}.json", evidence)
        artifacts[label] = digest(content)
    result = {
        "schema_version": 1,
        "status": "pass",
        "scope": "M03-dataset-integrity-and-actual-storage-roles",
        "observed_at": now(),
        "cases": cases,
        "checks": len(cases),
        "component_checks": {
            "integration": 2,
            "filesystem": len(filesystem["cases"]),
            "storage": len(storage["cases"]),
            "pipeline": len(pipeline["cases"]),
        },
        "source_sha256": digest(source),
        "source_lock_digest": lock_digest,
        "dataset_reference": pipeline["dataset_reference"],
        "candidate_reference": pipeline["candidate_reference"],
        "execution": execution,
        "storage_inputs": storage["inputs"],
        "approved_sql_hashes_before": before,
        "approved_sql_hashes_after": after,
        "artifact_hashes": artifacts,
        "limitations": [
            "Synthetic data; fixtures are not universal semantic poisoning detection",
            "Shared component checks overlap other reports, not independent statistical trials",
            "SQL roles enforce storage permissions; host administrator and curator remain trusted",
            "Filesystem staging is trusted curator workspace, not a multi-user storage security boundary",
            "Linux symlink probes run in an offline container, not Windows NTFS privilege certification",
            "Independent controller identities, backup/restore and full M04/M20 remain pending",
            "Container vulnerability audit is a separate M01 requirement, not covered by this gate",
            "M03 pass does not authorize release or complete R1",
        ],
    }
    write_json(state / "evidence/integrity-qualification.json", result)
    return result
