import argparse
import subprocess
import sys
from pathlib import Path

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

GATES = tuple(f"M{number:02}" for number in range(1, 24))


def report(gate, profile, root, state=None):
    started = now()
    policy_path = root / "policies/local-cpu.json"
    policy = read_json(policy_path)
    if profile != policy["environment"] or gate not in GATES:
        raise Rejected("unknown_acceptance_profile_or_gate")
    result = {
        "schema_version": 1,
        "gate": gate,
        "status": "inconclusive",
        "profile": profile,
        "started_at": started,
        "finished_at": now(),
        "policy_digest": digest(canonical(policy)),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "input_digests": {"source_fingerprint": source_fingerprint(root)},
        "cases": [],
        "metrics": {},
        "artifact_hashes": {},
        "exit_code": 2,
        "redaction_version": 1,
        "residual_risks": ["Full gate implementation and runtime evidence not yet available"],
    }
    state = Path(state) if state else root / ".runtime"
    if gate == "M01":
        if not all(
            (state / name).is_file() for name in ("workspace.json", "cluster.json", "kubeconfig")
        ):
            result["residual_risks"] = [
                "M01 requires an explicitly bootstrapped owned lab and current worker/storage images"
            ]
            return result
        from mlsecops.foundation import qualify

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                cases=evidence["cases"],
                exit_code=0,
                metrics={"checks": evidence["checks"]},
                residual_risks=evidence["limitations"],
                artifact_hashes={
                    "foundation_qualification": digest(
                        bounded_read(state / "evidence/foundation-qualification.json")
                    )
                },
            )
            result["input_digests"].update(
                worker_image=evidence["image_id"],
                inventory=digest(canonical(evidence["inventory"])),
                materials=digest(canonical(evidence["materials"])),
            )
        except (Rejected, OSError, subprocess.TimeoutExpired) as error:
            unavailable = isinstance(error, (OSError, subprocess.TimeoutExpired)) or (
                isinstance(error, Rejected)
                and str(error).startswith(("required_tool_", "cluster_kubeconfig_unavailable"))
            )
            result.update(
                status="inconclusive" if unavailable else "fail",
                exit_code=2 if unavailable else 1,
                residual_risks=[
                    str(error) if isinstance(error, Rejected) else "M01 environment unavailable"
                ],
            )
        result["finished_at"] = now()
    elif gate == "M02":
        from mlsecops.data_qualification import qualify

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                cases=evidence["cases"],
                exit_code=0,
                metrics={"rows": evidence["rows"]},
                residual_risks=evidence["limitations"],
                artifact_hashes={
                    "data_qualification": digest(
                        bounded_read(state / "evidence/data-qualification.json")
                    )
                },
            )
            result["input_digests"].update(
                source=evidence["source_sha256"], data_lock=evidence["source_lock_digest"]
            )
        except (Rejected, OSError) as error:
            result.update(status="fail", exit_code=1, residual_risks=[str(error)])
        result["finished_at"] = now()
    elif gate == "M03":
        if not (state / "storage.json").exists():
            result["residual_risks"] = [
                "M03 requires explicit storage bootstrap and current worker image"
            ]
            return result
        from mlsecops.integrity_qualification import qualify

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                cases=evidence["cases"],
                exit_code=0,
                metrics={"checks": evidence["checks"], **evidence["component_checks"]},
                residual_risks=evidence["limitations"],
                artifact_hashes={
                    **evidence["artifact_hashes"],
                    "integrity_qualification": digest(
                        bounded_read(state / "evidence/integrity-qualification.json")
                    ),
                },
            )
            result["input_digests"].update(
                source=evidence["source_sha256"],
                data_lock=evidence["source_lock_digest"],
                dataset_reference=evidence["dataset_reference"],
                candidate_reference=evidence["candidate_reference"],
                worker_image=evidence["execution"]["image_id"],
                storage_config=evidence["storage_inputs"]["config_digest"],
            )
        except (Rejected, OSError) as error:
            result.update(status="fail", exit_code=1, residual_risks=[str(error)])
        result["finished_at"] = now()
    elif gate in {"M04", "M05"}:
        if gate == "M04":
            write_json(
                safe_child(state, "evidence/access-qualification.json"),
                {"status": "inconclusive", "started_at": started},
            )
        required = (
            (state / "controllers/resources.json", state / "storage.json", state / "cluster.json")
            if gate == "M04"
            else (state / "evidence/M04.json", state / "evidence/access-qualification.json")
        )
        if not all(path.is_file() for path in required):
            result["residual_risks"] = [f"{gate} requires current CP1 native component evidence"]
            return result
        from mlsecops.isolation_gates import qualify_access, qualify_training

        qualifier = qualify_access if gate == "M04" else qualify_training
        filename = "access-qualification.json" if gate == "M04" else "training-isolation.json"
        try:
            evidence = qualifier(root, state)
            result.update(
                status=evidence["status"],
                cases=evidence["cases"],
                exit_code=0,
                metrics={"checks": evidence["checks"]},
                residual_risks=evidence["limitations"],
                artifact_hashes={
                    **evidence["artifact_hashes"],
                    "isolation_qualification": digest(bounded_read(state / "evidence" / filename)),
                },
            )
            result["input_digests"].update(worker_image=evidence["image_id"])
        except (Rejected, OSError, subprocess.TimeoutExpired) as error:
            unavailable = isinstance(error, (OSError, subprocess.TimeoutExpired)) or (
                isinstance(error, Rejected) and str(error).startswith("required_tool_")
            )
            result.update(
                status="inconclusive" if unavailable else "fail",
                exit_code=2 if unavailable else 1,
                residual_risks=[
                    str(error) if isinstance(error, Rejected) else f"{gate} environment unavailable"
                ],
            )
        result["finished_at"] = now()
    elif gate == "M06":
        if not all(
            (state / "tracking-service" / name).is_file()
            for name in ("configuration.json", "resources.json")
        ):
            result["residual_risks"] = [
                "M06 requires explicit private tracking bootstrap and a current local-cpu worker image"
            ]
            return result
        from mlsecops.reproducibility_gate import qualify

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                source_dirty=evidence["source_dirty"],
                cases=evidence["cases"],
                exit_code=0,
                metrics={"checks": evidence["checks"], **evidence["metrics"]},
                residual_risks=evidence["limitations"],
                artifact_hashes={
                    **evidence["artifact_hashes"],
                    "reproducibility_qualification": digest(
                        bounded_read(state / "evidence/reproducibility-qualification.json")
                    ),
                },
            )
            result["input_digests"].update(evidence["input_digests"])
        except (Rejected, OSError, subprocess.TimeoutExpired) as error:
            unavailable = isinstance(error, (OSError, subprocess.TimeoutExpired)) or (
                isinstance(error, Rejected)
                and str(error).startswith(
                    (
                        "required_tool_",
                        "storage_docker_",
                        "storage_resource_missing",
                        "image_source_fingerprint_mismatch",
                        "tracking_https_not_ready",
                        "tracking_postgres_not_ready",
                        "artifact_unavailable",
                    )
                )
            )
            result.update(
                status="inconclusive" if unavailable else "fail",
                exit_code=2 if unavailable else 1,
                residual_risks=[
                    str(error) if isinstance(error, Rejected) else "M06 runtime unavailable"
                ],
            )
        result["finished_at"] = now()
    elif gate == "M07":
        if not (state / "workspace.json").is_file():
            result["residual_risks"] = [
                "M07 requires explicit workspace bootstrap and a current worker image"
            ]
            return result
        from mlsecops.evaluation_gate import qualify
        from mlsecops.holdout_diagnostics import ClaimFailure

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                source_dirty=evidence["source_dirty"],
                cases=evidence["cases"],
                exit_code={"pass": 0, "fail": 1, "inconclusive": 2}[evidence["status"]],
                metrics={"checks": evidence["checks"], **evidence["metrics"]},
                residual_risks=evidence["limitations"],
                diagnostics=evidence["diagnostics"],
                artifact_hashes={
                    **evidence["artifact_hashes"],
                    "evaluation_gate": digest(
                        bounded_read(state / "evidence/evaluation-gate.json")
                    ),
                },
            )
            result["input_digests"].update(evidence["input_digests"])
        except (Rejected, OSError, subprocess.TimeoutExpired) as error:
            unavailable = isinstance(error, (OSError, subprocess.TimeoutExpired)) or (
                isinstance(error, Rejected)
                and str(error).startswith(
                    (
                        "required_tool_",
                        "storage_docker_",
                        "storage_resource_missing",
                        "image_source_fingerprint_mismatch",
                        "storage_port_unavailable",
                        "artifact_unavailable",
                        "evaluation_quality_inconclusive",
                    )
                )
            )
            result.update(
                status="inconclusive" if unavailable else "fail",
                exit_code=2 if unavailable else 1,
                residual_risks=[
                    str(error) if isinstance(error, Rejected) else "M07 runtime unavailable"
                ],
            )
            if isinstance(error, ClaimFailure):
                result["diagnostics"] = {"holdout_concurrency": error.diagnostics}
        result["finished_at"] = now()
    elif gate in {"M08", "M09", "M22"}:
        if not all(
            (state / name).is_file()
            for name in (
                "workspace.json",
                "storage.json",
                "storage-demo.json",
                "storage-trust.json",
                "trusted-keys.json",
            )
        ):
            result["residual_risks"] = [
                f"{gate} requires an existing evaluated candidate in owned storage"
            ]
            return result
        if gate == "M08":
            from mlsecops.poisoning_gate import qualify

            name = "poisoning"
        elif gate == "M22":
            from mlsecops.absolute_poisoning_gate import qualify

            name = "absolute-poisoning"
        else:
            from mlsecops.robustness_gate import qualify

            name = "robustness"

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                source_dirty=evidence["source_dirty"],
                cases=evidence["cases"],
                exit_code={"pass": 0, "fail": 1, "inconclusive": 2}[evidence["status"]],
                metrics={"checks": evidence["checks"], **evidence["metrics"]},
                residual_risks=evidence["limitations"],
                artifact_hashes={
                    **evidence["artifact_hashes"],
                    f"{name}_gate": digest(bounded_read(state / f"evidence/{name}-gate.json")),
                },
            )
            result["input_digests"].update(evidence["input_digests"])
        except (Rejected, OSError, subprocess.TimeoutExpired) as error:
            unavailable = isinstance(error, (OSError, subprocess.TimeoutExpired)) or (
                isinstance(error, Rejected)
                and str(error).startswith(
                    (
                        "required_tool_",
                        "storage_docker_",
                        "storage_resource_missing",
                        "image_source_fingerprint_mismatch",
                        "artifact_unavailable",
                    )
                )
            )
            result.update(
                status="inconclusive" if unavailable else "fail",
                exit_code=2 if unavailable else 1,
                residual_risks=[
                    str(error) if isinstance(error, Rejected) else f"{gate} runtime unavailable"
                ],
            )
        result["finished_at"] = now()
    elif gate == "M12":
        required = ("workspace.json", "kubeconfig", "storage.json", "storage-demo.json")
        if not all((state / name).is_file() for name in required):
            result["residual_risks"] = [
                "M12 requires the owned hosted cluster, source storage and actual evaluated candidate"
            ]
            return result
        from mlsecops.inference_gate import qualify

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                started_at=evidence["started_at"],
                source_dirty=evidence["source_dirty"],
                cases=evidence["cases"],
                exit_code=0,
                metrics={"checks": evidence["checks"], **evidence["metrics"]},
                residual_risks=evidence["limitations"],
                artifact_hashes=evidence["artifact_hashes"],
            )
            result["input_digests"].update(evidence["input_digests"])
        except (Rejected, OSError, subprocess.TimeoutExpired) as error:
            unavailable = (
                isinstance(error, (OSError, subprocess.TimeoutExpired))
                or str(error) == "trust_hosted_runner_required"
            )
            result.update(
                status="inconclusive" if unavailable else "fail",
                exit_code=2 if unavailable else 1,
                residual_risks=[
                    "M12 prerequisites unavailable"
                    if unavailable
                    else "M12 inference verification rejected"
                ],
            )
        result["finished_at"] = now()
    elif gate == "M21":
        if not (state / "workspace.json").is_file():
            result["residual_risks"] = [
                "M21 requires explicit workspace bootstrap and a current worker image"
            ]
            return result
        from mlsecops.intake_gate import qualify

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                source_dirty=evidence["source_dirty"],
                cases=evidence["cases"],
                exit_code={"pass": 0, "fail": 1, "inconclusive": 2}[evidence["status"]],
                metrics={"checks": evidence["checks"], **evidence["metrics"]},
                residual_risks=evidence["limitations"],
                artifact_hashes={
                    **evidence["artifact_hashes"],
                    "intake_gate": digest(bounded_read(state / "evidence/intake-gate.json")),
                },
            )
            result["input_digests"].update(evidence["input_digests"])
        except (Rejected, OSError, subprocess.TimeoutExpired) as error:
            unavailable = isinstance(error, (OSError, subprocess.TimeoutExpired)) or (
                isinstance(error, Rejected)
                and str(error).startswith(
                    (
                        "M21_linux_required",
                        "required_tool_",
                        "storage_docker_",
                        "storage_resource_missing",
                        "storage_loopback_port_unavailable",
                        "image_source_fingerprint_mismatch",
                        "artifact_unavailable",
                    )
                )
            )
            result.update(
                status="inconclusive" if unavailable else "fail",
                exit_code=2 if unavailable else 1,
                residual_risks=[
                    str(error)
                    if isinstance(error, Rejected) and str(error).startswith("M21_")
                    else "M21 runtime unavailable or verification rejected"
                ],
            )
        result["finished_at"] = now()
    elif gate == "M20":
        required = (
            "workspace.json",
            "kubeconfig",
            "controllers/resources.json",
            "kubernetes-storage/migration-inputs.json",
            "storage.json",
        )
        if not all((state / name).is_file() for name in required):
            result["residual_risks"] = [
                "M20 requires the owned cluster, private migrated storage, current controller profile and original host storage"
            ]
            return result
        from mlsecops.authority_qualification import qualify

        try:
            evidence = qualify(root, state)
            result.update(
                status=evidence["status"],
                cases=evidence["cases"],
                exit_code=0,
                metrics={
                    "checks": evidence["checks"],
                    "negative_native_batches": evidence["negative_native_batches"],
                    **evidence["component_checks"],
                },
                residual_risks=evidence["limitations"],
                artifact_hashes={
                    **evidence["artifact_hashes"],
                    "authority_qualification": digest(
                        bounded_read(state / "evidence/authority-qualification.json")
                    ),
                },
            )
            result["input_digests"].update(
                {
                    name: evidence[name]
                    for name in (
                        "image_id",
                        "dataset_reference",
                        "candidate_reference",
                        "model_digest",
                        "policy_digest",
                    )
                }
            )
        except (Rejected, OSError, subprocess.TimeoutExpired) as error:
            result.update(
                status="fail",
                exit_code=1,
                residual_risks=[
                    str(error) if isinstance(error, Rejected) else "M20 runtime execution failed"
                ],
            )
        result["finished_at"] = now()
    return result


def main():
    parser = argparse.ArgumentParser(description="Fail-closed R1 acceptance reports")
    parser.add_argument("--gate", choices=GATES, required=True)
    parser.add_argument("--profile", choices=["local-cpu"], default="local-cpu")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    try:
        write_json(
            arguments.output,
            {
                "schema_version": 1,
                "gate": arguments.gate,
                "profile": arguments.profile,
                "status": "inconclusive",
                "exit_code": 2,
                "started_at": now(),
                "residual_risks": ["Acceptance running; previous output is not current evidence"],
            },
        )
        result = report(
            arguments.gate, arguments.profile, Path(__file__).resolve().parents[1], arguments.state
        )
        write_json(arguments.output, result)
        print(f"{result['gate']}: {result['status']}")
        return result["exit_code"]
    except (Rejected, OSError) as error:
        print(f"Acceptance rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
