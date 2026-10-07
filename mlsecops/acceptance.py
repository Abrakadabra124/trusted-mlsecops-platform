import argparse
import sys
from pathlib import Path

from mlsecops.contracts import Rejected, bounded_read, canonical, digest, now, read_json, write_json
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
    if gate == "M02":
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
    return result


def main():
    parser = argparse.ArgumentParser(description="Fail-closed R1 acceptance reports")
    parser.add_argument("--gate", choices=GATES, required=True)
    parser.add_argument("--profile", choices=["local-cpu"], default="local-cpu")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    try:
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
