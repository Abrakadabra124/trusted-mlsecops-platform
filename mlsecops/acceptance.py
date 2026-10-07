import argparse
import sys
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.inventory import command, source_fingerprint

GATES = tuple(f"M{number:02}" for number in range(1, 24))


def report(gate, profile, root):
    started = now()
    policy_path = root / "policies/local-cpu.json"
    policy = read_json(policy_path)
    if profile != policy["environment"] or gate not in GATES:
        raise Rejected("unknown_acceptance_profile_or_gate")
    return {
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


def main():
    parser = argparse.ArgumentParser(description="Fail-closed R1 acceptance reports")
    parser.add_argument("--gate", choices=GATES, required=True)
    parser.add_argument("--profile", choices=["local-cpu"], default="local-cpu")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = report(arguments.gate, arguments.profile, Path(__file__).resolve().parents[1])
        write_json(arguments.output, result)
        print(f"{result['gate']}: {result['status']}")
        return result["exit_code"]
    except (Rejected, OSError) as error:
        print(f"Acceptance rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
