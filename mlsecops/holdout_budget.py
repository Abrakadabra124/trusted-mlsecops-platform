import argparse
import sys
from pathlib import Path

from mlsecops import storage
from mlsecops.contracts import Rejected, canonical, digest

LIMIT = 32


def policy():
    return {
        "schema_version": 1,
        "purpose": "synthetic-release-lab-holdout",
        "maximum_attempts": LIMIT,
        "scope": "holdout-content-digest-within-authoritative-storage",
        "failed_attempts": "spent-without-refund",
    }


def reservation(holdout_digest, slot):
    storage.object_id(holdout_digest)
    if type(slot) is not int or not 1 <= slot <= LIMIT:
        raise Rejected("holdout_budget_slot_invalid")
    return canonical(
        {
            "schema_version": 1,
            "kind": "holdout-reservation",
            "holdout_digest": holdout_digest,
            "slot": slot,
        }
    )


def reserve(client, holdout_digest):
    storage.object_id(holdout_digest)
    for slot in range(1, LIMIT + 1):
        content = reservation(holdout_digest, slot)
        if storage.claim(client, "evaluations", content):
            return {
                "holdout_digest": holdout_digest,
                "slot": slot,
                "reservation": digest(content),
                "policy_digest": digest(canonical(policy())),
            }
    raise Rejected("holdout_budget_exhausted")


def inspect(client, holdout_digest):
    occupied = []
    for slot in range(1, LIMIT + 1):
        content = reservation(holdout_digest, slot)
        try:
            stored = storage.get(client, "evaluations", digest(content))
        except Rejected as error:
            if str(error) != "storage_object_missing":
                raise
        else:
            if stored != content:
                raise Rejected("holdout_budget_ledger_mismatch")
            occupied.append(slot)
    return {
        "holdout_digest": holdout_digest,
        "policy": policy(),
        "occupied_slots": occupied,
        "remaining_upper_bound": LIMIT - len(occupied),
        "scope": "read-only-observation-not-authorization",
    }


def main():
    parser = argparse.ArgumentParser(description="Read-only holdout access ledger inspection")
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--holdout", required=True)
    arguments = parser.parse_args()
    try:
        print(canonical(inspect(arguments.client, arguments.holdout)).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Holdout budget inspection rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
