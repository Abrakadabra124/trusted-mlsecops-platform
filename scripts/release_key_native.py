"""Disposable SQL qualification; controlled selections never constitute ML approval."""

import argparse
import copy
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path

import psycopg

from mlsecops import (
    promotion_recovery,
    promotion_state,
    release_key_rotation,
    release_key_store,
    release_policy,
    signing,
    storage,
    trust,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, now, safe_child, write_json
from mlsecops.inventory import command, source_fingerprint
from mlsecops.storage_bootstrap import admin, validate
from mlsecops.storage_pki import ROLES
from scripts.promotion_native import record


def qualify(root, state):
    state = Path(state).resolve()
    marker = validate(state)
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("release_key_native_source_dirty")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    campaign, started = uuid.uuid4().hex, now()
    environment = "rotation-" + campaign
    promoter = state / "storage-clients/promoter"
    keys = {
        role: safe_child(state, f"evidence/release-keys-{campaign}/{role}.pem")
        for role in ("root", "online", *release_policy.ROLES)
    }
    public = {role: signing.create_key(path) for role, path in keys.items()}
    clock = now()
    policy = {
        "schema_version": 1,
        "environment": environment,
        "version": 1,
        "issued_at": clock - 1,
        "expires_at": clock + 3600,
        "required_gates": list(release_policy.GATES),
        "identities": {
            role: {"issuer": "controlled-" + role, "public_key": public[role]}
            for role in release_policy.ROLES
        },
    }
    pin = digest(canonical(policy))
    promotion_state.install(state)
    original = promotion_recovery.read(marker["name"])
    checksum = release_key_store.migrate(state)
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected("release_key_native_invariant:" + name)
        cases.append(name)

    confirmed("migration-idempotent", release_key_store.migrate(state) == checksum)
    migrated = promotion_recovery.read(marker["name"])
    confirmed(
        "migration-preserves-existing-tables",
        all(migrated["tables"][name] == value for name, value in original["tables"].items()),
    )
    promotion_state.configure(state, environment, pin)
    material = storage.put(
        promoter, "releases", canonical({"controlled-not-ML-approval": campaign})
    )

    def selection(sequence, policy_pin):
        return storage.put(
            promoter,
            "releases",
            canonical(
                {
                    "schema_version": 1,
                    "kind": "promotion-selection",
                    "environment": environment,
                    "policy_sha256": policy_pin,
                    "sequence": sequence,
                    "subject_sha256": "b" * 64,
                    "proposal_reference": material,
                    "authorization_reference": material,
                    "issued_at": clock,
                    "expires_at": clock + 1800,
                }
            ),
        )

    selected = selection(1, pin)
    record(promoter, selected)
    revoked, references = [], []
    for sequence, role in enumerate(release_policy.ROLES, 1):
        issued = now()
        new_key = safe_child(state, f"evidence/release-keys-{campaign}/{role}-next.pem")
        following = copy.deepcopy(policy)
        following.update(version=policy["version"] + 1, issued_at=issued)
        following["identities"][role]["public_key"] = signing.create_key(new_key)
        next_pin = digest(canonical(following))
        intent = {
            "schema_version": 1,
            "environment": environment,
            "role": role,
            "previous_policy_sha256": pin,
            "next_policy_sha256": next_pin,
            "sequence": sequence,
            "request_sha256": selected,
            "issued_at": issued,
            "expires_at": issued + 300,
        }
        package = {
            "schema_version": 1,
            "authorization": signing.sign(intent, "release-key-rotation", keys["root"]),
            "previous_policy": signing.sign(policy, "promotion-policy", keys["root"]),
            "next_policy": signing.sign(following, "promotion-policy", keys["root"]),
        }
        verified = release_key_rotation.verify(
            package,
            trusted_root=public["root"],
            expected_policy=pin,
            head={"sequence": sequence, "request_sha256": selected},
            environment=environment,
            clock=issued,
        )
        revoked.append(verified["previous_key"])
        online = {
            "schema_version": 1,
            "environment": environment,
            "version": sequence,
            "promotion_policy_sha256": next_pin,
            "issued_at": issued,
            "expires_at": issued + 600,
            "revoked_keys": sorted(revoked),
            "revoked_artifacts": [],
        }
        envelope = signing.sign(online, "trust-policy", keys["online"])

        def rotate():
            lease = trust.Lease(
                lambda: (envelope, now()),
                trusted_root=public["online"],
                environment=environment,
                minimum_version=sequence,
            )
            return release_key_store.rotate(
                state,
                package,
                trusted_root=public["root"],
                expected_policy=pin,
                environment=environment,
                lease=lease,
            )

        before = promotion_state.state(state / "storage-clients/serving", environment)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: rotate(), range(2)))
        confirmed(
            role + "-concurrent-identical-transition",
            all(
                value["rotation_sha256"] == digest(canonical(package))
                and value["release_ready"] is False
                for value in outcomes
            ),
        )
        confirmed(
            role + "-head-unchanged",
            promotion_state.state(state / "storage-clients/serving", environment) == before,
        )
        complete = promotion_recovery.read(marker["name"])
        confirmed(
            role + "-exact-retry-no-history-write",
            rotate()["reused"] and promotion_recovery.read(marker["name"]) == complete,
        )
        confirmed(
            role + "-single-rotation-row",
            admin(
                marker["name"],
                f"SELECT count(*) FROM ml_promotion.policy_rotations WHERE environment='{environment}';",
            )
            == str(sequence),
        )
        for label, changed in (
            ("wrong-head", {**verified, "intent": {**intent, "sequence": sequence + 1}}),
            ("expired", {**verified, "intent": {**intent, "issued_at": 1, "expires_at": 2}}),
        ):
            try:
                admin(marker["name"], release_key_store.record_sql(changed, canonical(package)))
            except Rejected:
                confirmed(
                    role + "-sql-" + label + "-no-mutation",
                    promotion_recovery.read(marker["name"]) == complete,
                )
            else:
                raise Rejected("release_key_native_guard_bypassed")
        obsolete = selection(sequence + 1, pin)
        try:
            record(promoter, obsolete)
        except psycopg.Error as error:
            confirmed(role + "-old-policy-selection-denied", error.sqlstate == "P1002")
        else:
            raise Rejected("release_key_native_old_policy_selected")
        selected = selection(sequence + 1, next_pin)
        confirmed(role + "-new-policy-selection", record(promoter, selected) == selected)
        references.append(digest(canonical(package)))
        policy, pin = following, next_pin

    current = promotion_recovery.read(marker["name"])
    confirmed(
        "old-and-new-policy-events-remain-valid",
        current["tables"]["policy_rotations"]["invalid"] == 0,
    )
    for label, mutation in (
        (
            "current-policy",
            f"UPDATE ml_promotion.authorities SET policy_sha256='{'c' * 64}' WHERE environment='{environment}'",
        ),
        (
            "history-chain",
            f"UPDATE ml_promotion.policy_rotations SET previous_policy_sha256='{'c' * 64}' WHERE environment='{environment}' AND version=3",
        ),
        (
            "boundary-request",
            f"UPDATE ml_promotion.policy_rotations SET request_sha256='{selected}' WHERE environment='{environment}' AND version=2",
        ),
    ):
        value = decode(
            admin(
                marker["name"],
                "BEGIN;" + mutation + ";" + promotion_recovery.ledger_sql(2) + ";ROLLBACK;",
            ).encode()
        )
        try:
            promotion_recovery.validate_ledger(value)
        except Rejected:
            confirmed(
                label + "-corruption-detected", promotion_recovery.read(marker["name"]) == current
            )
        else:
            raise Rejected("release_key_native_corruption_missed")
    for role in ROLES:
        with storage.connect(state / f"storage-clients/{role}") as connection:
            try:
                connection.execute("DELETE FROM ml_promotion.policy_rotations WHERE false")
            except psycopg.Error as error:
                confirmed(role + "-rotation-mutation-denied", error.sqlstate == "42501")
            else:
                raise Rejected("release_key_native_role_mutation")
            finally:
                connection.rollback()
    confirmed(
        "source-unchanged",
        source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision,
    )
    return {
        "schema_version": 1,
        "scope": "controlled-release-signer-SQL-history-not-full-M11",
        "status": "pass",
        "release_ready": False,
        "campaign_id": campaign,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "migration_sha256": checksum,
        "cases": cases,
        "rotations": references,
        "head_sequence": 4,
        "policy_version": 4,
        "ledger_sha256": digest(canonical(current)),
        "limitations": [
            "Controlled selections are not approved ML releases",
            "Online trust is a real signed in-process fixture, not a live authority service",
            "Actual signer change in serving and complete candidate-bound M11 still required",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Disposable release-key SQL qualification")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    arguments = parser.parse_args()
    output = None
    try:
        validate(arguments.state)
        output = safe_child(arguments.state, "evidence/release-key-native.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        report = qualify(Path(__file__).resolve().parents[1], arguments.state)
        write_json(output, report)
        print(canonical({**report, "cases": len(report["cases"])}).decode())
        return 0
    except (Rejected, psycopg.Error, OSError, KeyError, TypeError, ValueError, RuntimeError):
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "release_ready": False})
        print("Release key qualification failed; inspect owned state locally", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
