import argparse
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path

import psycopg

from mlsecops import promotion_state, storage, storage_backup, storage_snapshot
from mlsecops.contracts import Rejected, canonical, digest, now, safe_child, write_json
from mlsecops.inventory import command, source_fingerprint
from mlsecops.storage_bootstrap import admin, docker, validate
from mlsecops.storage_pki import ROLES


def record(client, reference):
    with storage.connect(client) as connection:
        return connection.execute(
            "SELECT ml_promotion.record_selection(%s)", (reference,)
        ).fetchone()[0]


def qualify(root, state):
    marker = validate(state)
    started = now()
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    campaign = uuid.uuid4().hex
    environment = "controlled-" + campaign
    policy = digest(canonical({"scope": "controlled-ledger-not-ML-approval", "campaign": campaign}))
    clients = {role: safe_child(state, f"storage-clients/{role}") for role in ROLES}
    promoter, serving = clients["promoter"], clients["serving"]
    migration = promotion_state.install(state)
    if promotion_state.install(state) != migration:
        raise Rejected("promotion_native_migration_changed")
    cases = ["idempotent-explicit-migration"]
    promotion_state.configure(state, environment, policy)
    base = {
        "schema_version": 1,
        "kind": "promotion-selection",
        "environment": environment,
        "policy_sha256": policy,
        "sequence": 1,
        "subject_sha256": digest(campaign.encode()),
        "proposal_reference": storage.put(
            promoter, "releases", canonical({"controlled-proposal": campaign})
        ),
        "authorization_reference": storage.put(
            promoter, "releases", canonical({"controlled-transport-only": campaign})
        ),
    }

    def clock():
        with storage.connect(promoter) as connection:
            return connection.execute(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint"
            ).fetchone()[0]

    issued = clock()
    base.update(issued_at=issued, expires_at=issued + 1800)

    def store(**changes):
        return storage.put(promoter, "releases", canonical({**base, **changes}))

    def confirmed(name, condition):
        if not condition:
            raise Rejected("promotion_native_invariant_failed:" + name)
        cases.append(name)

    def rejected(name, sqlstate, operation):
        try:
            operation()
        except psycopg.Error as error:
            if error.sqlstate != sqlstate:
                raise Rejected("promotion_native_wrong_sqlstate:" + name) from None
            cases.append(name)
        else:
            raise Rejected("promotion_native_denial_bypassed:" + name)

    first = store()
    confirmed("initial-record", record(promoter, first) == first)
    confirmed("idempotent-identical-request", record(promoter, first) == first)
    second = store(sequence=2)

    def concurrent(references):
        barrier = threading.Barrier(2, timeout=10)

        def attempt(reference):
            barrier.wait()
            try:
                return "pass", record(promoter, reference)
            except psycopg.Error as error:
                return "rejected", error.sqlstate

        with ThreadPoolExecutor(max_workers=2) as pool:
            return list(pool.map(attempt, references))

    confirmed(
        "concurrent-identical-idempotency", concurrent([second, second]) == [("pass", second)] * 2
    )
    competing = environment + "-race"
    promotion_state.configure(state, competing, policy)
    proposals = [
        store(environment=competing, subject_sha256=digest(f"{campaign}:{index}".encode()))
        for index in (1, 2)
    ]
    outcomes = concurrent(proposals)
    confirmed(
        "concurrent-different-one-winner",
        sum(outcome[0] == "pass" for outcome in outcomes) == 1
        and sum(outcome == ("rejected", "P1004") for outcome in outcomes) == 1,
    )
    winner = next(value for status, value in outcomes if status == "pass")
    confirmed(
        "concurrent-winner-readback",
        promotion_state.state(serving, competing)["request_sha256"] == winner,
    )
    before = promotion_state.state(serving, environment)
    promotion_state.configure(state, environment, policy)
    confirmed(
        "configuration-does-not-reset-head", promotion_state.state(serving, environment) == before
    )
    try:
        promotion_state.configure(state, environment, "0" * 64)
    except Rejected as error:
        confirmed(
            "policy-reconfiguration-rejected", str(error) == "promotion_configuration_conflict"
        )
    else:
        raise Rejected("promotion_native_policy_reset")
    for name, reference, code in (
        ("old-sequence", first, "P1004"),
        ("skipped-sequence", store(sequence=4), "P1004"),
        ("same-sequence-other-subject", store(sequence=2, subject_sha256="0" * 64), "P1004"),
        ("wrong-policy", store(sequence=3, policy_sha256="0" * 64), "P1002"),
        ("unknown-environment", store(environment=environment + "-missing"), "P1002"),
        ("expired", store(sequence=3, issued_at=issued - 60, expires_at=issued - 1), "P1003"),
        ("future", store(sequence=3, issued_at=issued + 1000, expires_at=issued + 1100), "P1003"),
        ("missing-material", store(sequence=3, proposal_reference="0" * 64), "P1001"),
    ):
        rejected(name, code, lambda reference=reference: record(promoter, reference))
    for field, value in (
        ("schema_version", True),
        ("sequence", True),
        ("sequence", 0),
        ("expires_at", None),
        ("extra", "field"),
    ):
        reference = store(**{field: value})
        rejected(
            "invalid-" + field + "-" + str(value), "P1001", lambda: record(promoter, reference)
        )
    third = store(sequence=3)
    try:
        with storage.connect(promoter) as connection:
            connection.execute("SELECT ml_promotion.record_selection(%s)", (third,))
            raise Rejected("controlled-rollback")
    except Rejected as error:
        if str(error) != "controlled-rollback":
            raise
    confirmed(
        "transaction-rollback-preserves-head", promotion_state.state(serving, environment) == before
    )
    confirmed("rolled-back-request-can-retry", record(promoter, third) == third)

    waiting_environment = environment + "-wait"
    promotion_state.configure(state, waiting_environment, policy)
    pending_first = store(environment=waiting_environment)
    expiring_at = clock() + 2
    expiring = store(
        environment=waiting_environment,
        sequence=2,
        issued_at=expiring_at - 2,
        expires_at=expiring_at,
    )
    ready = threading.Event()
    waiting_pid = []

    def waiter():
        with storage.connect(promoter) as connection:
            connection.execute("SET LOCAL lock_timeout = '5s'")
            waiting_pid.append(connection.execute("SELECT pg_backend_pid()").fetchone()[0])
            ready.set()
            try:
                connection.execute("SELECT ml_promotion.record_selection(%s)", (expiring,))
            except psycopg.Error as error:
                return error.sqlstate
            return "unexpected-success"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with storage.connect(promoter) as holder:
            holder.execute("SELECT ml_promotion.record_selection(%s)", (pending_first,))
            future = pool.submit(waiter)
            if not ready.wait(5):
                raise Rejected("promotion_native_waiter_not_started")
            deadline = time.monotonic() + 3
            while (
                admin(
                    marker["name"],
                    f"SELECT count(*) FROM pg_stat_activity WHERE pid = {waiting_pid[0]} AND wait_event_type = 'Lock';",
                )
                != "1"
            ):
                if time.monotonic() >= deadline:
                    raise Rejected("promotion_native_lock_not_observed")
                time.sleep(0.05)
            cases.append("actual-row-lock-wait-observed")
            while clock() <= expiring_at:
                time.sleep(0.05)
        confirmed("expiry-rechecked-after-row-lock", future.result(timeout=6) == "P1003")
    confirmed(
        "expired-waiter-did-not-advance-head",
        promotion_state.state(serving, waiting_environment)["sequence"] == 1,
    )

    for role, client in clients.items():
        for table in ("heads", "events", "authorities"):
            values = {
                "heads": ("environment, sequence, request_sha256", (environment, 3, third)),
                "events": ("environment, sequence, request_sha256", (environment, 3, third)),
                "authorities": ("environment, policy_sha256", (environment, policy)),
            }
            columns, parameters = values[table]
            placeholders = ", ".join(["%s"] * len(parameters))
            queries = {
                "delete": (f"DELETE FROM ml_promotion.{table} WHERE false", None),
                "update": (
                    f"UPDATE ml_promotion.{table} SET environment = environment WHERE false",
                    None,
                ),
                "truncate": (f"TRUNCATE ml_promotion.{table}", None),
                "insert": (
                    f"INSERT INTO ml_promotion.{table} ({columns}) VALUES ({placeholders})",
                    parameters,
                ),
            }
            for operation, (query, parameters) in queries.items():

                def mutate(client=client, query=query, parameters=parameters):
                    with storage.connect(client) as connection:
                        try:
                            connection.execute(query, parameters)
                        finally:
                            connection.rollback()

                rejected(f"{role}-{table}-direct-{operation}-denied", "42501", mutate)
        if role != "promoter":
            rejected(f"{role}-record-denied", "42501", lambda client=client: record(client, third))
    try:
        storage_backup.create(root, state)
    except Rejected as error:
        confirmed(
            "legacy-backup-cannot-omit-ledger",
            str(error) == "backup_promotion_ledger_not_supported",
        )
    else:
        raise Rejected("promotion_native_incomplete_backup_allowed")
    try:
        with storage_snapshot.snapshot(marker["name"]):
            raise Rejected("promotion_native_snapshot_omitted_ledger")
    except Rejected as error:
        confirmed(
            "exported-snapshot-rejects-ledger",
            str(error) == "backup_promotion_ledger_not_supported",
        )
    durable = promotion_state.state(serving, environment)
    docker(["restart", marker["name"]], timeout=60)
    deadline = time.monotonic() + 30
    while True:
        try:
            restored = promotion_state.state(serving, environment)
            break
        except Rejected:
            if time.monotonic() >= deadline:
                raise Rejected("promotion_native_restart_not_ready") from None
            time.sleep(0.2)
    confirmed("service-restart-preserves-head", restored == durable)
    confirmed("restart-preserves-idempotency", record(promoter, third) == third)
    confirmed(
        "ownership-and-source-stable",
        validate(state)["container_id"] == marker["container_id"]
        and source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision,
    )
    return {
        "schema_version": 1,
        "scope": "promotion-ledger-native-SQL-controlled-payloads-not-full-M10",
        "status": "pass",
        "full_M10": "inconclusive",
        "release_ready": False,
        "admission_evidence": "controlled SQL payloads, not approved ML models",
        "campaign_id": campaign,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "migration_sha256": migration,
        "cases": cases,
        "durable_sequence": durable["sequence"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Explicit disposable SQL promotion-ledger qualification"
    )
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    arguments = parser.parse_args()
    output = None
    try:
        validate(arguments.state)
        output = safe_child(arguments.state, "evidence/promotion-native.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        report = qualify(Path(__file__).resolve().parents[1], arguments.state)
        write_json(output, report)
        print(canonical({**report, "cases": len(report["cases"])}).decode())
        return 0
    except (Rejected, psycopg.Error, OSError, KeyError, TypeError, ValueError, RuntimeError):
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "release_ready": False})
        print(
            "Promotion ledger qualification rejected; inspect owned state locally", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
