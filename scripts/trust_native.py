import argparse
import shutil
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path

import psycopg

from mlsecops import (
    bootstrap,
    signing,
    storage,
    storage_backup,
    storage_bootstrap,
    storage_restore,
    trust,
    trust_authority,
)
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, safe_child, write_json
from mlsecops.inventory import command, source_fingerprint


def qualify(root, state):
    state = Path(state).resolve()
    source = storage_bootstrap.validate(state)
    original_ledger = storage_restore.ledger(source["name"])
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("trust_qualification_source_dirty")
    fingerprint = source_fingerprint(root)
    campaign = uuid.uuid4().hex
    destination = state / "evidence" / ("trust-" + campaign)
    if destination.exists():
        raise Rejected("trust_qualification_target_exists")
    started = now()
    cases = []

    def confirmed(label, condition=True):
        if not condition:
            raise Rejected("trust_case_failed:" + label)
        cases.append(label)
        print(canonical({"case": label, "status": "pass"}).decode(), flush=True)

    def rejected(label, operation, code=None):
        try:
            operation()
        except Rejected as error:
            if code is not None and str(error) != code:
                raise Rejected("trust_wrong_denial:" + label) from None
            confirmed(label)
        else:
            raise Rejected("trust_negative_bypass:" + label)

    bootstrap.initialize(root, destination)
    owned = None
    outage_trace = None
    try:
        storage_bootstrap.bootstrap(destination, 15444)
        owned = storage_bootstrap.validate(destination)
        confirmed("separate-authority-workspace", owned["workspace_id"] != source["workspace_id"])
        public = read_json(destination / "trusted-keys.json")["trust"]
        key = destination / "keys/trust.pem"
        migration = trust_authority.install(destination, "local-cpu", public)
        confirmed(
            "migration-idempotent",
            trust_authority.install(destination, "local-cpu", public) == migration,
        )
        rejected(
            "foreign-authority-config",
            lambda: trust_authority.install(destination, "foreign", public),
            "trust_configuration_conflict",
        )
        trust_authority.update(destination, "a" * 64, key)
        serving = destination / "storage-clients/serving"
        promoter = destination / "storage-clients/promoter"

        def reader():
            return trust_authority.read(serving, "local-cpu", public)

        lease = trust.Lease(reader, trusted_root=public, environment="local-cpu", minimum_version=1)
        lease.refresh()
        scope = {"policy_sha256": "a" * 64, "artifacts": ["b" * 64], "keys": []}
        confirmed("actual-tls-read-and-lease", lease.check(**scope)["version"] == 1)
        confirmed(
            "promoter-sees-same-document",
            trust_authority.read(promoter, "local-cpu", public)[0] == reader()[0],
        )
        with storage.connect(serving) as connection:
            tls = connection.execute(
                "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
            ).fetchone()
        confirmed("mutual-tls-13", tls == (True, "TLSv1.3"))
        initial = reader()[0]
        confirmed("same-document-retry", trust_authority.publish(destination, initial)["reused"])
        for role in ("serving", "promoter", "publisher", "scorer", "curator", "ingestor"):
            client = destination / "storage-clients" / role
            queries = ["DELETE FROM ml_trust.documents", "TRUNCATE ml_trust.documents"]
            if role not in ("serving", "promoter"):
                queries.append("SELECT * FROM ml_trust.documents")
            for position, query in enumerate(queries):
                try:
                    with storage.connect(client) as connection:
                        connection.execute(query)
                except psycopg.Error as error:
                    confirmed(f"role-{role}-denial-{position}", error.sqlstate == "42501")
                else:
                    raise Rejected("trust_native_permission_bypass")
        for extended in (False, True):
            rejected(
                f"model-backup-excludes-authority-{extended}",
                lambda: storage_backup.create(root, destination, include_promotion=extended),
                "backup_snapshot_unavailable",
            )
        trust_authority.update(destination, "a" * 64, key, revoked_artifacts=["b" * 64])
        lease.refresh()
        rejected(
            "model-revocation-without-grace", lambda: lease.check(**scope), "trust_artifact_revoked"
        )
        confirmed(
            "independent-subject-still-allowed",
            lease.check(**{**scope, "artifacts": ["c" * 64]})["version"] == 2,
        )
        revoked_key = digest(
            signing.decode64(read_json(destination / "trusted-keys.json")["evaluator"])
        )
        trust_authority.update(destination, "a" * 64, key, revoked_keys=[revoked_key])
        lease.refresh()
        rejected(
            "signer-revocation-without-grace",
            lambda: lease.check(**{**scope, "artifacts": [], "keys": [revoked_key]}),
            "trust_key_revoked",
        )
        rejected(
            "old-policy-rejected",
            lambda: lease.check(**{**scope, "policy_sha256": "c" * 64}),
            "trust_policy_changed",
        )
        rejected(
            "old-document-replay",
            lambda: trust_authority.publish(destination, initial),
            "trust_update_conflict_or_unrevocation",
        )
        _, previous = trust_authority.current(destination)
        payload = trust.validate(previous["envelope"], public, "local-cpu")
        rejected(
            "unrevocation-denied",
            lambda: trust_authority.publish(
                destination,
                signing.sign(
                    {**payload, "version": 4, "revoked_artifacts": []}, "trust-policy", key
                ),
            ),
            "trust_update_conflict_or_unrevocation",
        )
        foreign = destination / "keys/curator.pem"
        rejected(
            "foreign-signer-denied",
            lambda: trust_authority.publish(
                destination, signing.sign({**payload, "version": 4}, "trust-policy", foreign)
            ),
            "untrusted_key",
        )
        barrier = threading.Barrier(2)

        def concurrent(reference):
            envelope = signing.sign(
                {**payload, "version": 4, "revoked_artifacts": sorted(["b" * 64, reference])},
                "trust-policy",
                key,
            )
            barrier.wait(timeout=10)
            try:
                trust_authority.publish(destination, envelope)
                return "committed"
            except Rejected:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(concurrent, ["d" * 64, "e" * 64]))
        confirmed("concurrent-update-single-winner", sorted(results) == ["committed", "rejected"])
        lease.refresh()
        confirmed("version-four-durable", lease.check(**{**scope, "artifacts": []})["version"] == 4)
        storage_bootstrap.docker(["restart", owned["container_id"]], timeout=60)
        storage_bootstrap.bootstrap(destination, 15444)
        confirmed(
            "restart-keeps-current-version",
            trust_authority.read(serving, "local-cpu", public)[0]
            == trust_authority.current(destination)[1]["envelope"],
        )
        lease.refresh()
        rejected("restart-keeps-revocation", lambda: lease.check(**scope), "trust_artifact_revoked")
        safe_scope = {**scope, "artifacts": []}
        lease.refresh()
        last_success = time.monotonic()
        storage_bootstrap.docker(["stop", owned["container_id"]], timeout=60)
        rejected("outage-refresh-unavailable", lease.refresh, "trust_service_unavailable")
        confirmed(
            "outage-cached-until-original-deadline", lease.check(**safe_scope)["version"] == 4
        )
        time.sleep(max(0, lease.deadline - time.monotonic() - 0.2))
        last_allowed = None
        while True:
            observed = time.monotonic()
            try:
                lease.check(**safe_scope)
                last_allowed = observed - last_success
            except Rejected as error:
                if str(error) != "trust_lease_expired":
                    raise
                denied_at = observed - last_success
                break
            time.sleep(0.001)
        outage_trace = {
            "last_allowed_seconds": last_allowed,
            "first_denied_seconds": denied_at,
            "deadline_from_success_seconds": lease.deadline - last_success,
        }
        confirmed(
            "outage-denial-within-sixty-seconds",
            last_allowed is not None and 0 < last_allowed < denied_at <= 60,
        )
        fresh = trust.Lease(reader, trusted_root=public, environment="local-cpu", minimum_version=4)
        rejected(
            "fresh-client-cannot-start-offline",
            lambda: fresh.check(**safe_scope),
            "trust_lease_unavailable",
        )
        storage_bootstrap.docker(["start", owned["container_id"]])
        storage_bootstrap.bootstrap(destination, 15444)
        fresh.refresh()
        confirmed("online-recovery-requires-fresh-read", fresh.check(**safe_scope)["version"] == 4)
        trust_authority.update(
            destination, "a" * 64, key, revoked_keys=[digest(signing.decode64(public))]
        )
        rejected("root-revocation-cancels-lease", fresh.refresh, "trust_root_revoked")
        rejected(
            "no-root-revocation-fallback",
            lambda: fresh.check(**safe_scope),
            "trust_lease_unavailable",
        )
    finally:
        if owned is not None:
            observed = storage_bootstrap.validate(destination)
            if (
                destination.resolve().parent != (state / "evidence").resolve()
                or observed["workspace_id"] != owned["workspace_id"]
                or observed["workspace_id"] == source["workspace_id"]
            ):
                raise Rejected("trust_cleanup_ownership")
            storage_bootstrap.docker(["rm", "--force", observed["container_id"]])
            storage_bootstrap.docker(["network", "rm", observed["network"]])
            storage_bootstrap.docker(["volume", "rm", observed["volume"]])
            shutil.rmtree(destination.resolve())
    confirmed("owned-authority-cleanup", not destination.exists())
    confirmed(
        "model-storage-and-source-unchanged",
        storage_bootstrap.validate(state)["container_id"] == source["container_id"]
        and storage_restore.ledger(source["name"]) == original_ledger
        and source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return {
        "schema_version": 1,
        "scope": "online-trust-component-not-full-M11",
        "status": "pass",
        "release_ready": False,
        "full_M11": "inconclusive",
        "campaign_id": campaign,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_dirty": False,
        "source_fingerprint": fingerprint,
        "migration_sha256": migration,
        "cases": cases,
        "outage_trace": outage_trace,
        "limitations": [
            "Controlled subjects are not ML approvals",
            "Endpoint integration and root rotation pending",
            "Trusted host and authority DB administrator",
            "No automatic authority restore from model backups",
        ],
    }


def main(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    options = parser.parse_args(arguments)
    output = None
    try:
        storage_bootstrap.validate(options.state)
        output = safe_child(options.state, "evidence/trust-qualification.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        result = qualify(Path(__file__).resolve().parents[1], options.state)
        write_json(output, result)
        print(canonical({**result, "cases": len(result["cases"])}).decode())
        return 0
    except (Rejected, psycopg.Error, OSError, KeyError, TypeError, ValueError, RuntimeError):
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "release_ready": False})
        print(
            canonical({"status": "fail", "reason": "trust_native_rejected"}).decode(),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
