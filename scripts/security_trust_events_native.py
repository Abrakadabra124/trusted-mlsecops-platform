"""Owned hosted SQL history -> separate observer CLI -> real durable collector.

Synthetic authority keys and revocations, real SQL/TLS/signatures/processes.
This source qualification does not claim a continuously deployed observer/M23.
"""

import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from mlsecops import (
    security_event_delivery,
    security_event_outbox,
    signing,
    storage,
    trust,
    trust_authority,
    trust_root_store,
)
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.inventory import command, source_fingerprint
from scripts import security_event_audit_fixture as audit_fixture
from scripts.release_reader_native import disposable


def qualify():
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("trust_security_hosted_required")
    root = Path(__file__).resolve().parents[1]
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("trust_security_dirty_source")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    cases, durations = [], []

    def check(name, condition):
        if not condition:
            raise Rejected("trust_security_case:" + name)
        cases.append(name)

    with disposable(root, root / ".runtime", uuid.uuid4().hex, "trust-events", 15449) as state:
        with audit_fixture.live() as fx:
            old_key, new_key = (fx.directory / name for name in ("old-root.pem", "new-root.pem"))
            old_root, new_root = signing.create_key(old_key), signing.create_key(new_key)
            trust_authority.install(state, "local-cpu", old_root)
            initial = trust_authority.update(
                state, "a" * 64, old_key, revoked_artifacts=["b" * 64], revoked_keys=["c" * 64]
            )
            serving = state / "storage-clients/serving"
            producer = decode(fx.audit_config.read_bytes())
            producer.update(
                schema_version=1,
                producer_key_file=str(fx.fx.keys["trust"]),
                state_directory=str(fx.directory / "trust-outbox"),
            )
            producer["state_sha256"] = security_event_outbox.initialize(
                producer["state_directory"],
                fx.registry,
                security_event_outbox.key_identity(fx.fx.keys["trust"]),
                clock_ms=fx.now(),
            )
            fx.write("trust-producer.json", canonical(producer))
            observer = dict(
                schema_version=1,
                trust_client=str(serving),
                environment="local-cpu",
                initial_root=old_root,
                producer_config=str(fx.directory / "trust-producer.json"),
                rotations=[],
            )

            def outbox():
                return security_event_delivery.configured(
                    observer["producer_config"]
                ).store.snapshot()

            def observe(*, expected=True):
                fx.write("trust-observer.json", canonical(observer))
                start = time.monotonic()
                result = subprocess.run(
                    [
                        sys.executable,
                        "-W",
                        "error",
                        "-m",
                        "mlsecops.security_trust_events",
                        "--config",
                        str(fx.directory / "trust-observer.json"),
                    ],
                    cwd=root,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=30,
                    check=False,
                    env={**os.environ, "PYTHONUTF8": "1"},
                )
                if not expected:
                    check(
                        "observer-refuses-with-private-output",
                        result.returncode == 1
                        and result.stdout == b""
                        and result.stderr == b"trust_security_rejected\n",
                    )
                    return None
                check(
                    "separate-cli-exits-successfully",
                    result.returncode == 0 and result.stderr == b"",
                )
                value = decode(result.stdout)
                check(
                    "observer-does-not-grant-release",
                    value["state"] == "observed" and value["release_ready"] is False,
                )
                durations.append(time.monotonic() - start)
                return value

            check(
                "initial-history-observed",
                observe()["document_sha256"] == initial["document_sha256"]
                and len(outbox()["records"]) == 2,
            )
            before = outbox()
            committed = trust_authority.update(
                state, "a" * 64, old_key, revoked_artifacts=["d" * 64]
            )
            check("commit-without-running-observer-does-not-enqueue", outbox() == before)
            fx.stop()
            observe(expected=False)
            pending = outbox()["records"][-1]
            check(
                "offline-observer-persists-committed-revocation",
                len(outbox()["records"]) == 3 and pending["receipt"] is None,
            )
            fx.start()
            check(
                "restart-recovers-committed-history",
                observe()["document_sha256"] == committed["document_sha256"],
            )
            recovered = outbox()
            check(
                "same-event-after-process-and-collector-restart",
                recovered["records"][-1]["envelope"] == pending["envelope"]
                and all(item["receipt"] is not None for item in recovered["records"]),
            )
            observe()
            check("exact-cli-retry-idempotent", outbox() == recovered)
            renewal = trust_authority.update(state, "a" * 64, old_key)
            check(
                "renewal-observed-without-new-revocation",
                observe()["document_sha256"] == renewal["document_sha256"]
                and outbox() == recovered,
            )

            trust_root_store.migrate(state)
            _, previous = trust_authority.current(state)
            payload = trust.validate(previous["envelope"], old_root, "local-cpu")
            following = {
                **payload,
                "version": previous["version"] + 1,
                "issued_at": previous["clock"],
                "expires_at": previous["clock"] + 3600,
                "revoked_keys": sorted(
                    [*payload["revoked_keys"], digest(signing.decode64(old_root))]
                ),
            }
            document = signing.sign(following, "trust-policy", new_key)
            intent = dict(
                schema_version=1,
                environment="local-cpu",
                current_root=old_root,
                next_root=new_root,
                previous_version=previous["version"],
                previous_sha256=previous["sha256"],
                next_version=following["version"],
                next_sha256=digest(canonical(document)),
                issued_at=previous["clock"],
                expires_at=previous["clock"] + 300,
            )
            package = dict(
                schema_version=1,
                authorization=signing.sign(intent, "trust-root-rotation", old_key),
                acceptance=signing.sign(intent, "trust-root-rotation", new_key),
                document=document,
            )
            rotated = trust_root_store.rotate(
                state, package, current_root=old_root, next_root=new_root
            )
            observe(expected=False)
            check("unconfigured-new-root-does-not-mutate-outbox", outbox() == recovered)
            fx.write("rotation.json", canonical(package))
            observer["rotations"] = [
                dict(
                    version=rotated["version"],
                    next_root=new_root,
                    package_file=str(fx.directory / "rotation.json"),
                )
            ]
            check(
                "operator-pinned-dual-signature-rotation-observed",
                observe()["document_sha256"] == rotated["document_sha256"]
                and len(outbox()["records"]) == 4,
            )
            changed = trust_authority.update(state, "e" * 64, new_key)
            check(
                "policy-change-observed-under-new-root",
                observe()["document_sha256"] == changed["document_sha256"]
                and len(outbox()["records"]) == 5,
            )

            records = outbox()["records"]
            reasons, subjects, identities = [], [], []
            for record in records:
                event = fx.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
                fx.registry.receipt(record["receipt"], event)
                value = event.document()
                check(
                    "signed-trust-route-and-receipt-" + str(value["sequence"]),
                    event.route == "security.trust"
                    and value["kind"] == "trust.revoked"
                    and value["bundle_sha256"] is None,
                )
                reasons.append(value["reason"])
                subjects.append(value["asset_sha256"])
                identities.append(value["event_id"])
            check(
                "all-categories-bound-to-committed-documents",
                reasons == ["artifact", "key", "artifact", "key", "policy"]
                and subjects
                == [initial["document_sha256"]] * 2
                + [
                    committed["document_sha256"],
                    rotated["document_sha256"],
                    changed["document_sha256"],
                ]
                and len(set(identities)) == 5,
            )
            with storage.connect(serving) as connection:
                rights = connection.execute(
                    "SELECT current_user, has_table_privilege(current_user, 'ml_trust.documents', 'SELECT'), has_table_privilege(current_user, 'ml_trust.documents', 'INSERT'), has_table_privilege(current_user, 'ml_trust.documents', 'UPDATE'), has_table_privilege(current_user, 'ml_trust.documents', 'DELETE'), has_table_privilege(current_user, 'ml_trust.root_rotations', 'SELECT')"
                ).fetchone()
            check(
                "existing-read-only-role-no-rotation-package-grant",
                rights == ("ml_serving", True, False, False, False, False),
            )
            # A deliberate gap in this owned test authority is not silently skipped.
            container, execute = trust_authority.commands(state, None)
            execute(
                container, "SET ROLE ml_owner; DELETE FROM ml_trust.documents WHERE version = 2;"
            )
            before = outbox()
            observe(expected=False)
            check("missing-committed-version-denied-before-outbox-change", outbox() == before)
            check("each-online-observation-within-60-seconds", max(durations) < 60)
        check("collector-cleanup-confirmed", fx.process is None and not fx.directory.exists())
    check("owned-sql-and-volume-cleanup-confirmed", not state.exists())
    check(
        "runtime-source-unchanged",
        source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return dict(
        source=revision,
        fingerprint=fingerprint,
        cases=cases,
        status="pass",
        release_ready=False,
        max_online_observation_seconds=max(durations),
        scope="bounded-trust-history-observer-not-continuous-M23",
    )


if __name__ == "__main__":
    print(canonical(qualify()).decode())
