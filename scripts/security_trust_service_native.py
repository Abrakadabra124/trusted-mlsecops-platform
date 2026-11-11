"""Hosted continuous SQL observer, actual delivery/outage and stopped-source alarm."""

import os
import signal
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path

from mlsecops import (
    security_event_delivery,
    security_event_outbox,
    security_event_store,
    signing,
    trust_authority,
)
from mlsecops.contracts import Rejected, bounded_read, canonical, decode
from mlsecops.inventory import command, source_fingerprint
from scripts import security_event_audit_fixture as audit_fixture
from scripts.release_reader_native import disposable
from scripts.security_identity_events_native import readback


def collector_reader(settings, registry):
    return security_event_store.Store(
        settings["state_directory"], settings["state_sha256"], registry
    )


def failure_state(private_log, outbox, collector):
    # Finite counts only; unknown readback stays unknown, never a successful zero.
    result = {"observer_failed_checks": None, "outbox": None, "collector": None}
    try:
        result["observer_failed_checks"] = (
            bounded_read(private_log, 65536).splitlines().count(b"trust_observer_check_failed")
        )
    except Exception:
        pass
    for name, reader in (("outbox", outbox), ("collector", collector)):
        try:
            records = reader()["records"]
            result[name] = {
                "records": len(records),
                "receipts": sum(record["receipt"] is not None for record in records),
            }
        except Exception:
            pass
    return result


def qualify():
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("trust_observer_hosted_required")
    root = Path(__file__).resolve().parents[1]
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("trust_observer_dirty_source")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    cases, deliveries = [], []

    def check(name, condition):
        if not condition:
            raise Rejected("trust_observer_case:" + name)
        cases.append(name)

    with disposable(root, root / ".runtime", uuid.uuid4().hex, "trust-service", 15449) as state:
        with audit_fixture.live(initial_heartbeat=False, heartbeat_roles=("trust",)) as fx:
            authority_key = fx.directory / "authority.pem"
            authority_root = signing.create_key(authority_key)
            trust_authority.install(state, "local-cpu", authority_root)
            trust_authority.update(state, "a" * 64, authority_key)
            producer = decode(fx.audit_config.read_bytes())
            producer.update(
                schema_version=1,
                producer_key_file=str(fx.fx.keys["trust"]),
                state_directory=str(fx.directory / "trust-outbox"),
            )
            identity = security_event_outbox.key_identity(fx.fx.keys["trust"])
            producer["state_sha256"] = security_event_outbox.initialize(
                producer["state_directory"], fx.registry, identity, clock_ms=fx.now()
            )
            producer_path = str(fx.directory / "trust-producer.json")
            fx.write("trust-producer.json", canonical(producer))
            observer_directory = fx.directory / "observer"
            observer_directory.mkdir(mode=0o700)
            config = observer_directory / "config.json"
            client = state / "storage-clients/serving"
            config.write_bytes(
                canonical(
                    dict(
                        schema_version=1,
                        trust_client=str(client),
                        environment="local-cpu",
                        initial_root=authority_root,
                        producer_config=producer_path,
                        rotations=[],
                    )
                )
            )
            config.chmod(0o600)
            settings = decode((fx.directory / "collector.json").read_bytes())
            collector = collector_reader(settings, fx.registry)
            private_log = fx.directory / "observer-private.log"
            args = [
                sys.executable,
                "-W",
                "error",
                "-m",
                "mlsecops.security_trust_service",
                "--config",
                str(config),
            ]
            process = None

            def snapshot():
                return readback(
                    lambda: security_event_delivery.configured(producer_path).store.snapshot()
                )

            def heartbeat():
                value = snapshot()["heartbeat"]
                return None if value is None else fx.registry.heartbeat(value, clock_ms=fx.now())

            def wait_for(predicate, seconds=45):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    if process is not None and process.poll() is not None:
                        raise Rejected("trust_observer_case:unexpected_exit")
                    if predicate():
                        return
                    time.sleep(0.1)
                raise Rejected("trust_observer_case:observation_deadline")

            def start():
                nonlocal process
                with private_log.open("ab") as output:
                    process = subprocess.Popen(
                        args,
                        cwd=root,
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )

            def stop():
                nonlocal process
                if process is None:
                    return
                if process.poll() is None:
                    process.terminate()
                graceful = True
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    graceful = False
                    os.killpg(process.pid, signal.SIGKILL)
                    code = process.wait(timeout=5)
                # The test created this isolated session/process group. Signal0
                # independently verifies no child survived its supervisor.
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    graceful = False
                    os.killpg(process.pid, signal.SIGKILL)
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            os.killpg(process.pid, 0)
                        except ProcessLookupError:
                            break
                        if time.monotonic() >= deadline:
                            raise Rejected("trust_observer_case:owned_group_cleanup_unconfirmed")
                        time.sleep(0.05)
                process = None
                check("supervisor-stopped-with-confirmed-child-cleanup", graceful and code == 0)

            def received_heartbeat():
                return next(
                    (
                        stream["heartbeat"]
                        for stream in readback(collector.snapshot)["telemetry"]["streams"]
                        if stream["producer_id"] == identity
                    ),
                    None,
                )

            try:
                start()
                wait_for(lambda: heartbeat() is not None)
                wait_for(lambda: received_heartbeat() is not None)
                check(
                    "source-heartbeat-reaches-independent-collector",
                    received_heartbeat()["envelope"] == snapshot()["heartbeat"]
                    and fx.exchange("GET", "/health")[0] == 200,
                )
                first = heartbeat()
                duplicate = subprocess.run(
                    args,
                    cwd=root,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                check(
                    "second-supervisor-refused-before-child",
                    duplicate.returncode == 1
                    and duplicate.stdout == b""
                    and duplicate.stderr == b"trust_observer_rejected\n",
                )
                began = time.monotonic()
                committed = trust_authority.update(
                    state, "a" * 64, authority_key, revoked_artifacts=["b" * 64]
                )
                wait_for(
                    lambda: (
                        len(snapshot()["records"]) == 1
                        and snapshot()["records"][0]["receipt"] is not None
                    )
                )
                deliveries.append(time.monotonic() - began)
                wait_for(lambda: heartbeat()["sequence"] > first["sequence"])
                periodic_seconds = (heartbeat()["observed_at_ms"] - first["observed_at_ms"]) / 1000
                record = snapshot()["records"][0]
                event = fx.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
                fx.registry.receipt(record["receipt"], event)
                check(
                    "committed-revocation-delivered-by-actual-periodic-source",
                    event.route == "security.trust"
                    and event.document()["asset_sha256"] == committed["document_sha256"]
                    and deliveries[-1] <= 60
                    and 25 <= periodic_seconds <= 40,
                )
                # Remove only this fixture's credential directory, while the
                # supervisor stays alive. Missing SQL credentials must not heartbeat.
                before = snapshot()
                unavailable = client.with_name("serving-unavailable")
                client.rename(unavailable)
                try:
                    time.sleep(35)
                    check(
                        "unavailable-source-cannot-mask-failure-with-heartbeat",
                        process.poll() is None
                        and snapshot() == before
                        and b"trust_observer_check_failed" in bounded_read(private_log, 65536),
                    )
                finally:
                    unavailable.rename(client)
                wait_for(lambda: heartbeat()["sequence"] > first["sequence"] + 1)
                wait_for(lambda: received_heartbeat()["envelope"] == snapshot()["heartbeat"])
                fx.stop()
                trust_authority.update(state, "a" * 64, authority_key, revoked_artifacts=["c" * 64])
                wait_for(
                    lambda: (
                        len(snapshot()["records"]) == 2
                        and snapshot()["records"][-1]["receipt"] is None
                    )
                )
                pending = snapshot()["records"][-1]
                check(
                    "collector-outage-keeps-owned-supervisor-and-pending-event",
                    process.poll() is None,
                )
                fx.start()
                wait_for(lambda: snapshot()["records"][-1]["receipt"] is not None)
                check(
                    "recovery-preserves-original-event-and-no-duplicates",
                    len(snapshot()["records"]) == 2
                    and snapshot()["records"][-1]["envelope"] == pending["envelope"]
                    and snapshot()["records"][0] == record,
                )
                old = heartbeat()
                stop()
                start()
                wait_for(lambda: heartbeat()["sequence"] > old["sequence"])
                wait_for(lambda: received_heartbeat()["envelope"] == snapshot()["heartbeat"])
                check(
                    "supervisor-restart-preserves-history-and-increases-counter",
                    len(snapshot()["records"]) == 2,
                )
                stop()
                last = snapshot()["heartbeat"]
                observed = heartbeat()["observed_at_ms"]
                anchor = time.monotonic() - (fx.now() - observed) / 1000
                notice = None
                while time.monotonic() - anchor <= 120:
                    status, page = fx.exchange("GET", "/incidents/0")
                    if status != 200:
                        raise Rejected("trust_observer_case:operator_readback_unavailable")
                    for item in page["incidents"]:
                        value = fx.registry.verify(
                            item["envelope"], clock_ms=item["ingested_at_ms"]
                        )
                        if (
                            value.document()["kind"] == "telemetry.gap"
                            and value.document()["reason"] == "heartbeat"
                            and value.document()["observed_at_ms"] >= observed + 90000
                        ):
                            fx.registry.receipt(item["receipt"], value)
                            notice = item
                    if notice is not None:
                        break
                    time.sleep(0.5)
                notice_seconds = time.monotonic() - anchor
                check(
                    "stopped-observer-detected-by-signed-gap-within-120s",
                    notice is not None
                    and 90 <= notice_seconds <= 120
                    and snapshot()["heartbeat"] == last
                    and fx.exchange("GET", "/health")[0] == 503,
                )
                try:
                    fx.audit.check("a" * 64)
                except Rejected:
                    check("absent-source-denies-fresh-promotion-audit", True)
                else:
                    raise Rejected("trust_observer_case:missing_source_allowed_audit")
                check(
                    "private-output-has-no-credentials-or-source-payload",
                    fx.ingress.encode() not in bounded_read(private_log, 65536)
                    and b"PRIVATE-CANARY" not in bounded_read(private_log, 65536),
                )
            except Exception:
                print(
                    canonical(
                        {
                            "observer_diagnostic": failure_state(
                                private_log, snapshot, lambda: readback(collector.snapshot)
                            )
                        }
                    ).decode(),
                    flush=True,
                )
                raise
            finally:
                stop()
        check("collector-private-state-cleaned", fx.process is None and not fx.directory.exists())
    check("owned-sql-volume-cleaned", not state.exists())
    check(
        "source-unchanged",
        source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return dict(
        status="pass",
        source=revision,
        fingerprint=fingerprint,
        cases=cases,
        max_commit_delivery_seconds=max(deliveries),
        periodic_seconds=periodic_seconds,
        stopped_source_notice_seconds=notice_seconds,
        release_ready=False,
        scope="continuous-trust-source-not-full-M23-or-R1",
    )


if __name__ == "__main__":
    try:
        print(canonical(qualify()).decode())
    except Exception as error:
        reason = str(error)
        print(
            canonical(
                dict(
                    status="failed",
                    failure_type=type(error).__name__,
                    reason=reason
                    if isinstance(error, Rejected) and reason.startswith("trust_observer_case:")
                    else "trust_observer_native_rejected",
                    fixture_lines=[
                        frame.lineno
                        for frame in traceback.extract_tb(error.__traceback__)
                        if Path(frame.filename).resolve() == Path(__file__).resolve()
                    ][-4:],
                )
            ).decode()
        )
        raise SystemExit(1) from None
