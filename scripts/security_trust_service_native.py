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
    security_trust_events,
    security_trust_evidence,
    signing,
    trust_authority,
)
from mlsecops.contracts import Rejected, atomic_write, bounded_read, canonical, decode, digest
from mlsecops.inventory import command, source_fingerprint
from scripts import security_event_audit_fixture as audit_fixture
from scripts.release_reader_native import disposable
from scripts.security_identity_events_native import readback


def method_materials(root):
    return {
        name: digest(bounded_read(root / name, 1024 * 1024))
        for name in security_trust_evidence.METHOD_FILES
    }


def capture_state(fixture, producer_snapshot, collector_snapshot, *, registry_envelope):
    """Export complete validated store records, including while HTTP is stopped.

    This deliberately exports incidents from the collector Store, not a fabricated
    HTTP result or a lossy projection. No key/config/log file enters the packet.
    """
    queue = producer_snapshot()
    book = readback(collector_snapshot)
    return dict(
        registry=dict(
            envelope=registry_envelope,
            root=fixture.fx.publics["root"],
            pin=fixture.registry.sha256,
            clock_ms=fixture.now(),
        ),
        outboxes=[queue],
        collector=book,
        incidents=book["records"],
    )


def retain_packet(root, packet, **pins):
    """Called only after both owned contexts exited and source cleanup was checked."""
    report = security_trust_evidence.verify(packet, **pins)
    content = canonical(packet)
    binding = canonical(pins)
    if len(binding) > 65536:
        raise Rejected("trust_observer_binding_limit")
    stem = "trust-service-" + uuid.uuid4().hex
    destination = root / ".runtime/evidence" / (stem + ".primary.json")
    binding_path = destination.with_name(stem + ".binding.json")
    atomic_write(destination, content)
    # Existing public owner pins, exported separately from the primary packet.
    # The public summary hashes both files; the sidecar creates no new authority.
    atomic_write(binding_path, binding)
    retained_binding = bounded_read(binding_path, 65536)
    if retained_binding != binding:
        raise Rejected("trust_observer_binding_readback_mismatch")
    retained = bounded_read(destination, security_trust_evidence.MAX_BYTES)
    replay = security_trust_evidence.verify(
        decode(retained, security_trust_evidence.MAX_BYTES), **decode(retained_binding, 65536)
    )
    if retained != content or replay != report:
        raise Rejected("trust_observer_retained_readback_mismatch")
    return {
        **replay,
        "primary_sha256": digest(retained),
        "binding_sha256": digest(retained_binding),
    }


def collector_reader(settings, registry):
    return security_event_store.Store(
        settings["state_directory"], settings["state_sha256"], registry
    )


def source_readback(path):
    """Failure-time context only, not a replay or proof of the failed child's cause."""
    result = dict(
        configuration_valid=None, signed_sql_history_valid=None, producer_state_valid=None
    )
    try:
        config, _ = security_trust_events.configuration(path)
        if config["rotations"]:
            return result  # This native scenario uses the initial root only.
        result["configuration_valid"] = True
    except Exception:
        result["configuration_valid"] = False
        return result
    try:
        history = security_trust_events.read(config["trust_client"], config["environment"])
        security_trust_events.project(
            history, environment=config["environment"], initial_root=config["initial_root"]
        )
        result["signed_sql_history_valid"] = True
    except Exception:
        result["signed_sql_history_valid"] = False
    try:
        emitter = security_event_delivery.configured(config["producer_config"])
        emitter.store.snapshot()
        emitter.store.registry.valid(time.time_ns() // 1_000_000)
        result["producer_state_valid"] = True
    except Exception:
        result["producer_state_valid"] = False
    return result


def failure_state(private_log, outbox, collector):
    # Finite counts only; unknown readback stays unknown, never a successful zero.
    result = {
        "observer_failed_checks": None,
        "observer_failure_categories": None,
        "outbox": None,
        "collector": None,
    }
    try:
        lines = bounded_read(private_log, 65536).splitlines()
        result["observer_failed_checks"] = lines.count(b"trust_observer_check_failed")
        categories = {
            value: 0 for value in (*security_trust_events.DIAGNOSTIC_CODES.values(), "unclassified")
        }
        for line in lines:
            try:
                entry = decode(line, 512)
                if (
                    type(entry) is dict
                    and set(entry) == {"state", "category", "release_ready"}
                    and entry["state"] == "trust_observer_child_failure"
                    and type(entry["category"]) is str
                    and entry["category"] in categories
                    and entry["release_ready"] is False
                ):
                    categories[entry["category"]] += 1
            except Rejected:
                continue
        result["observer_failure_categories"] = categories
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
    materials = method_materials(root)
    cases, deliveries = [], []
    started = time.monotonic()
    stages, commits, stops = [], [], []
    observations = {}

    def elapsed():
        return time.monotonic() - started

    def check(name, condition):
        if not condition:
            raise Rejected("trust_observer_case:" + name)
        cases.append(name)

    with disposable(root, root / ".runtime", uuid.uuid4().hex, "trust-service", 15449) as state:
        with audit_fixture.live(initial_heartbeat=False, heartbeat_roles=("trust",)) as fx:
            authority_key = fx.directory / "authority.pem"
            authority_root = signing.create_key(authority_key)
            # Pins come from this owning harness, never from the retained packet.
            pins = dict(
                expected_source=revision,
                expected_fingerprint=fingerprint,
                expected_materials=materials.copy(),
                expected_registry_root=fx.fx.publics["root"],
                expected_registry_pin=fx.registry.sha256,
                expected_trust_root=authority_root,
            )
            registry_envelope = decode(bounded_read(fx.directory / "registry.json", 65536), 65536)
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

            def capture(name):
                captured = capture_state(
                    fx, snapshot, collector.snapshot, registry_envelope=registry_envelope
                )
                stage = dict(name=name, at_seconds=elapsed(), state=captured)
                stages.append(stage)
                if len(canonical(stages)) > security_trust_evidence.MAX_BYTES:
                    raise Rejected("trust_observer_evidence_limit")
                return captured

            def capture_commit(result):
                history = security_trust_events.read(client, "local-cpu")
                security_trust_events.project(
                    history, environment="local-cpu", initial_root=authority_root
                )
                if history["head_sha256"] != result["document_sha256"]:
                    raise Rejected("trust_observer_commit_readback_mismatch")
                commits.append(dict(at_seconds=elapsed(), result=result, history=history))

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
                stops.append(
                    dict(at_seconds=elapsed(), exit_code=code, graceful=graceful, group_absent=True)
                )

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
                observations["initial_health"] = 200
                capture("initial")
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
                observations.update(
                    duplicate_exit_code=duplicate.returncode,
                    duplicate_stdout_empty=duplicate.stdout == b"",
                    duplicate_rejection=duplicate.stderr == b"trust_observer_rejected\n",
                )
                busy_marker = canonical(
                    dict(
                        state="trust_observer_child_failure",
                        category="journal_busy",
                        release_ready=False,
                    )
                )
                previous_busy = bounded_read(private_log, 65536).splitlines().count(busy_marker)
                first_envelope = received_heartbeat()["envelope"]
                with security_event_store.locked(producer["state_directory"]):
                    began = time.monotonic()
                    committed = trust_authority.update(
                        state, "a" * 64, authority_key, revoked_artifacts=["b" * 64]
                    )
                    capture_commit(committed)
                    wait_for(
                        lambda: (
                            bounded_read(private_log, 65536).splitlines().count(busy_marker)
                            > previous_busy
                        ),
                        seconds=max(0, began + 45 - time.monotonic()),
                    )
                    check(
                        "confirmed-lock-contention-cannot-publish-heartbeat",
                        received_heartbeat()["envelope"] == first_envelope,
                    )
                    observations["contention_heartbeat"] = received_heartbeat()["envelope"]
                    observations["busy_failures"] = (
                        bounded_read(private_log, 65536).splitlines().count(busy_marker)
                        - previous_busy
                    )
                contention_released = time.monotonic()
                wait_for(
                    lambda: (
                        len(snapshot()["records"]) == 1
                        and snapshot()["records"][0]["receipt"] is not None
                    ),
                    seconds=max(0, began + 45 - time.monotonic()),
                )
                delivered_at = time.monotonic()
                deliveries.append(delivered_at - began)
                contention_recovery_seconds = delivered_at - contention_released
                observations.update(
                    commit_started_seconds=began - started,
                    contention_released_seconds=contention_released - started,
                    first_delivery_seconds=delivered_at - started,
                )
                check(
                    "confirmed-lock-contention-recovers-within-original-wait", deliveries[-1] <= 45
                )
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
                capture("revoked_b")
                # Remove only this fixture's credential directory, while the
                # supervisor stays alive. Missing SQL credentials must not heartbeat.
                before = snapshot()
                capture("unavailable_before")
                previous_failed = (
                    bounded_read(private_log, 65536)
                    .splitlines()
                    .count(b"trust_observer_check_failed")
                )
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
                    observations.update(
                        unavailable_observer_alive=process.poll() is None,
                        source_failed_checks=bounded_read(private_log, 65536)
                        .splitlines()
                        .count(b"trust_observer_check_failed")
                        - previous_failed,
                    )
                    capture("unavailable_after")
                finally:
                    unavailable.rename(client)
                wait_for(lambda: heartbeat()["sequence"] > first["sequence"] + 1)
                wait_for(lambda: received_heartbeat()["envelope"] == snapshot()["heartbeat"])
                capture("restored")
                fx.stop()
                committed = trust_authority.update(
                    state, "a" * 64, authority_key, revoked_artifacts=["c" * 64]
                )
                capture_commit(committed)
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
                observations["outage_observer_alive"] = process.poll() is None
                capture("pending_c")
                fx.start()
                wait_for(lambda: snapshot()["records"][-1]["receipt"] is not None)
                check(
                    "recovery-preserves-original-event-and-no-duplicates",
                    len(snapshot()["records"]) == 2
                    and snapshot()["records"][-1]["envelope"] == pending["envelope"]
                    and snapshot()["records"][0] == record,
                )
                capture("recovered")
                old = heartbeat()
                stop()
                start()
                wait_for(lambda: heartbeat()["sequence"] > old["sequence"])
                wait_for(lambda: received_heartbeat()["envelope"] == snapshot()["heartbeat"])
                check(
                    "supervisor-restart-preserves-history-and-increases-counter",
                    len(snapshot()["records"]) == 2,
                )
                capture("restarted")
                stop()
                capture("stopped")
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
                observations["final_health"] = 503
                capture("gap")
                try:
                    fx.audit.check("a" * 64)
                except Rejected:
                    check("absent-source-denies-fresh-promotion-audit", True)
                    observations["promotion_denied"] = True
                else:
                    raise Rejected("trust_observer_case:missing_source_allowed_audit")
                check(
                    "private-output-has-no-credentials-or-source-payload",
                    fx.ingress.encode() not in bounded_read(private_log, 65536)
                    and b"PRIVATE-CANARY" not in bounded_read(private_log, 65536),
                )
                observations["private_output_clean"] = True
            except Exception:
                print(
                    canonical(
                        {
                            "observer_diagnostic": failure_state(
                                private_log, snapshot, lambda: readback(collector.snapshot)
                            ),
                            "source_readback": source_readback(str(config)),
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
        and method_materials(root) == materials
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    summary = dict(
        status="pass",
        source=revision,
        fingerprint=fingerprint,
        cases=cases,
        max_commit_delivery_seconds=max(deliveries),
        periodic_seconds=periodic_seconds,
        forced_contention_recovery_seconds=contention_recovery_seconds,
        stopped_source_notice_seconds=notice_seconds,
        release_ready=False,
        scope="continuous-trust-source-not-full-M23-or-R1",
    )
    packet = dict(
        schema_version=1,
        source=revision,
        fingerprint=fingerprint,
        materials=materials,
        cases=cases,
        trust=dict(environment="local-cpu", initial_root=authority_root, commits=commits),
        stages=stages,
        observations={**observations, "stops": stops},
        cleanup=dict(
            at_seconds=elapsed(),
            collector_stopped=fx.process is None,
            collector_directory_absent=not fx.directory.exists(),
            sql_directory_absent=not state.exists(),
            source_unchanged=True,
        ),
    )
    replay = retain_packet(root, packet, **pins)
    # Preserve the original public interface and actual harness timing values.
    for field in ("cases", "source", "fingerprint", "scope", "release_ready"):
        if replay[field] != summary[field]:
            raise Rejected("trust_observer_summary_replay_mismatch")
    for field in (
        "max_commit_delivery_seconds",
        "periodic_seconds",
        "forced_contention_recovery_seconds",
        "stopped_source_notice_seconds",
    ):
        if abs(replay[field] - summary[field]) > 1:
            raise Rejected("trust_observer_timing_replay_mismatch")
    return {
        **summary,
        **{key: replay[key] for key in ("packet_sha256", "primary_sha256", "binding_sha256")},
    }


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
