"""Hosted, same-job original-candidate roundtrip and full shared M11/M12 qualification."""

import os
import secrets
import sys
import traceback
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

from mlsecops import acceptance, cluster, kube_storage, storage_bootstrap
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    safe_child,
)
from mlsecops.security_events import hexadecimal
from scripts import ci_campaign_producer as campaign
from scripts import (
    ci_candidate_transfer as bridge,
)
from scripts import (
    ci_consumer_recovery as recovery,
)
from scripts import (
    consumer_candidate_state,
    m17_recovery_native,
    shared_serving_receipt,
)
from scripts import (
    frozen_candidate_transfer as transfer,
)
from scripts import (
    shared_serving_native as shared,
)
from scripts.ci_campaign_producer import IMAGE, put, run_owner
from scripts.kube_trust_native import hosted
from scripts.serving_output_native import source

PUBLIC_REPORT = "evidence/ci-consumer-native-public.json"
CLEANUP_REPORT = "evidence/ci-consumer-native-cleanup-public.json"
PRIVATE_PACKET = recovery.DIRECTORY + "/packet.json"
PINS = (
    "M11_PROPOSAL_SHA256",
    "M12_PROPOSAL_SHA256",
    "M11_DEMO_SHA256",
    "M11_M12_ACTUAL_SHA256",
    shared.PIN,
    "M12_EARLY_SHA256",
)


def need(value):
    if not value:
        raise Rejected("ci_consumer_native_rejected")


@contextmanager
def private_output(producer, action):
    path = safe_child(producer, "evidence/ci-consumer-native-" + action + ".log")
    atomic_write(path, b"")
    # Both Python writers and child processes inheriting fd 1/2 stay private.
    with path.open("a", encoding="utf-8") as log, ExitStack() as restore:
        for descriptor in (1, 2):
            original = os.dup(descriptor)
            # Register each acquired descriptor immediately. Every callback runs
            # even if flush, another restore, or another close raises.
            restore.callback(os.close, original)
            restore.callback(os.dup2, original, descriptor)
        try:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(log.fileno(), 1)
            os.dup2(log.fileno(), 2)
            with redirect_stdout(log), redirect_stderr(log):
                yield
        finally:
            log.flush()


@contextmanager
def pins(freeze):
    before = {name: os.environ.get(name) for name in PINS}
    try:
        for name in PINS:
            os.environ.pop(name, None)
        os.environ["M11_PROPOSAL_SHA256"] = os.environ["M12_PROPOSAL_SHA256"] = freeze[
            transfer.delivery.PROPOSAL
        ]
        os.environ["M11_DEMO_SHA256"] = freeze["storage-demo.json"]
        yield
    finally:
        for name, value in before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def import_candidate(root, state, **arguments):
    # Integrated by the parent independently; missing helper fails closed at this stage.
    from scripts import consumer_candidate_storage

    return consumer_candidate_storage.import_candidate(root, state, **arguments)


def retain(root, state, destination, **arguments):
    from scripts import m18_shared_retention

    index_pin = m18_shared_retention.retain(root, state, destination, **arguments)
    # Retention and its independent offline read are mandatory, not a fallback gate.
    replay = m18_shared_retention.replay(root, destination, index_pin=index_pin, **arguments)
    need(replay["release_ready"] is False)
    return dict(index_pin=index_pin, replay=replay)


@contextmanager
def observed(callback):
    try:
        yield
    except BaseException as primary:
        try:
            callback()
        except Exception:
            primary.add_note("consumer_ownership_observation_failed")
        raise
    else:
        callback()


def cleanup_owned(witness, summary):
    try:
        summary["cleanup"] = witness.cleanup()
    finally:
        # Diagnostic stages never replace the verified boolean cleanup result.
        summary["cleanup_diagnostics"] = recovery.cleanup_diagnostics(
            witness.record.get("cleanup_diagnostics")
        )


def consumer(root, producer, state, prepared, owner, sealed, witness, summary, producer_marker):
    primary = None
    try:
        summary["stage"] = "consumer_sql"
        witness.arm_sql(state)
        with observed(witness.observe_sql):
            storage_bootstrap.bootstrap(state, port=15440)
        marker = storage_bootstrap.validate(state)
        need(marker["workspace_id"] == prepared["workspace_id"] != producer_marker["workspace_id"])
        need(marker["container_id"] != producer_marker["container_id"] and marker["port"] == 15440)
        storage_raw = bounded_read(state / "storage.json")
        need(decode(storage_raw) == marker)
        storage_pin = digest(storage_raw)
        witness.record.update(storage_pin=storage_pin, storage_marker=marker)
        witness.save()
        summary["stage"] = "import"
        imported = import_candidate(
            root,
            state,
            **owner,
            expected_workspace_id=prepared["workspace_id"],
            storage_pin=storage_pin,
        )
        need(
            imported["status"] == "pass"
            and imported["proposal_reference"] == owner["expected"]["proposal_reference"]
            and imported["workspace_id"] == prepared["workspace_id"]
            and imported["storage_pin"] == storage_pin
        )
        summary["stage"] = "consumer_cluster"
        witness.arm_cluster()
        with observed(lambda: witness.observe_cluster(state)):
            cluster.bootstrap(state)
        cluster.validate_cluster(state)
        kube_storage.bootstrap(state)
        summary["stage"] = "window"
        values, current = bridge._fresh(root, state, owner)
        bridge._window(sealed["context"], values, current)
        need(source(root, IMAGE) == {k: owner["expected"][k] for k in transfer.delivery.SOURCE})
        summary["stage"] = "actual"
        early = shared.capture(root, state, IMAGE)
        early_pin = put(state, shared.EARLY, early)
        os.environ["M11_M12_ACTUAL_SHA256"] = early_pin
        summary["stage"] = "consumer_offline"
        m17_recovery_native.stop_owned(state)
        offline = shared_serving_receipt.offline_pin(state)
        summary["stage"] = "controlled"
        full = shared.late(root, state, IMAGE, early_pin)
        os.environ[shared.PIN] = put(state, shared.FULL, full)
        reports = {}
        for gate in ("M11", "M12"):
            summary["stage"] = gate
            report = acceptance.report(gate, "local-cpu", root, state=state)
            put(state, "evidence/" + gate + ".json", report)
            # Retain original reports even when the ordinary gate refuses.
            put(producer, recovery.DIRECTORY + "/" + gate + ".json", report)
            need(report["status"] == "pass" and report["exit_code"] == 0)
            reports[gate] = report
        summary["stage"] = "receipt"
        receipt = shared_serving_receipt.receipt(state, os.environ)
        need(shared_serving_receipt.offline_pin(state) == offline)
        summary["stage"] = "cleanup"
        cleanup_owned(witness, summary)
        need(all(summary["cleanup"].values()))
        summary["stage"] = "recheck"
        need(shared_serving_receipt.receipt(state, os.environ) == receipt)
        need(shared_serving_receipt.offline_pin(state) == offline)
        summary["stage"] = "retention"
        retained = retain(
            root,
            state,
            safe_child(producer, recovery.DIRECTORY + "/retained"),
            **owner,
            report_pins={
                g: digest(bounded_read(state / ("evidence/" + g + ".json"))) for g in ("M11", "M12")
            },
            actual_pin=early_pin,
            native_pin=os.environ[shared.PIN],
        )
        need(retained["replay"]["receipt"] == receipt)
        for gate in ("M11", "M12"):
            count = receipt["reports"][gate]["checks"]
            need(type(count) is int and count > 0)
            summary["gate_counts"][gate] = count
        put(
            producer,
            PRIVATE_PACKET,
            dict(
                schema_version=1,
                authority=owner,
                materialization=prepared,
                imported=imported,
                early=early,
                full=full,
                reports=reports,
                receipt=receipt,
                consumer_offline=offline,
                cleanup=summary["cleanup"],
                retention=retained,
                release_ready=False,
            ),
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        if primary is not None:
            try:
                cleanup_owned(witness, summary)
                if not all(summary["cleanup"].values()):
                    primary.add_note("consumer_cleanup_incomplete")
            except Exception:
                primary.add_note("consumer_cleanup_unverified")


def run(root, producer, summary):
    hosted()
    original = source(root, IMAGE)
    summary["source_commit"] = hexadecimal(original["source_revision"], 40)
    owner_run = run_owner()
    marker = storage_bootstrap.validate(producer)
    campaign.require_unproposed(producer)
    witness = recovery.Recovery.begin(producer, owner_run, original)
    try:
        owner = campaign.freeze_original(root, producer, original, owner_run, summary)
        key = secrets.token_bytes(32)
        summary["stage"] = "seal"
        sealed = bridge.seal(root, producer, key=key, **owner, phase="M11-M12")
        summary["stage"] = "producer_offline"
        m17_recovery_native.stop_owned(producer)
        offline = shared_serving_receipt.offline_pin(producer)
        witness.record["producer_offline"] = offline
        witness.save()
        summary["stage"] = "materialize"
        with (
            pins(owner["freeze"]),
            consumer_candidate_state.materialize(
                root,
                sealed["envelope"],
                trust_key_path=producer / "keys/trust.pem",
                key=key,
                **owner,
                phase="M11-M12",
                expected_context=sealed["context"],
                ciphertext_pin=sealed["ciphertext_sha256"],
                manifest_pin=sealed["manifest_sha256"],
            ) as (state, prepared),
        ):
            consumer(root, producer, state, prepared, owner, sealed, witness, summary, marker)
            need(shared_serving_receipt.offline_pin(producer) == offline)
        summary["stage"] = "complete"
    except BaseException as error:
        # Also covers failure before entering, or while leaving, the owning file context.
        try:
            cleanup_owned(witness, summary)
        except Exception:
            error.add_note("consumer_cleanup_unverified")
        raise


def projection():
    return dict(
        schema_version=1,
        scope="consumer-native-component",
        status="fail",
        source_commit=None,
        stage="preflight",
        cause="rejected",
        gate_counts={"M11": 0, "M12": 0},
        cleanup={"sql": False, "cluster": False},
        cleanup_diagnostics=recovery.cleanup_diagnostics(None),
        release_ready=False,
    )


def execute(root, *, cleanup=False):
    producer = root / ".runtime"
    summary = projection()
    try:
        with private_output(producer, "cleanup" if cleanup else "run"):
            try:
                if cleanup:
                    summary["stage"] = "cleanup"
                    hosted()
                    witness = recovery.Recovery(producer)
                    need(witness.record["run_owner"] == run_owner())
                    summary["source_commit"] = hexadecimal(
                        witness.record["source"]["source_revision"], 40
                    )
                    cleanup_owned(witness, summary)
                    need(all(summary["cleanup"].values()))
                else:
                    run(root, producer, summary)
                summary.update(status="pass", cause="none")
            except BaseException as error:
                traceback.print_exc()
                summary["cause"] = (
                    "interrupted"
                    if isinstance(error, (KeyboardInterrupt, SystemExit))
                    else "rejected"
                    if isinstance(error, Rejected)
                    else "dependency"
                    if isinstance(error, ImportError)
                    else "operation"
                )
        put(producer, CLEANUP_REPORT if cleanup else PUBLIC_REPORT, summary)
    except Exception:
        summary.update(status="fail", cause="local_io")
    return summary


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in ([], ["cleanup"]):
        summary = projection()
        summary.update(stage="arguments", cause="arguments")
    else:
        summary = execute(Path(__file__).resolve().parents[1], cleanup=bool(arguments))
    print(canonical(summary).decode())
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
