"""Hosted original-candidate M13/M14/M15 composition; private component evidence only."""

import os
import secrets
import sys
import traceback
from contextlib import contextmanager
from pathlib import Path

from mlsecops import acceptance, storage, storage_bootstrap, storage_pki
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
)
from scripts import ci_campaign_producer as campaign
from scripts import ci_candidate_transfer as bridge
from scripts import ci_consumer_native as driver
from scripts import ci_producer_cluster as producer_cluster
from scripts import ci_serving_recovery as lifecycle
from scripts import ci_serving_retention as exporter
from scripts import ci_upstream_transfer as upstream
from scripts import (
    consumer_candidate_state,
    m17_recovery_native,
    serving_retention,
    shared_serving_receipt,
)
from scripts import consumer_candidate_storage as candidate_storage
from scripts import consumer_validation_storage as validation_storage
from scripts import frozen_candidate_transfer as transfer

DIRECTORY = "ci-serving-native"
OFFLINE = DIRECTORY + "/producer-offline.json"
GATES = ("M13", "M14", "M15")
ADMISSIONS = {
    "M13": "evidence/privacy-gate-private.json",
    "M14": "evidence/M14-frozen-private.json",
    "M15": "evidence/M15-frozen-private.json",
}
LABELS = dict(
    PROPOSAL=transfer.delivery.PROPOSAL,
    DEMO="storage-demo.json",
    KEYS="trusted-keys.json",
    TRUST="storage-trust.json",
)
PINS = tuple(
    g + "_" + label + "_SHA256"
    for g in GATES
    for label in LABELS
    if g != "M13" or label in ("PROPOSAL", "DEMO")
)
STAGES = (
    "arguments",
    "preflight",
    "producer_cleanup",
    "proposal",
    "freeze",
    "seal",
    "producer_offline",
    "materialize",
    "upstream",
    "consumer_tls",
    "consumer_sql",
    "candidate_import",
    "validation_import",
    "retention_start",
    "consumer_cluster",
    *GATES,
    "transition_M13",
    "transition_M14",
    "cleanup",
    "retention",
    "context_exit",
    "replay",
    "output",
    "complete",
)


def need(value):
    if not value:
        raise Rejected("ci_serving_native_rejected")


@contextmanager
def environment(producer):
    before = dict(os.environ)
    try:
        for name in (*PINS, "SERVING_RETENTION"):
            os.environ.pop(name, None)
        path = safe_child(producer, "evidence/ci-serving-native-github-output.private")
        atomic_write(path, b"")
        os.environ["GITHUB_OUTPUT"] = str(path)
        yield
    finally:
        # Gates may introduce additional pins; restore the complete caller environment.
        os.environ.clear()
        os.environ.update(before)


def pins(freeze):
    for gate in GATES:
        for label, name in LABELS.items():
            if gate != "M13" or label in ("PROPOSAL", "DEMO"):
                os.environ[gate + "_" + label + "_SHA256"] = freeze[name]


def recover(producer, original, run_owner, progress):
    progress["cleanup"] = dict.fromkeys((*GATES, "SQL"), False)
    result = lifecycle.Lifecycle.load(producer, run_owner=run_owner, source=original).cleanup()
    require_fields(result, (*GATES, "SQL"))
    need(all(type(value) is bool for value in result.values()))
    progress["cleanup"] = result
    need(all(result.values()))


def offline_check(producer, original, run_owner):
    record = read_json(safe_child(producer, OFFLINE))
    require_fields(record, ("source", "run_owner", "offline_pin"))
    need(record["source"] == original and record["run_owner"] == run_owner)
    need(shared_serving_receipt.offline_pin(producer) == storage.object_id(record["offline_pin"]))


@contextmanager
def cleanup_on_error(producer, original, run_owner, progress):
    try:
        yield
    except BaseException as primary:
        try:
            recover(producer, original, run_owner, progress)
        except BaseException:
            primary.add_note("serving_cleanup_unverified")
        raise


def consumer(
    root, producer, state, prepared, owner, sealed, key, progress, marker, offline, upstream_pins
):
    original = {k: owner["expected"][k] for k in transfer.delivery.SOURCE}
    progress["stage"] = "consumer_tls"
    storage_pki.initialize(state)  # Consumer SQL TLS only, never release signing trust.
    life = lifecycle.Lifecycle.begin(producer, state, run_owner=owner["run_owner"], source=original)
    progress["stage"] = "consumer_sql"
    storage_pin = life.bootstrap_sql(state)
    target = storage_bootstrap.validate(state)
    need(target["workspace_id"] == prepared["workspace_id"] != marker["workspace_id"])
    need(target["container_id"] != marker["container_id"] and target["port"] == 15440)
    raw = bounded_read(safe_child(state, "storage.json"))
    need(decode(raw) == target and digest(raw) == storage_pin)
    args = dict(**owner, expected_workspace_id=prepared["workspace_id"], storage_pin=storage_pin)
    progress["stage"] = "candidate_import"
    imported = candidate_storage.import_candidate(root, state, **args)
    need(
        imported["status"] == "pass"
        and imported["proposal_reference"] == owner["expected"]["proposal_reference"]
    )
    need(
        imported["workspace_id"] == prepared["workspace_id"]
        and imported["storage_pin"] == storage_pin
    )
    progress["stage"] = "validation_import"
    value = sealed["validation"]
    imported = validation_storage.import_validation(
        root,
        state,
        value["envelope"],
        key=key,
        **args,
        phase="M13",
        expected_context=value["context"],
        ciphertext_pin=value["ciphertext_sha256"],
    )
    need(
        imported["status"] == "pass"
        and imported["workspace_id"] == prepared["workspace_id"]
        and imported["storage_pin"] == storage_pin
    )
    progress["stage"] = "retention_start"
    retention_pin = serving_retention.retain(
        root,
        state,
        freeze_pin=owner["freeze_pin"],
        source_pin=storage_pin,
        pins=owner["freeze"],
        revision=original["source_revision"],
    )
    progress["stage"] = "consumer_cluster"
    life.start(state, storage_pin)
    reports = upstream_pins.copy()
    admissions, transitions = {}, []
    for gate in GATES:
        progress["stage"] = gate
        pins(owner["freeze"])
        os.environ["SERVING_RETENTION"] = retention_pin
        need(driver.source(root, driver.IMAGE) == original)
        values, current = bridge._fresh(root, state, owner)
        for packet in sealed.values():
            bridge._window(packet["context"], values, current)
        serving_retention.preflight(root, state, retention_pin, original["source_revision"], gate)
        report = acceptance.report(gate, "local-cpu", root, state=state)
        reports[gate] = driver.put(state, "evidence/" + gate + ".json", report)
        driver.put(producer, DIRECTORY + "/" + gate + ".json", report)
        need(
            report["gate"] == gate
            and report["status"] == "pass"
            and type(report["exit_code"]) is int
            and report["exit_code"] == 0
        )
        count = len(report["cases"])
        need(0 < count <= 100000)
        progress["gate_counts"][gate] = count
        admissions[gate] = digest(bounded_read(safe_child(state, ADMISSIONS[gate])))
        if gate != "M15":
            progress["stage"] = "transition_" + gate
            transitions.append(life.transition(state, gate, storage_pin))
    progress["stage"] = "cleanup"
    recover(producer, original, owner["run_owner"], progress)
    need(shared_serving_receipt.offline_pin(producer) == offline)
    progress["stage"] = "retention"
    arguments = dict(
        **owner,
        report_pins=reports,
        admission_pins=admissions,
        transitions=transitions,
        consumer_storage_pin=storage_pin,
    )
    destination = safe_child(producer, DIRECTORY + "/retained")
    result = exporter.retain(root, state, destination, **arguments)
    need(result["release_ready"] is False)
    driver.put(
        producer,
        DIRECTORY + "/retention-private.json",
        dict(authority=arguments, index_pin=result["index_pin"], release_ready=False),
    )
    return destination, result["index_pin"], arguments


def run(root, producer, progress):
    driver.hosted()
    original, run_owner = driver.source(root, driver.IMAGE), driver.run_owner()
    lifecycle.binding(run_owner, original)
    offline = None
    try:
        marker = storage_bootstrap.validate(producer)
        campaign.require_unproposed(producer)
        safe_child(producer, DIRECTORY).mkdir(mode=0o700, exist_ok=False)
        progress["stage"] = "producer_cleanup"
        producer_cluster.cleanup(producer)
        owner = campaign.freeze_original(root, producer, original, run_owner, progress)
        key = secrets.token_bytes(32)
        progress["stage"] = "seal"
        reports, sealed = campaign.seal_serving(root, producer, owner, key)
        progress["stage"] = "producer_offline"
        m17_recovery_native.stop_owned(producer)
        offline = shared_serving_receipt.offline_pin(producer)
        driver.put(
            producer, OFFLINE, dict(source=original, run_owner=run_owner, offline_pin=offline)
        )
        progress["stage"] = "materialize"
        candidate, up = sealed["candidate"], sealed["upstream"]
        with consumer_candidate_state.materialize(
            root,
            candidate["envelope"],
            trust_key_path=producer / "keys/trust.pem",
            key=key,
            **owner,
            phase="M13",
            expected_context=candidate["context"],
            ciphertext_pin=candidate["ciphertext_sha256"],
            manifest_pin=candidate["manifest_sha256"],
        ) as (state, prepared):
            progress["stage"] = "upstream"
            with upstream.materialize(
                root,
                state,
                up["envelope"],
                key=key,
                **owner,
                reports=reports,
                phase="M13",
                expected_context=up["context"],
                ciphertext_pin=up["ciphertext_sha256"],
                workspace_id=prepared["workspace_id"],
            ) as (view, attached):
                need(view == state and attached["reports"] == reports)
                with cleanup_on_error(producer, original, run_owner, progress):
                    destination, index_pin, arguments = consumer(
                        root,
                        producer,
                        state,
                        prepared,
                        owner,
                        sealed,
                        key,
                        progress,
                        marker,
                        offline,
                        reports,
                    )
                progress["stage"] = "context_exit"
        need(not state.exists())
        progress["stage"] = "replay"
        replay = exporter.replay(root, destination, index_pin=index_pin, **arguments)
        need(replay["release_ready"] is False)
        need(driver.source(root, driver.IMAGE) == original)
        need(shared_serving_receipt.offline_pin(producer) == offline)
    except BaseException as primary:
        # Also covers failure before begin and after either owning context exited.
        # A missing witness is refusal, not permission to adopt or delete by name.
        try:
            recover(producer, original, run_owner, progress)
        except BaseException:
            primary.add_note("serving_cleanup_unverified")
        try:
            if offline is None:
                m17_recovery_native.stop_owned(producer)
            else:
                need(shared_serving_receipt.offline_pin(producer) == offline)
        except BaseException:
            primary.add_note("producer_offline_unverified")
        raise


def projection(progress, passed):
    return dict(
        status="pass" if passed else "fail",
        stage=progress["stage"] if progress["stage"] in STAGES else "preflight",
        gate_counts={
            g: n if type(n := progress["gate_counts"].get(g)) is int and 0 <= n <= 100000 else 0
            for g in GATES
        },
        cleanup_counts=dict(
            required=4, verified=sum(progress["cleanup"].get(g) is True for g in (*GATES, "SQL"))
        ),
    )


def execute(root, *, cleanup=False):
    producer = root / ".runtime"
    progress = dict(stage="preflight", gate_counts={}, cleanup={})
    passed = False
    try:
        with (
            driver.private_output(producer, "serving-cleanup" if cleanup else "serving-run"),
            environment(producer),
        ):
            try:
                if cleanup:
                    progress["stage"] = "cleanup"
                    driver.hosted()
                    original, run_owner = driver.source(root, driver.IMAGE), driver.run_owner()
                    recover(producer, original, run_owner, progress)
                    offline_check(producer, original, run_owner)
                else:
                    run(root, producer, progress)
                progress["stage"] = "output"
            except BaseException:
                traceback.print_exc()
                raise
        progress["stage"] = "complete"
        passed = True
    except BaseException:
        pass
    return projection(progress, passed)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ["cleanup"]):
        result = projection(dict(stage="arguments", gate_counts={}, cleanup={}), False)
    else:
        result = execute(Path(__file__).resolve().parents[1], cleanup=bool(args))
    print(canonical(result).decode())
    return int(result["status"] != "pass")


if __name__ == "__main__":
    sys.exit(main())
