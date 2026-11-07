"""Configure the ordinary monitor for M14 and reconcile its bounded primary receipt tail."""

import asyncio
import time
from contextlib import contextmanager

from mlsecops import monitoring, monitoring_alerts, monitoring_config, monitoring_state, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields, write_json
from mlsecops.load_measurement import MAX_ATTEMPTS
from mlsecops.release_policy import checked

FIELDS = (
    "schema_version",
    "reference_sha256",
    "epoch",
    "state",
    "healthy",
    "faults",
    "observations",
    "windows_evaluated",
    "pending_windows",
    "pending_alerts",
    "alerts_delivered",
    "delivery_failures",
    "evicted_windows",
    "unclosed_observations",
    "epoch_admission",
    "history_restored",
    "release_ready",
)


def reference(expected):
    supplied = expected["monitoring"]
    value = checked(supplied["reference"], "monitor-reference", supplied["reference_public"])
    monitoring.validate_reference(value)
    if (value["model_sha256"], value["bundle_sha256"]) != (expected["model"], expected["bundle"]):
        raise Rejected("load_monitor_reference")
    return value


def binding(value, reference, epoch):
    require_fields(value, ("reference_sha256", "epoch", "sink_public", "state_sha256"))
    monitoring_alerts.epoch_id(value["epoch"])
    monitoring_alerts.public_key(value["sink_public"])
    monitoring.sha256(value["state_sha256"])
    if value["reference_sha256"] != digest(canonical(reference)) or value["epoch"] != epoch:
        raise Rejected("load_monitor_binding")
    return value


def observations(observation, overload):
    monitoring.integer(overload["correct"], 0, 40)
    if type(overload["recovered"]) is not bool:
        raise Rejected("load_monitor_accounting")
    # collect retains warmup records too; initial prediction precedes collect.
    return (
        1
        + sum(row["status"] == 200 for row in observation["records"])
        + overload["correct"]
        + int(overload["recovered"])
    )


def verify(proof, reference, epoch, expected_observations):
    require_fields(proof, ("binding", "state", "receipts"))
    pins = binding(proof["binding"], reference, epoch)
    state = proof["state"]
    require_fields(state, FIELDS)
    monitoring.integer(state["schema_version"], 1, 1)
    for name in (
        "observations",
        "windows_evaluated",
        "pending_windows",
        "pending_alerts",
        "alerts_delivered",
        "delivery_failures",
        "evicted_windows",
        "unclosed_observations",
    ):
        monitoring.integer(state[name], 0, MAX_ATTEMPTS + 100)
    admission = {
        "schema_version": 1,
        "state_sha256": pins["state_sha256"],
        "role": "producer",
        "epoch": epoch,
        "reference_sha256": pins["reference_sha256"],
        "previous_epochs": 0,
        "history_unavailable": False,
    }
    if (
        state["reference_sha256"] != pins["reference_sha256"]
        or state["epoch"] != epoch
        or state["state"] != "observing"
        or state["healthy"] is not True
        or state["faults"] != []
        or state["observations"] != expected_observations
        or state["windows_evaluated"] < 1
        or state["pending_windows"] != 0
        or state["pending_alerts"] != 0
        or state["history_restored"] is not False
        or state["release_ready"] is not False
        or canonical(state["epoch_admission"]) != canonical(admission)
    ):
        raise Rejected("load_monitor_inactive_or_lost")
    receipts = proof["receipts"]
    if type(receipts) is not list or len(receipts) != min(state["alerts_delivered"], 128):
        raise Rejected("load_monitor_receipt_count")
    for sequence, item in enumerate(receipts, state["alerts_delivered"] - len(receipts) + 1):
        event = item["event"]
        receipt = monitoring_alerts.receipt(item["envelope"], event, pins["sink_public"])
        start = monitoring.integer(item["admitted_ns"], 0, 2**63 - 1)
        end = monitoring.integer(item["finished_ns"], start, 2**63 - 1)
        delta = (end - start) / 1000000000
        if (
            event["reference_sha256"] != pins["reference_sha256"]
            or event["epoch"] != epoch
            or event["sequence"] != sequence
            or delta >= 120
            or type(item["delivery_seconds"]) is not float
            or item["delivery_seconds"] != delta
            or item["event_sha256"] != receipt["event_sha256"]
            or item["received_at_ms"] != receipt["received_at_ms"]
            or item["kind"] != event["kind"]
            or item["window_sha256"] != event["window_sha256"]
        ):
            raise Rejected("load_monitor_receipt")
    return {
        "status": "pass",
        "enabled": True,
        "reference_sha256": pins["reference_sha256"],
        "epoch": epoch,
        "observations": state["observations"],
        "windows_evaluated": state["windows_evaluated"],
        "alerts_delivered": state["alerts_delivered"],
        "retained_receipts": len(receipts),
        "evicted_windows": state["evicted_windows"],
        "proof_sha256": digest(canonical(proof)),
        "release_ready": False,
    }


class Session:
    def __init__(self, runtime, reference, pins):
        self.runtime, self.reference, self.binding = runtime, reference, pins

    def capture(self):
        async def read():
            state = self.runtime.snapshot()
            return decode(
                canonical(
                    {
                        "binding": self.binding,
                        "state": {key: state[key] for key in FIELDS},
                        "receipts": list(self.runtime._receipts),
                    }
                )
            )

        operation = read()
        try:
            future = asyncio.run_coroutine_threadsafe(operation, self.runtime.task.get_loop())
        except BaseException:
            operation.close()
            raise
        try:
            return future.result(timeout=3)
        except BaseException:
            future.cancel()
            raise

    def finish(self, count):
        deadline = time.monotonic() + 10
        while True:
            proof = self.capture()
            if not proof["state"]["pending_windows"] and not proof["state"]["pending_alerts"]:
                return proof, verify(proof, self.reference, self.binding["epoch"], count)
            if time.monotonic() >= deadline:
                raise Rejected("load_monitor_pending")
            time.sleep(0.05)


@contextmanager
def session(root, expected, epoch, listen):
    frozen = reference(expected)
    root.mkdir(mode=0o700)
    keys = {role: root / (role + ".pem") for role in ("producer", "sink", "label")}
    publics = {role: signing.create_key(path) for role, path in keys.items()}
    state_directory = str(root / "epochs")
    state_pin = monitoring_state.initialize(state_directory)
    ref = digest(canonical(frozen))
    write_json(root / "reference.json", expected["monitoring"]["reference"])
    common = {
        "schema_version": 1,
        "reference_sha256": ref,
        "epoch": epoch,
        "state_directory": state_directory,
        "state_sha256": state_pin,
    }
    write_json(
        root / "sink.json",
        {
            **common,
            "producer_public": publics["producer"],
            "receipt_key_file": str(keys["sink"]),
            "port": 8910,
        },
    )
    app, _ = monitoring_config.sink(str(root / "sink.json"))
    with listen(app) as port:
        write_json(
            root / "producer.json",
            {
                **common,
                "reference_file": str(root / "reference.json"),
                "reference_public": expected["monitoring"]["reference_public"],
                "producer_key_file": str(keys["producer"]),
                "label_public": publics["label"],
                "sink_public": publics["sink"],
                "sink_port": port,
            },
        )
        runtime = monitoring_config.producer(str(root / "producer.json"))
        try:
            yield Session(
                runtime,
                frozen,
                {
                    "reference_sha256": ref,
                    "epoch": epoch,
                    "sink_public": publics["sink"],
                    "state_sha256": state_pin,
                },
            )
        finally:
            if runtime.task is not None and (
                not runtime.task.done() or runtime.snapshot()["faults"]
            ):
                raise Rejected("load_monitor_shutdown")
