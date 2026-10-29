"""Finite startup diagnostics: no exception text, identities, inputs or keys."""

from mlsecops.contracts import canonical, decode

PHASES = {
    "clear",
    "reader",
    "integrity",
    "worker-create",
    "worker-start",
    "worker-identity",
    "worker-ping",
    "reader-check",
    "context",
    "heartbeat",
    "deadline",
    "unknown",
}
WORKER_PHASES = {"none", "create", "observe", "attach", "load"}
CAUSES = {
    "unknown",
    "serving_model_changed_before_load",
    "serving_loaded_identity",
    "serving_exchange_rejected",
    "serving_load_failed",
    "serving_release_expired",
    "serving_clock_skew",
    "serving_head_missing",
    "storage_connection_rejected",
    "trust_clock_invalid",
    "trust_server_clock_skew",
    "trust_policy_changed",
    "trust_artifact_revoked",
    "trust_key_revoked",
    "trust_lease_expired",
    "serving_worker_pod_identity",
    "serving_worker_start_deadline",
    "serving_worker_image_mismatch",
}


def record(phase, worker, error):
    nested = getattr(worker, "startup_failure", None)
    return {
        "event": "serving-startup-refused",
        "phase": phase if type(phase) is str and phase in PHASES else "unknown",
        "worker_phase": nested[0]
        if type(nested) is tuple
        and len(nested) == 2
        and type(nested[0]) is str
        and nested[0] in WORKER_PHASES
        else "none",
        "cause": (
            nested[1]
            if type(nested) is tuple
            and len(nested) == 2
            and type(nested[1]) is str
            and nested[1] in CAUSES
            else str(error)
            if str(error) in CAUSES
            else "unknown"
        ),
    }


def validated(content):
    try:
        value = decode(content, 512)
        if (
            set(value) == {"event", "phase", "worker_phase", "cause"}
            and value["event"] == "serving-startup-refused"
            and value["phase"] in PHASES
            and value["worker_phase"] in WORKER_PHASES
            and value["cause"] in CAUSES
            and content.strip() == canonical(value)
        ):
            return value
    except (ValueError, TypeError, KeyError):
        pass
    return None


def content(engine):
    value = getattr(engine, "startup_failure", None)
    try:
        encoded = canonical(value)
        if validated(encoded) is not None:
            return encoded
    except (ValueError, TypeError):
        pass
    return canonical(record("unknown", None, RuntimeError()))
