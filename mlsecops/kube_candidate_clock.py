"""Native qualification faults in Reader dependencies, never in host/SQL clocks."""

import copy
import math
import time

from mlsecops import signing
from mlsecops.contracts import Rejected

FAULTS = {
    "wall-backward": "trust_clock_invalid",
    "monotonic-backward": "trust_clock_invalid",
    "wall-jump": "trust_clock_invalid",
    "server-skew": "trust_server_clock_skew",
    "invalid-signature": "invalid_signature",
}


def exercise(engine, request, body, expected, check, *, fault, reader_factory):
    if fault not in FAULTS:
        raise Rejected("candidate_clock_fault")
    cause = FAULTS[fault]

    def require(label, actual, wanted):
        check(fault + "-" + label, actual, wanted)

    status, result = request("/v1/predict", body)
    require("before-status", status, 200)
    require("before-model", result.get("model_sha256"), expected["model"])
    require("before-bundle", result.get("bundle_sha256"), expected["bundle"])
    error = max(
        abs(prediction["score"] - score)
        for prediction, score in zip(result["predictions"], expected["scores"], strict=True)
    )
    require("before-golden-1e-6", math.isfinite(error) and error <= 1e-6, True)
    reader, worker, generation = engine.reader, engine.worker, engine.generation
    lease = reader.trust
    wall, monotonic, source = lease.wall_clock, lease.monotonic_clock, lease.reader
    reader_check, predict = reader.check, worker.predict
    observed, predictions, trace = [], [], []

    def checked(loaded):
        try:
            return reader_check(loaded)
        except Rejected as rejected:
            observed.append(cause if str(rejected) == cause else "unexpected_rejection")
            raise

    def predicted(rows):
        predictions.append(True)
        return predict(rows)

    def changed_source():
        envelope, server_clock = source()
        if fault == "server-skew":
            return envelope, server_clock - 10
        envelope = copy.deepcopy(envelope)
        signature = bytearray(signing.decode64(envelope["signatures"][0]["sig"]))
        signature[0] ^= 1
        envelope["signatures"][0]["sig"] = signing.encode64(bytes(signature))
        return envelope, server_clock

    started = time.monotonic()

    def denied(label, path, value=None):
        began, wall_started = time.monotonic() - started, time.time()
        status, result = request(path, value)
        trace.append(
            {
                "phase": label,
                "started_seconds": began,
                "finished_seconds": time.monotonic() - started,
                "wall_started": wall_started,
                "wall_finished": time.time(),
                "status": status,
            }
        )
        require(label + "-503", status, 503)
        require(label + "-no-predictions", "predictions" in result, False)

    try:
        # Exclude heartbeat/check while replacing dependencies. Release the lock
        # before HTTP so a busy 429 can never masquerade as a trust denial.
        with engine.exclusive():
            require("warm-cache", lease.payload is not None, True)
            sampled_wall, sampled_monotonic = lease.sample()
            reader.check, worker.predict = checked, predicted
            if fault == "wall-backward":
                lease.wall_clock = lambda: sampled_wall - 0.25
            elif fault == "monotonic-backward":
                lease.monotonic_clock = lambda: sampled_monotonic - 1
            elif fault == "wall-jump":
                lease.wall_clock = lambda: wall() + 30
            else:
                lease.reader = changed_source
        denied("injected-predict", "/v1/predict", body)
        denied("injected-ready", "/readyz")
        with engine.exclusive():
            require("exact-cause", observed, [cause])
            require("cache-cleared", lease.payload is None, True)
            require("reader-cleared", reader.current is None, True)
            require("generation-fenced", generation.is_set(), True)
            lease.wall_clock, lease.monotonic_clock, lease.reader = wall, monotonic, source
        denied("restored-predict-1", "/v1/predict", body)
        denied("restored-predict-2", "/v1/predict", body)
        denied("restored-ready", "/readyz")
        require("no-worker-predictions-after-injection", len(predictions), 0)
        require("same-fenced-generation", engine.generation is generation, True)
    finally:
        with engine.exclusive():
            lease.wall_clock, lease.monotonic_clock, lease.reader = wall, monotonic, source
            reader.check, worker.predict = reader_check, predict
    recovered = reader_factory().load()
    require("fresh-reader-model", recovered.model_sha256, expected["model"])
    require("fresh-reader-bundle", recovered.subject_sha256, expected["bundle"])
    require("fresh-reader-not-release", recovered.release_ready, False)
    return {
        "fault": fault,
        "cause": observed[0],
        "scope": "injected-reader-dependencies",
        "max_golden_error": error,
        "trace": trace,
    }
