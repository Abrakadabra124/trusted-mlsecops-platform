"""Disposable native M12 exercise. Never an approved-release serving entrypoint."""

import copy
import http.client
import json
import math
import secrets
import socket
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import uvicorn

from mlsecops import (
    kube_candidate_clock,
    kube_candidate_replay,
    kube_candidate_trust,
    kube_trust_isolation,
    serving,
    serving_http,
    trust,
    trust_authority,
)
from mlsecops.candidate_serving_reader import CandidateReader
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json
from mlsecops.controller_api import Client
from mlsecops.controller_worker import remove
from mlsecops.datasets import FEATURES
from mlsecops.kube_serving_runtime import Worker
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce
from mlsecops.trust_targets import Target, select


def candidate(config):
    target = select(config.get("trust_target", Target.PRIMARY.value))
    environment = config["context"]["policy"]["environment"]
    public = config["permit_public"]
    lease = trust.Lease(
        lambda: trust_authority.read(
            "/trust-client", environment, public, expected_host=target.host
        ),
        trusted_root=public,
        environment=environment,
        minimum_version=1,
    )
    return CandidateReader(
        "/client",
        trust_lease=lease,
        **{
            key: value
            for key, value in config.items()
            if key not in ("kubernetes_worker", "trust_target")
        },
    )


@contextmanager
def site(engine):
    """Real loopback HTTP, production app/lifespan and owned private journal."""
    with tempfile.TemporaryDirectory(prefix="m12-", dir="/tmp") as temporary:
        directory = Path(temporary)
        audit = directory / "audit"
        audit.mkdir(mode=0o700)
        token = secrets.token_hex(32)
        app = serving_http.create_app(engine, token, audit_path=audit)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                lifespan="on",
                access_log=False,
                log_config=None,
                log_level="critical",
                proxy_headers=False,
                server_header=False,
                timeout_keep_alive=1,
            )
        )
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        started = False

        def request(path, body=None, *, authorized=True):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            try:
                connection.request(
                    "GET" if body is None else "POST",
                    path,
                    body=canonical(body) if isinstance(body, dict) else body,
                    headers={
                        "Content-Type": "application/json",
                        **({"Authorization": "Bearer " + token} if authorized else {}),
                    },
                )
                response = connection.getresponse()
                return response.status, decode(response.read(65537), 65536)
            finally:
                connection.close()

        try:
            thread.start()
            started = True
            deadline = time.monotonic() + 100
            while not server.started:
                if not thread.is_alive() or time.monotonic() >= deadline:
                    raise Rejected("candidate_probe_startup")
                time.sleep(0.05)
            yield request
        finally:
            server.should_exit = True
            if started:
                thread.join(timeout=60)
            listener.close()
            if started and thread.is_alive():
                raise Rejected("candidate_probe_shutdown")
            # Also covers failure before uvicorn entered lifespan.
            engine.close()


def matrix(request, engine, expected, check):
    body = {
        "schema_version": 1,
        "instances": [dict(zip(FEATURES, row, strict=True)) for row in expected["features"]],
    }
    row = body["instances"][0]
    ready_status, ready = request("/readyz")
    check("verified-ready", ready_status, 200)
    check("ready-model", ready["model_sha256"], expected["model"])
    check("ready-bundle", ready["bundle_sha256"], expected["bundle"])
    status, result = request("/v1/predict", body)
    check("golden-status", status, 200)
    check("golden-model", result["model_sha256"], expected["model"])
    check("golden-bundle", result["bundle_sha256"], expected["bundle"])
    predictions = result["predictions"]
    error = max(abs(p["score"] - s) for p, s in zip(predictions, expected["scores"], strict=True))
    check("golden-parity-1e-6", error <= 1e-6, True)
    check(
        "finite-bounded-scores",
        all(
            type(p["score"]) in (int, float) and math.isfinite(p["score"]) and 0 <= p["score"] <= 1
            for p in predictions
        ),
        True,
    )
    check("unauthorized-401", request("/v1/predict", body, authorized=False)[0], 401)
    invalid = [
        ("empty", b""),
        ("malformed", b"{"),
        ("fields", {**body, "unknown": 0}),
        ("version", {**body, "schema_version": 2}),
        ("boolean-version", {**body, "schema_version": True}),
        ("unknown-feature", {**body, "instances": [{**row, "unknown": 0}]}),
        (
            "missing-feature",
            {**body, "instances": [{k: v for k, v in row.items() if k != FEATURES[0]}]},
        ),
        ("boolean-feature", {**body, "instances": [{**row, FEATURES[0]: True}]}),
        ("empty-batch", {**body, "instances": []}),
        ("101-rows", {**body, "instances": [row] * 101}),
        *[
            (name, json.dumps({**body, "instances": [{**row, FEATURES[0]: value}]}).encode())
            for name, value in (("nan", math.nan), ("inf", math.inf), ("negative-inf", -math.inf))
        ],
    ]
    for name, value in invalid:
        check("422-" + name, request("/v1/predict", value)[0], 422)
    check("413-over-64KiB", request("/v1/predict", b"x" * 65537)[0], 413)
    exact = canonical(body)
    check("64KiB-accepted", request("/v1/predict", exact + b" " * (65536 - len(exact)))[0], 200)
    status, boundary = request("/v1/predict", {**body, "instances": [row] * 100})
    check("100-rows-status", status, 200)
    check("100-rows-count", len(boundary["predictions"]), 100)
    outside = {**body, "instances": [{**row, FEATURES[0]: -0.1}]}
    status, abstained = request("/v1/predict", outside)
    check("outside-support-status", status, 200)
    check("outside-support-abstains", abstained["predictions"][0]["decision"], "abstain")
    check("outside-support-no-score", abstained["predictions"][0]["score"], None)
    with engine.lock:
        check("429-busy", request("/v1/predict", body)[0], 429)
    check("ready-after-invalid", request("/readyz")[0], 200)
    return body, error


def clock_matrix(config, expected, check, client, factory):
    """Fresh Engine per injected fault; no repeated matrix in live fault Jobs."""
    if expected.get("clock_cache") is not True or "fault" in expected:
        return []
    body = {
        "schema_version": 1,
        "instances": [dict(zip(FEATURES, row, strict=True)) for row in expected["features"]],
    }
    reports = []
    for fault in kube_candidate_clock.FAULTS:
        engine = serving.Engine(candidate(config), worker_factory=factory)
        with site(engine) as request:
            reports.append(
                kube_candidate_clock.exercise(
                    engine,
                    request,
                    body,
                    expected,
                    check,
                    fault=fault,
                    reader_factory=lambda: candidate(config),
                )
            )
        check(fault + "-worker-cleanup", len(client.request("pods")["items"]), 0)
    return reports


def replay_matrix(config, expected, body, saved, check, client, factory):
    if saved is None:
        return None
    if expected.get("fault") != "policy-change":
        raise Rejected("candidate_replay_fault")
    check("pre-replay-worker-absence", len(client.request("pods")["items"]), 0)
    engine = serving.Engine(candidate(config), worker_factory=factory)
    with site(engine) as request:
        report = kube_candidate_clock.exercise(
            engine,
            request,
            body,
            expected,
            check,
            fault="version-replay",
            reader_factory=lambda: candidate(config),
            replayed=saved,
        )
    check("version-replay-worker-cleanup", len(client.request("pods")["items"]), 0)
    # An explicit new Engine is necessary: the old generation must stay fenced.
    recovered = serving.Engine(candidate(config), worker_factory=factory)
    with site(recovered) as request:
        _, error = matrix(
            request,
            recovered,
            expected,
            lambda label, actual, wanted: check("replay-recovery-" + label, actual, wanted),
        )
    check("replay-recovery-worker-cleanup", len(client.request("pods")["items"]), 0)
    return {**report, "recovery_max_golden_error": error}


def qualify(config, expected):
    cases = []

    def check(label, actual, wanted):
        passed = type(actual) is type(wanted) and actual == wanted
        cases.append(
            {
                "id": label,
                "status": "pass" if passed else "fail",
                "expected": wanted,
                "actual": actual,
            }
        )
        if not passed:
            print(canonical({"failed_case": label, "status": "fail"}).decode(), flush=True)
            raise Rejected("candidate_probe_case:" + label)

    client = Client("serving")
    check("initial-worker-absence", len(client.request("pods")["items"]), 0)
    target = select(config.get("trust_target", Target.PRIMARY.value))
    if expected.get("cold_only") is True:
        if "fault" in expected:
            raise Rejected("candidate_cold_fault_conflict")
        label = "cold-key-revocation" if target is Target.PRIMARY else "cold-model-revocation"
        cause = "trust_key_revoked" if target is Target.PRIMARY else "trust_artifact_revoked"
        try:
            candidate(config).load()
        except Rejected as rejected:
            check(label, cause if str(rejected) == cause else "unexpected_rejection", cause)
        else:
            check(label, "accepted", cause)
        check("cold-worker-absence", len(client.request("pods")["items"]), 0)
        return {
            "status": "pass",
            "release_ready": False,
            "scope": "candidate-cold-revocation",
            "authority_target": target.value,
            "model_sha256": expected["model"],
            "subject_sha256": expected["bundle"],
            "cases": cases,
        }
    isolation = None
    if expected.get("independent_authorities") is True and (
        "fault" not in expected or expected["fault"] == "revocation"
    ):
        isolation = kube_trust_isolation.verify(target, check)
    calls = []

    def factory(model, image):
        calls.append(digest(model))
        return Worker(model, image, config["kubernetes_worker"])

    # These are test fault injections, never configuration options on the normal CLI.
    for fault in (
        "unsigned-permit",
        "unsigned-proposal",
        "changed-model",
        "mutable-model",
        "malformed-model",
    ):
        selected = copy.deepcopy(config)
        if fault == "unsigned-permit":
            selected["permit_envelope"] = None
        elif fault == "unsigned-proposal":
            selected.update(expected["unsigned_proposal"])
        reader = candidate(selected)
        if fault in {"unsigned-permit", "unsigned-proposal"}:
            try:
                reader.load()
            except Rejected as error:
                check(
                    fault + "-signature-reason",
                    str(error),
                    "unexpected_fields"
                    if fault == "unsigned-permit"
                    else "invalid_signature_count",
                )
            else:
                check(fault + "-signature-reason", "accepted", "rejected")
        if fault in {"changed-model", "mutable-model", "malformed-model"}:
            loaded = reader.load()
            model = bytearray(loaded.model) if fault == "mutable-model" else b"not-an-ONNX-model"
            changed = replace(
                loaded,
                model=model,
                **({"model_sha256": digest(model)} if fault == "malformed-model" else {}),
            )
            reader.load = lambda value=changed: value
        before = len(calls)
        engine = serving.Engine(reader, worker_factory=factory)
        with site(engine) as request:
            check(fault + "-ready-503", request("/readyz")[0], 503)
            check(
                fault + "-predict-503",
                request("/v1/predict", {"schema_version": 1, "instances": []})[0],
                503,
            )
            check(
                fault + "-worker-constructions",
                len(calls) - before,
                1 if fault == "malformed-model" else 0,
            )
        check(fault + "-cleanup", len(client.request("pods")["items"]), 0)

    clocks = clock_matrix(config, expected, check, client, factory)
    # The subsequent fresh Engine also verifies same-candidate inference recovery.
    engine = serving.Engine(candidate(config), worker_factory=factory)
    lifecycle = saved = None
    with site(engine) as request:
        body, error = matrix(request, engine, expected, check)
        workers = client.request("pods")["items"]
        check("one-persistent-worker", len(workers), 1)
        check("actual-candidate-not-release", engine.loaded.release_ready, False)
        check("qualification-audit-context", engine.audit_context.kind, "candidate-qualification")
        if "fault" in expected:
            if expected["fault"] == "policy-change":
                with engine.exclusive():
                    saved = kube_candidate_replay.capture(engine.reader.trust)
            lifecycle = kube_candidate_trust.exercise(
                lambda: candidate(config), request, body, expected, check, pause=engine.exclusive
            )
        else:
            worker = workers[0]
            owner = worker["metadata"]["ownerReferences"][0]
            remove(client, "jobs", worker["metadata"]["labels"]["job-name"], owner["uid"])
            deadline = time.monotonic() + 15
            while client.request("pods")["items"] and time.monotonic() < deadline:
                time.sleep(0.1)
            check("stopped-worker-503", request("/v1/predict", body)[0], 503)
            check("stopped-worker-not-ready", request("/readyz")[0], 503)
    replay = replay_matrix(config, expected, body, saved, check, client, factory)
    check("final-worker-absence", len(client.request("pods")["items"]), 0)
    return {
        "status": "pass",
        "release_ready": False,
        "cases": cases,
        "max_golden_error": error,
        "model_sha256": expected["model"],
        "subject_sha256": expected["bundle"],
        "authority_target": select(config.get("trust_target", Target.PRIMARY.value)).value,
        **({"authority_isolation": isolation} if isolation is not None else {}),
        **({"clock_cache": clocks} if clocks else {}),
        **({"version_replay": replay} if replay is not None else {}),
        **({"lifecycle": lifecycle} if lifecycle is not None else {}),
    }


def main():
    try:
        enforce()
        parser = Arguments(prog="candidate-inference-probe")
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path, required=True)
        arguments = parser.parse_args()
        report = qualify(read_json(arguments.config), read_json(arguments.request))
        print(canonical(report).decode())
        return 0
    except Exception:
        print(
            canonical(
                {"status": "fail", "release_ready": False, "code": "candidate_inference_rejected"}
            ).decode()
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
