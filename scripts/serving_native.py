import http.client
import os
import secrets
import socket
import tempfile
import threading
import time
from contextlib import contextmanager
from functools import partial
from pathlib import Path

import uvicorn

from mlsecops import (
    audit_retention,
    release_bundle,
    serving,
    serving_access,
    serving_audit,
    serving_http,
    signing,
)
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.datasets import FEATURES
from mlsecops.inventory import command
from mlsecops.serving_runtime import Worker


def bind_real_runtime(fixture, image):
    from scripts import model_contract_qualification as model_fixtures
    from scripts.artifact_intake_fixture import receipt as intake_receipt

    model_fixtures.ModelContractTests.setUpClass()
    generated = model_fixtures.ModelContractTests
    authorization = fixture.fixture
    bundle = authorization.bundle
    candidate = bundle.materials.fixture
    candidate.model = generated.content
    reference = digest(candidate.model)
    candidate.metadata["model_digest"] = reference
    candidate.record["model_object"] = candidate.put("candidates", candidate.model)
    candidate.bound["report"]["model_digest"] = reference
    candidate.bound["report"]["prediction_protocol"]["model_digest"] = reference
    candidate.bound["report"]["scan"] = generated.trained["scan"]
    candidate.bound["report"]["intake"] = intake_receipt(
        candidate.model, candidate.expected["image_id"], generated.trained["scan"]
    )
    candidate.rebound_candidate()
    bundle.materials.context.update(
        candidate_reference=candidate.candidate_ref, evaluation_reference=candidate.evaluation_ref
    )
    bundle.capsule = bundle.materials.create()
    bundle.arguments["expected_serving_image"] = image
    package = bundle.create()
    manifest = release_bundle.index(package["envelope"], bundle.materials.public)
    subject = digest(canonical(manifest))
    reports = {}
    for gate, content in authorization.reports.items():
        report = decode(content)
        report["input_digests"].update(release_subject=subject, model=reference)
        reports[gate] = canonical(report)
    authorization.assurance.update(
        subject_sha256=subject, reports={gate: digest(content) for gate, content in reports.items()}
    )
    authorization.approval.update(
        subject_sha256=subject, assurance_sha256=digest(canonical(authorization.assurance))
    )
    fixture.arguments.update(
        package=package,
        reports=reports,
        expected_serving_image=image,
        assurance_envelope=signing.sign(
            authorization.assurance, "release-assurance", authorization.authorities.keys["assessor"]
        ),
        approval_envelope=signing.sign(
            authorization.approval, "release-approval", authorization.authorities.keys["approver"]
        ),
    )
    return generated.features[:3], generated.trained["python_scores"][:3]


@contextmanager
def site(engine, *, clients=None, audit=None):
    from scripts.serving_privacy_probe import scan_owned_audit

    if audit is not None:
        with _site(engine, clients=clients, audit=audit) as request:
            yield request
        return
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary)
        journal = serving_audit.Journal(
            path if os.name == "posix" else path / "audit.jsonl",
            retention=audit_retention.Policy() if os.name == "posix" else None,
        )
        journal.start()
        try:
            with _site(engine, clients=clients, audit=journal) as request:
                request.audit_scan = partial(scan_owned_audit, path)
                yield request
        finally:
            journal.close()


@contextmanager
def _site(engine, *, clients, audit):
    if clients is None:
        token = secrets.token_hex(32)
        access = serving_access.Access.single(token)
    else:
        access = serving_access.Access(clients)
        token = clients["clients"][0]["token"]
    metrics_token = secrets.token_hex(32)
    app = serving_http.create_app(engine, clients=access, audit=audit, metrics_token=metrics_token)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            access_log=False,
            proxy_headers=False,
            server_header=False,
            log_level="warning",
            timeout_keep_alive=1,
            limit_concurrency=16,
        )
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        runner = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        runner.start()
        try:
            deadline = time.monotonic() + 45
            while not server.started:
                if not runner.is_alive() or time.monotonic() >= deadline:
                    raise Rejected("serving_native_startup")
                time.sleep(0.05)

            def request(
                path, payload=None, authorized=True, *, credential=None, headers=None, raw=False
            ):
                body = (
                    payload
                    if isinstance(payload, bytes)
                    else canonical(payload)
                    if payload is not None
                    else None
                )
                request_headers = {"Content-Type": "application/json", **(headers or {})}
                if authorized:
                    request_headers["Authorization"] = "Bearer " + (
                        token if credential is None else credential
                    )
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=45)
                try:
                    connection.request(
                        "GET" if payload is None else "POST", path, body, request_headers
                    )
                    response = connection.getresponse()
                    content = response.read(65537)
                    if len(content) > 65536 or response.read(1):
                        raise Rejected("serving_native_response_overflow")
                    if response.length not in (None, 0):
                        raise Rejected("serving_native_response_incomplete")
                    if raw:
                        return response.status, response.getheaders(), content
                    return response.status, decode(content, 65536)
                finally:
                    connection.close()

            def admissions(credentials):
                principals = [access.authenticate(["Bearer " + value]) for value in credentials]
                if None in principals or len(set(principals)) != len(principals):
                    raise Rejected("serving_native_client_unknown")
                snapshot = access.admissions()
                return [snapshot[principal] for principal in principals] + [sum(snapshot.values())]

            request.admissions = admissions
            request.audit_status = audit.status
            request.privacy_credential = token
            request.metrics_credential = metrics_token
            yield request
        finally:
            server.should_exit = True
            runner.join(timeout=45)
            engine.close()
            if runner.is_alive():
                raise Rejected("serving_native_shutdown")


def check_clients(request, body, tokens, confirmed):
    before = request.admissions(tokens)
    started = time.monotonic()
    observations = [
        request("/v1/predict", {}, credential=credential)
        for credential in (tokens[0], tokens[0], tokens[1], tokens[1])
    ]
    elapsed = time.monotonic() - started
    if not 0 <= elapsed < 1:
        raise Rejected("client_quota_window_inconclusive")
    statuses = [status for status, _ in observations]
    confirmed(
        "independent-client-burst-boundary",
        statuses == [422, 429, 422, 429]
        and all(
            observations[index][1].get("error", {}).get("code") == "client_limited"
            for index in (1, 3)
        ),
    )
    time.sleep(1.05)
    recovered = [request("/v1/predict", body, credential=credential)[0] for credential in tokens]
    confirmed("client-quota-refill-recovers", recovered == [200, 200])
    after = request.admissions(tokens)
    deltas = [right - left for left, right in zip(before, after, strict=True)]
    confirmed("client-admission-accounting", deltas == [2, 2, 4])
    return {
        "status": "pass",
        "boundary_statuses": statuses,
        "window_seconds": elapsed,
        "refill_statuses": recovered,
        "admitted_deltas": deltas,
        "release_ready": False,
    }


def check_http(services, reader, golden, confirmed, rejected, *, exercise=None):
    engine = serving.Engine(reader)
    clients = {
        "schema_version": 1,
        "clients": [
            {
                "principal_id": secrets.token_hex(16),
                "token": secrets.token_hex(32),
                "requests_per_second": rate,
                "burst": burst,
                "max_in_flight": 4,
            }
            for rate, burst in ((1, 1), (1, 1), (20, 40))
        ],
    }
    transport = services.enter_context(site(engine, clients=clients))
    request = partial(transport, credential=clients["clients"][2]["token"])
    request.audit_status = transport.audit_status
    request.audit_scan = transport.audit_scan
    request.privacy_credential = clients["clients"][2]["token"]
    request.metrics_credential = transport.metrics_credential
    features, expected = golden
    body = {
        "schema_version": 1,
        "instances": [dict(zip(FEATURES, row, strict=True)) for row in features],
    }
    status, ready = request("/readyz")
    confirmed("http-ready-after-actual-ONNX-load", status == 200 and ready["ready"] is True)
    identifier = engine.worker.container
    status, result = request("/v1/predict", body)
    maximum_error = max(
        abs(item["score"] - score)
        for item, score in zip(result["predictions"], expected, strict=True)
    )
    confirmed("http-golden-CPU-consistency", status == 200 and maximum_error <= 1e-5)
    confirmed(
        "http-running-digest-bound",
        result["model_sha256"] == engine.loaded.model_sha256
        and result["bundle_sha256"] == engine.loaded.subject_sha256,
    )
    mixed = {**body, "instances": [body["instances"][0], {name: 2 for name in FEATURES}]}
    status, result = request("/v1/predict", mixed)
    confirmed(
        "http-mixed-score-and-abstain",
        status == 200
        and [item["decision"] for item in result["predictions"]] == ["score", "abstain"],
    )
    confirmed("persistent-worker-reused", engine.worker.container == identifier)
    confirmed("http-missing-auth-401", request("/v1/predict", body, authorized=False)[0] == 401)
    status, invalid = request("/v1/predict", {**body, "model_url": "http://PRIVATE-CANARY.invalid"})
    confirmed(
        "http-invalid-422-redacted",
        status == 422 and "PRIVATE-CANARY" not in canonical(invalid).decode(),
    )
    confirmed("http-oversized-413", request("/v1/predict", b"x" * 65537)[0] == 413)
    confirmed("client-errors-do-not-disable-model", request("/readyz")[0] == 200)
    quota = check_clients(
        transport, body, [item["token"] for item in clients["clients"][:2]], confirmed
    )
    confirmed("primary-client-remains-available", request("/v1/predict", body)[0] == 200)
    confirmed(
        "foreign-client-identity-401",
        request("/v1/predict", body, credential=secrets.token_hex(32))[0] == 401,
    )
    rejected(
        "native-malformed-model-never-ready",
        lambda: Worker(b"not-onnx", reader.image).start(),
        "serving_load_failed",
    )
    command(["docker", "kill", "--signal", "STOP", identifier])
    started = time.monotonic()
    confirmed("stopped-worker-inference-503", request("/v1/predict", body)[0] == 503)
    elapsed = time.monotonic() - started
    engine.drain()
    query = ["docker", "container", "ls", "--all", "--quiet", "--filter", f"id={identifier}"]
    confirmed("deadline-removes-only-owned-worker", elapsed < 40 and not command(query))
    confirmed("failed-worker-readiness-503", request("/readyz")[0] == 503)
    engine.activate()
    confirmed(
        "explicit-verified-reload-recovers",
        request("/v1/predict", body)[0] == 200 and engine.worker.container != identifier,
    )
    if exercise is not None:
        exercise(engine, request, body)
    return (
        request,
        body,
        {
            "golden_rows": len(features),
            "maximum_error": maximum_error,
            "stopped_worker_denial_seconds": elapsed,
            "client_quota": quota,
        },
    )
