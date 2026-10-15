import http.client
import secrets
import socket
import threading
import time
from contextlib import contextmanager

import uvicorn

from mlsecops import release_bundle, serving, serving_http, signing
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
def site(engine):
    token = secrets.token_hex(32)
    app = serving_http.create_app(engine, token)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            access_log=False,
            proxy_headers=False,
            server_header=False,
            log_level="warning",
            timeout_keep_alive=1,
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

            def request(path, payload=None, authorized=True):
                body = (
                    payload
                    if isinstance(payload, bytes)
                    else canonical(payload)
                    if payload is not None
                    else None
                )
                headers = {"Content-Type": "application/json"}
                if authorized:
                    headers["Authorization"] = "Bearer " + token
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=45)
                try:
                    connection.request("GET" if payload is None else "POST", path, body, headers)
                    response = connection.getresponse()
                    content = response.read(65537)
                    return response.status, decode(content, 65536)
                finally:
                    connection.close()

            yield request
        finally:
            server.should_exit = True
            runner.join(timeout=45)
            engine.close()
            if runner.is_alive():
                raise Rejected("serving_native_shutdown")


def check_http(services, reader, golden, confirmed, rejected, *, exercise=None):
    engine = serving.Engine(reader)
    request = services.enter_context(site(engine))
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
        },
    )
