"""Actual-candidate privacy probe; private evidence, never release approval."""

import secrets
import sys
from dataclasses import asdict
from functools import partial
from pathlib import Path

from mlsecops import audit_snapshot, release_bundle, serving, signing, worker_transport
from mlsecops.contracts import Rejected, canonical, read_json, require_fields, write_json
from mlsecops.controller_api import Client
from mlsecops.datasets import FEATURES
from mlsecops.kube_candidate_probe import candidate
from mlsecops.kube_serving_lifecycle import valid
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce
from scripts import audit_correlation_probe, audit_evidence_probe, serving_output_probe
from scripts.audit_http_observation import Ledger
from scripts.candidate_serving_native import context_matrix, privacy_matrix
from scripts.kube_privacy_diagnostic import location, validated
from scripts.kube_privacy_exchange import DIRECTORY, send
from scripts.kube_privacy_worker import Worker
from scripts.serving_native import check_clients, site

PHASE = "startup"
PHASES = {"startup", "bind", "http", "worker", "audit", "capture"}


def qualify(config, expected, input_observer):
    global PHASE
    DIRECTORY.mkdir(mode=0o700)
    PHASE = "bind"
    client = Client("serving")
    if client.request("pods")["items"]:
        raise Rejected("privacy_initial_worker_present")
    package = release_bundle.load(
        "/client", config["proposal_reference"], publisher_public=config["publisher_public"]
    )
    context = audit_correlation_probe.candidate(
        package,
        config["context"],
        config["permit_envelope"],
        config["permit_public"],
        config["publisher_public"],
    )
    binding = {
        "campaign_id": config["expected_campaign"],
        "source": {
            k: config["kubernetes_worker"][k]
            for k in ("source_revision", "source_fingerprint", "image_id")
        },
    }
    cases, needles, workers = [], [], []
    ledger, retained = Ledger(), {}

    def check(label, value):
        if value is not True:
            raise Rejected("privacy_probe_case:" + label)
        cases.append({"id": label, "status": "pass", "expected": True, "actual": True})

    def observe_worker(worker, content):
        global PHASE
        PHASE = "worker"
        check("all-client-input-canaries-available", len(needles) == 9)
        return send(
            DIRECTORY,
            "worker",
            binding["campaign_id"],
            {
                "job": worker.name,
                "job_uid": worker.job_uid,
                "pod_uid": worker.pod_uid,
                "pod": worker.pod_snapshot,
                "session": worker.binding["session_id"],
                "stream": signing.encode64(content),
                "needles": [signing.encode64(value) for value in needles],
            },
        )

    def factory(model, image):
        worker = Worker(model, image, config["kubernetes_worker"], observer=observe_worker)
        workers.append(worker)
        return worker

    def closed(path):
        global PHASE
        PHASE = "audit"
        correlation = audit_correlation_probe.exercise(path, context)
        result = audit_evidence_probe.retain(
            path,
            DIRECTORY / "audit",
            ledger,
            binding=binding,
            expected_context=context,
        )
        check("retained-primary-correlation", result["correlation"] == correlation)
        packet = audit_snapshot.load_packet(DIRECTORY / "audit")
        observed = send(
            DIRECTORY, "audit", binding["campaign_id"], {"packet": signing.encode64(packet)}
        )
        check("operator-reverified-primary-packet", observed == result)
        retained.update(result)

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
    engine = serving.Engine(candidate(config), worker_factory=factory)
    with site(engine, clients=clients, audit_export=closed, http_ledger=ledger) as transport:
        PHASE = "http"
        request = partial(transport, credential=clients["clients"][2]["token"])
        for name in ("audit_status", "audit_scan", "metrics_credential"):
            setattr(request, name, getattr(transport, name))
        request.privacy_credential = clients["clients"][2]["token"]
        body = {
            "schema_version": 1,
            "instances": [dict(zip(FEATURES, row, strict=True)) for row in expected["features"]],
        }
        status, response = request("/v1/predict", body)
        check("actual-golden-response", status == 200 and valid(status, response, expected))
        error = max(
            abs(row["score"] - score)
            for row, score in zip(response["predictions"], expected["scores"], strict=True)
        )
        check(
            "actual-candidate-context",
            asdict(engine.audit_context) == context and engine.loaded.release_ready is False,
        )
        context_result = context_matrix(engine, request, body, check, engine.audit_context)
        check("missing-auth-401", request("/v1/predict", body, authorized=False)[0] == 401)
        quotas = check_clients(transport, body, [v["token"] for v in clients["clients"][:2]], check)

        def observe(values):
            check("single-privacy-input-observation", not needles)
            all_values = (
                values
                + tuple(v["token"].encode() for v in clients["clients"][:2])
                + (request.metrics_credential.encode(),)
            )
            input_observer(all_values)
            needles.extend(all_values)

        privacy = privacy_matrix(request, body, check, observe)
        with engine.lock:
            check("actual-pressure-429", request("/v1/predict", body)[0] == 429)
        with engine.exclusive():
            engine.invalidate()
        check("fenced-predict-503", request("/v1/predict", body)[0] == 503)
        check("fenced-ready-503", request("/readyz")[0] == 503)
        engine.drain()
    check("one-observed-worker", len(workers) == 1 and workers[0].observation is not None)
    check("final-worker-absence", client.request("pods")["items"] == [])
    return {
        "status": "pass",
        "scope": "actual-candidate-kubernetes-privacy-not-full-M13",
        "release_ready": False,
        "cases": cases,
        "model_sha256": expected["model"],
        "subject_sha256": expected["bundle"],
        "max_golden_error": error,
        "privacy": privacy,
        "quotas": quotas,
        "context": context_result,
        "audit": retained,
        "worker_observation": workers[0].observation,
    }


def finish(envelope):
    value, diagnostic = worker_transport.unwrap(envelope)
    require_fields(value, ("native", "observation"))
    observation = value["observation"]
    require_fields(
        observation,
        (
            "schema_version",
            "scope",
            "status",
            "release_ready",
            "canary_count",
            "stdout_characters",
            "stderr_characters",
        ),
    )
    if (
        diagnostic["bytes"] != 0
        or diagnostic["gpu_discovery_warning"]
        or observation["scope"] != serving_output_probe.SCOPE
        or type(observation["schema_version"]) is not int
        or observation["schema_version"] != 1
        or observation["status"] != "inconclusive"
        or observation["release_ready"] is not False
        or type(observation["canary_count"]) is not int
        or observation["canary_count"] != 9
        or any(
            type(observation[k]) is not int or not 0 <= observation[k] <= 65536
            for k in ("stdout_characters", "stderr_characters")
        )
        or type(value["native"]) is not dict
        or value["native"].get("status") != "pass"
        or value["native"].get("release_ready") is not False
    ):
        raise Rejected("privacy_probe_output_incomplete")
    return {
        **value["native"],
        "output_observation": {
            **observation,
            "status": "pass",
            "fd_lifecycle_complete": True,
            "native_stderr_bytes": 0,
        },
    }


def main(arguments=None):
    try:
        enforce()
        parser = Arguments(prog="kubernetes-privacy-probe")
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path, required=True)
        parser.add_argument("--child", action="store_true")
        options = parser.parse_args(arguments)
        if options.child:
            report = serving_output_probe.produce(
                lambda observe: qualify(
                    read_json(options.config), read_json(options.request), observe
                ),
                canary_count=9,
            )
        else:
            report = finish(
                worker_transport.capture(
                    [
                        sys.executable,
                        "-m",
                        "scripts.kube_privacy_probe",
                        "--child",
                        "--config",
                        str(options.config),
                        "--request",
                        str(options.request),
                    ],
                    timeout=240,
                    canonical_output=True,
                )
            )
        print(canonical(report).decode())
        return 0
    except Exception as error:
        phase = PHASE
        diagnostic = location(error)
        if DIRECTORY.is_dir():
            try:
                if options.child:
                    write_json(DIRECTORY / "failure.json", {"phase": phase, "location": diagnostic})
                else:
                    failure = read_json(DIRECTORY / "failure.json")
                    phase = failure["phase"]
                    diagnostic = validated(failure.get("location")) or diagnostic
            except Exception:
                pass
        print(
            canonical(
                {
                    "status": "fail",
                    "release_ready": False,
                    "phase": phase if phase in PHASES else "capture",
                    "code": "kubernetes_privacy_rejected",
                    "location": diagnostic,
                }
            ).decode()
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
