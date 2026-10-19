import argparse
import json
import math
import re
import sys
import time
import uuid
from contextlib import ExitStack, suppress
from pathlib import Path

from mlsecops import (
    release_authorization,
    release_bundle,
    release_policy,
    sandbox,
    serving,
    signing,
    storage_bootstrap,
    storage_pki,
    storage_restore,
    trust_authority,
)
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.datasets import FEATURES
from mlsecops.inventory import command, source_fingerprint
from mlsecops.prediction_protocol import PredictionBatch
from scripts import audit_correlation_probe
from scripts.audit_export_probe import exercise as export_audit
from scripts.candidate_serving_reader import KIND, CandidateReader, bind_proposal
from scripts.release_reader_native import disposable
from scripts.serving_metrics_probe import scan as scan_metrics
from scripts.serving_native import check_http, site
from scripts.serving_outage_native import ObservedLease
from scripts.serving_outage_native import exercise as exercise_outage
from scripts.serving_pause_native import exercise as exercise_pause
from scripts.serving_privacy_probe import exercise as exercise_privacy


def audit_idle(request):
    deadline = time.monotonic() + 5
    while True:
        state = request.audit_status()
        if not state["healthy"] or state["unconfirmed"]:
            raise Rejected("candidate_audit_unavailable")
        if state["pending"] == state["reservations"] == 0:
            return state
        if time.monotonic() >= deadline:
            raise Rejected("candidate_audit_pending")
        time.sleep(0.01)


def context_matrix(engine, request, body, confirmed, context):
    before = audit_idle(request)
    confirmed(
        "context-candidate-not-release-selection",
        context.kind == "candidate-qualification"
        and context.schema_version == 2
        and not context.release_ready
        and not hasattr(context, "selection_sha256"),
    )
    for name, operation in (
        ("ready", engine.check_result),
        ("prediction", lambda: engine.predict_result([[0.5] * len(FEATURES)])),
    ):
        result = operation()
        confirmed(
            "context-" + name + "-generation-bound",
            result.audit_context == context
            and result.generation is engine.generation
            and not result.generation.is_set()
            and result.payload["model_sha256"] == context.model_sha256
            and result.payload["bundle_sha256"] == context.bundle_sha256,
        )
    ready_status, ready = request("/readyz")
    predict_status, predicted = request("/v1/predict", body)
    serialized = canonical([ready, predicted]).decode()
    confirmed(
        "context-private-references-not-public",
        ready_status == predict_status == 200
        and all(
            value not in serialized
            for value in (
                context.permit_sha256,
                context.proposal_sha256,
                "audit_context",
                "selection_sha256",
                "permit_sha256",
                "proposal_sha256",
            )
        ),
    )
    confirmed(
        "context-public-shape-unchanged",
        set(ready) == {"ready", "bundle_sha256", "model_sha256", "request_id"}
        and set(predicted)
        == {"schema_version", "bundle_sha256", "model_sha256", "request_id", "predictions"},
    )
    after = audit_idle(request)
    accepted, durable = after["accepted"] - before["accepted"], after["durable"] - before["durable"]
    confirmed("audit-http-pair-accepted", accepted == 8)
    confirmed("audit-http-pair-durable", durable == 8 and after["held_slots"] == 0)
    return {
        "scope": "actual-candidate-http-audit-pair-not-full-M13",
        "status": "pass",
        "accepted_delta": accepted,
        "durable_delta": durable,
        "release_ready": False,
    }


def privacy_matrix(request, body, confirmed):
    metrics = {}

    def check_metrics(transport, needles):
        metrics.update(scan_metrics(transport, needles))

    result = exercise_privacy(request, body, metrics_check=check_metrics)
    confirmed("privacy-http-input-and-output-matrix", result["request_cases"] == 12)
    confirmed(
        "privacy-owned-audit-input-absent",
        result["audit_events_confirmed"] == 36 and result["audit_files_scanned"] > 0,
    )
    confirmed("privacy-native-telemetry-disabled", not result["ambient_signals_used"])
    confirmed("privacy-approved-metrics-cardinality", metrics.get("series") == 69)
    return {**result, "approved_metric_series": metrics["series"]}


def http_matrix(engine, request, body, confirmed):
    row = body["instances"][0]
    invalid = (
        ("empty-body", b""),
        ("unknown-version", {**body, "schema_version": 2}),
        ("boolean-version", {**body, "schema_version": True}),
        ("unknown-feature", {**body, "instances": [{**row, "unexpected": 0}]}),
        (
            "missing-feature",
            {
                **body,
                "instances": [{key: value for key, value in row.items() if key != FEATURES[0]}],
            },
        ),
        ("boolean-feature", {**body, "instances": [{**row, FEATURES[0]: True}]}),
        ("empty-batch", {**body, "instances": []}),
        ("over-100-rows", {**body, "instances": [row] * 101}),
        *(
            (name, json.dumps({**body, "instances": [{**row, FEATURES[0]: value}]}).encode())
            for name, value in (
                ("nan", float("nan")),
                ("infinity", float("inf")),
                ("negative-infinity", -float("inf")),
            )
        ),
    )
    for name, payload in invalid:
        confirmed("http-422-" + name, request("/v1/predict", payload)[0] == 422)
    status, result = request("/v1/predict", {**body, "instances": [row] * 100})
    confirmed("http-100-row-boundary", status == 200 and len(result["predictions"]) == 100)
    with engine.lock:
        confirmed("http-real-lock-pressure-429", request("/v1/predict", body)[0] == 429)
    confirmed("http-remains-ready-after-invalid-and-overload", request("/readyz")[0] == 200)


def qualify(root, state, image, *, trust_port=15446):
    state = Path(state).resolve()
    source = storage_bootstrap.validate(state)
    original_ledger = storage_restore.ledger(source["name"])
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("candidate_serving_source_dirty")
    image = sandbox.resolve_image(image)
    expected = {
        "image_id": image,
        "source_revision": revision,
        "source_fingerprint": source_fingerprint(root),
    }
    names = ("evidence/release-native.json", "storage-trust.json", "trusted-keys.json")
    paths = [safe_child(state, name) for name in names]
    originals = {path: digest(bounded_read(path)) for path in paths}
    report, source_trust, public = (read_json(path) for path in paths)
    client = safe_child(state, "storage-clients/serving")
    package = release_bundle.load(
        client, report["proposal_reference"], publisher_public=public["approver"]
    )
    context, verified = bind_proposal(
        report,
        package,
        policy=read_json(root / "policies/local-cpu.json"),
        source_trust=source_trust,
        publisher_public=public["approver"],
        expected=expected,
        clock=math.ceil(time.time()),
    )
    source_campaign = report["campaign_id"]
    if (
        not isinstance(source_campaign, str)
        or re.fullmatch(r"[a-f0-9]{32}", source_campaign) is None
    ):
        raise Rejected("candidate_serving_source_campaign")
    production_policy = read_json(
        safe_child(state, f"release-proposals/{source_campaign}/policy-envelope.json")
    )
    campaign = uuid.uuid4().hex
    destination = safe_child(state, f"serving-qualifications/{campaign}")
    if destination.exists():
        raise Rejected("candidate_serving_campaign_exists")
    started = now()
    cases = []

    def confirmed(label, condition=True):
        print(
            canonical({"case": label, "status": "pass" if condition else "fail"}).decode(),
            flush=True,
        )
        if not condition:
            raise Rejected("candidate_serving_case_failed:" + label)
        cases.append(label)

    def rejected(label, operation, code):
        try:
            operation()
        except Rejected as error:
            if str(error) != code:
                raise Rejected("candidate_serving_wrong_denial:" + label) from None
            confirmed(label)
        else:
            raise Rejected("candidate_serving_negative_bypass:" + label)

    confirmed("original-signed-proposal-bound", verified["quality_component"] == "pass")
    rejected(
        "actual-release-remains-denied-without-assurance",
        lambda: release_authorization.verify(
            package=package,
            policy_envelope=production_policy,
            assurance_envelope=None,
            approval_envelope=None,
            reports={},
            context=context,
            trusted_root=public["trust"],
            expected_policy=report["policy_sha256"],
            expected_serving_image=image,
            clock=math.ceil(time.time()),
        ),
        "release_assurance_required",
    )
    with disposable(root, state, campaign, "candidate-trust", trust_port) as authority:
        key = safe_child(authority, "keys/qualification.pem")
        qualification_public = signing.create_key(key)
        issued = int(time.time())
        permit = {
            "schema_version": 1,
            "purpose": KIND,
            "campaign_id": campaign,
            "environment": context["policy"]["environment"],
            "proposal_sha256": report["proposal_reference"],
            "subject_sha256": verified["subject_sha256"],
            "model_sha256": digest(verified["model"]),
            **expected,
            "issued_at": issued,
            "expires_at": min(issued + 600, verified["manifest"]["expires_at"]),
        }
        if permit["expires_at"] - issued < 120:
            raise Rejected("candidate_serving_proposal_window_too_short")
        envelope = signing.sign(permit, KIND, key)
        policy_hash = digest(canonical(permit))
        write_json(safe_child(destination, "permit.json"), envelope)
        write_json(safe_child(destination, "public.json"), {"qualification": qualification_public})
        trust_authority.install(authority, permit["environment"], qualification_public)
        trust_authority.update(authority, policy_hash, key)
        trust_client = safe_child(authority, "storage-clients/serving")

        def reader(selected=envelope):
            lease = ObservedLease(
                lambda: trust_authority.read(
                    trust_client, permit["environment"], qualification_public
                ),
                trusted_root=qualification_public,
                environment=permit["environment"],
                minimum_version=1,
            )
            return CandidateReader(
                client,
                context=context,
                publisher_public=public["approver"],
                proposal_reference=report["proposal_reference"],
                permit_envelope=selected,
                permit_public=qualification_public,
                expected_permit=policy_hash,
                expected_campaign=campaign,
                trust_lease=lease,
            )

        rejected(
            "qualification-permit-is-not-release-approval",
            lambda: release_policy.checked(envelope, "release-approval", qualification_public),
            "wrong_payload_type",
        )
        current = reader()
        loaded = current.load()
        confirmed(
            "source-candidate-loaded-without-resigning",
            loaded.model == verified["model"] and not loaded.release_ready,
        )
        features = [[value] * len(FEATURES) for value in (0.1, 0.5, 0.9)]
        batch = PredictionBatch(loaded.model, features)
        output, execution = sandbox.run_worker(image, batch.request, timeout=30)
        scores, _, receipt = batch.consume(output)
        confirmed("one-shot-reference-same-model", receipt["model_digest"] == loaded.model_sha256)
        write_json(
            safe_child(destination, "reference.json"),
            {"features": features, "response": output, "receipt": receipt, "execution": execution},
        )
        with site(serving.Engine(reader(None))) as unavailable:
            confirmed("unsigned-permit-never-ready", unavailable("/readyz")[0] == 503)
            confirmed(
                "unsigned-permit-never-predicts",
                unavailable(
                    "/v1/predict",
                    {
                        "schema_version": 1,
                        "instances": [dict(zip(FEATURES, features[0], strict=True))],
                    },
                )[0]
                == 503,
            )
        with ExitStack() as services:
            outage = {}
            paused = {}
            expiry = {}
            audit = {}
            privacy = {}
            public_audit = {}
            correlation = {}
            expected_context = audit_correlation_probe.candidate(
                package, context, envelope, qualification_public, public["approver"]
            )

            def closed_audit(path):
                correlation.update(audit_correlation_probe.exercise(path, expected_context))
                confirmed(
                    "closed-audit-private-primary-material-correlation",
                    correlation["status"] == "pass",
                )
                public_audit.update(export_audit(path))
                confirmed(
                    "closed-audit-public-export-schema-counters-and-canaries",
                    public_audit["status"] == "pass",
                )
                confirmed(
                    "closed-audit-export-not-release-approval",
                    public_audit["release_ready"] is False,
                )

            def exercise(engine, request, body):
                audit.update(context_matrix(engine, request, body, confirmed, loaded.audit_context))
                http_matrix(engine, request, body, confirmed)
                if loaded.expires_at - math.ceil(time.time()) < 100:
                    raise Rejected("candidate_outage_proposal_window_too_short")
                outage.update(
                    exercise_outage(
                        engine,
                        request,
                        body,
                        authority=authority,
                        port=trust_port,
                        reader_factory=reader,
                        expected=scores,
                        output=safe_child(destination, "http-outage.json"),
                        confirmed=confirmed,
                    )
                )
                paused.update(
                    exercise_pause(
                        engine,
                        request,
                        body,
                        authority=authority,
                        port=trust_port,
                        client=trust_client,
                        expected=scores,
                        output=safe_child(destination, "http-paused-query.json"),
                        confirmed=confirmed,
                    )
                )
                short_policy = trust_authority.update(authority, policy_hash, key, lifetime=8)
                expiry.update(
                    exercise_pause(
                        engine,
                        request,
                        body,
                        authority=authority,
                        port=trust_port,
                        client=trust_client,
                        expected=scores,
                        output=safe_child(destination, "http-expiring-query.json"),
                        confirmed=confirmed,
                        expiry_receipt=short_policy,
                        renew=lambda: trust_authority.update(authority, policy_hash, key),
                    )
                )

                privacy.update(privacy_matrix(request, body, confirmed))

            request, body, runtime = check_http(
                services,
                reader(),
                (features, scores),
                confirmed,
                rejected,
                exercise=exercise,
                audit_export=closed_audit,
            )
            runtime["http_trust_outage"] = outage
            runtime["http_paused_query"] = paused
            runtime["http_expiring_query"] = expiry
            runtime["http_audit"] = audit
            runtime["http_privacy"] = privacy
            runtime["public_audit_window"] = public_audit
            runtime["http_correlation"] = correlation
            trust_authority.update(
                authority, policy_hash, key, revoked_artifacts=[loaded.model_sha256]
            )
            confirmed(
                "actual-candidate-revocation-http-503", request("/v1/predict", body)[0] == 503
            )
            confirmed("actual-candidate-revocation-readiness-503", request("/readyz")[0] == 503)
    confirmed("qualification-authority-and-private-key-removed", not authority.exists())
    confirmed(
        "source-cas-budget-envelopes-and-checkout-unchanged",
        original_ledger == storage_restore.ledger(source["name"])
        and storage_bootstrap.validate(state)["container_id"] == source["container_id"]
        and originals == {path: digest(bounded_read(path)) for path in paths}
        and package
        == release_bundle.load(
            client, report["proposal_reference"], publisher_public=public["approver"]
        )
        and source_fingerprint(root) == expected["source_fingerprint"]
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    result = {
        "schema_version": 1,
        "scope": "actual-candidate-serving-qualification-not-release-approval",
        "status": "pass",
        "release_ready": False,
        "full_M12": "inconclusive",
        "campaign_id": campaign,
        "started_at": started,
        "finished_at": now(),
        "source": expected,
        "source_dirty": False,
        "cases": cases,
        "proposal_reference": report["proposal_reference"],
        "subject_sha256": verified["subject_sha256"],
        "model_sha256": loaded.model_sha256,
        "candidate_reference": context["candidate_reference"],
        "evaluation_reference": context["evaluation_reference"],
        "qualification_permit_sha256": policy_hash,
        "runtime": runtime,
        "reference_response_sha256": receipt["response_digest"],
        "limitations": [
            "Qualification permission is not release approval; failed gates remain blocking",
            "Golden consistency uses another ONNX worker, not independent sklearn parity",
            "Production Reader acceptance, privacy/audit and load acceptance remain separate",
        ],
    }
    write_json(safe_child(destination, "report.json"), result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Read-only actual-candidate qualification, never release approval"
    )
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument("--trust-port", type=int, default=15446)
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    arguments = parser.parse_args()
    output = None
    try:
        storage_pki.workspace_id(arguments.state)
        output = safe_child(arguments.state, "evidence/candidate-serving.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        storage_bootstrap.validate(arguments.state)
        result = qualify(
            Path(__file__).resolve().parents[1],
            arguments.state,
            arguments.image,
            trust_port=arguments.trust_port,
        )
        write_json(output, result)
        print(canonical(result).decode())
        return 0
    except Exception:
        if output is not None:
            with suppress(Exception):
                write_json(
                    output,
                    {
                        "status": "inconclusive",
                        "release_ready": False,
                        "error": "candidate_serving_native_rejected",
                    },
                )
        print("candidate_serving_native_rejected", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
