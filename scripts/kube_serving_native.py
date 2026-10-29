"""Hosted normal serving CLI with separate worker, real API, SQL and trust."""

import copy
import sys
import uuid
from contextlib import suppress
from pathlib import Path

from mlsecops import (
    controller_bootstrap,
    kube_promotion,
    kube_serving_probe,
    kube_storage,
    kube_trust,
    serving_startup,
    trust_authority,
)
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest, now, safe_child, write_json
from mlsecops.controller_resources import mount_api
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from mlsecops.private_cli import Arguments
from mlsecops.storage_pki import workspace_id
from scripts import promotion_qualification as fixtures
from scripts import serving_native
from scripts.kube_approval_fixture import renew, shorten
from scripts.kube_promotion_native import actual, stage
from scripts.kube_promotion_replay import exercise as exercise_replay
from scripts.kube_promotion_snapshot import read as ledger
from scripts.kube_serving_faults import Coordinator, acknowledge, progress
from scripts.kube_trust_native import hosted
from scripts.promotion_entrypoint_native import configuration

NAMESPACE = "ml-serving"


def invoke(state, profile, config, expected, *, coordinator=None, candidate_probe=False):
    name = "serving-probe-" + uuid.uuid4().hex
    maps = [
        kube_promotion.configuration_map(state, name + "-" + field, field, value)
        for field, value in (("config", config), ("request", expected))
    ]
    for document in maps:
        document["metadata"]["namespace"] = NAMESPACE
    spec = kube_promotion.pod_spec(
        profile, maps[0]["metadata"]["name"], maps[1]["metadata"]["name"]
    )
    spec["serviceAccountName"] = "serving"
    spec["containers"][0]["command"][2] = (
        "mlsecops.kube_candidate_probe" if candidate_probe else "mlsecops.kube_serving_probe"
    )
    spec["containers"][0]["resources"]["limits"]["memory"] = "1Gi"
    spec["containers"][0]["resources"]["requests"]["memory"] = "256Mi"
    mount_api(spec)
    job = job_document(name, NAMESPACE, spec, 240)
    job["metadata"]["labels"]["trusted-mlsecops/workspace"] = workspace_id(state)
    created = []
    phases = []

    def observe(pod):
        verify_running_image(pod, profile["image_id"])
        if (
            not kube_storage.matches(spec, pod["spec"])
            or pod["metadata"]["ownerReferences"][0]["uid"] != created[-1][1]
        ):
            raise Rejected("kube_serving_probe_pod_changed")
        raw = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                NAMESPACE,
                "-c",
                "worker",
                "--limit-bytes=65537",
            ],
        ).stdout
        safe_child(state, "evidence/" + name + "-private.log").write_bytes(raw)
        observed = progress(raw, expected["fault"])
        if observed[: len(phases)] != phases:
            raise Rejected("kube_serving_fault_progress_changed")
        for phase in observed[len(phases) :]:
            coordinator(phase)
            acknowledge(state, pod["metadata"]["name"], phase, expected["fault"])
            phases.append(phase)

    try:
        for document in [*maps, job]:
            observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
            uid = observed["metadata"]["uid"]
            created.append((document, uid))
            kube_storage.verify_resource(document, observed, uid)
        terminal, pod, elapsed = wait_job(
            state, NAMESPACE, name, 240, **({"observe": observe} if coordinator is not None else {})
        )
        verify_running_image(pod, profile["image_id"])
        if (
            not kube_storage.matches(spec, pod["spec"])
            or pod["metadata"]["ownerReferences"][0]["uid"] != created[-1][1]
        ):
            raise Rejected("kube_serving_probe_pod_changed")
        raw = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                NAMESPACE,
                "-c",
                "worker",
                "--limit-bytes=65537",
            ],
        ).stdout
        # Raw output stays private, including on failure.
        evidence = safe_child(state, "evidence/" + name + "-private.log")
        evidence.write_bytes(raw)
        for line in raw.splitlines():
            diagnostic = serving_startup.validated(line)
            if diagnostic is not None:
                print(canonical(diagnostic).decode(), flush=True)
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if (
            terminal["type"] != "Complete"
            or len(statuses) != 1
            or statuses[0].get("state", {}).get("terminated", {}).get("exitCode") != 0
        ):
            failure = {"probe_failure": "unclassified", "release_ready": False}
            with suppress(Rejected):
                document = decode(raw.splitlines()[-1] if raw else raw, 65536)
                if (
                    isinstance(document, dict)
                    and set(document) == {"status", "phase", "error", "code"}
                    and document["status"] == "fail"
                    and document["phase"] in kube_serving_probe.PHASES
                    and document["error"] in kube_serving_probe.ERRORS
                    and document["code"] in kube_serving_probe.CODES
                ):
                    failure.update(document)
            if len(statuses) == 1:
                terminated = statuses[0].get("state", {}).get("terminated", {})
                if type(terminated.get("exitCode")) is int:
                    failure["exit_code"] = terminated["exitCode"]
                if terminated.get("reason") in {
                    "OOMKilled",
                    "Error",
                    "Completed",
                    "ContainerCannotRun",
                }:
                    failure["container_reason"] = terminated["reason"]
            print(canonical(failure).decode(), flush=True)
            raise Rejected("kube_serving_probe_job_failed")
        report = decode(raw.splitlines()[-1] if raw else raw, 65536)
        if coordinator is not None and phases != ["ready", "denied"]:
            raise Rejected("kube_serving_fault_not_exercised")
        if report.get("status") != "pass" or report.get("release_ready") is not False:
            raise Rejected("kube_serving_probe_report")
        return {**report, "elapsed_seconds": elapsed}
    finally:
        kube_promotion.cleanup(state, created, namespace=NAMESPACE)


def prepare(root, state, image):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("kube_serving_dirty_source")
    kube_storage.validate(state)
    kube_trust.bootstrap(state)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint, started = source_fingerprint(root), now()
    print(canonical({"stage": "serving-api-bootstrap"}).decode(), flush=True)
    profile = controller_bootstrap.bootstrap(root, state, image, serving=True)["profile"]
    print(canonical({"stage": "actual-candidate-refusal"}).decode(), flush=True)
    actual_result = actual(root, state, image)
    return {
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "started_at": started,
        "profile": profile,
        "actual": actual_result,
    }


def qualify(
    root,
    state,
    image,
    *,
    include_candidate=False,
    prepared=None,
    include_key_revocation=False,
    include_trust_lifecycle=False,
):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    prepared = prepare(root, state, image) if prepared is None else prepared
    revision, fingerprint, started = (
        prepared[name] for name in ("source_revision", "source_fingerprint", "started_at")
    )
    profile, actual_result = prepared["profile"], prepared["actual"]
    if (
        command(["git", "-C", str(root), "status", "--porcelain"])
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != revision
        or source_fingerprint(root) != fingerprint
    ):
        raise Rejected("kube_serving_prepared_source_changed")
    fixtures.PromotionAdmissionContracts.setUpClass()
    fixture = fixtures.PromotionAdmissionContracts()
    try:
        fixture.setUp()
        features, scores = serving_native.bind_real_runtime(fixture, profile["image_id"])
        arguments = fixture.arguments
        previous = copy.deepcopy(arguments)
        promotion = configuration(
            "/client", "/trust-client", arguments, fixture.trust_fixture.public
        )
        kube_promotion.configure(state, promotion)
        trust_authority.install(
            state, "local-cpu", fixture.trust_fixture.public, backend=kube_trust.binding
        )
        trust_authority.update(
            state,
            promotion["expected_policy"],
            fixture.trust_fixture.key,
            backend=kube_trust.binding,
        )
        config = {key: value for key, value in promotion.items() if key != "schema_version"}
        config.update(
            minimum_sequence=1,
            audit_directory="/tmp/audit",
            token_file="/tmp/token",
            kubernetes_worker=profile,
        )
        expected = {"ready": False, "features": features, "scores": scores}
        before = ledger(state)
        print(canonical({"stage": "controlled-before-approval"}).decode(), flush=True)
        refused = invoke(state, profile, config, expected)
        if ledger(state) != before:
            raise Rejected("kube_serving_refusal_wrote_storage")
        expires = shorten(fixture)
        request = stage(
            state,
            arguments["package"],
            arguments["policy_envelope"],
            arguments["assurance_envelope"],
            arguments["approval_envelope"],
            arguments["reports"],
        )
        accepted = kube_promotion.invoke(root, state, promotion, request, image)
        model = digest(fixture.fixture.bundle.materials.fixture.model)
        expected.update(ready=True, model=model, bundle=accepted["receipt"]["subject_sha256"])
        after = ledger(state)
        print(canonical({"stage": "controlled-after-approval"}).decode(), flush=True)
        admitted = invoke(state, profile, config, expected)
        print(canonical({"stage": "signed-approval-expiry"}).decode(), flush=True)
        expiry = invoke(state, profile, config, {**expected, "expires_at": expires})
        cold_expired = invoke(
            state,
            profile,
            config,
            {**expected, "ready": False, "reader_refusal": "release_expired_or_future_document"},
        )
        expired_retry = kube_promotion.invoke(root, state, promotion, request, image)
        if expired_retry["status"] != "rejected" or ledger(state) != after:
            raise Rejected("kube_serving_expired_retry_admitted_or_wrote")
        expired_snapshot_hash = digest(canonical(after))
        old_subject = expected["bundle"]
        renew(fixture, profile["image_id"])
        renewed_request = stage(
            state,
            arguments["package"],
            arguments["policy_envelope"],
            arguments["assurance_envelope"],
            arguments["approval_envelope"],
            arguments["reports"],
        )
        renewed = kube_promotion.invoke(root, state, promotion, renewed_request, image)
        receipt = renewed["receipt"]
        if receipt is None or receipt["sequence"] != 2 or receipt["subject_sha256"] == old_subject:
            raise Rejected("kube_serving_recovery_binding")
        config["minimum_sequence"] = 2
        expected["bundle"] = receipt["subject_sha256"]
        print(canonical({"stage": "unexpired-previous-sequence"}).decode(), flush=True)
        replay = exercise_replay(root, state, image, promotion, previous, renewed_request, receipt)
        after = ledger(state)
        print(canonical({"stage": "explicit-release-renewal"}).decode(), flush=True)
        recovery = invoke(state, profile, config, expected)
        lifecycle = {}
        for fault in ("outage", "blackhole", "policy-change", "revocation"):
            print(canonical({"stage": "live-trust-" + fault}).decode(), flush=True)
            with Coordinator(
                state, fault, promotion["expected_policy"], fixture.trust_fixture.key, model
            ) as coordinator:
                lifecycle[fault] = invoke(
                    state, profile, config, {**expected, "fault": fault}, coordinator=coordinator
                )
                print(
                    canonical({"completed_fault": fault, "result": lifecycle[fault]}).decode(),
                    flush=True,
                )
        print(canonical({"stage": "controlled-after-revocation"}).decode(), flush=True)
        revoked = invoke(state, profile, config, {**expected, "ready": False})
        if (
            ledger(state) != after
            or source_fingerprint(root) != fingerprint
            or command(["git", "-C", str(root), "status", "--porcelain"])
        ):
            raise Rejected("kube_serving_source_or_ledger_changed")
        candidate_result = None
        if include_candidate or include_key_revocation or include_trust_lifecycle:
            from scripts.kube_candidate_native import qualify as candidate_qualify

            candidate_result = candidate_qualify(
                root,
                state,
                image,
                prepared=(profile, actual_result),
                qualification_key=fixture.trust_fixture.key,
                include_key_revocation=include_key_revocation,
                include_trust_lifecycle=include_trust_lifecycle,
            )
        return {
            "schema_version": 1,
            "status": "pass",
            "release_ready": False,
            "scope": "normal-CLI-isolated-worker-controlled-release-not-full-M12",
            "full_M12": "inconclusive",
            "source_revision": revision,
            "source_fingerprint": fingerprint,
            "source_dirty": False,
            "started_at": started,
            "finished_at": now(),
            "image_id": profile["image_id"],
            "actual": actual_result,
            "controlled_model": model,
            "before_approval": refused,
            "approved": admitted,
            "after_revocation": revoked,
            "approval_expiry": {
                "active": expiry,
                "cold": cold_expired,
                "retry": expired_retry,
                "renewed_receipt": receipt,
                "recovery": recovery,
                "expired_retry_ledger_unchanged": True,
                "expired_retry_snapshot_sha256": expired_snapshot_hash,
                "expired_retry_snapshot_scope": [
                    "CAS",
                    "promotion-authorities",
                    "promotion-events",
                    "promotion-heads",
                ],
            },
            "live_trust": lifecycle,
            "unexpired_replay": replay,
            **({"actual_inference": candidate_result} if candidate_result is not None else {}),
            "limitations": [
                "Controlled approvals are not acceptance of the actual candidate",
                "Full M11/M13/M14 and durable audit/recovery remain required",
                "System image findings and M22 independent challenges remain blocking",
            ],
        }
    finally:
        fixture.doCleanups()
        fixtures.PromotionAdmissionContracts.tearDownClass()


def main(arguments=None):
    output = None
    try:
        hosted()
        parser = Arguments(prog="kubernetes-serving-native")
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--image", default="trusted-mlsecops:dev")
        options = parser.parse_args(arguments)
        output = safe_child(options.state, "evidence/kubernetes-serving.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        report = qualify(
            Path(__file__).resolve().parents[1],
            options.state,
            options.image,
            include_key_revocation=True,
            include_trust_lifecycle=True,
        )
        write_json(output, report)
        print(canonical(report).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(
                    output,
                    {
                        "status": "inconclusive"
                        if isinstance(error, KeyboardInterrupt)
                        else "fail",
                        "release_ready": False,
                    },
                )
        print("kubernetes_serving_native_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
