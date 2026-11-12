"""Hosted normal serving CLI with separate worker, real API, SQL and trust."""

import copy
import sys
import uuid
from contextlib import suppress
from pathlib import Path

from mlsecops import (
    controller_bootstrap,
    kube_promotion,
    kube_security_events,
    kube_security_resources,
    kube_serving_probe,
    kube_storage,
    kube_trust,
    load_diagnostics,
    monitoring_probe,
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
from mlsecops.trust_targets import Target, select
from scripts import kube_cli_privacy_exchange as cli_exchange
from scripts import promotion_qualification as fixtures
from scripts import serving_native
from scripts.kube_approval_fixture import renew
from scripts.kube_privacy_bundle import manifest as privacy_bundle
from scripts.kube_privacy_diagnostic import validated as privacy_location
from scripts.kube_promotion_native import actual, configuration, initialize_campaign, stage
from scripts.kube_promotion_replay import exercise as exercise_replay
from scripts.kube_promotion_snapshot import read as ledger
from scripts.kube_rollback_native import exercise as exercise_rollback
from scripts.kube_rollback_native import variant as rollback_variant
from scripts.kube_root_rotation import exercise as exercise_root_rotation
from scripts.kube_serving_faults import acknowledge, progress
from scripts.kube_trust_native import hosted

NAMESPACE = "ml-serving"


def serving_configuration(promotion):
    kube_promotion.validate_config(promotion)
    return {
        **{
            key: copy.deepcopy(value)
            for key, value in promotion.items()
            if key not in ("schema_version", "security_audit_config")
        },
        "identity_audit_file": "/security/identity-audit.json",
    }


def invoke(
    state,
    profile,
    config,
    expected,
    *,
    coordinator=None,
    candidate_probe=False,
    trust_target=Target.PRIMARY,
    privacy_operator=None,
    cli_privacy=False,
    load_operator=None,
    monitoring_operator=None,
):
    trust_target = select(trust_target)
    if monitoring_operator is not None and (
        not candidate_probe
        or load_operator is not None
        or privacy_operator is not None
        or coordinator is not None
        or cli_privacy
        or trust_target is not Target.PRIMARY
        or "fault" in expected
    ):
        raise Rejected("monitor_probe_mode_conflict")
    if load_operator is not None and (
        not candidate_probe
        or privacy_operator is not None
        or coordinator is not None
        or cli_privacy
        or trust_target is not Target.PRIMARY
        or "fault" in expected
    ):
        raise Rejected("load_probe_mode_conflict")
    if (
        type(cli_privacy) is not bool
        or cli_privacy
        and (
            candidate_probe
            or privacy_operator is not None
            or coordinator is not None
            or trust_target is not Target.PRIMARY
            or expected.get("ready") is not True
            or "fault" in expected
            or "expires_at" in expected
        )
    ):
        raise Rejected("cli_privacy_mode_conflict")
    if privacy_operator is not None and (
        not candidate_probe or coordinator is not None or trust_target is not Target.PRIMARY
    ):
        raise Rejected("privacy_probe_mode_conflict")
    if (trust_target is not Target.PRIMARY and not candidate_probe) or select(
        config.get("trust_target", Target.PRIMARY.value)
    ) is not trust_target:
        raise Rejected("candidate_authority_target")
    if not candidate_probe:
        if (
            config.get("identity_audit_file") != "/security/identity-audit.json"
            or "security_audit_config" in config
        ):
            raise Rejected("kube_serving_audit_configuration")
    elif "identity_audit_file" in config or "security_audit_config" in config:
        # Candidate applications use the fixed serving Secret, never a caller path.
        raise Rejected("kube_serving_audit_configuration")
    audit_marker = kube_security_events.validate(
        state,
        profile=profile,
        environment=config["context"]["policy"]["environment"],
        **({"authority_root": config["trust_root"]} if trust_target is Target.PRIMARY else {}),
    )
    from mlsecops.kube_serving_handoff import require_probe_slot, wait_pods_absent

    require_probe_slot(state, marker=audit_marker)
    name = "serving-probe-" + uuid.uuid4().hex
    bundle = kube_promotion.configuration_map(state, name + "-bundle", "config", config)
    bundle["metadata"]["namespace"] = NAMESPACE
    bundle["data"]["request.json"] = canonical(expected).decode()
    maps = [bundle]
    spec = kube_promotion.credential_spec(
        profile, bundle["metadata"]["name"], bundle["metadata"]["name"], trust_target=trust_target
    )
    spec["serviceAccountName"] = "serving"
    spec = kube_security_resources.serving_spec(spec)
    spec["containers"][0]["command"][2] = (
        "mlsecops.monitoring_probe"
        if monitoring_operator is not None
        else "mlsecops.load_probe"
        if load_operator is not None
        else "scripts.kube_cli_privacy_probe"
        if cli_privacy
        else "scripts.kube_privacy_probe"
        if privacy_operator is not None
        else "mlsecops.kube_candidate_probe"
        if candidate_probe
        else "mlsecops.kube_serving_probe"
    )
    spec["containers"][0]["resources"]["limits"]["memory"] = "1Gi"
    spec["containers"][0]["resources"]["requests"]["memory"] = "256Mi"
    scratch = next(volume for volume in spec["volumes"] if volume["name"] == "scratch")
    scratch["emptyDir"]["sizeLimit"] = "640Mi"
    if privacy_operator is not None or cli_privacy:
        code = privacy_bundle(
            Path(__file__).resolve().parents[1],
            name + "-code",
            workspace_id(state),
            **({"entry": "kube_cli_privacy_probe"} if cli_privacy else {}),
        )
        bundle["data"].update(code["data"])
        bundle["metadata"]["annotations"] = code["metadata"]["annotations"]
        spec["volumes"].append(
            {
                "name": "qualification-code",
                "configMap": {
                    "name": bundle["metadata"]["name"],
                    "defaultMode": 292,
                    "items": [{"key": key, "path": key} for key in sorted(code["data"])],
                },
            }
        )
        spec["containers"][0]["volumeMounts"].append(
            {"name": "qualification-code", "mountPath": "/app/scripts", "readOnly": True}
        )
    if (
        sum(len(key.encode()) + len(value.encode()) for key, value in bundle["data"].items())
        > 1024 * 1024
    ):
        raise Rejected("kube_serving_probe_bundle_limit")
    mount_api(spec)
    deadline = 360 if load_operator is not None or monitoring_operator is not None else 240
    job = job_document(name, NAMESPACE, spec, deadline)
    job["metadata"]["labels"]["trusted-mlsecops/workspace"] = workspace_id(state)
    created = []
    phases = []
    output_limit = 2 * 1024 * 1024 if cli_privacy else 65536
    cli_receiver = cli_exchange.Receiver(state) if cli_privacy else None

    def observe(pod):
        verify_running_image(pod, profile["image_id"])
        if (
            not kube_storage.matches(spec, pod["spec"])
            or pod["metadata"]["ownerReferences"][0]["uid"] != created[-1][1]
        ):
            raise Rejected("kube_serving_probe_pod_changed")
        if privacy_operator is not None:
            privacy_operator.observe(pod)
            return
        if load_operator is not None:
            load_operator.observe(pod)
            return
        if monitoring_operator is not None:
            monitoring_operator.observe(pod)
            return
        if cli_receiver is not None:
            cli_receiver.observe(pod)
            return
        raw = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                NAMESPACE,
                "-c",
                "worker",
                "--limit-bytes=" + str(output_limit + 1),
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
        if monitoring_operator is not None:
            monitoring_operator.start()
        if load_operator is not None:
            load_operator.start()
        if privacy_operator is not None:
            privacy_operator.start()
        for index, document in enumerate([*maps, job]):
            print(
                canonical(
                    {
                        "stage": "serving-probe-create",
                        "resource": "Job" if document is job else "ConfigMap",
                        "index": index,
                    }
                ).decode(),
                flush=True,
            )
            observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
            uid = observed["metadata"]["uid"]
            created.append((document, uid))
            kube_storage.verify_resource(document, observed, uid)
        terminal, pod, elapsed = wait_job(
            state,
            NAMESPACE,
            name,
            deadline,
            **(
                {"observe": observe}
                if coordinator is not None
                or privacy_operator is not None
                or cli_receiver is not None
                or load_operator is not None
                or monitoring_operator is not None
                else {}
            ),
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
                "--limit-bytes=" + str(output_limit + 1),
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
                    monitoring_operator is not None
                    and isinstance(document, dict)
                    and set(document) == {"status", "release_ready", "code", "cause", "location"}
                    and document["status"] == "fail"
                    and document["release_ready"] is False
                    and document["code"] == "monitor_probe_rejected"
                    and type(document["cause"]) is str
                    and document["cause"] in monitoring_probe.FAILURES
                    and privacy_location(document["location"]) is not None
                ):
                    failure.update(probe_failure="monitoring", **document)
                if (
                    load_operator is not None
                    and isinstance(document, dict)
                    and set(document) == {"status", "release_ready", "code", "phase", "cause"}
                    and document["status"] == "fail"
                    and document["release_ready"] is False
                    and document["code"] == "load_probe_rejected"
                    and type(document["cause"]) is str
                    and document["cause"] in load_diagnostics.FAILURES
                    and document["phase"]
                    in {"startup", "activate", "start", "measure", "finish", "shutdown", "cleanup"}
                ):
                    failure.update(probe_failure="load", **document)
                if (
                    (privacy_operator is not None or cli_privacy)
                    and isinstance(document, dict)
                    and set(document) == {"status", "release_ready", "phase", "code", "location"}
                    and document["status"] == "fail"
                    and document["release_ready"] is False
                    and document["phase"]
                    in {"startup", "bind", "http", "worker", "audit", "capture"}
                    and document["code"] == "kubernetes_privacy_rejected"
                    and privacy_location(document["location"]) is not None
                ):
                    failure.update(
                        probe_failure="privacy",
                        phase=document["phase"],
                        code=document["code"],
                        location=document["location"],
                    )
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
        report = decode(raw.splitlines()[-1] if raw else raw, output_limit)
        if cli_privacy and raw != canonical(report) + b"\n":
            raise Rejected("cli_privacy_uncontrolled_output")
        if coordinator is not None and phases != ["ready", "denied"]:
            raise Rejected("kube_serving_fault_not_exercised")
        if report.get("status") != "pass" or report.get("release_ready") is not False:
            raise Rejected("kube_serving_probe_report")
        if privacy_operator is not None:
            report = privacy_operator.finish(report, raw)
        if load_operator is not None:
            report = load_operator.finish(report, raw)
        if monitoring_operator is not None:
            report = monitoring_operator.finish(report, raw)
        if cli_receiver is not None:
            report["_privacy_needles"] = cli_receiver.finish(raw)
        return {**report, "elapsed_seconds": elapsed}
    finally:
        kube_promotion.cleanup(state, created, namespace=NAMESPACE)
        wait_pods_absent(state)


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
    initialize_campaign(root, state, image)
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
    from scripts.kube_approval_campaign import qualify as approval_campaign
    from scripts.kube_owned_probe import invoke

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
        authority_key, authority_public = initialize_campaign(root, state, image)
        promotion = configuration("/client", "/trust-client", arguments, authority_public)
        trust_authority.update(
            state,
            promotion["expected_policy"],
            authority_key,
            backend=kube_trust.binding,
        )
        kube_promotion.configure(state, promotion)
        config = serving_configuration(promotion)
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
        approval_pair = approval_campaign(
            root, state, image, profile, promotion, config, fixture, expected
        )
        approval = approval_pair["value"]
        request, model, expected, after, admitted, expiry = (
            approval[name]
            for name in ("request", "model", "expected", "after", "admitted", "expiry")
        )
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
        renewed_model, renewed_scores = rollback_variant(fixture, profile["image_id"], features)
        if (
            renewed_model == model
            or max(abs(a - b) for a, b in zip(scores, renewed_scores, strict=True)) <= 1e-5
        ):
            raise Rejected("rollback_fixture_models_not_distinct")
        promotion["context"] = copy.deepcopy(arguments["context"])
        config["context"] = copy.deepcopy(arguments["context"])
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
        expected.update(model=renewed_model, scores=renewed_scores)
        print(canonical({"stage": "unexpired-previous-sequence"}).decode(), flush=True)
        replay = exercise_replay(root, state, image, promotion, previous, renewed_request, receipt)
        after = ledger(state)
        print(canonical({"stage": "explicit-release-renewal"}).decode(), flush=True)
        recovery = invoke(state, profile, config, expected)
        print(canonical({"stage": "authorized-whole-bundle-rollback"}).decode(), flush=True)
        rollback_config = {**promotion, "context": copy.deepcopy(previous["context"])}
        rollback = exercise_rollback(
            root,
            state,
            image,
            rollback_config,
            previous,
            approval["receipt"],
            receipt,
            fixture.fixture.authorities.keys["approver"],
        )
        config.update(context=copy.deepcopy(previous["context"]), minimum_sequence=3)
        expected.update(bundle=old_subject, model=model, scores=scores)
        rollback["serving"] = invoke(state, profile, config, expected)
        rollback.update(target_model=model, from_model=renewed_model)
        after = ledger(state)
        print(canonical({"stage": "planned-authority-root-rotation"}).decode(), flush=True)
        next_key = authority_key.with_name("rotated-authority.pem")
        rotation = exercise_root_rotation(state, authority_key, next_key)
        from scripts.kube_controlled_trust_campaign import qualify as controlled_trust

        authority_key = next_key
        trust_window = controlled_trust(
            state,
            profile,
            config,
            rollback_config,
            expected,
            rotation,
            promotion["expected_policy"],
            authority_key,
            model,
        )
        observed_trust = trust_window["value"]
        rotation.update(
            old_config_refusal=observed_trust["old_config_refusal"],
            serving=observed_trust["serving"],
        )
        lifecycle, revoked = observed_trust["live_trust"], observed_trust["revoked"]
        rollback["revoked_retry"] = kube_promotion.invoke(
            root, state, rollback_config, rollback["request"], image
        )
        if rollback["revoked_retry"]["status"] != "rejected":
            raise Rejected("rollback_revoked_target_admitted")
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
                qualification_key=authority_key,
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
            "controlled_renewed_model": renewed_model,
            "authorized_rollback": rollback,
            "authority_root_rotation": rotation,
            "before_approval": refused,
            "approved": admitted,
            "after_revocation": revoked,
            "approval_expiry": {
                "ownership_return": approval_pair["ownership"],
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
            "trust_lifecycle_ownership_return": trust_window["ownership"],
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
