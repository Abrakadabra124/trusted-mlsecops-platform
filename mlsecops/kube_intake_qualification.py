import uuid
from pathlib import Path

from mlsecops import artifact_intake, boundary_qualification, controller_runtime
from mlsecops.cluster import kubectl
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    canonical,
    decode,
    digest,
    now,
    read_json,
    write_json,
)
from mlsecops.controller_bootstrap import verify_saved
from mlsecops.intake_gate import checked_cases, fresh
from mlsecops.intake_probe import CASE_IDS, MATRIX
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.kube_storage_resources import client_pod_spec
from mlsecops.kube_worker import job_document, verify_running_image, wait_job

HOST_CASES = {
    "independent-promoter-readback",
    "protected-storage-unchanged",
    "controller-profile-unchanged",
    "current-source-unchanged",
    "controller-reader-jobs-cleaned",
}


def invoke(state, profile, role, request):
    name = "intake-" + uuid.uuid4().hex
    namespace = "ml-" + role
    arguments = ["mlsecops.intake_probe", "--request", "/request.json"]
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "immutable": True,
        "metadata": {"name": name, "namespace": namespace},
        "data": {"request.json": canonical(request).decode()},
    }
    if role == "scorer":
        controller_runtime.signer(state)
        spec = controller_runtime.controller_spec(profile, role, name, arguments)
    elif role == "promoter":
        spec = client_pod_spec(profile["image"], role, [*arguments, "--read-only"])
        spec["volumes"].append({"name": "request", "configMap": {"name": name, "defaultMode": 292}})
        spec["containers"][0]["volumeMounts"].append(
            {
                "name": "request",
                "mountPath": "/request.json",
                "subPath": "request.json",
                "readOnly": True,
            }
        )
    else:
        raise Rejected("kube_intake_host_role")
    document = job_document(name, namespace, spec, 600)
    with (
        boundary_qualification.temporary_resource(state, config),
        boundary_qualification.temporary_resource(state, document) as (created, _),
    ):
        terminal, pod, elapsed = wait_job(state, namespace, name, 600)
        verify_running_image(pod, profile["image_id"])
        observed = boundary_qualification.pod_for_job(
            state, namespace, name, created["metadata"]["uid"]
        )
        if (
            observed is None
            or observed["metadata"]["uid"] != pod["metadata"]["uid"]
            or not boundary_qualification.isolated_spec(spec, pod)
        ):
            raise Rejected("kube_intake_host_pod_identity")
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                namespace,
                "-c",
                "worker",
                "--limit-bytes=1048577",
            ],
            check=False,
        ).stdout
        if terminal["type"] != "Complete":
            atomic_write(state / "evidence/kube-intake-diagnostic.log", content)
            raise Rejected("kube_intake_probe_failed")
        result = decode(content, 1024 * 1024)
        result["controller"] = {
            "job_uid": created["metadata"]["uid"],
            "pod_uid": pod["metadata"]["uid"],
            "pod_spec_digest": digest(canonical(pod["spec"])),
            "elapsed_seconds": elapsed,
        }
    return result


def reconcile(evidence, persisted, content, image, fingerprint, materials, started):
    try:
        checked_cases(evidence, CASE_IDS)
        if (
            type(evidence["schema_version"]) is not int
            or evidence["schema_version"] != 1
            or evidence["scope"] != "scoped-kubernetes-intake-matrix"
            or evidence["image_id"] != image
            or evidence["source_fingerprint"] != fingerprint
            or evidence["model_digest"] != digest(content)
            or evidence["materials"] != materials
            or evidence["release_ready"] is not False
            or persisted["release_ready"] is not False
            or persisted["candidate_reference"] != evidence["candidate_reference"]
            or persisted["model_digest"] != digest(content)
            or persisted["positive"] != evidence["positive"]["evaluation"]
            or persisted["denials"] != [item["payload"] for item in evidence["denials"]]
            or len(evidence["denials"]) != 2
        ):
            raise Rejected("kube_intake_material_binding")
        fresh(evidence["observed_at"], started)
        observation = evidence["process"]
        if (
            observation["uid"] != 65532
            or observation["model_parser_loaded"] is not False
            or observation["host_socket_present"] is not False
            or observation["signer_present"] is not True
            or observation["api_token_present"] is not True
            or not 0 < observation["peak_memory_kib"] < 512 * 1024
        ):
            raise Rejected("kube_intake_process_binding")
        identities, pods = set(), set()
        for case in evidence["cases"]:
            if case["id"] not in MATRIX:
                continue
            report = case["report"]
            payload = (
                b"\x80\x04N." if case["id"] in ("unsafe-format", "unsafe-no-findings") else content
            )
            if case["id"] in ("clean-before", "clean-after"):
                artifact_intake.validate_receipt(report, payload, image)
            else:
                artifact_intake.validate_failure(report, payload, image)
                reason = {
                    "unsafe-format": "model_parse_rejected",
                    "native-crash": "scanner_crash",
                    "native-deadline": "scanner_timeout",
                }.get(case["id"], "scanner_protocol_rejected")
                if report["reason"] != reason:
                    raise Rejected("kube_intake_rejection_binding")
            terminal = case["execution"]
            if case["id"] == "native-deadline":
                valid = (
                    terminal["condition"] == "Failed"
                    and terminal["reason"] == "DeadlineExceeded"
                    and terminal["selector_matches"] is True
                )
            elif case["id"] == "native-crash":
                valid = (
                    terminal["condition"] == "Failed"
                    and type(terminal["exit_code"]) is int
                    and terminal["exit_code"] != 0
                )
            else:
                valid = terminal["condition"] == "Complete" and terminal["exit_code"] == 0
            if not valid:
                raise Rejected("kube_intake_terminal_binding")
            for field in ("started_at", "finished_at"):
                fresh(report[field], started)
            if case["cleanup_verified"] is not True:
                raise Rejected("kube_intake_cleanup_unproven")
            identities.add(report["inspection_id"])
            pods.add(case["execution"]["pod_uid"])
        if (
            len(identities) != len(MATRIX)
            or len(pods) != len(MATRIX)
            or evidence["controller"]["pod_uid"] in pods
            or persisted["controller"]["pod_uid"] in pods
            or persisted["controller"]["pod_uid"] == evidence["controller"]["pod_uid"]
        ):
            raise Rejected("kube_intake_reused_execution")
        positive = persisted["positive"]
        if (
            positive["report"]["quality_component"] != "pass"
            or positive["report"]["model_digest"] != digest(content)
            or positive["report"]["image_id"] != image
            or positive["candidate_reference"] != evidence["candidate_reference"]
            or positive["dataset_reference"] != evidence["dataset_reference"]
        ):
            raise Rejected("kube_intake_clean_evaluation_binding")
        fresh(positive["report"]["created_at"], started)
        slots = {positive["holdout_access"]["slot"]}
        for denial in persisted["denials"]:
            artifact_intake.validate_failure(denial["intake"], content, image)
            fresh(denial["intake"]["started_at"], started)
            fresh(denial["intake"]["finished_at"], started)
            if (
                denial["candidate_reference"] != evidence["candidate_reference"]
                or denial["decision"] != "deny-evaluation"
                or denial["release_ready"] is not False
            ):
                raise Rejected("kube_intake_denial_binding")
            slots.add(denial["holdout_access"]["slot"])
        if len(slots) != 3:
            raise Rejected("kube_intake_budget_reuse")
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("kube_intake_evidence_shape") from error


def qualify(root, state, content, image, materials):
    root, state = Path(root).resolve(), Path(state).resolve()
    started = now()
    marker = verify_saved(state, read_json(state / "controllers/resources.json"))
    profile = marker["profile"]
    fingerprint = source_fingerprint(root)
    if (
        not marker["ready"]
        or profile["image_id"] != image
        or profile["source_fingerprint"] != fingerprint
        or profile["source_revision"] != command(["git", "-C", str(root), "rev-parse", "HEAD"])
    ):
        raise Rejected("kube_intake_host_profile_stale")
    before = ledger(state)
    demo = read_json(state / "evidence/controller-demo.json")
    inputs = read_json(state / "kubernetes-storage/migration-inputs.json")
    request = {
        "schema_version": 1,
        "profile": profile,
        "candidate_reference": demo["publisher"]["result"]["candidate_reference"],
        "trust": inputs["trust"],
    }
    report = invoke(state, profile, "scorer", request)
    persisted = invoke(
        state,
        profile,
        "promoter",
        {
            "context": request,
            "evaluation_reference": report["positive"]["evaluation_reference"],
            "denial_references": [item["reference"] for item in report["denials"]],
        },
    )
    reconcile(report, persisted, content, image, fingerprint, materials, started)
    after = ledger(state)
    if (
        any(after[name] != value for name, value in before.items() if name != "evaluations")
        or after["evaluations"]["rows"] - before["evaluations"]["rows"] != 6
    ):
        raise Rejected("kube_intake_history_binding")
    if (
        verify_saved(state, read_json(state / "controllers/resources.json"))["profile"] != profile
        or source_fingerprint(root) != fingerprint
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != profile["source_revision"]
    ):
        raise Rejected("kube_intake_source_changed")
    report["cases"].extend({"id": name, "status": "pass"} for name in sorted(HOST_CASES))
    report.update(
        checks=len(report["cases"]),
        started_at=started,
        finished_at=now(),
        source_revision=profile["source_revision"],
        persisted_readback_digest=digest(canonical(persisted)),
    )
    write_json(state / "evidence/kube-intake-qualification.json", report)
    return report
