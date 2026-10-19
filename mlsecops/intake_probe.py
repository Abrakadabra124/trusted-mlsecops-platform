import copy
import re
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import patch

from mlsecops import (
    artifact_intake,
    controller_worker,
    holdout_budget,
    intake_denial,
    storage_pipeline,
)
from mlsecops.authority_probe import evaluation_snapshot
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, require_fields
from mlsecops.controller import process_state
from mlsecops.controller_api import APIError, Client
from mlsecops.inventory import source_fingerprint
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce as enforce_privacy

MUTATIONS = (
    "zero-inspected",
    "partial",
    "stale-response",
    "foreign-model",
    "extra-output",
    "wrong-tool",
    "unsafe-no-findings",
)
MATRIX = (
    "clean-before",
    "unsafe-format",
    *MUTATIONS,
    "native-crash",
    "native-deadline",
    "clean-after",
)
CASE_IDS = set(MATRIX) | {
    "inspect-does-not-spend-holdout",
    "fresh-clean-evaluation",
    "denial-zero-inspected",
    "denial-stale-response",
    "exact-three-spent-slots",
    "exact-sql-history-delta",
    "scorer-process-boundary",
}


def corrupt(name, source, previous):
    output = copy.deepcopy(source)
    if name == "stale-response":
        return copy.deepcopy(previous)
    mutations = {
        "zero-inspected": lambda: output.update(inspected=0),
        "partial": lambda: output.update(unsupported=1, skipped=1, errors=1),
        "foreign-model": lambda: output.update(model_digest="0" * 64),
        "extra-output": lambda: output["approved_outputs"].append("0" * 64),
        "wrong-tool": lambda: output["tool"].update(policy="obsolete"),
        "unsafe-no-findings": lambda: output.update(status="pass"),
    }
    if name not in mutations:
        raise Rejected("kube_intake_unknown_mutation")
    mutations[name]()
    return output


def cleanup(client, created):
    deadline = time.monotonic() + 30
    while True:
        remaining = False
        for resource, name, uid in created:
            try:
                observed = client.request(resource, name)
            except APIError as error:
                if error.status != 404:
                    raise
            else:
                if observed["metadata"]["uid"] != uid:
                    raise Rejected("kube_intake_cleanup_identity")
                remaining = True
            if resource == "jobs" and client.request("pods", job=name)["items"]:
                remaining = True
        if not remaining:
            return
        if time.monotonic() >= deadline:
            raise Rejected("kube_intake_cleanup_deadline")
        time.sleep(0.5)


def inspect_case(profile, name, content, previous):
    client = Client("scorer")
    created, terminals, responses = [], [], []
    observed_pods = []
    original_request, original_documents = Client.request, controller_worker.documents
    selector = {"trusted-mlsecops/intake-deadline": uuid.uuid4().hex}

    def observe(active, resource, item=None, method="GET", value=None, job=None):
        observed = original_request(active, resource, item, method, value, job)
        if method == "POST":
            created.append((resource, observed["metadata"]["name"], observed["metadata"]["uid"]))
        if resource == "jobs" and method == "GET":
            if ("jobs", item, observed["metadata"]["uid"]) not in created:
                raise Rejected("kube_intake_job_identity")
            pods = original_request(active, "pods", job=item)["items"]
            if len(pods) > 1:
                raise Rejected("kube_intake_pod_identity")
            if pods:
                if not any(
                    owner.get("uid") == observed["metadata"]["uid"]
                    and owner.get("controller") is True
                    for owner in pods[0]["metadata"].get("ownerReferences", [])
                ) or (
                    observed_pods
                    and observed_pods[0]["metadata"]["uid"] != pods[0]["metadata"]["uid"]
                ):
                    raise Rejected("kube_intake_pod_identity")
                observed_pods[:] = pods
            for condition in observed.get("status", {}).get("conditions", []):
                if (
                    condition.get("type") in ("Complete", "Failed")
                    and condition.get("status") == "True"
                ):
                    if not observed_pods or (
                        not pods and condition.get("reason") != "DeadlineExceeded"
                    ):
                        raise Rejected("kube_intake_pod_identity")
                    pod = observed_pods[0]
                    statuses = pod.get("status", {}).get("containerStatuses", [])
                    terminals.append(
                        {
                            "job_uid": observed["metadata"]["uid"],
                            "pod_uid": pod["metadata"]["uid"],
                            "condition": condition["type"],
                            "reason": condition.get("reason"),
                            "pod_spec_digest": digest(canonical(pod["spec"])),
                            "runtime_image_id": statuses[0].get("imageID")
                            if len(statuses) == 1
                            else None,
                            "exit_code": statuses[0]
                            .get("state", {})
                            .get("terminated", {})
                            .get("exitCode")
                            if len(statuses) == 1
                            else None,
                            "selector_matches": pod["spec"].get("nodeSelector") == selector,
                            "pod_deleted_at_terminal": not pods,
                        }
                    )
        return observed

    def documents(*args, **kwargs):
        config, job = original_documents(*args, **kwargs)
        if name == "native-deadline":
            job["spec"]["template"]["spec"]["nodeSelector"] = selector
        return config, job

    def executor(image, request):
        if request["action"] != "inspect" or image != profile["image_id"]:
            raise Rejected("kube_intake_worker_scope")
        delivered = copy.deepcopy(request)
        if name == "native-crash":
            delivered["model_digest"] = "0" * 64
        output, execution = controller_worker.run(
            profile, "scorer", delivered, timeout=3 if name == "native-deadline" else 60
        )
        artifact_intake.checked_response(output, request)
        if (
            execution["backend"] != "scoped-kubernetes-controller"
            or execution["namespace"] != "ml-eval"
            or execution["input_digest"] != digest(canonical(request))
        ):
            raise Rejected("kube_intake_execution_binding")
        responses.append(copy.deepcopy(output))
        return (corrupt(name, output, previous) if name in MUTATIONS else output), execution

    payload = b"\x80\x04N." if name in ("unsafe-format", "unsafe-no-findings") else content
    with (
        patch.object(Client, "request", observe),
        patch.object(controller_worker, "documents", documents),
    ):
        try:
            report = artifact_intake.inspect_candidate(
                payload, digest(payload), profile["image_id"], profile["image_id"], executor
            )
        except artifact_intake.IntakeFailure as error:
            report = error.report
    cleanup(client, created)
    if (
        len(created) != 2
        or {item[0] for item in created} != {"jobs", "configmaps"}
        or len(terminals) != 1
    ):
        raise Rejected("kube_intake_job_not_proven")
    terminal = terminals[0]
    if name == "native-deadline":
        valid = (
            terminal["condition"] == "Failed"
            and terminal["reason"] == "DeadlineExceeded"
            and terminal["selector_matches"]
        )
    elif name == "native-crash":
        observed_image = re.search(r"sha256:[0-9a-f]{64}$", terminal["runtime_image_id"] or "")
        valid = (
            terminal["condition"] == "Failed"
            and type(terminal["exit_code"]) is int
            and terminal["exit_code"] != 0
            and observed_image is not None
            and observed_image.group() in {profile["manifest_id"], profile["config_id"]}
        )
    else:
        valid = terminal["condition"] == "Complete" and len(responses) == 1
    if not valid:
        raise Rejected("kube_intake_terminal_not_proven")
    if name in ("clean-before", "clean-after"):
        artifact_intake.validate_receipt(report, payload, profile["image_id"])
    else:
        artifact_intake.validate_failure(report, payload, profile["image_id"])
        expected = {
            "unsafe-format": "model_parse_rejected",
            "native-crash": "scanner_crash",
            "native-deadline": "scanner_timeout",
        }.get(name, "scanner_protocol_rejected")
        if report["reason"] != expected:
            raise Rejected("kube_intake_wrong_rejection")
    return {
        "id": name,
        "status": "pass",
        "report": report,
        "execution": terminal,
        "cleanup_verified": True,
    }, responses[0] if responses else None


def context(request, client, role):
    require_fields(request, ("schema_version", "profile", "candidate_reference", "trust"))
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise Rejected("kube_intake_request_schema")
    controller_worker.validate_profile(request["profile"])
    root = Path(__file__).resolve().parents[1]
    if (
        request["profile"]["source_fingerprint"] != source_fingerprint(root)
        or read_json(client / "connection.json")["role"] != role
    ):
        raise Rejected("kube_intake_context_identity")
    policy = read_json(root / "policies/local-cpu.json")
    record, metadata, model = storage_pipeline.load_candidate(
        client, request["candidate_reference"], policy
    )
    if any(
        metadata[name] != request["profile"][name]
        for name in ("image_id", "source_revision", "source_fingerprint")
    ):
        raise Rejected("kube_intake_candidate_stale")
    return root, policy, record, metadata, model


def qualify(request):
    client = Path("/client")
    root, policy, record, metadata, content = context(request, client, "scorer")
    process_state("scorer")
    profile, candidate, trust = request["profile"], request["candidate_reference"], request["trust"]
    holdout = metadata["materials"]["holdout.json"]["sha256"]
    budget = holdout_budget.inspect(client, holdout)
    if budget["remaining_upper_bound"] < 3:
        raise Rejected("kube_intake_budget_insufficient")
    before = set(evaluation_snapshot(client))
    cases, previous = [], None
    for name in MATRIX:
        case, response = inspect_case(profile, name, content, previous)
        cases.append(case)
        if name == "clean-before":
            previous = response

    def confirmed(name, condition):
        if not condition:
            raise Rejected("kube_intake_check_failed:" + name)
        cases.append({"id": name, "status": "pass"})

    confirmed(
        "inspect-does-not-spend-holdout",
        set(evaluation_snapshot(client)) == before
        and holdout_budget.inspect(client, holdout) == budget,
    )
    executions = []

    def clean_executor(image, request):
        if image != profile["image_id"]:
            raise Rejected("kube_intake_worker_scope")
        output, execution = controller_worker.run(profile, "scorer", request, timeout=60)
        executions.append(execution)
        return output, execution

    positive = storage_pipeline.evaluate(
        client,
        candidate,
        policy,
        profile["image_id"],
        trust,
        Path("/signer/key.pem"),
        clean_executor,
    )
    confirmed(
        "fresh-clean-evaluation",
        storage_pipeline.read_evaluation(
            client, positive["evaluation_reference"], candidate, policy, trust
        )
        == positive["evaluation"]
        and len(executions) == 2,
    )
    denials = []
    for name in ("zero-inspected", "stale-response"):
        actions = []

        def corrupted_executor(image, request):
            actions.append(request["action"])
            if request["action"] != "inspect":
                raise Rejected("kube_intake_prediction_after_denial")
            output, execution = clean_executor(image, request)
            return corrupt(name, output, previous), execution

        try:
            storage_pipeline.evaluate(
                client,
                candidate,
                policy,
                profile["image_id"],
                trust,
                Path("/signer/key.pem"),
                corrupted_executor,
            )
        except intake_denial.RecordedDenial as error:
            payload = intake_denial.read(client, error.reference, candidate, policy, trust)
            confirmed(
                "denial-" + name,
                actions == ["inspect"]
                and error.status == "fail"
                and payload["intake"]["reason"] == "scanner_protocol_rejected",
            )
            denials.append({"reference": error.reference, "payload": payload})
        else:
            raise Rejected("kube_intake_unsafe_evaluation")
    accesses = [
        positive["evaluation"]["holdout_access"],
        *(item["payload"]["holdout_access"] for item in denials),
    ]
    after = holdout_budget.inspect(client, holdout)
    confirmed(
        "exact-three-spent-slots",
        len({item["slot"] for item in accesses}) == 3
        and set(after["occupied_slots"]) - set(budget["occupied_slots"])
        == {item["slot"] for item in accesses}
        and len(after["occupied_slots"]) == len(budget["occupied_slots"]) + 3,
    )
    confirmed(
        "exact-sql-history-delta",
        set(evaluation_snapshot(client))
        == before
        | {item["reservation"] for item in accesses}
        | {positive["evaluation_reference"]}
        | {item["reference"] for item in denials},
    )
    observation = process_state("scorer")
    confirmed(
        "scorer-process-boundary",
        not observation["model_parser_loaded"] and 0 < observation["peak_memory_kib"] < 512 * 1024,
    )
    if len(cases) != len(CASE_IDS) or {case["id"] for case in cases} != CASE_IDS:
        raise Rejected("kube_intake_cases_incomplete")
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "scoped-kubernetes-intake-matrix",
        "observed_at": now(),
        "source_fingerprint": source_fingerprint(root),
        "image_id": profile["image_id"],
        "candidate_reference": candidate,
        "dataset_reference": record["dataset_reference"],
        "model_digest": digest(content),
        "policy_digest": digest(canonical(policy)),
        "materials": metadata["materials"],
        "cases": cases,
        "checks": len(cases),
        "positive": positive,
        "denials": denials,
        "process": observation,
        "executions": executions,
        "release_ready": False,
    }


def readback(request, client):
    require_fields(request, ("context", "evaluation_reference", "denial_references"))
    core = request["context"]
    _, policy, record, metadata, content = context(core, client, "promoter")
    references = request["denial_references"]
    if not isinstance(references, list) or len(references) != 2 or len(set(references)) != 2:
        raise Rejected("kube_intake_readback_set")
    if (
        Path("/signer/key.pem").exists()
        or Path("/api/token").exists()
        or any(name in sys.modules for name in ("onnx", "onnxruntime"))
    ):
        raise Rejected("kube_intake_reader_authority")
    candidate, trust = core["candidate_reference"], core["trust"]
    return {
        "candidate_reference": candidate,
        "model_digest": digest(content),
        "positive": storage_pipeline.read_evaluation(
            client, request["evaluation_reference"], candidate, policy, trust
        ),
        "denials": [
            intake_denial.read(client, reference, candidate, policy, trust)
            for reference in references
        ],
        "release_ready": False,
    }


def main():
    try:
        enforce_privacy()
        parser = Arguments(
            prog="intake-probe", description="Scoped intake qualification, not a release approval"
        )
        parser.add_argument("--request", type=Path, required=True)
        parser.add_argument("--read-only", action="store_true")
        arguments = parser.parse_args()
        request = read_json(arguments.request)
        result = readback(request, Path("/client")) if arguments.read_only else qualify(request)
        print(canonical(result).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(
            canonical(
                {"status": "fail", "reason": "kube_intake_probe_incomplete", "release_ready": False}
            ).decode()
        )
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
