import time

from mlsecops import kube_storage
from mlsecops.cluster import validate_cluster
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
from mlsecops.inventory import source_fingerprint
from mlsecops.kube_qualification import probe
from mlsecops.kube_worker import load_image
from scripts import candidate_serving_native, release_native


def exercise(engine, request, body, *, state, image, image_id):
    worker = engine.worker.container

    def sample():
        started = time.time()
        status, response = request("/v1/predict", body)
        if status != 200 or engine.worker is None or engine.worker.container != worker:
            raise Rejected("training_fault_serving_unavailable_or_restarted")
        try:
            stable = {
                name: response[name] for name in ("model_sha256", "bundle_sha256", "predictions")
            }
        except (KeyError, TypeError):
            raise Rejected("training_fault_serving_response_invalid") from None
        return stable, {
            "started_at": started,
            "finished_at": time.time(),
            "response_sha256": digest(canonical(stable)),
        }

    reference, before = sample()
    faults = {}
    for action in ("deadline", "oom"):
        samples = []

        def observe(pod):
            current, observation = sample()
            if current != reference:
                raise Rejected("training_fault_prediction_changed")
            observation = {**observation, "pod_uid": pod["metadata"]["uid"]}
            samples.append(observation)
            return observation

        result = probe(
            state,
            image,
            image_id,
            action,
            deadline=10 if action == "deadline" else 60,
            observe=observe,
        )
        if (
            not samples
            or not any(item.get("running_after_response") is True for item in samples)
            or result.get("observations", 0) < 1
            or result["condition"] != "Failed"
        ):
            raise Rejected("training_fault_no_running_overlap_or_not_limited")
        if (
            (
                action == "deadline"
                and (result["reason"] != "DeadlineExceeded" or result["elapsed_seconds"] > 45)
            )
            or (action == "oom" and result["termination"] != "OOMKilled")
            or any(item["pod_uid"] != result["pod_uid"] for item in samples)
        ):
            raise Rejected("training_fault_wrong_termination_or_identity")
        after, observation = sample()
        if after != reference:
            raise Rejected("training_fault_post_prediction_changed")
        faults[action] = {"probe": result, "during": samples, "after": observation}
    return {
        "status": "pass",
        "model_sha256": reference["model_sha256"],
        "bundle_sha256": reference["bundle_sha256"],
        "response_sha256": before["response_sha256"],
        "before": before,
        "faults": faults,
        "serving_worker_unchanged": True,
    }


def qualify(root, state, image):
    access = read_json(safe_child(state, "evidence/access-qualification.json"))
    gate = read_json(safe_child(state, "evidence/M04.json"))
    if (
        gate.get("status") != "pass"
        or gate.get("exit_code") != 0
        or gate.get("artifact_hashes", {}).get("isolation_qualification")
        != digest(bounded_read(safe_child(state, "evidence/access-qualification.json")))
    ):
        raise Rejected("training_isolation_current_M04_not_pass")
    for name, filename in (
        ("storage", "kubernetes-storage-qualification"),
        ("authority", "authority-qualification"),
        ("access", "M20-access"),
        ("controller", "M20-controller"),
        ("isolation", "M20-isolation"),
    ):
        path = safe_child(state, f"evidence/{filename}.json")
        if read_json(path).get("status") != "pass" or digest(bounded_read(path)) != access.get(
            "artifact_hashes", {}
        ).get(name):
            raise Rejected("training_isolation_access_dependency_changed")
    tag, image_id = load_image(state, image)
    if (
        access.get("status") != "pass"
        or access.get("image_id") != image_id
        or access.get("source_fingerprint") != source_fingerprint(root)
    ):
        raise Rejected("training_isolation_access_not_current")
    isolation_path = safe_child(state, "evidence/M20-isolation.json")
    isolation = read_json(isolation_path)
    if (
        digest(bounded_read(isolation_path)) != access["artifact_hashes"]["isolation"]
        or validate_cluster(state)["namespace_uid"] != access["cluster_namespace_uid"]
        or kube_storage.validate(state)["volume_uid"] != access["storage_volume_uid"]
        or isolation["status"] != "pass"
        or isolation["image_id"] != image_id
        or isolation["source_fingerprint"] != access["source_fingerprint"]
    ):
        raise Rejected("training_isolation_resources_or_evidence_changed")
    release_native.qualify(root, state, image_id)
    observations = {}

    def during_serving(engine, request, body):
        if observations:
            raise Rejected("training_isolation_repeated_observer")
        observations.update(
            exercise(engine, request, body, state=state, image=tag, image_id=image_id)
        )

    serving = candidate_serving_native.qualify(root, state, image_id, during_serving=during_serving)
    if (
        observations.get("status") != "pass"
        or serving["status"] != "pass"
        or serving["release_ready"] is not False
        or observations["model_sha256"] != serving["model_sha256"]
        or observations["bundle_sha256"] != serving["subject_sha256"]
    ):
        raise Rejected("training_isolation_actual_candidate_binding")
    cases = [
        {"id": name, "expected": True, "actual": True, "status": "pass"}
        for name in (
            "M04-real-access-and-network-denials",
            "actual-candidate-not-fixture-or-approved-release",
            "deadline-enforced-during-inference",
            "oom-enforced-during-inference",
            "same-model-predictions-before-during-after",
            "serving-worker-not-restarted",
        )
    ]
    cases.extend({**case, "id": f"runtime:{case['id']}"} for case in isolation["cases"])
    if isolation["status"] != "pass" or any(case["status"] != "pass" for case in cases):
        raise Rejected("training_isolation_runtime_prerequisites")
    result = {
        "schema_version": 1,
        "status": "pass",
        "observed_at": now(),
        "source_fingerprint": source_fingerprint(root),
        "image_id": image_id,
        "candidate_reference": serving["candidate_reference"],
        "model_sha256": serving["model_sha256"],
        "cases": cases,
        "checks": len(cases),
        "serving_under_fault": observations,
        "artifact_hashes": {
            "serving_qualification": digest(canonical(serving)),
            "access": digest(canonical(access)),
            "isolation": digest(canonical(isolation)),
        },
        "limitations": [
            "Actual qualified candidate uses the existing HTTP app and bounded Docker ONNX worker",
            "Training faults run in the owned Kubernetes lab on the same host",
            "No release approval; M14 load/latency and M16 failover remain separate",
            "Concurrent samples prove availability/correctness, not absence of all latency effects",
        ],
    }
    write_json(safe_child(state, "evidence/training-isolation.json"), result)
    return result
