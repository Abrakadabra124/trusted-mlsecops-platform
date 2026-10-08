import uuid
from pathlib import Path

from mlsecops import (
    boundary_qualification,
    controller_qualification,
    controller_runtime,
    kube_artifact_reader,
    kube_qualification,
    prediction_protocol_qualification,
)
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
from mlsecops.controller_bootstrap import bootstrap, verify_saved
from mlsecops.inventory import source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from mlsecops.signing import verify


def combine(components, binding):
    if set(components) != {"isolation", "protocol", "controller", "outputs", "access"}:
        raise Rejected("authority_components_incomplete")
    cases, hashes = [], {}
    for name, report in components.items():
        if (
            report.get("status") != "pass"
            or not isinstance(report.get("cases"), list)
            or not report["cases"]
        ):
            raise Rejected(f"authority_component_not_pass:{name}")
        fields = ["source_fingerprint"]
        if name != "protocol":
            fields.append("image_id")
        if name in {"access", "controller", "outputs"}:
            fields.append("dataset_reference")
        if name in {"controller", "outputs"}:
            fields.extend(("candidate_reference", "model_digest", "policy_digest"))
        if any(report.get(field) != binding[field] for field in fields):
            raise Rejected(f"authority_component_binding:{name}")
        identifiers = set()
        for case in report["cases"]:
            if not isinstance(case, dict):
                raise Rejected(f"authority_component_case:{name}")
            identifier = case.get("id")
            if (
                case.get("status") != "pass"
                or not isinstance(identifier, str)
                or not identifier
                or identifier in identifiers
            ):
                raise Rejected(f"authority_component_case:{name}")
            identifiers.add(identifier)
            cases.append(
                {
                    "expected": "pass",
                    "actual": case["status"],
                    **case,
                    "id": f"{name}:{identifier}",
                }
            )
        hashes[name] = digest(canonical(report) + b"\n")
    return cases, hashes


def native_outputs(state, profile, candidate, trust):
    name = f"authority-{uuid.uuid4().hex}"
    request = {
        "schema_version": 1,
        "profile": profile,
        "candidate_reference": candidate,
        "trust": trust,
    }
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "immutable": True,
        "metadata": {"name": name, "namespace": "ml-scorer"},
        "data": {"request.json": canonical(request).decode()},
    }
    controller_runtime.signer(state)
    spec = controller_runtime.controller_spec(
        profile, "scorer", name, ["mlsecops.authority_probe", "--request", "/request.json"]
    )
    document = job_document(name, "ml-scorer", spec, 720)
    with (
        boundary_qualification.temporary_resource(state, config),
        boundary_qualification.temporary_resource(state, document) as (created, _),
    ):
        terminal, pod, elapsed = wait_job(state, "ml-scorer", name, 720)
        verify_running_image(pod, profile["image_id"])
        observed = boundary_qualification.pod_for_job(
            state, "ml-scorer", name, created["metadata"]["uid"]
        )
        if observed["metadata"]["uid"] != pod["metadata"][
            "uid"
        ] or not boundary_qualification.isolated_spec(spec, pod):
            raise Rejected("authority_scorer_identity_or_spec")
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                "ml-scorer",
                "-c",
                "worker",
                "--limit-bytes=1048577",
            ],
            check=False,
        ).stdout
        if terminal["type"] != "Complete":
            atomic_write(state / "evidence/authority-diagnostic.log", content)
            raise Rejected("authority_scorer_probe_failed")
        result = decode(content, 1024 * 1024)
        result["controller"] = {
            "job_uid": created["metadata"]["uid"],
            "pod_uid": pod["metadata"]["uid"],
            "pod_spec_digest": digest(canonical(pod["spec"])),
            "elapsed_seconds": elapsed,
        }
        return result


def qualify(root, state, image="trusted-mlsecops:dev"):
    from mlsecops.authority_contract_qualification import qualify as qualify_contracts

    root, state = Path(root).resolve(), Path(state).resolve()
    contracts = qualify_contracts()
    profile = bootstrap(root, state, image)["profile"]
    before = ledger(state)
    inputs = read_json(state / "kubernetes-storage/migration-inputs.json")
    components = {}

    def save(name, report):
        components[name] = report
        write_json(state / f"evidence/M20-{name}.json", report)
        if report.get("status") != "pass":
            raise Rejected(f"authority_component_not_pass:{name}")
        return report

    save("isolation", kube_qualification.qualify(state, image))
    save("protocol", prediction_protocol_qualification.qualify())
    controller = save("controller", controller_qualification.qualify(root, state, image))
    outputs = save(
        "outputs",
        native_outputs(state, profile, controller["candidate_reference"], inputs["trust"]),
    )
    save("access", boundary_qualification.qualify(root, state))
    binding = {
        "source_fingerprint": source_fingerprint(root),
        "image_id": profile["image_id"],
        "dataset_reference": inputs["dataset_reference"],
        "candidate_reference": controller["candidate_reference"],
        "model_digest": controller["model_digest"],
        "policy_digest": digest(canonical(read_json(root / "policies/local-cpu.json"))),
    }
    cases, artifacts = combine(components, binding)
    cases.extend({**case, "id": f"contracts:{case['id']}"} for case in contracts["cases"])
    write_json(state / "evidence/M20-contracts.json", contracts)
    artifacts["contracts"] = digest(canonical(contracts) + b"\n")

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"authority_binding_failed:{name}")
        cases.append({"id": f"gate:{name}", "status": "pass", "expected": True, "actual": True})

    confirmed(
        "parser-outside-privileged-scorer", outputs["process"]["model_parser_loaded"] is False
    )
    confirmed(
        "bounded-native-scorer-memory", 0 < outputs["process"]["peak_memory_kib"] < 512 * 1024
    )
    for index, evaluation in enumerate(outputs["positive_evaluations"]):
        stored = kube_artifact_reader.read(
            state,
            profile["image"],
            profile["image_id"],
            {
                "schema_version": 1,
                "role": "scorer",
                "candidate_reference": binding["candidate_reference"],
                "evaluation_reference": evaluation["evaluation_reference"],
                "trust": inputs["trust"],
                "policy_digest": binding["policy_digest"],
            },
        )
        checked = verify(stored["evaluation"], "stored-evaluation", inputs["trust"]["evaluator"])
        confirmed(
            f"positive-{index}:independent-persisted-signature", checked == evaluation["evaluation"]
        )
        confirmed(
            f"positive-{index}:subject-binding",
            checked["candidate_reference"] == binding["candidate_reference"]
            and checked["dataset_reference"] == binding["dataset_reference"]
            and checked["report"]["model_digest"] == binding["model_digest"]
            and checked["report"]["image_id"] == binding["image_id"],
        )
    after = ledger(state)
    confirmed(
        "protected-data-and-releases-unchanged",
        all(
            after[name] == item
            for name, item in before.items()
            if name not in {"candidates", "evaluations"}
        ),
    )
    confirmed(
        "three-valid-evaluations-only",
        after["evaluations"]["rows"] - before["evaluations"]["rows"] == 3,
    )
    verified = verify_saved(state, read_json(state / "controllers/resources.json"))
    confirmed("profile-unchanged-through-gate", verified["profile"] == profile)
    for namespace in ("ml-scorer", "ml-publisher", "ml-train", "ml-eval"):
        for resource in ("jobs", "pods", "configmaps"):
            observed = decode(
                kubectl(state, ["get", resource, "-n", namespace, "-o", "json"]).stdout
            )["items"]
            confirmed(
                f"cleanup:{namespace}:{resource}",
                not any(
                    item["metadata"]["name"].startswith(
                        ("authority-", "controller-worker-", "controller-run-", "boundary-")
                    )
                    for item in observed
                ),
            )
    result = {
        "schema_version": 1,
        "status": "pass",
        "scope": "M20-synthetic-local-worker-evaluator-authority",
        "observed_at": now(),
        **binding,
        "cases": cases,
        "checks": len(cases),
        "component_checks": {
            **{name: len(report["cases"]) for name, report in components.items()},
            "contracts": len(contracts["cases"]),
            "integration": sum(case["id"].startswith("gate:") for case in cases),
        },
        "artifact_hashes": artifacts,
        "evaluation_references": [
            controller["evaluation_reference"],
            *(item["evaluation_reference"] for item in outputs["positive_evaluations"]),
        ],
        "negative_native_batches": outputs["negative_batches"],
        "release_ready": False,
        "limitations": [
            "Synthetic CPU lab only; host/cluster administrator and shared kernel trusted",
            "Native faults injected after real worker transport in a qualification scorer, not parser exploits",
            "Signer/SQL spies wrap real functions; positive writes are independently read and verified",
            "No semantic correctness guarantee for well-formed malicious scores or covert channels",
            "Single-use batch is not persistent holdout budget M07 or release replay M11",
            "Component probes overlap; counts are not independent statistical guarantees",
            "Operator evidence files are not the protected M23 audit sink",
            "Full M01/M04/M05 and remaining R1 gates still required; no production release",
        ],
    }
    write_json(state / "evidence/authority-qualification.json", result)
    return result
