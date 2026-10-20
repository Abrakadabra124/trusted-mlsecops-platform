import uuid
from pathlib import Path

from mlsecops import boundary_probe, kube_storage
from mlsecops.cluster import NAMESPACES, validate_cluster
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import source_fingerprint
from mlsecops.sandbox import resolve_image
from mlsecops.storage_pki import ROLES
from mlsecops.storage_schema import TABLES


def required_access_cases():
    for role, readable, writable in (
        (
            "publisher",
            {"train", "validation", "manifests", "lineage", "candidates"},
            {"candidates"},
        ),
        (
            "scorer",
            {"holdout", "manifests", "lineage", "candidates", "evaluations"},
            {"evaluations"},
        ),
        ("serving", {"releases"}, set()),
    ):
        actual_read = {
            name for name, (writer, readers) in TABLES.items() if role in (writer, *readers)
        }
        actual_write = {name for name, (writer, _) in TABLES.items() if role == writer}
        if actual_read != readable or actual_write != writable:
            raise Rejected("isolation_access_policy_contract_changed")
    return {
        "isolation": {
            *(f"identity-{identity}-create-job" for identity in NAMESPACES.values()),
            *(
                f"identity-{identity}-read-{namespace}-{resource}"
                for identity in NAMESPACES.values()
                for namespace, resource in (
                    ("ml-control", "secrets"),
                    ("ml-eval", "configmaps"),
                    ("ml-train", "configmaps"),
                )
            ),
        },
        "access": {
            *(
                f"{identity}:{name}"
                for identity in ("trainer", "evaluator")
                for name in (
                    "completed",
                    "pod-owner",
                    "worker-spec",
                    "separate-pid-namespace",
                    "complete-path-matrix",
                    "sql-network-denied",
                    "api-network-denied",
                    "witness-still-running",
                )
            ),
            *(
                f"{identity}:denied:{path}"
                for identity in ("trainer", "evaluator")
                for path in boundary_probe.PROTECTED
            ),
        },
        "controller": {
            "scoped-training-worker",
            "scoped-prediction-worker",
            "image-bound-training-provenance",
            "separate-controller-and-worker-pods",
            "separate-scorer-and-prediction-worker",
            "persisted-evaluation-signature-and-bytes",
            "protected-splits-and-release-history-unchanged",
        },
        "storage": {
            *(
                f"{role}:{operation}-{table}"
                for role in ROLES
                for table in TABLES
                for operation in ("read", "insert", "update", "delete", "truncate")
            ),
            *(
                f"{role}:{name}"
                for role in ROLES
                for name in (
                    "authenticated-role",
                    "role-binding",
                    "only-own-bundle",
                    "tls-1.3",
                    "no-owner",
                    "no-superuser",
                    "no-ddl",
                    "no-temp",
                    "certificate-role-mismatch",
                    "server-hostname-mismatch",
                    "missing-client-certificate",
                    "plaintext",
                    "superuser-tcp",
                )
            ),
            *(
                f"{role}:absent:{path}"
                for role in ROLES
                for path in (
                    "/var/run/secrets/kubernetes.io/serviceaccount/token",
                    "/var/run/docker.sock",
                    "/app/.runtime",
                    "/etc/kubernetes/admin.conf",
                    "/source",
                )
            ),
            *(f"{role}:suite-complete" for role in ROLES),
            *(f"{role}:api-create-privileged-pod" for role in ROLES),
            *(
                f"{role}:api-read-secrets:{namespace}"
                for role in ROLES
                for namespace in (f"ml-{role}", "ml-storage", "ml-control")
            ),
            "network-denied:ml-train:trainer",
            "network-denied:ml-eval:evaluator",
            "network-denied:ml-publisher:default",
            "network-positive-same-endpoint",
            "dns-tcp-positive-control",
            "postgres-egress-dns-denied",
            "sql-probes-rolled-back",
        },
    }


def reconcile_access(components, binding):
    required = required_access_cases()
    if set(components) != set(required):
        raise Rejected("isolation_access_components_missing")
    cases = []
    for name, expected in required.items():
        report = components[name]
        image_field = "worker_image" if name == "storage" else "image_id"
        if (
            report.get("status") != "pass"
            or report.get("source_fingerprint") != binding["source_fingerprint"]
            or report.get(image_field) != binding["image_id"]
            or not isinstance(report.get("cases"), list)
        ):
            raise Rejected(f"isolation_access_component_binding:{name}")
        identifiers = []
        for case in report["cases"]:
            identifier = case.get("id")
            if not isinstance(identifier, str) or not identifier or case.get("status") != "pass":
                raise Rejected(f"isolation_access_case_invalid:{name}")
            identifiers.append(identifier)
            cases.append(
                {
                    "id": f"{name}:{identifier}",
                    "expected": "pass",
                    "actual": "pass",
                    "status": "pass",
                }
            )
        if len(set(identifiers)) != len(identifiers) or not expected.issubset(identifiers):
            raise Rejected(f"isolation_access_matrix_incomplete:{name}")
        if name == "storage" and report.get("count") != len(identifiers):
            raise Rejected("isolation_access_storage_count_mismatch")
    return cases


def perform_access_checks(root, state):
    from mlsecops import acceptance, kube_storage_qualification

    write_json(safe_child(state, "evidence/M20.json"), {"status": "inconclusive", "exit_code": 2})
    authority = acceptance.report("M20", "local-cpu", root, state)
    write_json(safe_child(state, "evidence/M20.json"), authority)
    if authority["status"] != "pass":
        raise Rejected("isolation_fresh_M20_not_pass")
    destination = safe_child(state, "evidence/kubernetes-storage-qualification.json")
    write_json(destination, {"status": "inconclusive", "reason": "fresh-access-campaign-running"})
    storage = kube_storage_qualification.qualify(root, state, "trusted-mlsecops:dev")
    write_json(destination, storage)


def qualify_access(root, state, image="trusted-mlsecops:dev"):
    root, state = Path(root).resolve(), Path(state)
    attempt = uuid.uuid4().hex
    output = safe_child(state, "evidence/access-qualification.json")
    write_json(output, {"status": "inconclusive", "attempt_id": attempt, "started_at": now()})
    perform_access_checks(root, state)
    cluster = validate_cluster(state)
    storage = kube_storage.validate(state)
    binding = {"source_fingerprint": source_fingerprint(root), "image_id": resolve_image(image)}
    authority_path = safe_child(state, "evidence/authority-qualification.json")
    authority = read_json(authority_path)
    if authority.get("status") != "pass" or any(
        authority.get(key) != value for key, value in binding.items()
    ):
        raise Rejected("isolation_authority_not_current")
    paths = {
        **{
            name: safe_child(state, f"evidence/M20-{name}.json")
            for name in ("isolation", "access", "controller")
        },
        "storage": safe_child(state, "evidence/kubernetes-storage-qualification.json"),
    }
    components = {name: read_json(path) for name, path in paths.items()}
    hashes = {name: digest(bounded_read(path)) for name, path in paths.items()}
    if any(
        hashes[name] != authority.get("artifact_hashes", {}).get(name)
        for name in ("isolation", "access", "controller")
    ):
        raise Rejected("isolation_authority_evidence_changed")
    if (
        components["isolation"]["cluster"]["namespace_uid"] != cluster["namespace_uid"]
        or components["storage"]["volume_uid"] != storage["volume_uid"]
        or any(
            components[name]["dataset_reference"] != authority["dataset_reference"]
            for name in ("access", "controller")
        )
    ):
        raise Rejected("isolation_resource_or_dataset_changed")
    cases = reconcile_access(components, binding)
    result = {
        "schema_version": 1,
        "status": "pass",
        "attempt_id": attempt,
        "scope": "M04-current-owned-lab-identity-and-access",
        "observed_at": now(),
        **binding,
        "cluster_namespace_uid": cluster["namespace_uid"],
        "storage_volume_uid": storage["volume_uid"],
        "dataset_reference": authority["dataset_reference"],
        "cases": cases,
        "checks": len(cases),
        "artifact_hashes": {**hashes, "authority": digest(bounded_read(authority_path))},
        "limitations": [
            "Executes complete M20 and storage native campaigns once per M04 attempt",
            "Host and cluster administrator are trusted; evidence files are operator-controlled",
            "M05 resilience and production release authorization are separate gates",
        ],
    }
    write_json(output, result)
    return result


def qualify_training(root, state, image="trusted-mlsecops:dev"):
    from scripts.isolation_native import qualify

    return qualify(Path(root), Path(state), image)
