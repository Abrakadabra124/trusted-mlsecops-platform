"""Hosted-only integration of the separate authority and restricted trust readers."""

import os
import sys
import uuid
from contextlib import suppress
from pathlib import Path

from mlsecops import kube_storage, kube_trust, trust_authority
from mlsecops.cluster import kubectl
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.controller_bootstrap import image_profile
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.kube_storage_qualification import probe as network_probe
from mlsecops.kube_storage_resources import WORKSPACE
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from mlsecops.private_cli import Arguments
from mlsecops.storage_pki import workspace_id


def hosted():
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("trust_hosted_runner_required")


def reader(state, profile, role, public, policy, version, revoked=(), *, unavailable=False):
    name, namespace = "trust-reader-" + uuid.uuid4().hex, f"ml-{role}"
    arguments = [
        "mlsecops.kube_trust_probe",
        "--role",
        role,
        "--root",
        public,
        "--policy",
        policy,
        "--version",
        str(version),
    ]
    for reference in revoked:
        arguments.extend(["--revoked", reference])
    if unavailable:
        arguments.append("--unavailable")
    spec = kube_trust.client_spec(profile["image"], role, arguments)
    document = job_document(name, namespace, spec, 90)
    document["metadata"]["labels"][WORKSPACE] = workspace_id(state)
    created = None
    try:
        created = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
        kube_storage.verify_resource(document, created, created["metadata"]["uid"])
        terminal, pod, _ = wait_job(state, namespace, name, 90)
        verify_running_image(pod, profile["image_id"])
        if (
            not kube_storage.matches(spec, pod["spec"])
            or pod["spec"].get("ephemeralContainers")
            or pod["metadata"]["ownerReferences"][0]["uid"] != created["metadata"]["uid"]
        ):
            raise Rejected("trust_reader_pod_boundary_changed")
        output = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-c",
                "worker",
                "-n",
                namespace,
                "--limit-bytes=65537",
            ],
        ).stdout
        if terminal["type"] != "Complete":
            raise Rejected("trust_reader_job_failed")
        result = decode(output, 65536)
        if (
            result.get("status") != "pass"
            or result.get("role") != role
            or result.get("release_ready") is not False
            or not result.get("cases")
        ):
            raise Rejected("trust_reader_report_invalid")
        return result
    finally:
        if created is not None:
            kube_storage.verify_resource(
                document, kube_storage.get(state, document), created["metadata"]["uid"]
            )
            kubectl(state, ["delete", "job", name, "-n", namespace, "--wait=true", "--timeout=30s"])
            if kube_storage.get(state, document) is not None:
                raise Rejected("trust_reader_cleanup_incomplete")


def scale(state, document, uid, replicas):
    observed = kube_storage.get(state, document)
    expected = {**document, "spec": {**document["spec"], "replicas": 1 - replicas}}
    kube_storage.verify_resource(expected, observed, uid)
    kubectl(
        state,
        ["scale", "statefulset/postgres", "-n", kube_trust.NAMESPACE, f"--replicas={replicas}"],
    )


def qualify(root, state, image):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("trust_native_dirty_source")
    started = now()
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    kube_storage.validate(state)
    source_ledger = ledger(state)
    first = kube_trust.bootstrap(state)
    marker = kube_trust.validate(state)
    if (
        kube_trust.bootstrap(state) != first
        or kube_trust.validate(state)["volume_uid"] != marker["volume_uid"]
    ):
        raise Rejected("trust_bootstrap_not_idempotent")
    model_ca = read_json(state / "kubernetes-storage/storage-pki/identity.json")["certificates"][
        "ca"
    ]
    trust_ca = read_json(state / "kubernetes-trust/storage-pki/identity.json")["certificates"]["ca"]
    if model_ca == trust_ca:
        raise Rejected("trust_shared_model_ca")
    profile = image_profile(root, state, image)
    public = read_json(state / "trusted-keys.json")["trust"]
    policy = digest(canonical(read_json(root / "policies/local-cpu.json")))
    key = state / "keys/trust.pem"
    migration = trust_authority.install(state, "local-cpu", public, backend=kube_trust.binding)
    if trust_authority.install(state, "local-cpu", public, backend=kube_trust.binding) != migration:
        raise Rejected("trust_install_not_idempotent")
    trust_authority.update(state, policy, key, backend=kube_trust.binding)
    _, current = trust_authority.current(state, backend=kube_trust.binding)
    if not trust_authority.publish(state, current["envelope"], backend=kube_trust.binding)[
        "reused"
    ]:
        raise Rejected("trust_publication_not_idempotent")
    cases = [
        "bootstrap-idempotent",
        "independent-model-and-trust-CAs",
        "migration-idempotent",
        "publication-exact-retry",
    ]

    def confirmed(label, condition=True):
        if not condition:
            raise Rejected("trust_native_case_failed:" + label)
        cases.append(label)
        print(canonical({"case": label, "status": "pass"}).decode(), flush=True)

    def check_reader(role, version, revoked=(), *, unavailable=False):
        result = reader(
            state, profile, role, public, policy, version, revoked, unavailable=unavailable
        )
        for label in result["cases"]:
            confirmed(f"{role}-v{version}:{label}")

    check_reader("promoter", 1)
    check_reader("serving", 1)
    service = kube_storage.get(
        state,
        {"kind": "Service", "metadata": {"name": "postgres", "namespace": kube_trust.NAMESPACE}},
    )
    for namespace, role in (
        ("ml-train", "trainer"),
        ("ml-eval", "evaluator"),
        ("ml-publisher", "publisher"),
        ("ml-scorer", "scorer"),
        ("ml-ingestor", "ingestor"),
        ("ml-curator", "curator"),
    ):
        outcome = network_probe(
            state,
            profile["image"],
            profile["image_id"],
            namespace,
            role,
            "network",
            service["spec"]["clusterIP"],
        )
        confirmed(f"{role}:trust-network-denied", outcome == {"result": "timeout"})
    reference = digest(b"controlled-revocation-not-a-release-approval")
    update = trust_authority.update(
        state, policy, key, revoked_artifacts=[reference], backend=kube_trust.binding
    )
    confirmed("signed-revocation-version-2", update["version"] == 2)
    check_reader("serving", 2, [reference])
    document = next(d for d in kube_trust.desired(state) if d["kind"] == "StatefulSet")
    uid = marker["resources"][kube_storage.reference(document)]
    # Restore only the same owned StatefulSet, even when the outage probe fails.
    try:
        scale(state, document, uid, 0)
        kubectl(
            state,
            ["wait", "--for=delete", "pod/postgres-0", "-n", kube_trust.NAMESPACE, "--timeout=60s"],
            timeout=75,
        )
        check_reader("promoter", 2, [reference], unavailable=True)
    finally:
        observed = kube_storage.get(state, document)
        if (observed or {}).get("spec", {}).get("replicas") == 0:
            scale(state, document, uid, 1)
            kubectl(
                state,
                [
                    "rollout",
                    "status",
                    "statefulset/postgres",
                    "-n",
                    kube_trust.NAMESPACE,
                    "--timeout=180s",
                ],
                timeout=210,
            )
    confirmed(
        "authority-restored-same-volume",
        kube_trust.validate(state)["volume_uid"] == marker["volume_uid"],
    )
    check_reader("promoter", 2, [reference])
    confirmed("model-storage-unchanged", ledger(state) == source_ledger)
    confirmed(
        "source-unchanged",
        source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return {
        "schema_version": 1,
        "scope": "kubernetes-trust-service-and-isolated-readers-not-full-M10-M11",
        "status": "pass",
        "release_ready": False,
        "full_M10": "inconclusive",
        "full_M11": "inconclusive",
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "source_dirty": False,
        "image": profile,
        "storage_image": first["image"],
        "cases": cases,
        "limitations": [
            "Controlled authority policy and revocation; not actual candidate approval",
            "Promotion CLI and serving deployment must still consume this isolated authority",
            "Single-node lab; no HA, full lease or M17 recovery acceptance",
        ],
    }


def main(arguments=None):
    output = None
    try:
        hosted()
        parser = Arguments(prog="kubernetes-trust-native")
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--image", default="trusted-mlsecops:dev")
        options = parser.parse_args(arguments)
        kube_storage.validate(options.state)
        output = safe_child(options.state, "evidence/kubernetes-trust.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        result = qualify(Path(__file__).resolve().parents[1], options.state, options.image)
        write_json(output, result)
        print(canonical(result).decode())
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
        print("kubernetes_trust_native_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
