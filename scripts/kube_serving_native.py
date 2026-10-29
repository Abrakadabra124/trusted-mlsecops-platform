"""Hosted normal serving CLI with separate worker, real API, SQL and trust."""

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
    trust_authority,
)
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest, now, safe_child, write_json
from mlsecops.controller_resources import mount_api
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from mlsecops.private_cli import Arguments
from mlsecops.storage_pki import workspace_id
from scripts import promotion_qualification as fixtures
from scripts import serving_native
from scripts.kube_promotion_native import actual, stage
from scripts.kube_trust_native import hosted
from scripts.promotion_entrypoint_native import configuration

NAMESPACE = "ml-serving"


def invoke(state, profile, config, expected):
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
    spec["containers"][0]["command"][2] = "mlsecops.kube_serving_probe"
    spec["containers"][0]["resources"]["limits"]["memory"] = "1Gi"
    spec["containers"][0]["resources"]["requests"]["memory"] = "256Mi"
    mount_api(spec)
    job = job_document(name, NAMESPACE, spec, 240)
    job["metadata"]["labels"]["trusted-mlsecops/workspace"] = workspace_id(state)
    created = []
    try:
        for document in [*maps, job]:
            observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
            uid = observed["metadata"]["uid"]
            created.append((document, uid))
            kube_storage.verify_resource(document, observed, uid)
        terminal, pod, elapsed = wait_job(state, NAMESPACE, name, 240)
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
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if (
            terminal["type"] != "Complete"
            or len(statuses) != 1
            or statuses[0].get("state", {}).get("terminated", {}).get("exitCode") != 0
        ):
            failure = {"probe_failure": "unclassified", "release_ready": False}
            with suppress(Rejected):
                document = decode(raw, 65536)
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
        report = decode(raw, 65536)
        if report.get("status") != "pass" or report.get("release_ready") is not False:
            raise Rejected("kube_serving_probe_report")
        return {**report, "elapsed_seconds": elapsed}
    finally:
        kube_promotion.cleanup(state, created, namespace=NAMESPACE)


def qualify(root, state, image):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    kube_storage.validate(state)
    kube_trust.bootstrap(state)
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("kube_serving_dirty_source")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint, started = source_fingerprint(root), now()
    print(canonical({"stage": "serving-api-bootstrap"}).decode(), flush=True)
    profile = controller_bootstrap.bootstrap(root, state, image, serving=True)["profile"]
    print(canonical({"stage": "actual-candidate-refusal"}).decode(), flush=True)
    actual_result = actual(root, state, image)
    fixtures.PromotionAdmissionContracts.setUpClass()
    fixture = fixtures.PromotionAdmissionContracts()
    try:
        fixture.setUp()
        features, scores = serving_native.bind_real_runtime(fixture, profile["image_id"])
        arguments = fixture.arguments
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
        trust_authority.update(
            state,
            promotion["expected_policy"],
            fixture.trust_fixture.key,
            revoked_artifacts=[model],
            backend=kube_trust.binding,
        )
        print(canonical({"stage": "controlled-after-revocation"}).decode(), flush=True)
        revoked = invoke(state, profile, config, {**expected, "ready": False})
        if (
            ledger(state) != after
            or source_fingerprint(root) != fingerprint
            or command(["git", "-C", str(root), "status", "--porcelain"])
        ):
            raise Rejected("kube_serving_source_or_ledger_changed")
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
        report = qualify(Path(__file__).resolve().parents[1], options.state, options.image)
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
