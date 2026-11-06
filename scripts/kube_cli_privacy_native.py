"""Controlled production CLI privacy, kept distinct from the actual candidate."""

import uuid
from contextlib import contextmanager

from mlsecops import (
    audit_snapshot,
    kube_promotion,
    kube_storage,
    kube_trust,
    storage,
    trust_authority,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, safe_child, write_json
from scripts import audit_correlation_probe, promotion_qualification, serving_native
from scripts.kube_cli_privacy_probe import verify_snapshot
from scripts.kube_privacy_services import Windows
from scripts.kube_promotion_native import stage
from scripts.kube_promotion_snapshot import read as snapshot
from scripts.kube_serving_native import invoke
from scripts.kube_trust_native import hosted
from scripts.promotion_entrypoint_native import configuration

CLI_CASES = {
    "initial-worker-absence",
    "admission-denies-command",
    "admission-denies-credential",
    "admission-denies-privilege",
    "RBAC-denies-secrets",
    "RBAC-denies-serviceaccounts",
    "ordinary-CLI-ready-after-verified-load",
    "one-persistent-worker",
    "three-HTTP-predictions",
    "response-model-and-bundle-binding",
    "ONNX-golden-parity",
    "same-worker-UID-across-requests",
    "unauthenticated-401",
    "malformed-422",
    "oversized-413",
    "stopped-worker-503",
    "ordinary-CLI-termination-confirmed",
    "worker-cleanup-confirmed",
    "service-output-allowlisted",
    "audit-journal-created",
}


def primary(state, arguments, receipt):
    def read(reference):
        storage.object_id(reference)
        raw = kube_storage.admin(
            state,
            "SELECT encode(payload,'hex') FROM ml.releases WHERE sha256='"
            + reference
            + "' AND octet_length(payload)<=4194304;",
        )
        if type(raw) is not str or not 1 <= len(raw) <= 8 * 1024 * 1024:
            raise Rejected("cli_privacy_primary_limit")
        content = bytes.fromhex(raw)
        if digest(content) != reference:
            raise Rejected("cli_privacy_primary_digest")
        return decode(content, 4 * 1024 * 1024)

    selection = read(receipt["request_sha256"])
    authorization = read(selection["authorization_reference"])
    if selection["proposal_reference"] != digest(canonical(arguments["package"]["envelope"])):
        raise Rejected("cli_privacy_proposal_changed")
    return audit_correlation_probe.release(
        arguments["package"],
        arguments["context"],
        selection,
        authorization,
        arguments["trusted_root"],
    )


@contextmanager
def controlled(root, state, image, profile):
    hosted()
    fixtures = promotion_qualification.PromotionAdmissionContracts
    fixtures.setUpClass()
    fixture = fixtures()
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
        request = stage(
            state,
            arguments["package"],
            arguments["policy_envelope"],
            arguments["assurance_envelope"],
            arguments["approval_envelope"],
            arguments["reports"],
        )
        accepted = kube_promotion.invoke(root, state, promotion, request, image)
        if accepted["status"] != "recorded-not-activated" or accepted["receipt"] is None:
            raise Rejected("cli_privacy_controlled_approval")
        receipt = accepted["receipt"]
        context = primary(state, arguments, receipt)
        config = {k: v for k, v in promotion.items() if k != "schema_version"}
        config.update(
            minimum_sequence=1,
            audit_directory="/tmp/audit",
            token_file="/tmp/token",
            kubernetes_worker=profile,
        )
        expected = {
            "ready": True,
            "features": features,
            "scores": scores,
            "model": context["model_sha256"],
            "bundle": context["bundle_sha256"],
            "audit_context": context,
        }
        before = snapshot(state)
        destination = safe_child(state, "evidence/cli-privacy/" + uuid.uuid4().hex)
        write_json(destination / "context.json", context)
        services = Windows(state, destination / "services")
        result = invoke(state, profile, config, expected, cli_privacy=True)
        service_windows = services.close(result.pop("_privacy_needles", None))
        # invoke has terminated the CLI/probe and cleaned its owned Kubernetes resources.
        if primary(state, arguments, receipt) != context or snapshot(state) != before:
            raise Rejected("cli_privacy_primary_changed")
        privacy = result["privacy"]
        checked = verify_snapshot(privacy["snapshot"], context, privacy["http"])
        if canonical(checked) != canonical(privacy["audit"]):
            raise Rejected("cli_privacy_receipt_changed")
        packet = canonical(privacy)
        audit_snapshot.store_packet(destination / "closed-window", packet)
        retained = audit_snapshot.load_packet(destination / "closed-window")
        if retained != packet:
            raise Rejected("cli_privacy_retained_bytes")
        reloaded = decode(retained, 2 * 1024 * 1024)
        if verify_snapshot(reloaded["snapshot"], context, reloaded["http"]) != checked:
            raise Rejected("cli_privacy_retained_result")
        report = {
            "status": "pass",
            "scope": "controlled-ordinary-cli-privacy-not-full-M13",
            "release_ready": False,
            "full_M13": "inconclusive",
            "model_sha256": expected["model"],
            "subject_sha256": expected["bundle"],
            "native": result,
            "post_cleanup_primary_reverified": True,
            "retained_snapshot_reverified": True,
            "independent_admission_observed": False,
            "service_windows": service_windows,
            "privacy_campaign_id": destination.name,
        }
        write_json(destination / "report.json", report)
        yield report, fixture.trust_fixture.key
    finally:
        fixture.doCleanups()
        fixtures.tearDownClass()
