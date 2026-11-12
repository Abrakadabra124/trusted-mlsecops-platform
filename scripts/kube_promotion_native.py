"""Actual candidate refusal and separately labelled controlled admission in scoped Jobs."""

import sys
from contextlib import suppress
from pathlib import Path

from mlsecops import (
    controller_bootstrap,
    kube_promotion,
    kube_security_events,
    kube_storage,
    kube_trust,
    promotion_controller,
    release_bundle,
    release_policy,
    signing,
    storage,
    storage_bootstrap,
    trust_authority,
)
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, safe_child, write_json
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.private_cli import Arguments
from mlsecops.sandbox import resolve_image
from mlsecops.storage_pki import workspace_id
from mlsecops.storage_schema import MAX_BYTES
from scripts import (
    kube_security_native,
    release_native,
    security_event_audit_fixture,
    serving_native,
)
from scripts import promotion_qualification as fixtures
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS
from scripts.kube_trust_native import hosted
from scripts.promotion_entrypoint_native import configuration as host_configuration


def configuration(client, trust_client, arguments, trust_root):
    if client != "/client" or trust_client != "/trust-client":
        raise Rejected("kube_promotion_fixture_paths")
    return {
        "schema_version": 2,
        "storage_client": client,
        "trust_client": trust_client,
        "security_audit_config": "/security/audit.json",
        "trust_root": trust_root,
        "minimum_trust_version": 1,
        **{
            key: arguments[key]
            for key in ("context", "trusted_root", "expected_policy", "expected_serving_image")
        },
    }


def initialize_audit(root, state, image, initial_root):
    return kube_security_events.bootstrap(
        root,
        state,
        environment="local-cpu",
        initial_root=initial_root,
        policy=digest(
            canonical(
                {
                    "schema_version": 1,
                    "profile": "kubernetes-security-events",
                    "workspace": workspace_id(state),
                }
            )
        ),
        image=image,
    )


def campaign_authority(state):
    # The operator workspace already owns this role; never replace a missing key.
    key = safe_child(state, "keys/trust.pem")
    public = signing.encode64(signing.load_key(key).public_key().public_bytes_raw())
    if read_json(safe_child(state, "trusted-keys.json"))["trust"] != public:
        raise Rejected("kube_campaign_authority_pin")
    return key, public


def initialize_campaign(root, state, image):
    hosted()
    key, public = campaign_authority(state)
    trust_authority.install(state, "local-cpu", public, backend=kube_trust.binding)
    _, current = trust_authority.current(state, backend=kube_trust.binding)
    if current["envelope"] is None:
        # An explicit empty campaign identity, not a model approval or permit.
        seed = digest(canonical({"phase": "unapproved-campaign", "workspace": workspace_id(state)}))
        trust_authority.update(state, seed, key, backend=kube_trust.binding)
    initialize_audit(root, state, image, public)
    return key, public


def stage(state, package, policy, assurance=None, approval=None, reports=None):
    values = [
        *package["capsule"]["objects"].values(),
        canonical(package["capsule"]["envelope"]),
        *package["documents"].values(),
        canonical(package["envelope"]),
        canonical(policy),
        *(canonical(v) for v in (assurance, approval) if v is not None),
        *(reports or {}).values(),
    ]
    if (
        any(not isinstance(value, bytes) or not 0 < len(value) <= MAX_BYTES for value in values)
        or sum(map(len, values)) > 64 * 1024 * 1024
    ):
        raise Rejected("kube_promotion_stage_limit")
    for value in values:
        reference = digest(value)
        observed = kube_storage.admin(
            state,
            f"INSERT INTO ml.releases (sha256,payload) VALUES ('{reference}',decode('{value.hex()}','hex')) ON CONFLICT DO NOTHING; SELECT encode(sha256(payload),'hex') || ':' || octet_length(payload) FROM ml.releases WHERE sha256='{reference}';",
        )
        if observed != f"{reference}:{len(value)}":
            raise Rejected("kube_promotion_stage_readback")
    return {
        "schema_version": 1,
        "proposal_reference": digest(canonical(package["envelope"])),
        "policy_reference": digest(canonical(policy)),
        "assurance_reference": None if assurance is None else digest(canonical(assurance)),
        "approval_reference": None if approval is None else digest(canonical(approval)),
    }


def actual(root, state, image, *, authority_root=None):
    proposal = release_native.qualify(root, state, image)
    campaign = safe_child(state, "release-proposals/" + proposal["campaign_id"])
    envelope = read_json(campaign / "policy-envelope.json")
    demo, public = (read_json(state / n) for n in ("storage-demo.json", "trusted-keys.json"))
    policy = release_policy.checked(envelope, "promotion-policy", public["trust"])
    package = release_bundle.load(
        state / "storage-clients/promoter",
        proposal["proposal_reference"],
        publisher_public=policy["identities"]["publisher"]["public_key"],
    )
    context = {
        "candidate_reference": demo["candidate"]["candidate_reference"],
        "evaluation_reference": demo["evaluation_reference"],
        "policy": read_json(root / "policies/local-cpu.json"),
        "trust": read_json(state / "storage-trust.json"),
        "expected": proposal["source"],
        "owners": OWNERS,
        "known_owners": KNOWN_OWNERS,
    }
    client = state / "storage-clients/promoter"
    arguments = {
        "context": context,
        "trusted_root": public["trust"],
        "expected_policy": proposal["policy_sha256"],
        "expected_serving_image": proposal["source"]["image_id"],
    }
    reference = storage.put(client, "releases", canonical(envelope))
    request = {
        "schema_version": 1,
        "proposal_reference": proposal["proposal_reference"],
        "policy_reference": reference,
        "assurance_reference": None,
        "approval_reference": None,
    }
    with security_event_audit_fixture.live() as audit:
        local = host_configuration(client, client, arguments, public["trust"], audit.audit_config)
        try:
            promotion_controller.submit(local, request)
        except Rejected as error:
            if str(error) != "release_assurance_required":
                raise Rejected("kube_promotion_actual_wrong_refusal") from None
        else:
            raise Rejected("kube_promotion_actual_bypass")
    if stage(state, package, envelope) != request:
        raise Rejected("kube_promotion_actual_reference_changed")
    if authority_root is None:
        authority_root = kube_security_events.validate(state)["context"]["initial_root"]
    config = configuration("/client", "/trust-client", arguments, authority_root)
    before = ledger(state)
    result = kube_promotion.invoke(root, state, config, request, image)
    if result["status"] != "rejected" or ledger(state) != before:
        raise Rejected("kube_promotion_actual_refusal_changed_storage")
    return {
        "campaign_id": proposal["campaign_id"],
        "candidate": context["candidate_reference"],
        "proposal": proposal["proposal_reference"],
        "model": proposal["model_sha256"],
        "parent_refusal": "release_assurance_required",
        "job_outcome": result["status"],
    }


def head(state):
    return kube_storage.admin(
        state,
        "SELECT sequence || ':' || coalesce(request_sha256,'') FROM ml_promotion.heads WHERE environment='local-cpu';",
    )


def controlled(root, state, image, *, check_actual=False):
    # Local import: the ordinary serving harness also uses preparation helpers here.
    from mlsecops import kube_serving_service
    from scripts import kube_serving_service_native as serving_service

    fixtures.PromotionAdmissionContracts.setUpClass()
    fixture = fixtures.PromotionAdmissionContracts()
    service_started = False
    service_report = None
    try:
        fixture.setUp()
        features, scores = serving_native.bind_real_runtime(fixture, resolve_image(image))
        arguments = fixture.arguments
        authority_key, authority_public = initialize_campaign(root, state, image)
        config = {
            **configuration("/client", "/trust-client", arguments, authority_public),
            "storage_client": "/client",
            "trust_client": "/trust-client",
        }
        trust_authority.update(
            state, config["expected_policy"], authority_key, backend=kube_trust.binding
        )
        _, campaign_before = trust_authority.current(state, backend=kube_trust.binding)
        repeated_authority = initialize_campaign(root, state, image)
        _, campaign_after = trust_authority.current(state, backend=kube_trust.binding)
        campaign_unchanged = repeated_authority == (authority_key, authority_public) and all(
            campaign_before[field] == campaign_after[field]
            for field in ("environment", "root_public", "version", "sha256", "envelope")
        )
        if not campaign_unchanged:
            raise Rejected("kube_campaign_repeat_changed_trust")
        kube_promotion.configure(state, config)
        actual_result = (
            actual(root, state, image, authority_root=authority_public) if check_actual else None
        )
        request = stage(
            state,
            arguments["package"],
            arguments["policy_envelope"],
            arguments["assurance_envelope"],
            arguments["approval_envelope"],
            arguments["reports"],
        )
        cases = []

        def confirmed(label, condition):
            if not condition:
                raise Rejected("kube_promotion_controlled_case:" + label)
            cases.append(label)
            print(canonical({"case": label, "status": "pass"}).decode(), flush=True)

        before = ledger(state)
        confirmed("campaign-repeat-keeps-authority-policy-and-history", campaign_unchanged)
        confirmed("controlled-initial-head-zero", head(state) == "0:")
        denied = kube_promotion.invoke(
            root, state, config, {**request, "approval_reference": None}, image
        )
        confirmed("controlled-missing-approval-refused", denied["status"] == "rejected")
        confirmed(
            "controlled-missing-approval-no-write", ledger(state) == before and head(state) == "0:"
        )
        audit_proof = kube_security_native.qualify(root, state, config, request, image)
        serving_profile = controller_bootstrap.bootstrap(root, state, image, serving=True)[
            "profile"
        ]
        kube_serving_service.bootstrap(state, serving_profile, config)
        service_started = True
        expected = {"ready": False, "features": features, "scores": scores}
        serving_before = serving_service.observe(state, expected)
        confirmed("controlled-unapproved-http-refuses-without-write", ledger(state) == before)
        accepted = kube_promotion.invoke(root, state, config, request, image)
        receipt = accepted["receipt"]
        confirmed(
            "controlled-job-recorded-not-activated",
            accepted["status"] == "recorded-not-activated" and receipt["release_ready"] is False,
        )
        confirmed(
            "controlled-independent-SQL-head-readback",
            head(state) == "1:" + receipt["request_sha256"],
        )
        after = ledger(state)
        unactivated = serving_service.observe(state, expected)
        confirmed(
            "same-http-pod-remains-unready-until-explicit-replacement",
            unactivated["pod_uid"] == serving_before["pod_uid"],
        )
        replacement = serving_service.replace(state)
        before_identity = serving_service.snapshot(state)
        model = digest(fixture.fixture.bundle.materials.fixture.model)
        serving_active = serving_service.observe(
            state,
            {**expected, "ready": True, "model": model, "bundle": receipt["subject_sha256"]},
        )
        confirmed("controlled-admitted-http-onnx-inference-without-write", ledger(state) == after)
        after_identity = serving_service.snapshot(state)
        marker = kube_security_events.validate(state, profile=serving_profile)
        identity_count = kube_security_native.identity_receipts(
            before_identity,
            after_identity,
            kube_security_native.collector(state, marker),
        )
        confirmed("controlled-http-denial-has-independent-collector-receipt", identity_count > 0)
        ownership_transfer = serving_service.handoff(
            state,
            serving_profile,
            config,
            {**expected, "ready": True, "model": model, "bundle": receipt["subject_sha256"]},
        )
        confirmed("controlled-http-owner-transfer-preserves-model-ledger", ledger(state) == after)
        incompatible = serving_service.change_configuration(
            state,
            {**config, "expected_policy": digest(b"controlled-other-serving-policy")},
            {**expected, "reader_refusal": "serving_head_binding"},
        )
        restored_configuration = serving_service.change_configuration(
            state,
            config,
            {**expected, "ready": True, "model": model, "bundle": receipt["subject_sha256"]},
        )
        confirmed(
            "controlled-configuration-roundtrip-preserves-model-ledger", ledger(state) == after
        )
        repeated = kube_promotion.invoke(root, state, config, request, image)
        confirmed("controlled-exact-retry-same-receipt", repeated["receipt"] == receipt)
        confirmed(
            "controlled-exact-retry-no-new-objects-or-sequence",
            ledger(state) == after and head(state) == "1:" + receipt["request_sha256"],
        )
        trust_authority.update(
            state,
            config["expected_policy"],
            authority_key,
            revoked_artifacts=[model],
            backend=kube_trust.binding,
        )
        revoked = kube_promotion.invoke(root, state, config, request, image)
        confirmed("controlled-revoked-repeat-refused", revoked["status"] == "rejected")
        confirmed(
            "controlled-revoked-repeat-no-new-objects-or-sequence",
            ledger(state) == after and head(state) == "1:" + receipt["request_sha256"],
        )
        serving_revoked = serving_service.observe(
            state,
            {**expected, "reader_refusal": "trust_artifact_revoked", "worker_absent": False},
        )
        confirmed(
            "controlled-revoked-http-refuses-in-same-pod-without-write",
            ledger(state) == after
            and serving_revoked["pod_uid"] == restored_configuration["observation"]["pod_uid"],
        )
        service_report = {
            "before_admission": serving_before,
            "after_selection_before_replacement": unactivated,
            "after_admission": serving_active,
            "after_revocation": serving_revoked,
            "replacement": replacement,
            "ownership_transfer": ownership_transfer,
            "configuration_change": {
                "incompatible": incompatible,
                "restored": restored_configuration,
            },
            "identity_events_delivered": identity_count,
            "single_owner_lifecycle": True,
            "mandatory_serving_heartbeat": False,
            "release_ready": False,
        }
        return {
            "actual": actual_result,
            "audit": audit_proof,
            "cases": cases,
            "model": model,
            "request_sha256": receipt["request_sha256"],
            "image_id": accepted["execution"]["image_id"],
            "serving": service_report,
        }
    finally:
        try:
            if service_started:
                cleanup = kube_serving_service.stop(state)
                if service_report is not None:
                    service_report["cleanup"] = cleanup
        finally:
            fixture.doCleanups()
            fixtures.PromotionAdmissionContracts.tearDownClass()


def qualify(root, state, image):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    source = storage_bootstrap.validate(state)
    kube_storage.validate(state)
    kube_trust.bootstrap(state)
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("kube_promotion_native_dirty_source")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint, started = source_fingerprint(root), now()
    checked = controlled(root, state, image, check_actual=True)
    actual_outcome = checked.pop("actual")
    from scripts import kube_observer_rotation_native

    observer_rotation = kube_observer_rotation_native.qualify(state, campaign_authority(state)[0])
    if (
        storage_bootstrap.validate(state)["container_id"] != source["container_id"]
        or source_fingerprint(root) != fingerprint
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != revision
        or command(["git", "-C", str(root), "status", "--porcelain"])
    ):
        raise Rejected("kube_promotion_native_source_changed")
    return {
        "schema_version": 1,
        "scope": "isolated-promotion-CLI-actual-refusal-controlled-positive-not-full-M10",
        "status": "pass",
        "full_M10": "inconclusive",
        "release_ready": False,
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "source_dirty": False,
        "started_at": started,
        "finished_at": now(),
        "actual": actual_outcome,
        "controlled": checked,
        "observer_rotation": observer_rotation,
        "cases": [
            "actual-parent-missing-assurance",
            "actual-isolated-CLI-refusal",
            "actual-refusal-no-write",
            *checked["cases"],
            "source-unchanged",
        ],
        "limitations": [
            "Controlled positive approvals are not actual candidate acceptance",
            "Owned HTTP Deployment uses explicit Pod replacement; globally mandatory serving heartbeat remains required",
            "Actual candidate admission and full M10-M13/M19 remain required",
            "System image inventory/findings and M22 independent challenges remain blocking",
        ],
    }


def main(arguments=None):
    output = None
    try:
        hosted()
        parser = Arguments(prog="isolated-promotion-native")
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--image", default="trusted-mlsecops:dev")
        options = parser.parse_args(arguments)
        storage_bootstrap.validate(options.state)
        output = safe_child(options.state, "evidence/kubernetes-promotion.json")
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
        print("kubernetes_promotion_native_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
