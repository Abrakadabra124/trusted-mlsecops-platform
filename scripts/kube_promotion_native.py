"""Actual candidate refusal and separately labelled controlled admission in scoped Jobs."""

import sys
from contextlib import suppress
from pathlib import Path

from mlsecops import (
    kube_promotion,
    kube_storage,
    kube_trust,
    promotion_controller,
    release_bundle,
    release_policy,
    storage,
    storage_bootstrap,
    trust_authority,
)
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, safe_child, write_json
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.private_cli import Arguments
from mlsecops.sandbox import resolve_image
from mlsecops.storage_schema import MAX_BYTES
from scripts import promotion_qualification as fixtures
from scripts import release_native, serving_native
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS
from scripts.kube_trust_native import hosted
from scripts.promotion_entrypoint_native import configuration


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


def actual(root, state, image):
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
    local = configuration(client, client, arguments, public["trust"])
    reference = storage.put(client, "releases", canonical(envelope))
    request = {
        "schema_version": 1,
        "proposal_reference": proposal["proposal_reference"],
        "policy_reference": reference,
        "assurance_reference": None,
        "approval_reference": None,
    }
    try:
        promotion_controller.submit(local, request)
    except Rejected as error:
        if str(error) != "release_assurance_required":
            raise Rejected("kube_promotion_actual_wrong_refusal") from None
    else:
        raise Rejected("kube_promotion_actual_bypass")
    if stage(state, package, envelope) != request:
        raise Rejected("kube_promotion_actual_reference_changed")
    config = {**local, "storage_client": "/client", "trust_client": "/trust-client"}
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


def controlled(root, state, image):
    fixtures.PromotionAdmissionContracts.setUpClass()
    fixture = fixtures.PromotionAdmissionContracts()
    try:
        fixture.setUp()
        serving_native.bind_real_runtime(fixture, resolve_image(image))
        arguments = fixture.arguments
        config = {
            **configuration("/client", "/trust-client", arguments, fixture.trust_fixture.public),
            "storage_client": "/client",
            "trust_client": "/trust-client",
        }
        kube_promotion.configure(state, config)
        trust_authority.install(
            state, "local-cpu", fixture.trust_fixture.public, backend=kube_trust.binding
        )
        trust_authority.update(
            state, config["expected_policy"], fixture.trust_fixture.key, backend=kube_trust.binding
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
        confirmed("controlled-initial-head-zero", head(state) == "0:")
        denied = kube_promotion.invoke(
            root, state, config, {**request, "approval_reference": None}, image
        )
        confirmed("controlled-missing-approval-refused", denied["status"] == "rejected")
        confirmed(
            "controlled-missing-approval-no-write", ledger(state) == before and head(state) == "0:"
        )
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
        repeated = kube_promotion.invoke(root, state, config, request, image)
        confirmed("controlled-exact-retry-same-receipt", repeated["receipt"] == receipt)
        confirmed(
            "controlled-exact-retry-no-new-objects-or-sequence",
            ledger(state) == after and head(state) == "1:" + receipt["request_sha256"],
        )
        model = digest(fixture.fixture.bundle.materials.fixture.model)
        trust_authority.update(
            state,
            config["expected_policy"],
            fixture.trust_fixture.key,
            revoked_artifacts=[model],
            backend=kube_trust.binding,
        )
        revoked = kube_promotion.invoke(root, state, config, request, image)
        confirmed("controlled-revoked-repeat-refused", revoked["status"] == "rejected")
        confirmed(
            "controlled-revoked-repeat-no-new-objects-or-sequence",
            ledger(state) == after and head(state) == "1:" + receipt["request_sha256"],
        )
        return {
            "cases": cases,
            "model": model,
            "request_sha256": receipt["request_sha256"],
            "image_id": accepted["execution"]["image_id"],
        }
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
    actual_outcome = actual(root, state, image)
    checked = controlled(root, state, image)
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
        "cases": [
            "actual-parent-missing-assurance",
            "actual-isolated-CLI-refusal",
            "actual-refusal-no-write",
            *checked["cases"],
            "source-unchanged",
        ],
        "limitations": [
            "Controlled positive approvals are not actual candidate acceptance",
            "Serving runtime/HTTP in Kubernetes and full M10-M13/M19 remain required",
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
