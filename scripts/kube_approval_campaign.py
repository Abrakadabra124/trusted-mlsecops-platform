"""Observe positive serving and signed expiry during one serialized owner transfer."""

from mlsecops import kube_promotion
from mlsecops.contracts import Rejected, canonical, digest
from scripts import kube_owned_probe as ownership
from scripts import kube_serving_native as probes
from scripts.kube_approval_fixture import shorten
from scripts.kube_promotion_native import stage
from scripts.kube_promotion_snapshot import read as ledger
from scripts.kube_trust_native import hosted


def qualify(root, state, image, profile, promotion, config, fixture, expected):
    hosted()

    def observe():
        # Suspension is already verified. Keep the original 90 s approval;
        # there is no intermediate Deployment resume between these two Jobs.
        expires = shorten(fixture)
        arguments = fixture.arguments
        request = stage(
            state,
            arguments["package"],
            arguments["policy_envelope"],
            arguments["assurance_envelope"],
            arguments["approval_envelope"],
            arguments["reports"],
        )
        accepted = kube_promotion.invoke(root, state, promotion, request, image)
        receipt = accepted.get("receipt")
        if (
            accepted.get("status") != "recorded-not-activated"
            or not isinstance(receipt, dict)
            or receipt.get("release_ready") is not False
        ):
            raise Rejected("approval_campaign_admission")
        model = digest(fixture.fixture.bundle.materials.fixture.model)
        active = {**expected, "ready": True, "model": model, "bundle": receipt["subject_sha256"]}
        after = ledger(state)
        print(canonical({"stage": "controlled-after-approval"}).decode(), flush=True)
        admitted = probes.invoke(state, profile, config, active)
        print(canonical({"stage": "signed-approval-expiry"}).decode(), flush=True)
        expiry = probes.invoke(state, profile, config, {**active, "expires_at": expires})
        return dict(
            receipt=receipt,
            request=request,
            model=model,
            expected=active,
            after=after,
            admitted=admitted,
            expiry=expiry,
        )

    return ownership.run(state, profile, observe)
