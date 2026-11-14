"""Stable A for hosted T19 lab traffic, using controlled signed approval fixtures."""

import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from mlsecops import (
    promotion_state,
    release_authorization,
    release_reader,
    serving,
    trust,
    trust_authority,
)
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import validate_features
from mlsecops.load_golden import Golden
from mlsecops.sandbox import resolve_image
from mlsecops.storage import object_id
from scripts import promotion_entrypoint_native
from scripts.kube_rollback_native import variant
from scripts.promotion_qualification import PromotionAdmissionContracts
from scripts.release_reader_native import disposable


def _check_head(reader, binding, expires):
    # load() authenticates the current SQL head, event, CAS materials and approval
    # at the current clock. The CAS selection also ties the proposal to the head.
    loaded = reader.load()
    record = release_reader.document(reader.client, loaded.request_sha256, 65536)
    if (
        loaded.sequence != binding["sequence"]
        or loaded.request_sha256 != binding["request_sha256"]
        or loaded.subject_sha256 != binding["subject_sha256"]
        or loaded.model_sha256 != binding["model_sha256"]
        or digest(loaded.model) != binding["model_sha256"]
        or loaded.expires_at != expires
        or record["proposal_reference"] != binding["proposal_reference"]
    ):
        raise Rejected("canary_stable_head_changed")
    reader.check(loaded)


@contextmanager
def stable_release(root, state, image, campaign, features):
    """Yield an inactive Engine, independent Golden and the five public binding fields.

    The caller must nest its HTTP lifespan inside this context. The signed positive
    reports and approval authorize only this synthetic fixture in disposable stores.
    """
    promotion_entrypoint_native.hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    if (
        not isinstance(campaign, str)
        or not campaign
        or Path(campaign).name != campaign
        or "/" in campaign
        or "\\" in campaign
    ):
        raise Rejected("canary_stable_campaign")
    validate_features(features, max_rows=1)
    features = [features[0].copy()]
    image = resolve_image(image)
    with (
        disposable(root, state, campaign, "models", 15444) as models,
        disposable(root, state, campaign, "trust", 15445) as authority,
        ExitStack() as cleanups,
    ):
        PromotionAdmissionContracts.setUpClass()
        cleanups.callback(PromotionAdmissionContracts.tearDownClass)
        fixture = PromotionAdmissionContracts()

        def clean_fixture():
            if not fixture.doCleanups():
                raise Rejected("canary_stable_fixture_cleanup")

        cleanups.callback(clean_fixture)
        fixture.setUp()
        model, scores = variant(fixture, image, features)
        args = fixture.arguments
        policy = args["expected_policy"]
        public = fixture.trust_fixture.public
        promotion_state.install(models)
        promotion_state.configure(models, "local-cpu", policy)
        trust_authority.install(authority, "local-cpu", public)
        trust_authority.update(authority, policy, fixture.trust_fixture.key)

        decision = release_authorization.verify(**args, clock=int(time.time()))
        proposal = digest(canonical(args["package"]["envelope"]))
        golden = Golden.from_expected(
            dict(features=features, scores=scores, model=model, bundle=decision["subject_sha256"])
        )
        receipt = promotion_entrypoint_native.controlled(root, models, authority, args, public)
        if (
            receipt["state"] != "recorded-not-activated"
            or receipt["release_ready"] is not False
            or receipt["environment"] != "local-cpu"
            or type(receipt["sequence"]) is not int
            or receipt["sequence"] != decision["sequence"]
            or receipt["sequence"] != 1
            or receipt["subject_sha256"] != golden.bundle
            or receipt["proposal_reference"] != proposal
        ):
            raise Rejected("canary_stable_receipt")
        binding = dict(
            subject_sha256=golden.bundle,
            model_sha256=golden.model,
            request_sha256=object_id(receipt["request_sha256"]),
            sequence=receipt["sequence"],
            proposal_reference=proposal,
        )

        trust_client = authority / "storage-clients/serving"
        lease = trust.Lease(
            lambda: trust_authority.read(trust_client, "local-cpu", public),
            trusted_root=public,
            environment="local-cpu",
            minimum_version=1,
        )
        reader = release_reader.Reader(
            models / "storage-clients/serving",
            context=args["context"],
            trusted_root=args["trusted_root"],
            expected_policy=policy,
            expected_serving_image=image,
            trust_lease=lease,
            minimum_sequence=1,
        )
        engine = serving.Engine(reader)
        _check_head(reader, binding, decision["expires_at"])
        try:
            yield engine, golden, binding.copy()
        finally:
            _check_head(reader, binding, decision["expires_at"])
