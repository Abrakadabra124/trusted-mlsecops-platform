"""Hosted T19 traffic on the original evaluated candidate under a disposable qualification permit."""

import math
import re
import time
from contextlib import contextmanager
from dataclasses import asdict
from functools import partial
from pathlib import Path
from threading import Lock

from mlsecops import (
    audit_lineage,
    release_authorization,
    release_bundle,
    release_policy,
    sandbox,
    serving,
    signing,
    storage_bootstrap,
    storage_restore,
    trust,
    trust_authority,
)
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    safe_child,
    write_json,
)
from mlsecops.datasets import validate_features
from mlsecops.load_golden import Golden
from mlsecops.prediction_protocol import PredictionBatch
from scripts.candidate_serving_reader import KIND, CandidateReader, bind_proposal
from scripts.promotion_entrypoint_native import hosted
from scripts.release_reader_native import disposable
from scripts.serving_output_native import source


@contextmanager
def _must_deny(reason):
    try:
        yield
    except Rejected as error:
        if str(error) != reason:
            raise
    else:
        raise Rejected("canary_candidate_expected_denial")


def _trust_update(authority, key, policy, root, environment, read, version, revoked):
    receipt = trust_authority.update(authority, policy, key, revoked_artifacts=revoked)
    envelope, clock = read()
    document = trust.validate(envelope, root, environment, clock)
    if (
        receipt
        != {"version": version, "document_sha256": digest(canonical(envelope)), "reused": False}
        or document["version"] != version
        or document["promotion_policy_sha256"] != policy
        or document["revoked_artifacts"] != revoked
        or document["revoked_keys"]
    ):
        raise Rejected("canary_candidate_trust_readback")
    return envelope, document


@contextmanager
def actual_candidate(root, state, image, campaign, proposal_pin, features, *, revoke_dataset=False):
    """Yield an inactive engine, independent one-row golden, public binding and one-shot revocation."""
    hosted()
    if not isinstance(campaign, str) or not re.fullmatch("[0-9a-f]{32}", campaign):
        raise Rejected("canary_candidate_campaign")
    validate_features(features, max_rows=1)
    root, state = Path(root), Path(state)
    report_path = safe_child(state, "evidence/release-native.json")
    raw = bounded_read(report_path)
    if digest(raw) != proposal_pin:
        raise Rejected("canary_candidate_proposal_pin")
    report = decode(raw)
    expected = source(root, image)
    storage = storage_bootstrap.validate(state)
    ledger = storage_restore.ledger(storage["name"])
    pins = {report_path: proposal_pin}

    def pinned_json(path):
        content = bounded_read(path)
        pins[path] = digest(content)
        return decode(content)

    public = pinned_json(safe_child(state, "trusted-keys.json"))
    client = safe_child(state, "storage-clients/serving")
    reference = report["proposal_reference"]
    package = release_bundle.load(client, reference, publisher_public=public["approver"])
    context, verified = bind_proposal(
        report,
        package,
        policy=pinned_json(root / "policies/local-cpu.json"),
        source_trust=pinned_json(safe_child(state, "storage-trust.json")),
        publisher_public=public["approver"],
        expected=expected,
        clock=math.ceil(time.time()),
    )
    demo_path = safe_child(state, "storage-demo.json")
    demo = pinned_json(demo_path)
    if (
        demo["candidate"]["candidate_reference"] != context["candidate_reference"]
        or demo["evaluation_reference"] != context["evaluation_reference"]
    ):
        raise Rejected("canary_candidate_storage_demo")
    source_campaign = verified["manifest"]["release_id"]
    if report["campaign_id"] != source_campaign:
        raise Rejected("canary_candidate_proposal_campaign")
    production = pinned_json(
        safe_child(state, f"release-proposals/{source_campaign}/policy-envelope.json")
    )
    with _must_deny("release_assurance_required"):
        release_authorization.verify(
            package=package,
            policy_envelope=production,
            assurance_envelope=None,
            approval_envelope=None,
            reports={},
            context=context,
            trusted_root=public["trust"],
            expected_policy=report["policy_sha256"],
            expected_serving_image=expected["image_id"],
            clock=math.ceil(time.time()),
        )

    batch = PredictionBatch(verified["model"], features)
    response, execution = sandbox.run_worker(expected["image_id"], batch.request, timeout=30)
    scores, _, receipt = batch.consume(response)
    if execution["image_id"] != expected["image_id"]:
        raise Rejected("canary_candidate_golden_image")
    model = receipt["model_digest"]
    subject = verified["subject_sha256"]
    golden = Golden.from_expected(
        dict(
            features=batch.request["features"], scores=scores.tolist(), model=model, bundle=subject
        )
    )
    try:
        with disposable(root, state, campaign, "canary-candidate-trust", 15446) as authority:
            key = safe_child(authority, "keys/qualification.pem")
            public_root = signing.create_key(key)
            environment = context["policy"]["environment"]
            issued = int(time.time())
            permit = {
                "schema_version": 1,
                "purpose": KIND,
                "campaign_id": campaign,
                "environment": environment,
                "proposal_sha256": reference,
                "subject_sha256": subject,
                "model_sha256": model,
                **expected,
                "issued_at": issued,
                "expires_at": min(issued + 600, verified["manifest"]["expires_at"]),
            }
            release_policy.window(permit, math.ceil(time.time()), maximum=600)
            envelope = signing.sign(permit, KIND, key)
            with _must_deny("wrong_payload_type"):
                release_policy.checked(envelope, "release-approval", public_root)
            policy = digest(canonical(permit))
            trust_authority.install(authority, environment, public_root)
            read = partial(
                trust_authority.read,
                safe_child(authority, "storage-clients/serving"),
                environment,
                public_root,
            )
            update = partial(_trust_update, authority, key, policy, public_root, environment, read)
            before, initial = update(1, [])
            reader = CandidateReader(
                client,
                context=context,
                publisher_public=public["approver"],
                proposal_reference=reference,
                permit_envelope=envelope,
                permit_public=public_root,
                expected_permit=policy,
                expected_campaign=campaign,
                trust_lease=trust.Lease(
                    read, trusted_root=public_root, environment=environment, minimum_version=1
                ),
            )
            lineage = audit_lineage.from_verified_package(
                package, verified["manifest"], context["trust"]["curator"]
            )
            private = dict(
                permit=envelope, storage_demo_sha256=pins[demo_path], lineage=asdict(lineage)
            )
            sidecar = safe_child(state, f"evidence/canary-native-{campaign}/candidate-source.json")
            write_json(sidecar, private)
            pins[sidecar] = digest(canonical(private) + b"\n")
            revoked_artifact = model
            if revoke_dataset:
                projection = decode(package["documents"]["asset_projection"])
                (dataset,) = (a for a in projection["graph"]["assets"] if a["kind"] == "dataset")
                revoked_artifact = dataset["sha256"]
                evidence = dict(projection=projection, proposal=package["envelope"])
                path = safe_child(sidecar.parent, "inventory-source.json")
                write_json(path, evidence)
                pins[path] = digest(canonical(evidence) + b"\n")
            binding = {
                **expected,
                "candidate_reference": context["candidate_reference"],
                "evaluation_reference": context["evaluation_reference"],
                "proposal_reference": reference,
                "subject_sha256": subject,
                "model_sha256": model,
                "permit_sha256": policy,
                "trust_root": public_root,
                "source_evidence_sha256": pins[sidecar],
            }
            available = True
            lock = Lock()

            def revoke_candidate():
                nonlocal available
                with lock:
                    if not available:
                        raise Rejected("canary_candidate_revocation_closed")
                    available = False
                    after, revoked = update(2, [revoked_artifact])
                    trust.successor(initial, revoked)
                    return {"root": public_root, "before": before, "after": after}

            try:
                yield serving.Engine(reader), golden, binding, revoke_candidate
                # Expiry during observation would also explain a 503 from B.
                release_policy.window(permit, math.ceil(time.time()), maximum=600)
            finally:
                with lock:
                    available = False
    finally:
        if (
            source(root, image) != expected
            or storage_bootstrap.validate(state) != storage
            or storage_restore.ledger(storage["name"]) != ledger
            or any(digest(bounded_read(path)) != pin for path, pin in pins.items())
        ):
            raise Rejected("canary_candidate_source_changed")
