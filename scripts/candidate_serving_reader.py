import copy
import math
import re
import threading
from dataclasses import dataclass, field

from mlsecops import (
    material_bundle,
    release_bundle,
    release_policy,
    serving_context,
    signing,
    storage,
    trust,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS

KIND = "candidate-serving-qualification"


def bind_proposal(report, package, *, policy, source_trust, publisher_public, expected, clock):
    required = {
        "scope": "release-proposal-and-authorization-denial-not-full-M10",
        "status": "pass",
        "source_dirty": False,
        "release_ready": False,
        "source": expected,
        "proposal_reference": digest(canonical(package["envelope"])),
    }
    if not isinstance(report, dict) or canonical(
        {key: report.get(key) for key in required}
    ) != canonical(required):
        raise Rejected("qualification_source_report_binding")
    capsule = release_policy.checked(
        package["capsule"]["envelope"], material_bundle.KIND, publisher_public
    )
    context = {
        "candidate_reference": capsule["candidate_reference"],
        "evaluation_reference": capsule["evaluation_reference"],
        "policy": policy,
        "trust": source_trust,
        "expected": expected,
        "owners": copy.deepcopy(OWNERS),
        "known_owners": list(KNOWN_OWNERS),
    }
    verified = release_bundle.verify(
        package,
        context=context,
        publisher_public=publisher_public,
        expected_serving_image=expected["image_id"],
        clock=clock,
    )
    if (report.get("subject_sha256"), report.get("model_sha256")) != (
        verified["subject_sha256"],
        digest(verified["model"]),
    ):
        raise Rejected("qualification_source_subject_binding")
    return context, verified


@dataclass(frozen=True)
class QualifiedCandidate:
    subject_sha256: str
    model_sha256: str
    expires_at: int
    model: bytes = field(repr=False)
    artifacts: frozenset[str] = field(repr=False)
    keys: frozenset[str] = field(repr=False)
    permit_sha256: str = field(repr=False)
    proposal_sha256: str = field(repr=False)
    scope: str = field(default=KIND, init=False)
    release_ready: bool = field(default=False, init=False)

    @property
    def audit_context(self):
        return serving_context.QualificationContext(
            self.permit_sha256, self.proposal_sha256, self.subject_sha256, self.model_sha256
        )


class CandidateReader:
    def __init__(
        self,
        client,
        *,
        context,
        publisher_public,
        proposal_reference,
        permit_envelope,
        permit_public,
        expected_permit,
        expected_campaign,
        trust_lease,
    ):
        self.client = client
        self.context = copy.deepcopy(context)
        self.publisher = publisher_public
        self.reference = storage.object_id(proposal_reference)
        self.permit = copy.deepcopy(permit_envelope)
        self.public = permit_public
        self.policy = storage.object_id(expected_permit)
        self.environment = self.context["policy"]["environment"]
        self.image = self.context["expected"]["image_id"]
        if signing.decode64(self.public) in {
            signing.decode64(public)
            for public in (
                self.publisher,
                *(self.context["trust"][role] for role in ("curator", "evaluator")),
            )
        }:
            raise Rejected("qualification_key_separation")
        if (
            not isinstance(expected_campaign, str)
            or re.fullmatch(r"[a-f0-9]{32}", expected_campaign) is None
        ):
            raise Rejected("qualification_campaign")
        self.campaign = expected_campaign
        if (
            trust_lease is None
            or trust_lease.root != self.public
            or trust_lease.environment != self.environment
        ):
            raise Rejected("qualification_trust_binding")
        self.trust = trust_lease
        self.current = None
        self.lock = threading.RLock()

    def clock(self):
        return math.ceil(self.trust.sample()[0])

    def permission(self):
        permit = release_policy.checked(self.permit, KIND, self.public)
        expected = {
            "schema_version": 1,
            "purpose": KIND,
            "campaign_id": self.campaign,
            "environment": self.environment,
            "proposal_sha256": self.reference,
            **self.context["expected"],
        }
        require_fields(
            permit, (*expected, "subject_sha256", "model_sha256", "issued_at", "expires_at")
        )
        if digest(canonical(permit)) != self.policy or canonical(
            {name: permit[name] for name in expected}
        ) != canonical(expected):
            raise Rejected("qualification_permit_binding")
        storage.object_id(permit["subject_sha256"])
        storage.object_id(permit["model_sha256"])
        release_policy.window(permit, self.clock(), maximum=600)
        return permit

    def scope(self, package, verified):
        manifest = verified["manifest"]
        projection = decode(package["documents"]["asset_projection"])
        split = decode(package["documents"]["split_manifest"])
        artifacts = {
            self.reference,
            self.policy,
            verified["subject_sha256"],
            digest(canonical(self.permit)),
            *manifest["materials"].values(),
            *(reference for _, reference in package["capsule"]["objects"]),
            *(asset["sha256"] for asset in projection["graph"]["assets"]),
            *(item["sha256"] for item in split["objects"].values()),
            self.context["trust"]["source_approval_digest"],
            projection["bindings"]["lineage_id"],
            projection["bindings"]["source_fingerprint"],
            manifest["training_image"].removeprefix("sha256:"),
            self.image.removeprefix("sha256:"),
        }
        keys = {
            digest(signing.decode64(public))
            for public in (
                self.public,
                self.publisher,
                *(self.context["trust"][role] for role in ("curator", "evaluator")),
            )
        }
        return frozenset(artifacts), frozenset(keys)

    def load(self):
        with self.lock:
            self.current = None
            if storage.connection_parameters(self.client)["user"] != "ml_serving":
                raise Rejected("qualification_storage_identity")
            permit = self.permission()
            self.trust.refresh()
            package = release_bundle.load(
                self.client, self.reference, publisher_public=self.publisher
            )
            if digest(canonical(package["envelope"])) != self.reference:
                raise Rejected("qualification_proposal_binding")
            verified = release_bundle.verify(
                package,
                context=self.context,
                publisher_public=self.publisher,
                expected_serving_image=self.image,
                clock=self.clock(),
            )
            model_sha256 = digest(verified["model"])
            if (permit["subject_sha256"], permit["model_sha256"]) != (
                verified["subject_sha256"],
                model_sha256,
            ):
                raise Rejected("qualification_subject_binding")
            artifacts, keys = self.scope(package, verified)
            loaded = QualifiedCandidate(
                verified["subject_sha256"],
                model_sha256,
                min(permit["expires_at"], verified["manifest"]["expires_at"]),
                verified["model"],
                artifacts,
                keys,
                digest(canonical(permit)),
                permit["proposal_sha256"],
            )
            self.trust.refresh()
            self.permission()
            if self.clock() >= loaded.expires_at:
                raise Rejected("qualification_expired")
            self.trust.check(
                policy_sha256=self.policy, artifacts=tuple(artifacts), keys=tuple(keys)
            )
            self.current = loaded
            return loaded

    def check(self, loaded):
        with self.lock:
            try:
                if self.current is None or loaded is not self.current:
                    raise Rejected("qualification_not_current")
                self.permission()
                if self.clock() >= loaded.expires_at:
                    raise Rejected("qualification_expired")
                try:
                    self.trust.refresh()
                except trust.Unavailable:
                    pass
                self.permission()
                if self.clock() >= loaded.expires_at:
                    raise Rejected("qualification_expired")
                return self.trust.check(
                    policy_sha256=self.policy,
                    artifacts=tuple(loaded.artifacts),
                    keys=tuple(loaded.keys),
                )
            except Exception:
                self.current = None
                raise
