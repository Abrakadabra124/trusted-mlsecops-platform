import copy
import math
import threading
import time
from dataclasses import dataclass, field

import psycopg

from mlsecops import (
    audit_lineage,
    promotion,
    promotion_state,
    release_authorization,
    release_bundle,
    release_policy,
    release_rollback,
    serving_context,
    storage,
    trust,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields


@dataclass(frozen=True)
class VerifiedRelease:
    environment: str
    sequence: int
    request_sha256: str
    subject_sha256: str
    model_sha256: str
    expires_at: int
    model: bytes = field(repr=False)
    artifacts: frozenset[str] = field(repr=False)
    keys: frozenset[str] = field(repr=False)
    lineage: audit_lineage.Lineage = field(repr=False)
    authorization_sha256: str = field(repr=False)
    assurance_sha256: str = field(repr=False)
    approval_sha256: str = field(repr=False)
    release_ready: bool = field(default=False, init=False)

    @property
    def audit_context(self):
        return serving_context.ReleaseTrace(
            self.request_sha256,
            self.subject_sha256,
            self.model_sha256,
            lineage=self.lineage,
            authorization_sha256=self.authorization_sha256,
            assurance_sha256=self.assurance_sha256,
            approval_sha256=self.approval_sha256,
        )


def document(client, reference, limit):
    content = storage.get(client, "releases", storage.object_id(reference))
    if not isinstance(content, bytes) or digest(content) != reference:
        raise Rejected("serving_material_integrity")
    value = decode(content, limit)
    if canonical(value) != content:
        raise Rejected("serving_noncanonical_material")
    return value


class Reader:
    def __init__(
        self,
        client,
        *,
        context,
        trusted_root,
        expected_policy,
        expected_serving_image,
        trust_lease,
        minimum_sequence,
    ):
        self.client = client
        self.context = copy.deepcopy(context)
        self.environment = release_policy.name(self.context["policy"]["environment"])
        self.root = trusted_root
        self.policy = storage.object_id(expected_policy)
        self.image = expected_serving_image
        if trust_lease is None or trust_lease.environment != self.environment:
            raise Rejected("serving_online_trust_required")
        self.trust = trust_lease
        self.floor = release_policy.integer(minimum_sequence)
        self.observed = None
        self.current = None
        self.lock = threading.RLock()

    def snapshot(self):
        if storage.connection_parameters(self.client)["user"] != "ml_serving":
            raise Rejected("serving_storage_identity")
        try:
            with storage.connect(self.client) as connection:
                row = connection.execute(
                    "SELECT head.sequence, head.request_sha256, authority.policy_sha256, "
                    "event.request_sha256, floor(extract(epoch FROM clock_timestamp()))::bigint "
                    "FROM ml_promotion.heads head "
                    "JOIN ml_promotion.authorities authority USING (environment) "
                    "LEFT JOIN ml_promotion.events event ON event.environment = head.environment "
                    "AND event.sequence = head.sequence WHERE head.environment = %s",
                    (self.environment,),
                ).fetchone()
        except psycopg.Error:
            raise Rejected("serving_head_unavailable") from None
        if row is None:
            raise Rejected("serving_head_missing")
        sequence, reference, policy, event, clock = row
        release_policy.integer(sequence)
        storage.object_id(reference)
        release_policy.integer(clock)
        if policy != self.policy or event != reference:
            raise Rejected("serving_head_binding")
        if sequence < self.floor or (
            sequence == self.floor and self.observed is not None and reference != self.observed
        ):
            raise Rejected("serving_sequence_replay")
        wall = time.time()
        if not math.isfinite(wall) or abs(clock - wall) > 2:
            raise Rejected("serving_clock_skew")
        return sequence, reference, max(clock, math.ceil(wall))

    def load(self):
        with self.lock:
            self.current = None
            sequence, reference, clock = self.snapshot()
            self.trust.refresh()
            selection = document(self.client, reference, 65536)
            promotion_state.request(canonical(selection))
            if (
                selection["environment"] != self.environment
                or selection["policy_sha256"] != self.policy
                or selection["sequence"] != sequence
            ):
                raise Rejected("serving_selection_binding")
            proof = selection["authorization_reference"]
            authorization = document(self.client, proof, 4 * release_policy.MAX_DOCUMENT)
            require_fields(
                authorization,
                (
                    "schema_version",
                    "policy_envelope",
                    "assurance_envelope",
                    "approval_envelope",
                    "reports",
                    "decision",
                ),
            )
            if (
                type(authorization["schema_version"]) is not int
                or authorization["schema_version"] != 1
            ):
                raise Rejected("serving_authorization_schema")
            authority = release_policy.verify_policy(
                authorization["policy_envelope"],
                trusted_root=self.root,
                expected_policy=self.policy,
                environment=self.environment,
                clock=clock,
            )
            references = authorization["reports"]
            require_fields(references, authority["required_gates"])
            reports = {}
            for gate, report_reference in references.items():
                content = storage.get(self.client, "releases", storage.object_id(report_reference))
                if len(content) > release_policy.MAX_DOCUMENT:
                    raise Rejected("serving_report_size")
                reports[gate] = content
                if sum(map(len, reports.values())) > 8 * release_policy.MAX_DOCUMENT:
                    raise Rejected("serving_reports_size")
            package = release_bundle.load(
                self.client,
                selection["proposal_reference"],
                publisher_public=authority["identities"]["publisher"]["public_key"],
            )
            arguments = {
                "package": package,
                **{
                    key: authorization[key]
                    for key in ("policy_envelope", "assurance_envelope", "approval_envelope")
                },
                "reports": reports,
                "context": self.context,
                "trusted_root": self.root,
                "expected_policy": self.policy,
                "expected_serving_image": self.image,
            }
            decision = release_authorization.verify(**arguments, clock=clock)
            approval = release_policy.checked(
                authorization["approval_envelope"],
                "release-approval",
                authority["identities"]["approver"]["public_key"],
            )
            expected = {
                **selection,
                **{
                    key: decision[key]
                    for key in (
                        "environment",
                        "policy_sha256",
                        "sequence",
                        "subject_sha256",
                        "expires_at",
                    )
                },
                "issued_at": approval["issued_at"],
            }
            if canonical(selection) != canonical(expected) or canonical(
                authorization["decision"]
            ) != canonical(decision):
                raise Rejected("serving_authorization_binding")
            if "rollback" in decision:
                release_rollback.history(
                    self.client, decision["rollback"], selection, reference, selected=True
                )
            scope = promotion.trust_scope(arguments, decision, authority)
            scope["artifacts"].update((reference, proof))
            manifest = release_bundle.index(
                package["envelope"], authority["identities"]["publisher"]["public_key"]
            )
            model_reference = manifest["materials"]["model"]
            loaded = VerifiedRelease(
                self.environment,
                sequence,
                reference,
                decision["subject_sha256"],
                model_reference,
                decision["expires_at"],
                package["capsule"]["objects"][("candidates", model_reference)],
                frozenset(scope["artifacts"]),
                frozenset(scope["keys"]),
                audit_lineage.from_verified_package(
                    package, manifest, self.context["trust"]["curator"]
                ),
                proof,
                decision["assurance_sha256"],
                decision["approval_sha256"],
            )
            self.trust.refresh()
            final_sequence, final_reference, final_clock = self.snapshot()
            if (sequence, reference) != (final_sequence, final_reference):
                raise Rejected("serving_head_changed")
            if final_clock < clock or final_clock >= loaded.expires_at:
                raise Rejected("serving_release_expired")
            self.trust.check(**scope)
            self.floor, self.observed, self.current = sequence, reference, loaded
            return loaded

    def check(self, loaded):
        with self.lock:
            if loaded is not self.current or loaded is None:
                raise Rejected("serving_release_not_current")
            try:
                try:
                    self.trust.refresh()
                except trust.Unavailable:
                    pass
                sequence, reference, clock = self.snapshot()
                if (sequence, reference) != (loaded.sequence, loaded.request_sha256):
                    raise Rejected("serving_head_changed")
                if clock >= loaded.expires_at:
                    raise Rejected("serving_release_expired")
                return self.trust.check(
                    policy_sha256=self.policy,
                    artifacts=tuple(loaded.artifacts),
                    keys=tuple(loaded.keys),
                )
            except Exception:
                self.current = None
                raise
