import math
import threading
import time

from mlsecops import release_policy, signing
from mlsecops.contracts import Rejected, canonical, digest, require_fields
from mlsecops.storage import object_id

FIELDS = (
    "schema_version",
    "environment",
    "version",
    "promotion_policy_sha256",
    "issued_at",
    "expires_at",
    "revoked_artifacts",
    "revoked_keys",
)


class Unavailable(Rejected):
    pass


def validate(envelope, public, environment, clock=None):
    release_policy.name(environment)
    payload = release_policy.checked(envelope, "trust-policy", public)
    require_fields(payload, FIELDS)
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["environment"] != environment
    ):
        raise Rejected("trust_policy_schema_or_environment")
    release_policy.integer(payload["version"])
    object_id(payload["promotion_policy_sha256"])
    issued, expires = (
        release_policy.integer(payload[name]) for name in ("issued_at", "expires_at")
    )
    if not 0 < expires - issued <= 86400:
        raise Rejected("trust_policy_window")
    if clock is not None:
        release_policy.window(payload, clock)
    for field, limit in (("revoked_artifacts", 2048), ("revoked_keys", 512)):
        values = payload[field]
        if not isinstance(values, list) or len(values) > limit:
            raise Rejected("trust_revocation_limit")
        for reference in values:
            object_id(reference)
        if values != sorted(set(values)):
            raise Rejected("trust_revocation_set")
    return payload


def successor(current, following):
    if (
        following["version"] != current["version"] + 1
        or following["environment"] != current["environment"]
        or following["issued_at"] < current["issued_at"]
        or any(
            not set(current[field]).issubset(following[field])
            for field in ("revoked_artifacts", "revoked_keys")
        )
    ):
        raise Rejected("trust_update_conflict_or_unrevocation")


class Lease:
    def __init__(
        self,
        reader,
        *,
        trusted_root,
        environment,
        minimum_version,
        wall_clock=time.time,
        monotonic_clock=time.monotonic,
    ):
        release_policy.name(environment)
        release_policy.integer(minimum_version)
        if len(signing.decode64(trusted_root)) != 32:
            raise Rejected("trust_root_invalid")
        self.reader = reader
        self.root = trusted_root
        self.environment = environment
        self.floor = minimum_version
        self.observed_digest = None
        self.revocations = {"revoked_artifacts": set(), "revoked_keys": set()}
        self.root_revoked = False
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock
        self.lock = threading.RLock()
        self.payload = None
        self.deadline = 0
        self.anchor = None
        self.last = None
        self.broken_clock = False

    def sample(self):
        wall, monotonic = self.wall_clock(), self.monotonic_clock()
        if (
            self.broken_clock
            or any(
                type(value) not in (int, float) or not math.isfinite(value)
                for value in (wall, monotonic)
            )
            or wall <= 0
            or monotonic < 0
            or (self.last is not None and (wall < self.last[0] or monotonic < self.last[1]))
            or (
                self.anchor is not None
                and abs((wall - self.anchor[0]) - (monotonic - self.anchor[1])) > 2
            )
        ):
            self.payload = None
            self.broken_clock = True
            raise Rejected("trust_clock_invalid")
        self.last = (wall, monotonic)
        if self.anchor is None:
            self.anchor = self.last
        return self.last

    def refresh(self):
        with self.lock:
            _, started = self.sample()
            try:
                if self.root_revoked:
                    raise Rejected("trust_root_revoked")
                envelope, server_clock = self.reader()
                wall, ended = self.sample()
                release_policy.integer(server_clock)
                if abs(server_clock - wall) > 2:
                    raise Rejected("trust_server_clock_skew")
                payload = validate(envelope, self.root, self.environment, int(wall))
                validate(envelope, self.root, self.environment, server_clock)
                reference = digest(canonical(envelope))
                if payload["version"] < self.floor or (
                    payload["version"] == self.floor
                    and self.observed_digest is not None
                    and reference != self.observed_digest
                ):
                    raise Rejected("trust_version_replay")
                for field, previous in self.revocations.items():
                    if not previous.issubset(payload[field]):
                        raise Rejected("trust_unrevocation")
                self.revocations = {field: set(payload[field]) for field in self.revocations}
                self.floor, self.observed_digest = payload["version"], reference
                if digest(signing.decode64(self.root)) in payload["revoked_keys"]:
                    self.root_revoked = True
                    raise Rejected("trust_root_revoked")
                self.deadline = min(
                    started + 60,
                    ended + payload["expires_at"] - wall,
                    started + payload["expires_at"] - server_clock - 1,
                )
                if ended >= self.deadline:
                    raise Rejected("trust_lease_expired")
                self.payload = payload
            except Unavailable:
                self.sample()
                raise
            except Exception:
                self.payload = None
                raise
            return {"version": self.floor, "document_sha256": reference}

    def check(self, *, policy_sha256, artifacts, keys):
        with self.lock:
            wall, monotonic = self.sample()
            if self.payload is None:
                raise Rejected("trust_lease_unavailable")
            if monotonic >= self.deadline or wall >= self.payload["expires_at"]:
                self.payload = None
                raise Rejected("trust_lease_expired")
            if object_id(policy_sha256) != self.payload["promotion_policy_sha256"]:
                raise Rejected("trust_policy_changed")
            for values, field, message in (
                (artifacts, "revoked_artifacts", "trust_artifact_revoked"),
                (keys, "revoked_keys", "trust_key_revoked"),
            ):
                if not isinstance(values, (list, tuple, set)) or len(values) > 4096:
                    raise Rejected("trust_subject_set_invalid")
                checked = {object_id(reference) for reference in values}
                if checked.intersection(self.payload[field]):
                    raise Rejected(message)
            return {"version": self.floor, "document_sha256": self.observed_digest}
