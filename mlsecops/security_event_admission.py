"""Fresh audit availability observation, never an ML release authorization.

Nonce-bound replies attest to a durable health poll. They do not assert that
the release selection was stored in the collector or provide distributed commit.
"""

import secrets
import time

from mlsecops import key_files, security_event_config, security_event_delivery, signing
from mlsecops import security_event_store as storage
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest

FRESH_MS = 5000
REQUEST_FIELDS = (
    "schema_version",
    "producer_id",
    "epoch",
    "config_sha256",
    "selection_sha256",
    "nonce",
    "requested_at_ms",
)
OBSERVATION_FIELDS = (
    "schema_version",
    "config_sha256",
    "request_sha256",
    "observed_at_ms",
    "health_sha256",
    "healthy",
    "release_ready",
)
CONFIG_FIELDS = (
    "schema_version",
    "registry_file",
    "registry_root",
    "registry_sha256",
    "producer_key_file",
    "ingress_token_file",
    "port",
)


def request(registry, envelope, *, clock_ms):
    registry.valid(clock_ms)
    producer = registry.producer(events.signer(envelope))
    value = events.signed(envelope, "security-audit-request", producer.public_key)
    events.shape(value, REQUEST_FIELDS)
    events.version(value["schema_version"])
    events.hexadecimal(value["selection_sha256"])
    events.hexadecimal(value["nonce"], 32)
    observed = events.integer(value["requested_at_ms"])
    if (
        producer.role != "promoter"
        or value["producer_id"] != producer.identity
        or value["epoch"] != producer.epoch
        or value["config_sha256"] != registry.sha256
        or abs(clock_ms - observed) > FRESH_MS
    ):
        raise Rejected("security_audit_request")
    registry.valid(observed)
    return value


def verify(registry, envelope, response, *, clock_ms):
    intent = request(registry, envelope, clock_ms=clock_ms)
    value = events.signed(response, "security-audit-observation", registry.receipt_public)
    events.shape(value, OBSERVATION_FIELDS)
    events.version(value["schema_version"])
    events.hexadecimal(value["health_sha256"])
    observed = events.integer(value["observed_at_ms"])
    registry.valid(observed)
    if (
        value["config_sha256"] != registry.sha256
        or value["request_sha256"] != digest(canonical(intent))
        or value["healthy"] is not True
        or value["release_ready"] is not False
        or abs(clock_ms - observed) > FRESH_MS
        or abs(observed - intent["requested_at_ms"]) > FRESH_MS
    ):
        raise Rejected("security_audit_observation")
    return value


class Client:
    def __init__(self, registry, key, exchange, *, clock=None, monotonic=None):
        self.registry, self.key, self.exchange = registry, key, exchange
        self.clock = clock or (lambda: time.time_ns() // 1_000_000)
        self.monotonic = monotonic or time.monotonic
        self.producer = registry.producer(
            digest(signing.load_key(key).public_key().public_bytes_raw())
        )
        if self.producer.role != "promoter":
            raise Rejected("security_audit_role")

    def check(self, selection_sha256):
        try:
            started, clock = self.monotonic(), self.clock()
            self.registry.valid(clock)
            events.hexadecimal(selection_sha256)
            value = dict(
                schema_version=1,
                producer_id=self.producer.identity,
                epoch=self.producer.epoch,
                config_sha256=self.registry.sha256,
                selection_sha256=selection_sha256,
                nonce=secrets.token_hex(16),
                requested_at_ms=clock,
            )
            envelope = signing.sign(value, "security-audit-request", self.key)
            result = self.exchange(envelope)
            finished = self.clock()
            if (
                not 0 <= self.monotonic() - started <= security_event_delivery.TIMEOUT
                or finished < clock
            ):
                raise Rejected("security_audit_deadline")
            return verify(self.registry, envelope, result, clock_ms=finished)
        except Exception:
            raise Rejected("promotion_audit_unavailable") from None


def configured(path):
    value = decode(bounded_read(storage.path(path), 16384), 16384)
    events.shape(value, CONFIG_FIELDS)
    events.version(value["schema_version"])
    registry = security_event_config.Registry(
        decode(bounded_read(storage.path(value["registry_file"]), 32768), 32768),
        trusted_root=value["registry_root"],
        expected_sha256=value["registry_sha256"],
        clock_ms=time.time_ns() // 1_000_000,
    )
    key = storage.path(value["producer_key_file"])
    token = events.hexadecimal(
        key_files.read(storage.path(value["ingress_token_file"])).decode("ascii")
    )
    return Client(
        registry,
        key,
        lambda envelope: security_event_delivery.exchange(
            value["port"], token, envelope, path="/admission"
        ),
    )


class Configured:
    """Load operator configuration at the boundary, after ML authorization.

    No missing-assurance request opens keys or reaches the collector. Each
    check reloads configuration, so there is no cached successful observation.
    """

    def __init__(self, path):
        self.path = storage.path(path)

    def check(self, selection_sha256):
        try:
            return configured(self.path).check(selection_sha256)
        except Exception:
            raise Rejected("promotion_audit_unavailable") from None
