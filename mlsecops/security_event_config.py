"""Pinned operator-signed producer registry, independent from model worker claims."""

from dataclasses import dataclass

from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest

CONFIG_FIELDS = (
    "schema_version",
    "policy_sha256",
    "issued_at_ms",
    "expires_at_ms",
    "receipt_public",
    "producers",
)
PRODUCER_FIELDS = ("public_key", "role", "epoch", "heartbeat_required")


@dataclass(frozen=True, slots=True)
class Producer:
    identity: str
    public_key: str
    role: str
    epoch: str
    heartbeat_required: bool


@dataclass(frozen=True, slots=True, init=False)
class Registry:
    sha256: str
    policy_sha256: str
    issued_at_ms: int
    expires_at_ms: int
    receipt_public: str
    producers: tuple[Producer, ...]

    def __init__(self, envelope, *, trusted_root, expected_sha256, clock_ms):
        root = events.public_key(trusted_root)
        events.hexadecimal(expected_sha256)
        value = events.signed(envelope, "security-event-config", root, maximum=32768)
        events.shape(value, CONFIG_FIELDS)
        events.version(value["schema_version"])
        if digest(canonical(value)) != expected_sha256:
            raise Rejected("security_config_pin")
        events.hexadecimal(value["policy_sha256"])
        issued, expires = (
            events.integer(value["issued_at_ms"]),
            events.integer(value["expires_at_ms"]),
        )
        if not 0 < expires - issued <= 86400000:
            raise Rejected("security_config_window")
        receipt = events.public_key(value["receipt_public"])
        if receipt == root:
            raise Rejected("security_config_roles")
        keys = {root, receipt}
        if type(value["producers"]) is not list or not 1 <= len(value["producers"]) <= 16:
            raise Rejected("security_producer_inventory")
        producers = []
        for item in value["producers"]:
            events.shape(item, PRODUCER_FIELDS)
            public = events.public_key(item["public_key"])
            if (
                public in keys
                or type(item["role"]) is not str
                or item["role"] not in events.ROLE_KINDS
                or type(item["heartbeat_required"]) is not bool
            ):
                raise Rejected("security_producer_authority")
            keys.add(public)
            producers.append(
                Producer(
                    digest(signing.decode64(public)),
                    public,
                    item["role"],
                    events.hexadecimal(item["epoch"], 32),
                    item["heartbeat_required"],
                )
            )
        if not any(producer.heartbeat_required for producer in producers):
            raise Rejected("security_heartbeat_required")
        for name, data in (
            ("sha256", expected_sha256),
            ("policy_sha256", value["policy_sha256"]),
            ("issued_at_ms", issued),
            ("expires_at_ms", expires),
            ("receipt_public", receipt),
            ("producers", tuple(producers)),
        ):
            object.__setattr__(self, name, data)
        self.valid(clock_ms)

    def valid(self, clock_ms):
        clock = events.integer(clock_ms)
        if not self.issued_at_ms <= clock < self.expires_at_ms:
            raise Rejected("security_config_expired_or_future")

    def producer(self, identity):
        events.hexadecimal(identity)
        for producer in self.producers:
            if producer.identity == identity:
                return producer
        raise Rejected("security_unknown_producer")

    def _read(self, envelope, kind, clock_ms):
        self.valid(clock_ms)
        producer = self.producer(events.signer(envelope))
        return events.signed(envelope, kind, producer.public_key), producer

    def _binding(self, value, producer, clock_ms, *, occurred_at_ms):
        if (
            value["producer_id"] != producer.identity
            or value["epoch"] != producer.epoch
            or value["policy_sha256"] != self.policy_sha256
        ):
            raise Rejected("security_producer_binding")
        observed = events.integer(value["observed_at_ms"])
        if (
            occurred_at_ms < self.issued_at_ms
            or not occurred_at_ms <= observed <= clock_ms + events.CLOCK_SKEW_MS
            or clock_ms - occurred_at_ms > events.MAX_AGE_MS
        ):
            raise Rejected("security_event_expired_or_future")

    def verify(self, envelope, *, clock_ms):
        value, producer = self._read(envelope, "security-event", clock_ms)
        value = events.checked(value)
        self._binding(value, producer, clock_ms, occurred_at_ms=value["occurred_at_ms"])
        if value["kind"] not in events.ROLE_KINDS[producer.role]:
            raise Rejected("security_event_role")
        return events.Event(canonical(value))

    def heartbeat(self, envelope, *, clock_ms):
        value, producer = self._read(envelope, "security-heartbeat", clock_ms)
        events.shape(value, events.HEARTBEAT_FIELDS)
        events.version(value["schema_version"])
        events.integer(value["sequence"])
        events.integer(value["last_event_sequence"], 0)
        self._binding(
            value, producer, clock_ms, occurred_at_ms=events.integer(value["observed_at_ms"])
        )
        return decode(canonical(value))

    def receipt(self, envelope, event):
        value = events.signed(envelope, "security-event-receipt", self.receipt_public)
        events.shape(value, events.RECEIPT_FIELDS)
        events.version(value["schema_version"])
        if value["release_ready"] is not False:
            raise Rejected("security_receipt_authority")
        expected = events.delivered(
            event,
            self.sha256,
            ingested_at_ms=value["ingested_at_ms"],
            routed_at_ms=value["routed_at_ms"],
            late=value["late"],
        )
        self.valid(value["ingested_at_ms"])
        self.valid(value["routed_at_ms"])
        document = event.document()
        self._binding(
            document,
            self.producer(document["producer_id"]),
            value["ingested_at_ms"],
            occurred_at_ms=document["occurred_at_ms"],
        )
        if canonical(value) != canonical(expected):
            raise Rejected("security_receipt_binding")
        return expected
