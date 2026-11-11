"""Producer-owned immutable sequence journal; receiver ingest time is independent.

No automatic eviction, initialization or timestamp rebasing. Receipt validation
uses the collector's pinned authority, not the producer's enqueue timestamp.
"""

from mlsecops import security_event_store as storage
from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest

MAX_RECORDS = 1024
MAX_PENDING = 16
FIELDS = ("schema_version", "config_sha256", "producer_id", "updated_at_ms", "records")
RECORD_FIELDS = ("envelope", "queued_at_ms", "receipt")
INPUT_FIELDS = ("kind", "reason", "correlation_id", "asset_sha256", "bundle_sha256")


def key_identity(key_path):
    return digest(signing.load_key(key_path).public_key().public_bytes_raw())


class Outbox:
    def __init__(self, registry, producer_id, document):
        if (
            type(document) is not dict
            or type(document.get("schema_version")) is not int
            or document["schema_version"] not in (1, 2)
        ):
            raise Rejected("security_outbox_schema")
        events.shape(document, FIELDS + (("heartbeat",) if document["schema_version"] == 2 else ()))
        self.registry, self.producer = registry, registry.producer(producer_id)
        if (
            document["config_sha256"] != registry.sha256
            or document["producer_id"] != producer_id
            or self.producer.role == "collector"
        ):
            raise Rejected("security_outbox_binding")
        registry.valid(document["updated_at_ms"])
        records = document["records"]
        if type(records) is not list or len(records) > MAX_RECORDS:
            raise Rejected("security_outbox_records")
        self._document = decode(canonical(document))
        self._ids, self._occurrences = {}, {}
        previous = 0
        for index, record in enumerate(self._document["records"]):
            events.shape(record, RECORD_FIELDS)
            queued = events.integer(record["queued_at_ms"])
            if not previous <= queued <= document["updated_at_ms"]:
                raise Rejected("security_outbox_clock")
            event = registry.verify(record["envelope"], clock_ms=queued)
            value = event.document()
            if (
                value["producer_id"] != producer_id
                or value["sequence"] != index + 1
                or value["occurred_at_ms"] != queued
                or value["observed_at_ms"] != queued
            ):
                raise Rejected("security_outbox_event_binding")
            occurrence = (value["kind"], value["correlation_id"])
            if occurrence in self._occurrences or value["event_id"] in self._ids:
                raise Rejected("security_outbox_duplicate")
            if record["receipt"] is not None:
                self._receipt(record["receipt"], record, document["updated_at_ms"])
            self._ids[value["event_id"]] = index
            self._occurrences[occurrence] = index
            previous = queued
        if len(self.pending()) > MAX_PENDING:
            raise Rejected("security_outbox_backlog")
        heartbeat = self._document.get("heartbeat")
        if heartbeat is not None:
            raw = events.signed(heartbeat, "security-heartbeat", self.producer.public_key)
            events.shape(raw, events.HEARTBEAT_FIELDS)
            value = registry.heartbeat(heartbeat, clock_ms=raw["observed_at_ms"])
            if (
                value["producer_id"] != producer_id
                or value["last_event_sequence"] > len(records)
                or value["observed_at_ms"] > document["updated_at_ms"]
            ):
                raise Rejected("security_outbox_heartbeat_binding")

    @classmethod
    def empty(cls, registry, producer_id, *, clock_ms):
        return cls(
            registry,
            producer_id,
            {
                "schema_version": 2,
                "config_sha256": registry.sha256,
                "producer_id": producer_id,
                "updated_at_ms": clock_ms,
                "records": [],
                "heartbeat": None,
            },
        )

    def document(self):
        return decode(canonical(self._document))

    def pending(self):
        return [record for record in self.document()["records"] if record["receipt"] is None]

    def _clock(self, clock_ms):
        self.registry.valid(clock_ms)
        if clock_ms < self._document["updated_at_ms"]:
            raise Rejected("security_outbox_clock")

    def heartbeat(self, key_path, *, clock_ms):
        self._clock(clock_ms)
        if self._document["schema_version"] != 2:
            raise Rejected("security_outbox_heartbeat_migration")
        if key_identity(key_path) != self.producer.identity:
            raise Rejected("security_outbox_key")
        previous = self._document["heartbeat"]
        sequence = 1
        if previous is not None:
            sequence = (
                events.signed(previous, "security-heartbeat", self.producer.public_key)["sequence"]
                + 1
            )
        value = dict(
            schema_version=1,
            producer_id=self.producer.identity,
            epoch=self.producer.epoch,
            sequence=events.integer(sequence),
            last_event_sequence=len(self._ids),
            observed_at_ms=clock_ms,
            policy_sha256=self.registry.policy_sha256,
        )
        envelope = signing.sign(value, "security-heartbeat", key_path)
        self.registry.heartbeat(envelope, clock_ms=clock_ms)
        self._document["heartbeat"] = envelope
        self._document["updated_at_ms"] = clock_ms
        return decode(canonical(envelope))

    def enqueue(self, request, *, clock_ms):
        self._clock(clock_ms)
        fields, key_path = request
        events.shape(fields, INPUT_FIELDS)
        if key_identity(key_path) != self.producer.identity:
            raise Rejected("security_outbox_key")
        # Validate bounded fields before indexing or comparing caller-controlled input.
        value = events.create(
            **fields,
            producer_id=self.producer.identity,
            epoch=self.producer.epoch,
            sequence=len(self._ids) + 1,
            occurred_at_ms=clock_ms,
            observed_at_ms=clock_ms,
            policy_sha256=self.registry.policy_sha256,
        )
        if value["kind"] not in events.ROLE_KINDS[self.producer.role]:
            raise Rejected("security_outbox_role")
        index = self._occurrences.get((value["kind"], value["correlation_id"]))
        if index is not None:
            record = self._document["records"][index]
            original = self.registry.verify(
                record["envelope"], clock_ms=record["queued_at_ms"]
            ).document()
            if any(value[name] != original[name] for name in INPUT_FIELDS):
                raise Rejected("security_outbox_conflict")
            return decode(canonical(record))
        if len(self._ids) >= MAX_RECORDS or len(self.pending()) >= MAX_PENDING:
            raise Rejected("security_outbox_full")
        envelope = signing.sign(value, "security-event", key_path)
        self.registry.verify(envelope, clock_ms=clock_ms)
        record = {"envelope": envelope, "queued_at_ms": clock_ms, "receipt": None}
        index = len(self._ids)
        self._ids[value["event_id"]] = index
        self._occurrences[(value["kind"], value["correlation_id"])] = index
        self._document["records"].append(record)
        self._document["updated_at_ms"] = clock_ms
        return decode(canonical(record))

    def _receipt(self, envelope, record, clock_ms):
        event = self.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
        value = self.registry.receipt(envelope, event)
        if (
            value["ingested_at_ms"] < record["queued_at_ms"] - events.CLOCK_SKEW_MS
            or value["routed_at_ms"] > clock_ms + events.CLOCK_SKEW_MS
        ):
            raise Rejected("security_outbox_receipt_time")
        return value

    def acknowledge(self, envelope, *, clock_ms):
        self._clock(clock_ms)
        value = events.signed(envelope, "security-event-receipt", self.registry.receipt_public)
        events.shape(value, events.RECEIPT_FIELDS)
        identity = events.hexadecimal(value["event_id"])
        if identity not in self._ids:
            raise Rejected("security_outbox_unknown_event")
        record = self._document["records"][self._ids[identity]]
        self._receipt(envelope, record, clock_ms)
        if record["receipt"] is not None:
            if canonical(envelope) != canonical(record["receipt"]):
                raise Rejected("security_outbox_receipt_conflict")
        else:
            record["receipt"] = decode(canonical(envelope))
            self._document["updated_at_ms"] = clock_ms
        return decode(canonical(record))


def initialize(root, registry, producer_id, *, clock_ms):
    storage.platform()
    document = Outbox.empty(registry, producer_id, clock_ms=clock_ms).document()
    return storage._initialize(root, registry, document)


class Store(storage.Store):
    def __init__(self, root, identity_sha256, registry, producer_id):
        super().__init__(root, identity_sha256, registry)
        self.producer_id = registry.producer(producer_id).identity

    def _decode(self, document):
        return Outbox(self.registry, self.producer_id, document)

    def enqueue(self, request, *, clock_ms):
        return self._update("enqueue", request, clock_ms)

    def heartbeat(self, key_path, *, clock_ms):
        return self._update("heartbeat", key_path, clock_ms)
