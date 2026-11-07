"""Bounded security-event transitions. This class alone provides no durability."""

from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode

MAX_RECORDS = 1024
REORDER_WINDOW = 64
FIELDS = ("schema_version", "config_sha256", "updated_at_ms", "records")
RECORD_FIELDS = ("envelope", "ingested_at_ms", "late", "receipt")


def candidate(envelope):
    # Only extracts a bounded identity for lookup. Never authorizes admission.
    events.signer(envelope)
    return events.Event(
        canonical(events.checked(decode(signing.decode64(envelope["payload"]), 2048)))
    )


class Ledger:
    def __init__(self, registry, document):
        events.shape(document, FIELDS)
        events.version(document["schema_version"])
        if document["config_sha256"] != registry.sha256:
            raise Rejected("security_store_config")
        registry.valid(document["updated_at_ms"])
        records = document["records"]
        if type(records) is not list or len(records) > MAX_RECORDS:
            raise Rejected("security_store_records")
        self.registry = registry
        self._document = decode(canonical(document))
        self._index, self._positions, self._highest = {}, {}, {}
        previous = 0
        for index, record in enumerate(self._document["records"]):
            events.shape(record, RECORD_FIELDS)
            ingested = events.integer(record["ingested_at_ms"])
            if not previous <= ingested <= document["updated_at_ms"]:
                raise Rejected("security_store_time")
            event = registry.verify(record["envelope"], clock_ms=ingested)
            late = self._check_new(event)
            if type(record["late"]) is not bool or record["late"] != late:
                raise Rejected("security_store_late")
            if record["receipt"] is not None:
                receipt = registry.receipt(record["receipt"], event)
                self._check_receipt(receipt, record, document["updated_at_ms"])
            self._remember(event, index)
            previous = ingested

    @classmethod
    def empty(cls, registry, *, clock_ms):
        return cls(
            registry,
            {
                "schema_version": 1,
                "config_sha256": registry.sha256,
                "updated_at_ms": clock_ms,
                "records": [],
            },
        )

    def document(self):
        return decode(canonical(self._document))

    def pending(self):
        return [r for r in self.document()["records"] if r["receipt"] is None]

    def _clock(self, clock_ms):
        self.registry.valid(clock_ms)
        if clock_ms < self._document["updated_at_ms"]:
            raise Rejected("security_store_clock_regressed")

    def _check_new(self, event):
        value = event.document()
        stream = (value["producer_id"], value["epoch"])
        position = (*stream, value["sequence"])
        if value["event_id"] in self._index or position in self._positions:
            raise Rejected("security_sequence_conflict")
        highest = self._highest.get(stream, 0)
        if not max(1, highest - REORDER_WINDOW) <= value["sequence"] <= highest + REORDER_WINDOW:
            raise Rejected("security_sequence_window")
        return value["sequence"] < highest

    def _remember(self, event, index):
        value = event.document()
        stream = (value["producer_id"], value["epoch"])
        self._index[value["event_id"]] = index
        self._positions[(*stream, value["sequence"])] = value["event_id"]
        self._highest[stream] = max(self._highest.get(stream, 0), value["sequence"])

    @staticmethod
    def _check_receipt(value, record, clock_ms):
        if (
            value["ingested_at_ms"] != record["ingested_at_ms"]
            or value["late"] != record["late"]
            or value["routed_at_ms"] > clock_ms
        ):
            raise Rejected("security_store_receipt")

    def ingest(self, envelope, *, clock_ms):
        self._clock(clock_ms)
        value = candidate(envelope).document()
        index = self._index.get(value["event_id"])
        if index is not None:
            record = self._document["records"][index]
            # Historical exact retry still needs the original producer's signature.
            # The current registry must be valid; old timestamps cannot admit a new event.
            event = self.registry.verify(envelope, clock_ms=record["ingested_at_ms"])
            original = self.registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
            if event != original:
                raise Rejected("security_retry_conflict")
            return decode(canonical(record))
        event = self.registry.verify(envelope, clock_ms=clock_ms)
        late = self._check_new(event)
        if len(self._document["records"]) >= MAX_RECORDS:
            raise Rejected("security_store_full")
        record = {
            "envelope": decode(canonical(envelope)),
            "ingested_at_ms": clock_ms,
            "late": late,
            "receipt": None,
        }
        self._remember(event, len(self._document["records"]))
        self._document["records"].append(record)
        self._document["updated_at_ms"] = clock_ms
        return decode(canonical(record))

    def acknowledge(self, envelope, *, clock_ms):
        self._clock(clock_ms)
        value = events.signed(envelope, "security-event-receipt", self.registry.receipt_public)
        events.shape(value, events.RECEIPT_FIELDS)
        event_id = events.hexadecimal(value["event_id"])
        if event_id not in self._index:
            raise Rejected("security_unknown_event")
        record = self._document["records"][self._index[event_id]]
        event = self.registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
        value = self.registry.receipt(envelope, event)
        self._check_receipt(value, record, clock_ms)
        if record["receipt"] is not None:
            if value != self.registry.receipt(record["receipt"], event):
                raise Rejected("security_receipt_conflict")
            return decode(canonical(record))
        record["receipt"] = decode(canonical(envelope))
        self._document["updated_at_ms"] = clock_ms
        return decode(canonical(record))
