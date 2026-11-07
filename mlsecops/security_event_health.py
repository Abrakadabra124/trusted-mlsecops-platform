"""Bounded durable heartbeat/gap episodes, independent from alert delivery."""

from mlsecops import security_events as events
from mlsecops.contracts import Rejected, canonical, decode, digest

REORDER_WINDOW = 64
DETECTION_MS = 3 * events.HEARTBEAT_MS
HEADROOM_MS = events.GAP_MS - DETECTION_MS
FIELDS = ("started_at_ms", "streams")
STREAM_FIELDS = (
    "producer_id",
    "heartbeat",
    "sequence_gap_since_ms",
    "sequence_generation",
    "heartbeat_gap_since_ms",
    "heartbeat_generation",
)
HEARTBEAT_RECORD = ("envelope", "ingested_at_ms")


def empty(registry, clock_ms):
    registry.valid(clock_ms)
    return {
        "started_at_ms": clock_ms,
        "streams": [
            {
                "producer_id": p.identity,
                "heartbeat": None,
                "sequence_gap_since_ms": None,
                "sequence_generation": 0,
                "heartbeat_gap_since_ms": None,
                "heartbeat_generation": 0,
            }
            for p in sorted(registry.producers, key=lambda p: p.identity)
        ],
    }


def known(facts, producer):
    positions = {sequence for identity, sequence, _ in facts if identity == producer}
    return max(positions, default=0), len(positions)


class Health:
    def __init__(self, registry, document, facts, updated_at_ms):
        events.shape(document, FIELDS)
        started = events.integer(document["started_at_ms"])
        registry.valid(started)
        if started > updated_at_ms or any(when < started for _, _, when in facts):
            raise Rejected("security_telemetry_time")
        streams = document["streams"]
        if type(streams) is not list or len(streams) != len(registry.producers):
            raise Rejected("security_telemetry_inventory")
        self.registry = registry
        self._document = decode(canonical(document))
        expected = sorted(p.identity for p in registry.producers)
        for stream, identity in zip(self._document["streams"], expected, strict=True):
            events.shape(stream, STREAM_FIELDS)
            if stream["producer_id"] != identity:
                raise Rejected("security_telemetry_inventory")
            heartbeat = self._heartbeat_value(stream)
            record = stream["heartbeat"]
            if record is not None:
                if not started <= record["ingested_at_ms"] <= updated_at_ms:
                    raise Rejected("security_telemetry_time")
                if heartbeat["producer_id"] != identity:
                    raise Rejected("security_telemetry_identity")
                self._claim(facts, identity, heartbeat["last_event_sequence"])
            missing = self._missing(stream, facts)
            trigger = self._heartbeat_trigger(stream)
            due = registry.producer(identity).heartbeat_required and updated_at_ms >= trigger
            for kind, active in (("sequence", missing), ("heartbeat", due)):
                generation = events.integer(stream[kind + "_generation"], 0)
                since = stream[kind + "_gap_since_ms"]
                if active != (since is not None):
                    raise Rejected("security_telemetry_episode")
                if since is not None:
                    events.integer(since)
                    if not started <= since <= updated_at_ms or generation == 0:
                        raise Rejected("security_telemetry_episode")
                    if kind == "heartbeat" and since > trigger:
                        raise Rejected("security_telemetry_episode")

    def document(self):
        return decode(canonical(self._document))

    def _stream(self, identity):
        return next(s for s in self._document["streams"] if s["producer_id"] == identity)

    def _heartbeat_value(self, stream):
        record = stream["heartbeat"]
        if record is None:
            return None
        events.shape(record, HEARTBEAT_RECORD)
        return self.registry.heartbeat(record["envelope"], clock_ms=record["ingested_at_ms"])

    def _claim(self, facts, identity, claimed):
        if claimed > known(facts, identity)[0] + REORDER_WINDOW:
            raise Rejected("security_heartbeat_claim_window")

    def _missing(self, stream, facts):
        highest, received = known(facts, stream["producer_id"])
        heartbeat = self._heartbeat_value(stream)
        expected = max(highest, heartbeat["last_event_sequence"] if heartbeat else 0)
        return expected > received

    def _heartbeat_deadline(self, stream):
        heartbeat = self._heartbeat_value(stream)
        observed = self._document["started_at_ms"]
        if heartbeat is not None:
            observed = min(heartbeat["observed_at_ms"], stream["heartbeat"]["ingested_at_ms"])
        return max(self._document["started_at_ms"], observed + events.GAP_MS)

    def _heartbeat_trigger(self, stream):
        return max(self._document["started_at_ms"], self._heartbeat_deadline(stream) - HEADROOM_MS)

    def heartbeat(self, envelope, *, facts, clock_ms):
        producer = self.registry.producer(events.signer(envelope))
        stream = self._stream(producer.identity)
        raw = events.signed(envelope, "security-heartbeat", producer.public_key)
        events.shape(raw, events.HEARTBEAT_FIELDS)
        sequence = events.integer(raw["sequence"])
        previous = self._heartbeat_value(stream)
        retry = previous is not None and sequence == previous["sequence"]
        admission = stream["heartbeat"]["ingested_at_ms"] if retry else clock_ms
        value = self.registry.heartbeat(envelope, clock_ms=admission)
        if retry:
            if canonical(previous) != canonical(value):
                raise Rejected("security_heartbeat_conflict")
            return decode(canonical(stream["heartbeat"])), False
        if previous is not None and (
            sequence < previous["sequence"]
            or value["observed_at_ms"] < previous["observed_at_ms"]
            or value["last_event_sequence"] < previous["last_event_sequence"]
        ):
            raise Rejected("security_heartbeat_regressed")
        self._claim(facts, producer.identity, value["last_event_sequence"])
        stream["heartbeat"] = {"envelope": decode(canonical(envelope)), "ingested_at_ms": clock_ms}
        return decode(canonical(stream["heartbeat"])), True

    @staticmethod
    def _episode(stream, kind, active, since_ms):
        field = kind + "_gap_since_ms"
        if active and stream[field] is None:
            count = events.integer(stream[kind + "_generation"] + 1)
            stream[field] = since_ms
            stream[kind + "_generation"] = count
        elif not active:
            stream[field] = None

    def reconcile(self, facts, clock_ms):
        for stream in self._document["streams"]:
            self._episode(stream, "sequence", self._missing(stream, facts), clock_ms)
            trigger = self._heartbeat_trigger(stream)
            due = (
                self.registry.producer(stream["producer_id"]).heartbeat_required
                and clock_ms >= trigger
            )
            self._episode(stream, "heartbeat", due, trigger)

    def report(self, *, clock_ms, pending, full):
        problems, awaiting = [], []
        gaps = expired = 0
        for stream in self._document["streams"]:
            producer = self.registry.producer(stream["producer_id"])
            if producer.heartbeat_required and stream["heartbeat"] is None:
                awaiting.append(producer.identity)
            for kind in ("sequence", "heartbeat"):
                since = stream[kind + "_gap_since_ms"]
                if since is None:
                    continue
                gaps += int(kind == "sequence")
                expired += int(kind == "heartbeat")
                if kind == "sequence":
                    trigger, deadline = since + DETECTION_MS, since + events.GAP_MS
                else:
                    trigger = since
                    deadline = min(since + HEADROOM_MS, self._heartbeat_deadline(stream))
                if clock_ms >= trigger:
                    notice_id = digest(
                        canonical(
                            {
                                "config": self.registry.sha256,
                                "producer": producer.identity,
                                "epoch": producer.epoch,
                                "reason": kind,
                                "generation": stream[kind + "_generation"],
                            }
                        )
                    )
                    problems.append(
                        {
                            "notice_id": notice_id,
                            "producer_id": producer.identity,
                            "epoch": producer.epoch,
                            "reason": kind,
                            "since_ms": since,
                            "deadline_at_ms": deadline,
                        }
                    )
        return {
            "schema_version": 1,
            "config_sha256": self.registry.sha256,
            "observed_at_ms": clock_ms,
            "healthy": not (awaiting or gaps or expired or pending or full),
            "awaiting_heartbeat": awaiting,
            "open_sequence_gaps": gaps,
            "expired_heartbeats": expired,
            "pending_deliveries": pending,
            "storage_full": full,
            "problems": problems,
            "release_ready": False,
        }
