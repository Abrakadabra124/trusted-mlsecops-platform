"""Bounded loopback or explicit mutual TLS delivery from a durable producer outbox.

No URL, DNS, redirects, proxies, detached tasks or implicit initialization.
One wire attempt has a total deadline; an unknown result retains the envelope.
"""

import re
import socket
import time

from mlsecops import key_files, security_event_config, security_event_outbox, security_event_tls
from mlsecops import security_event_store as storage
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, bounded_read, canonical, decode

TIMEOUT = 2
MAX_HEADER = 8192
CONFIG_FIELDS = (
    "schema_version",
    "registry_file",
    "registry_root",
    "registry_sha256",
    "state_directory",
    "state_sha256",
    "producer_key_file",
    "ingress_token_file",
    "port",
)


def exchange(port, token, envelope, *, path="/events", tls=None):
    if path not in ("/events", "/admission", "/heartbeat"):
        raise Rejected("security_delivery_path")
    events.integer(port, 1024)
    if port > 65535:
        raise Rejected("security_delivery_port")
    events.hexadecimal(token)
    events.signer(envelope)
    content = canonical(envelope)
    deadline = time.monotonic() + TIMEOUT

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise Rejected("security_delivery_timeout")
        return value

    try:
        target = (
            tls.open(port, remaining)
            if tls is not None
            else socket.create_connection(("127.0.0.1", port), timeout=remaining())
        )
        host = tls.server_name if tls is not None else "127.0.0.1"
        with target as connection:
            connection.settimeout(remaining())
            connection.sendall(
                b"POST "
                + path.encode("ascii")
                + b" HTTP/1.1\r\nHost: "
                + host.encode("ascii")
                + b"\r\n"
                b"Content-Type: application/json\r\nConnection: close\r\nAuthorization: Bearer "
                + token.encode("ascii")
                + b"\r\nContent-Length: "
                + str(len(content)).encode("ascii")
                + b"\r\n\r\n"
                + content
            )
            packet = bytearray()
            while b"\r\n\r\n" not in packet:
                connection.settimeout(remaining())
                chunk = connection.recv(1024)
                if not chunk:
                    raise Rejected("security_delivery_response")
                packet.extend(chunk)
                if len(packet) > MAX_HEADER + events.MAX_ENVELOPE:
                    raise Rejected("security_delivery_response")
                if b"\r\n\r\n" not in packet and len(packet) > MAX_HEADER:
                    raise Rejected("security_delivery_response")
            header, body = bytes(packet).split(b"\r\n\r\n", 1)
            lines = header.split(b"\r\n")
            if (
                len(header) > MAX_HEADER
                or re.fullmatch(rb"HTTP/1\.[01] 200 [^\r\n]*", lines[0]) is None
            ):
                raise Rejected("security_delivery_response")
            lengths, types = [], []
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if not separator or re.fullmatch(rb"[A-Za-z0-9-]+", name) is None:
                    raise Rejected("security_delivery_response")
                if name.lower() in (b"transfer-encoding", b"content-encoding"):
                    raise Rejected("security_delivery_response")
                if name.lower() == b"content-length":
                    lengths.append(value.strip())
                if name.lower() == b"content-type":
                    types.append(value.strip())
            if (
                len(lengths) != 1
                or re.fullmatch(rb"[0-9]{1,4}", lengths[0]) is None
                or not 0 < int(lengths[0]) <= events.MAX_ENVELOPE
                or types != [b"application/json"]
            ):
                raise Rejected("security_delivery_response")
            length = int(lengths[0])
            while len(body) < length:
                connection.settimeout(remaining())
                chunk = connection.recv(length + 1 - len(body))
                if not chunk:
                    raise Rejected("security_delivery_response")
                body += chunk
            if len(body) != length:
                raise Rejected("security_delivery_response")
            remaining()
            return decode(body, events.MAX_ENVELOPE)
    except OSError:
        raise Rejected("security_delivery_transport") from None


class Client:
    def __init__(self, registry, port, token_file, *, tls=None):
        events.integer(port, 1024)
        if port > 65535:
            raise Rejected("security_delivery_port")
        self.registry, self.port, self.token_file = registry, port, storage.path(token_file)
        self.tls = tls

    def send(self, envelope, *, path="/events"):
        token = events.hexadecimal(key_files.read(self.token_file).decode("ascii"))
        # Store revalidates receipt signature, exact event binding and receiver times.
        return exchange(
            self.port,
            token,
            envelope,
            path=path,
            **({"tls": self.tls} if self.tls is not None else {}),
        )


class Emitter:
    def __init__(self, store, producer_key, client, *, clock=None):
        self.store, self.key, self.client = store, producer_key, client
        self.clock = clock or (lambda: time.time_ns() // 1_000_000)
        document = store.snapshot()
        if document["producer_id"] != security_event_outbox.key_identity(producer_key):
            raise Rejected("security_outbox_key")

    def heartbeat(self):
        # Allocation commits before any network call; unknown send outcome must
        # never reset this durable sequence. This echo is not a signed receipt.
        envelope = self.store.heartbeat(self.key, clock_ms=self.clock())
        try:
            result = self.client.send(envelope, path="/heartbeat")
            events.shape(result, ("heartbeat", "release_ready"))
            record = result["heartbeat"]
            events.shape(record, ("envelope", "ingested_at_ms"))
            now = self.clock()
            value = self.store.registry.heartbeat(envelope, clock_ms=now)
            ingested = events.integer(record["ingested_at_ms"])
            if (
                result["release_ready"] is not False
                or canonical(record["envelope"]) != canonical(envelope)
                or not value["observed_at_ms"] - events.CLOCK_SKEW_MS
                <= ingested
                <= now + events.CLOCK_SKEW_MS
                or now < value["observed_at_ms"]
            ):
                raise Rejected("security_heartbeat_echo")
        except Exception:
            raise Rejected("security_heartbeat_delivery_unconfirmed") from None
        return dict(
            state="sent",
            sequence=value["sequence"],
            last_event_sequence=value["last_event_sequence"],
            release_ready=False,
        )

    def retry(self):
        count = 0
        document = self.store.snapshot()
        now = self.clock()
        self.store.registry.valid(now)
        if now < document["updated_at_ms"]:
            raise Rejected("security_outbox_clock")
        for record in document["records"]:
            if record["receipt"] is None:
                try:
                    self.store.registry.valid(self.clock())
                    receipt = self.client.send(record["envelope"])
                    event = self.store.registry.verify(
                        record["envelope"], clock_ms=record["queued_at_ms"]
                    )
                    self.store.registry.receipt(receipt, event)
                    self.store.acknowledge(receipt, clock_ms=self.clock())
                except Exception:
                    raise Rejected("security_delivery_unconfirmed") from None
                count += 1
        return count

    def emit(self, fields):
        record = self.store.enqueue((fields, self.key), clock_ms=self.clock())
        if record["receipt"] is None:
            self.retry()
            # Immutable occurrence lookup, no sequence or timestamp rebasing on retry.
            record = self.store.enqueue((fields, self.key), clock_ms=self.clock())
        if record["receipt"] is None:
            raise Rejected("security_delivery_unconfirmed")
        return record["receipt"]


def configured(path):
    value = decode(bounded_read(storage.path(path), 16384), 16384)
    return configuration(value)


def configuration(value):
    version = value.get("schema_version") if type(value) is dict else None
    events.shape(value, (*CONFIG_FIELDS, "tls") if version == 2 else CONFIG_FIELDS)
    if type(version) is not int or version not in (1, 2):
        raise Rejected("security_delivery_config_schema")
    tls = security_event_tls.Client(value["tls"]) if version == 2 else None
    registry = security_event_config.Registry(
        decode(bounded_read(storage.path(value["registry_file"]), 32768), 32768),
        trusted_root=value["registry_root"],
        expected_sha256=value["registry_sha256"],
        clock_ms=time.time_ns() // 1_000_000,
    )
    key = storage.path(value["producer_key_file"])
    store = security_event_outbox.Store(
        value["state_directory"],
        value["state_sha256"],
        registry,
        security_event_outbox.key_identity(key),
    )
    client = Client(registry, value["port"], value["ingress_token_file"], tls=tls)
    return Emitter(store, key, client)
