"""Replay bounded committed trust history into the existing durable producer.

No callback between SQL commit and enqueue, no authority writes, no SQL rights
expansion. Explicit operator-pinned rotation packages verify historical roots.
Observer event times are enqueue times, not attestations of SQL commit time.
"""

import errno
import sys

import psycopg

from mlsecops import (
    release_policy,
    security_event_delivery,
    storage,
    trust,
    trust_rotation,
)
from mlsecops import security_event_store as journal
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce

MAX_VERSIONS = 64
MAX_HISTORY_BYTES = 8 * 1024 * 1024
MAX_ROTATIONS = 4
HISTORY_FIELDS = (
    "schema_version",
    "root_public",
    "head_version",
    "head_sha256",
    "clock",
    "documents",
)
CONFIG_FIELDS = (
    "schema_version",
    "trust_client",
    "environment",
    "initial_root",
    "producer_config",
    "rotations",
)


def _rotations(rotations):
    if type(rotations) not in (list, tuple) or len(rotations) > MAX_ROTATIONS:
        raise Rejected("trust_security_rotation_limit")
    result = {}
    for item in rotations:
        events.shape(item, ("version", "next_root", "package"))
        version = events.integer(item["version"], 2)
        events.public_key(item["next_root"])
        if (
            version > MAX_VERSIONS
            or version in result
            or len(canonical(item["package"])) > release_policy.MAX_DOCUMENT
        ):
            raise Rejected("trust_security_rotation_binding")
        result[version] = item
    return result


def project(history, *, environment, initial_root, rotations=()):
    release_policy.name(environment)
    root = events.public_key(initial_root)
    events.shape(history, HISTORY_FIELDS)
    events.version(history["schema_version"])
    clock = events.integer(history["clock"])
    head = events.integer(history["head_version"])
    documents = history["documents"]
    if (
        type(documents) is not list
        or not 1 <= head <= MAX_VERSIONS
        or len(documents) != head
        or len(canonical(history)) > MAX_HISTORY_BYTES
    ):
        raise Rejected("trust_security_history_limit_or_gap")
    pinned = _rotations(rotations)
    previous = previous_envelope = None
    observed, used = [], set()
    for version, item in enumerate(documents, 1):
        events.shape(item, ("version", "sha256", "envelope"))
        content = canonical(item["envelope"])
        if (
            events.integer(item["version"]) != version
            or not 0 < len(content) <= release_policy.MAX_DOCUMENT
            or digest(content) != item["sha256"]
        ):
            raise Rejected("trust_security_document_binding")
        if previous is not None and trust_rotation.key_id(root) in previous["revoked_keys"]:
            raise Rejected("trust_security_revoked_signer")
        if version in pinned:
            rotation = pinned[version]
            intent = trust_rotation.authorization(rotation["package"], root)
            if previous is None or canonical(rotation["package"]["document"]) != content:
                raise Rejected("trust_security_rotation_document")
            trust_rotation.verify(
                rotation["package"],
                previous=previous_envelope,
                environment=environment,
                current_root=root,
                next_root=rotation["next_root"],
                clock=intent["issued_at"],
            )
            root = rotation["next_root"]
            used.add(version)
        payload = trust.validate(item["envelope"], root, environment)
        if payload["version"] != version or payload["issued_at"] > clock:
            raise Rejected("trust_security_document_version_or_future")
        if previous is not None:
            trust.successor(previous, payload)
        reasons = []
        for field, reason in (("revoked_artifacts", "artifact"), ("revoked_keys", "key")):
            if set(payload[field]) - (set(previous[field]) if previous else set()):
                reasons.append(reason)
        if previous and payload["promotion_policy_sha256"] != previous["promotion_policy_sha256"]:
            reasons.append("policy")
        for reason in reasons:
            correlation = digest(
                canonical(
                    dict(
                        environment=environment,
                        initial_root=initial_root,
                        document=item["sha256"],
                        reason=reason,
                    )
                )
            )[:32]
            observed.append(
                dict(
                    kind="trust.revoked",
                    reason=reason,
                    correlation_id=correlation,
                    asset_sha256=item["sha256"],
                    bundle_sha256=None,
                )
            )
        previous, previous_envelope = payload, item["envelope"]
    if (
        used != set(pinned)
        or root != history["root_public"]
        or documents[-1]["sha256"] != history["head_sha256"]
    ):
        raise Rejected("trust_security_head_or_rotation_binding")
    return observed


def read(client, environment):
    release_policy.name(environment)
    if storage.connection_parameters(client)["user"] != "ml_serving":
        raise Rejected("trust_security_reader_role")
    try:
        with storage.connect(client) as connection:
            # One statement snapshot; role has existing SELECT only. The limit
            # bounds transport even if a hostile/large authority exceeds the cap.
            rows = connection.execute(
                "WITH head AS (SELECT version, sha256 FROM ml_trust.documents ORDER BY version DESC LIMIT 1) "
                "SELECT settings.root_public, head.version, head.sha256, "
                "floor(extract(epoch FROM statement_timestamp()))::bigint, "
                "document.version, document.sha256, document.envelope "
                "FROM ml_trust.settings CROSS JOIN head CROSS JOIN ml_trust.documents document "
                "WHERE settings.environment = %s ORDER BY document.version LIMIT %s",
                (environment, MAX_VERSIONS + 1),
            ).fetchall()
    except psycopg.Error:
        raise Rejected("trust_security_source_unavailable") from None
    if not rows or len(rows) > MAX_VERSIONS:
        raise Rejected("trust_security_history_limit_or_gap")
    metadata = rows[0][:4]
    documents, size = [], 0
    for row in rows:
        if len(row) != 7 or row[:4] != metadata:
            raise Rejected("trust_security_snapshot_binding")
        content = bytes(row[6])
        size += len(content)
        if not 0 < len(content) <= release_policy.MAX_DOCUMENT or size > MAX_HISTORY_BYTES:
            raise Rejected("trust_security_history_limit_or_gap")
        envelope = decode(content, release_policy.MAX_DOCUMENT)
        if canonical(envelope) != content or digest(content) != row[5]:
            raise Rejected("trust_security_document_binding")
        documents.append(dict(version=row[4], sha256=row[5], envelope=envelope))
    return dict(
        schema_version=1,
        root_public=metadata[0],
        head_version=metadata[1],
        head_sha256=metadata[2],
        clock=metadata[3],
        documents=documents,
    )


def producer(emitter):
    document = emitter.store.snapshot()
    if emitter.store.registry.producer(document["producer_id"]).role != "trust":
        raise Rejected("trust_security_producer_role")
    return document


def sync(history, emitter, *, environment, initial_root, rotations=()):
    fields = project(
        history, environment=environment, initial_root=initial_root, rotations=rotations
    )
    expected = {item["correlation_id"]: item for item in fields}
    document = producer(emitter)
    for record in document["records"]:
        value = emitter.store.registry.verify(
            record["envelope"], clock_ms=record["queued_at_ms"]
        ).document()
        projection = {
            key: value[key]
            for key in ("kind", "reason", "correlation_id", "asset_sha256", "bundle_sha256")
        }
        if expected.get(value["correlation_id"]) != projection:
            raise Rejected("trust_security_history_conflicts_with_outbox")
    try:
        emitter.retry()
        for item in fields:
            emitter.emit(item)
    except Exception:
        raise Rejected("trust_security_delivery_unconfirmed") from None
    return dict(
        state="observed",
        version=history["head_version"],
        document_sha256=history["head_sha256"],
        events=len(fields),
        release_ready=False,
    )


def configuration(path, expected=None):
    content = bounded_read(journal.path(path), 16384)
    reference = digest(content)
    if expected is not None and reference != events.hexadecimal(expected):
        raise Rejected("trust_security_configuration_changed")
    config = decode(content, 16384)
    events.shape(config, CONFIG_FIELDS)
    events.version(config["schema_version"])
    journal.path(config["trust_client"])
    journal.path(config["producer_config"])
    release_policy.name(config["environment"])
    events.public_key(config["initial_root"])
    if type(config["rotations"]) is not list or len(config["rotations"]) > MAX_ROTATIONS:
        raise Rejected("trust_security_rotation_limit")
    return config, reference


def configured(path, *, expected=None, heartbeat=False):
    config, _ = configuration(path, expected)
    rotations = []
    for item in config["rotations"]:
        events.shape(item, ("version", "next_root", "package_file"))
        rotations.append(
            dict(
                version=item["version"],
                next_root=item["next_root"],
                package=decode(
                    bounded_read(journal.path(item["package_file"]), release_policy.MAX_DOCUMENT),
                    release_policy.MAX_DOCUMENT,
                ),
            )
        )
    _rotations(rotations)
    emitter = security_event_delivery.configured(journal.path(config["producer_config"]))
    document = producer(emitter)
    if heartbeat and (
        document["schema_version"] != 2
        or not emitter.store.registry.producer(document["producer_id"]).heartbeat_required
    ):
        raise Rejected("trust_security_heartbeat_profile")
    result = sync(
        read(journal.path(config["trust_client"]), config["environment"]),
        emitter,
        environment=config["environment"],
        initial_root=config["initial_root"],
        rotations=rotations,
    )
    if heartbeat:
        emitter.heartbeat()
    return result


DIAGNOSTIC_CODES = {
    41: "source_unavailable",
    42: "journal_busy",
    43: "journal_unavailable",
    44: "delivery_unconfirmed",
}


def diagnostic_code(error):
    """Bounded classification only; never export exception text, paths or data."""
    fallback = 1
    for _ in range(4):
        if isinstance(error, Rejected):
            reason = str(error)
            if reason == "trust_security_source_unavailable":
                return 41
            if reason == "security_store_unavailable":
                cause = error.__cause__ or error.__context__
                if isinstance(cause, BlockingIOError) and cause.errno in (
                    errno.EAGAIN,
                    errno.EWOULDBLOCK,
                ):
                    return 42
                return 43
            if reason == "trust_security_delivery_unconfirmed":
                fallback = 44
        error = error.__cause__ or error.__context__
        if error is None:
            break
    return fallback


def main(arguments=None):
    parser = Arguments()
    parser.add_argument("--config", required=True)
    parser.add_argument("--config-sha256")
    parser.add_argument("--heartbeat", action="store_true")
    parser.add_argument("--diagnostic-exit-code", action="store_true")
    options = None
    try:
        options = parser.parse_args(arguments)
        enforce()
        if options.heartbeat and options.config_sha256 is None:
            raise Rejected("trust_security_pin_required")
        if options.diagnostic_exit_code and not options.heartbeat:
            raise Rejected("trust_security_diagnostic_mode")
        print(
            canonical(
                configured(
                    options.config, expected=options.config_sha256, heartbeat=options.heartbeat
                )
            ).decode()
        )
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("trust_security_rejected", file=sys.stderr)
        if isinstance(error, KeyboardInterrupt):
            return 130
        return diagnostic_code(error) if options is not None and options.diagnostic_exit_code else 1


if __name__ == "__main__":
    raise SystemExit(main())
