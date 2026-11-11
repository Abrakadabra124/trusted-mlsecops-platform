"""Finite inventory decisions through the existing durable event producer.

An operator-pinned graph snapshot is not a live deployment enumeration. A
candidate observation reads signed SQL metadata and bounded model bytes for
digest validation, never final-holdout labels; none are copied into events.
"""

import secrets
import sys

from mlsecops import asset_graph, security_event_delivery
from mlsecops import security_event_store as journal
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, require_fields
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce

MAX_REQUEST = 4 * 1024 * 1024
CONFIG_FIELDS = ("schema_version", "mode", "request_file", "request_sha256", "producer_config")
GRAPH_FIELDS = ("document", "trusted_owners", "environment", "snapshot", "revoked")
CONTEXT_FIELDS = (
    "candidate_reference",
    "evaluation_reference",
    "policy",
    "trust",
    "expected",
    "owners",
    "known_owners",
)


def producer(audit):
    document = audit.store.snapshot()
    audit.store.registry.valid(audit.clock())
    if audit.store.registry.producer(document["producer_id"]).role not in (
        "controller",
        "promoter",
        "serving",
    ):
        raise Rejected("inventory_security_producer_role")


def capture(operation, *, audit, subject):
    if audit is None:
        return operation()
    producer(audit)
    try:
        audit.retry()
    except Exception:
        raise Rejected("inventory_security_delivery_unconfirmed") from None
    try:
        return operation()
    except asset_graph.InventoryMismatch as finding:
        if finding.reason not in ("digest", "dangling", "owner", "cycle"):
            raise Rejected("inventory_security_reason") from None
        reference = events.hexadecimal(subject())
        fields = dict(
            kind="inventory.mismatch",
            reason=finding.reason,
            correlation_id=secrets.token_hex(16),
            asset_sha256=reference,
            bundle_sha256=None,
        )
        try:
            audit.emit(fields)
        except Exception:
            raise Rejected("inventory_security_delivery_unconfirmed") from None
        raise


def configured(path):
    config = decode(bounded_read(journal.path(path), 16384), 16384)
    require_fields(config, CONFIG_FIELDS)
    events.version(config["schema_version"])
    if config["mode"] not in ("candidate", "graph"):
        raise Rejected("inventory_security_mode")
    reference = events.hexadecimal(config["request_sha256"])
    content = bounded_read(journal.path(config["request_file"]), MAX_REQUEST)
    if digest(content) != reference:
        raise Rejected("inventory_security_request_pin")
    request = decode(content, MAX_REQUEST)
    audit = security_event_delivery.configured(journal.path(config["producer_config"]))
    if config["mode"] == "candidate":
        from mlsecops import candidate_lineage

        require_fields(request, ("metadata_client", "review_client", "context"))
        require_fields(request["context"], CONTEXT_FIELDS)
        result = candidate_lineage.collect(
            journal.path(request["metadata_client"]),
            journal.path(request["review_client"]),
            audit=audit,
            **request["context"],
        )
        subject = result["bindings"]["candidate_reference"]
        scope = result["scope"]
    else:
        require_fields(request, GRAPH_FIELDS)
        capture(
            lambda: asset_graph.assess(**request),
            audit=audit,
            subject=lambda: reference,
        )
        subject = reference
        scope = "pinned-graph-and-observation-not-live-inventory"
    return dict(
        state="verified",
        subject_sha256=subject,
        scope=scope,
        full_M19="inconclusive",
        release_ready=False,
    )


def main(arguments=None):
    parser = Arguments()
    parser.add_argument("--config", required=True)
    try:
        options = parser.parse_args(arguments)
        enforce()
        print(canonical(configured(options.config)).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("inventory_security_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
