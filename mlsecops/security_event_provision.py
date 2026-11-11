"""Operator-only fresh-volume action. Runtime services never call this entrypoint."""

import sys
import time

from mlsecops import security_event_config as config
from mlsecops import security_event_outbox as outbox
from mlsecops import security_event_store as journal
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, bounded_read, canonical, decode
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce

ROOT = "/audit/state"
FIELDS = ("schema_version", "role", "registry", "registry_root", "registry_sha256", "producer_id")


def provision(value):
    events.shape(value, FIELDS)
    events.version(value["schema_version"])
    role = value["role"]
    if type(role) is not str or role not in ("collector", "trust", "promoter"):
        raise Rejected("security_provision_role")
    clock = time.time_ns() // 1_000_000
    registry = config.Registry(
        value["registry"],
        trusted_root=value["registry_root"],
        expected_sha256=value["registry_sha256"],
        clock_ms=clock,
    )
    producer = registry.producer(value["producer_id"])
    if producer.role != role or role == "trust" and not producer.heartbeat_required:
        raise Rejected("security_provision_identity")
    if role == "collector":
        pin = journal.initialize(ROOT, registry, clock_ms=clock)
        store = journal.Store(ROOT, pin, registry)
    else:
        pin = outbox.initialize(ROOT, registry, producer.identity, clock_ms=clock)
        store = outbox.Store(ROOT, pin, registry, producer.identity)
    store.snapshot()  # Reopen and verify committed identity, private files and state.
    return dict(
        schema_version=1,
        role=role,
        producer_id=producer.identity,
        registry_sha256=registry.sha256,
        state_sha256=pin,
        release_ready=False,
    )


def main(arguments=None):
    try:
        enforce()
        parser = Arguments(prog="security-event-provision")
        parser.add_argument("--config", required=True)
        options = parser.parse_args(arguments)
        value = decode(bounded_read(journal.path(options.config), 65536), 65536)
        print(canonical(provision(value)).decode())
        return 0
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        print("security_provision_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
