"""Serving-only identity decisions; no credential, address or request body input."""

import sys

from mlsecops import security_event_delivery
from mlsecops import security_event_store as journal
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, require_fields
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce

FIELDS = ("schema_version", "producer_config", "service_sha256")
ACTIONS = ("probe", "credential", "role")


def configuration(path, expected=None):
    content = bounded_read(journal.path(path), 16384)
    reference = digest(content)
    if expected is not None and reference != events.hexadecimal(expected):
        raise Rejected("identity_security_configuration_changed")
    value = decode(content, 16384)
    require_fields(value, FIELDS)
    events.version(value["schema_version"])
    journal.path(value["producer_config"])
    events.hexadecimal(value["service_sha256"])
    return value, reference


def execute(path, expected, action, correlation):
    if action not in ACTIONS:
        raise Rejected("identity_security_action")
    events.hexadecimal(expected)
    events.hexadecimal(correlation, 32)
    config, pin = configuration(path, expected)
    audit = security_event_delivery.configured(config["producer_config"])
    document = audit.store.snapshot()
    audit.store.registry.valid(audit.clock())
    if audit.store.registry.producer(document["producer_id"]).role != "serving":
        raise Rejected("identity_security_producer_role")
    if action == "probe":
        audit.retry()
    else:
        audit.emit(
            dict(
                kind="identity.denied",
                reason=action,
                correlation_id=correlation,
                asset_sha256=config["service_sha256"],
                bundle_sha256=None,
            )
        )
    return dict(
        state="ready" if action == "probe" else "delivered",
        config_sha256=pin,
        service_sha256=config["service_sha256"],
        correlation_id=correlation,
        action=action,
        release_ready=False,
    )


def main(arguments=None):
    parser = Arguments()
    parser.add_argument("--config", required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--correlation", required=True)
    try:
        options = parser.parse_args(arguments)
        enforce()
        print(
            canonical(
                execute(options.config, options.config_sha256, options.action, options.correlation)
            ).decode()
        )
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("identity_security_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
