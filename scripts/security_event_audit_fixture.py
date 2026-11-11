"""Owned real collector for hosted native promotion qualification only."""

import os
import sys
from contextlib import contextmanager

from mlsecops import promotion, security_event_admission, security_event_outbox, signing
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import security_event_live_qualification as fixtures


def heartbeat(fx, sequence=1):
    value = fx.fx.heartbeat(
        sequence=sequence,
        observed_at_ms=fx.now(),
        last_event_sequence=0,
        producer_id=digest(signing.decode64(fx.fx.publics["serving"])),
    )
    envelope = signing.sign(value, "security-heartbeat", fx.fx.keys["serving"])
    if fx.exchange("POST", "/heartbeat", envelope, token=fx.ingress)[0] != 200:
        raise Rejected("audit_fixture_heartbeat_failed")


@contextmanager
def live(*, initial_heartbeat=True, heartbeat_roles=("serving",)):
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("audit_fixture_hosted_required")
    fx = fixtures.LiveCollector("runTest")
    fx.heartbeat_roles = heartbeat_roles
    try:
        fx.setUp()
        config = decode((fx.directory / "collector.json").read_bytes())
        config = {
            k: config[k]
            for k in (
                "schema_version",
                "registry_file",
                "registry_root",
                "registry_sha256",
                "ingress_token_file",
                "port",
            )
        }
        config["producer_key_file"] = str(fx.fx.keys["promoter"])
        config["schema_version"] = 2
        config["state_directory"] = str(fx.directory / "promoter-outbox")
        config["state_sha256"] = security_event_outbox.initialize(
            config["state_directory"],
            fx.registry,
            security_event_outbox.key_identity(fx.fx.keys["promoter"]),
            clock_ms=fx.now(),
        )
        fx.audit_config = fx.directory / "audit.json"
        fx.write("audit.json", canonical(config))
        fx.start()
        if initial_heartbeat:
            heartbeat(fx)
        fx.audit = security_event_admission.Configured(str(fx.audit_config))
        yield fx
    finally:
        try:
            if hasattr(fx, "process"):
                fx.stop()  # Propagate cleanup failure; TestCase cleanups alone may collect it.
        finally:
            if not fx.doCleanups():
                raise Rejected("audit_fixture_cleanup_failed")


def promote(*args, **kwargs):
    with live() as fx:
        return promotion.promote(*args, audit=fx.audit, **kwargs)
