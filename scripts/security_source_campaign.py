"""Owned hosted intake/controller campaign with private post-cleanup replay."""

import os
import sys
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.security_intake_evidence import MAX_BYTES, verify
from mlsecops.trust_acceptance import materials
from scripts.security_event_source_live_qualification import SourceLive

PACKET = ".runtime/evidence/security-source-private.json"


def replay(path, *, expected, expected_sha256):
    content = bounded_read(path, MAX_BYTES)
    if digest(content) != expected_sha256:
        raise Rejected("source_campaign_primary_changed")
    return {
        **verify(decode(content, MAX_BYTES), expected=expected),
        "primary_file_sha256": expected_sha256,
    }


def retain(packet, path, *, expected):
    result = verify(packet, expected=expected)
    write_json(path, packet)
    restored = replay(path, expected=expected, expected_sha256=digest(canonical(packet) + b"\n"))
    if restored != {**result, "primary_file_sha256": digest(canonical(packet) + b"\n")}:
        raise Rejected("source_campaign_replay_changed")
    binding = {"expected": expected, "primary_sha256": restored["primary_file_sha256"]}
    binding_path = Path(path).with_suffix(".bindings.json")
    write_json(binding_path, binding)
    content = bounded_read(binding_path, MAX_BYTES)
    if content != canonical(binding) + b"\n":
        raise Rejected("source_campaign_binding_changed")
    return {**restored, "binding_sha256": digest(content)}


def qualify():
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("source_campaign_hosted_required")
    root = Path(__file__).resolve().parents[1]
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("source_campaign_dirty")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint, methods = source_fingerprint(root), materials(root)
    fixture = SourceLive("runTest")
    try:
        fixture.setUp()
        expected = dict(
            source=revision,
            fingerprint=fingerprint,
            materials=methods,
            root=fixture.fx.fx.publics["root"],
            pin=fixture.fx.registry.sha256,
            policy_sha256=digest(canonical(read_json(root / "policies/local-cpu.json"))),
            transport="owned-linux-http",
        )
        primary = fixture.capture_campaign()
    finally:
        if not fixture.doCleanups():
            raise Rejected("source_campaign_cleanup_failed")
    packet = dict(
        schema_version=1,
        source=revision,
        fingerprint=fingerprint,
        method_materials=methods,
        source_after=command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        fingerprint_after=source_fingerprint(root),
        materials_after=materials(root),
        source_clean=not command(["git", "-C", str(root), "status", "--porcelain"]),
        campaign=primary,
    )
    return retain(packet, root / PACKET, expected=expected)


if __name__ == "__main__":
    try:
        print(canonical(qualify()).decode("ascii"))
    except Exception:
        print(
            canonical(
                dict(status="fail", code="source_campaign_rejected", release_ready=False)
            ).decode("ascii")
        )
        raise SystemExit(1) from None
