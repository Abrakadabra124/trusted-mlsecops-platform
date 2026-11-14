"""Bounded M18/M23 primary assembly CLI; no capture campaign or replacement report.

Before measurements: python -m scripts.m18_security_driver case-inventory
Save expected_cases_sha256 externally, alongside the exact source revision.
After original M23 + transition: run capture, then replay using its index_sha256.

Both modes require M18_FREEZE_SHA256, M18_SECURITY_CASES_SHA256,
M23_{REPORT,PROPOSAL,SOURCES,INVENTORY,OUTAGE,TRANSITION,WORKSPACE}_SHA256,
M23_RUN_ID and M23_RUN_ATTEMPT. WORKSPACE is the hash of original workspace.json
bytes, not the workspace ID. Replay also requires M18_SECURITY_INDEX_SHA256.
Never infer pins, case inventory or original run owner from the tested report.

The original shared M18 freeze receipt and its four pinned files must remain
available, together with its already retained signed proposal package. Replay
needs no other original M23 files or live authority. Source SQL can be stopped.
Results are JSON; when set, GITHUB_OUTPUT also receives the scalar outputs.
This fragment grants neither full M18 acceptance nor release permission.
"""

import os
import sys
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, decode, safe_child
from scripts import m18_delivery_freeze as freeze
from scripts import m18_security_retention as retention

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "M18-original-security-primary"


def run(root, state, mode, *, freeze_pin, pins, owner, expected_cases, index_pin=None):
    """Verify the original signed M18 inputs before either ordinary M23 replay."""
    final, schema = retention.final, retention.schema
    final.need(mode in ("capture", "replay"), "security-driver-mode")
    final.same(expected_cases, retention.case_inventory(root), "security-prerun-cases")
    schema.shape(pins, retention.PIN_FIELDS)
    for pin in (*pins.values(), freeze_pin):
        schema.hexadecimal(pin)
    if mode == "capture":
        final.same(index_pin, None, "security-unexpected-index")
    else:
        schema.hexadecimal(index_pin)
    receipt = decode(final.pinned(safe_child(state, freeze.RECEIPT), freeze_pin))
    schema.shape(
        receipt,
        (
            "schema_version",
            "source_revision",
            "source_fingerprint",
            "image_id",
            "freeze",
            "policy_reference",
        ),
    )
    schema.version(receipt["schema_version"])
    revision, fingerprint = receipt["source_revision"], receipt["source_fingerprint"]
    final.clean(root, revision, fingerprint)
    final.same(
        receipt["freeze"][retention.candidate.PROPOSAL],
        pins["proposal"],
        "security-freeze-proposal",
    )
    values, _, _ = final.frozen(root, state, receipt, revision, fingerprint)
    args = dict(values=values, pins=pins, owner=owner, expected_cases=expected_cases)
    if mode == "capture":
        result = retention.collect(root, state, **args)
    else:
        result = retention.replay(root, state, index_pin=index_pin, **args)
        result["index_sha256"] = index_pin
    return dict(
        schema_version=1,
        scope=SCOPE,
        frozen_inputs_sha256=freeze_pin,
        expected_cases_sha256=expected_cases,
        **result,
    )


def main(arguments=None):
    args = sys.argv[1:] if arguments is None else arguments
    retention.final.need(
        args in (["case-inventory"], ["capture"], ["replay"]), "security-driver-arguments"
    )
    if args == ["case-inventory"]:
        result = dict(
            schema_version=1,
            scope=SCOPE,
            release_ready=False,
            expected_cases_sha256=retention.case_inventory(ROOT),
        )
    else:
        result = run(
            ROOT,
            ROOT / ".runtime",
            args[0],
            freeze_pin=os.environ["M18_FREEZE_SHA256"],
            pins={
                key: os.environ["M23_" + key.upper() + "_SHA256"] for key in retention.PIN_FIELDS
            },
            owner={
                "GITHUB_RUN_ID": os.environ["M23_RUN_ID"],
                "GITHUB_RUN_ATTEMPT": os.environ["M23_RUN_ATTEMPT"],
            },
            expected_cases=os.environ["M18_SECURITY_CASES_SHA256"],
            index_pin=os.environ["M18_SECURITY_INDEX_SHA256"] if args == ["replay"] else None,
        )
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as stream:
            for key, value in result.items():
                print(
                    f"{key}={canonical(value).decode() if not isinstance(value, str) else value}",
                    file=stream,
                )
    print(canonical(result).decode())


def cli():
    try:
        main()
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        sys.exit("M18 security primary verification failed")


if __name__ == "__main__":
    cli()
