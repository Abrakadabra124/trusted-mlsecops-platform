"""Unverified operator-submitted feedback in the existing append-only SQL quarantine.

The ingestor can store claims; only a curator can inspect them through this CLI.
Neither operation creates a verified label, source attestation or training dataset.
"""

import re
import sys
from pathlib import Path

from mlsecops import monitoring, storage
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, require_fields
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce as enforce_privacy

MAX_BYTES = 16384
FIELDS = ("model_sha256", "bundle_sha256", "records")
FLAGS = {
    "kind": "unverified-feedback",
    "training_eligible": False,
    "verified_labels": False,
    "release_ready": False,
}


def document(content):
    if type(content) is not bytes or not 0 < len(content) <= MAX_BYTES:
        raise Rejected("feedback_size")
    value = decode(content, MAX_BYTES)
    monitoring.schema(value, FIELDS)
    for field in FIELDS[:2]:
        monitoring.sha256(value[field])
    records = value["records"]
    if type(records) is not list or not 1 <= len(records) <= 100:
        raise Rejected("feedback_records")
    seen = set()
    for item in records:
        require_fields(item, ("request_id", "row_index", "label"))
        if (
            type(item["request_id"]) is not str
            or re.fullmatch("[a-f0-9]{32}", item["request_id"]) is None
        ):
            raise Rejected("feedback_request_id")
        row = monitoring.integer(item["row_index"], 0, 99)
        monitoring.integer(item["label"], 0, 1)
        identity = item["request_id"], row
        if identity in seen:
            raise Rejected("feedback_duplicate")
        seen.add(identity)
    return {**value, **FLAGS}


def role(client, expected):
    if (
        not Path(client).is_absolute()
        or storage.connection_parameters(client)["user"] != "ml_" + expected
    ):
        raise Rejected("feedback_role")


def receipt(record):
    return {
        "schema_version": 1,
        "status": "quarantined",
        "record_sha256": digest(canonical(record)),
        "submitted_records": len(record["records"]),
        "training_eligible": False,
        "verified_labels": False,
        "release_ready": False,
    }


def submit(client, content):
    role(client, "ingestor")
    record = document(content)
    content = canonical(record)
    reference = storage.put(client, "quarantine", content)
    if reference != digest(content):
        raise Rejected("feedback_write_binding")
    return receipt(record)


def read(client, reference):
    role(client, "curator")
    content = storage.get(client, "quarantine", reference)
    if len(content) > MAX_BYTES or digest(content) != reference:
        raise Rejected("feedback_read_binding")
    value = decode(content, MAX_BYTES)
    require_fields(value, ("schema_version", *FIELDS, *FLAGS))
    original = {key: value[key] for key in ("schema_version", *FIELDS)}
    expected = document(canonical(original))
    if canonical(value) != canonical(expected):
        raise Rejected("feedback_authority_forbidden")
    return expected


def main(arguments=None):
    try:
        enforce_privacy()
        parser = Arguments(prog="unverified-feedback")
        parser.add_argument("action", choices=("submit", "inspect"))
        parser.add_argument("--client", type=Path, required=True)
        parser.add_argument("--file", type=Path)
        parser.add_argument("--reference")
        options = parser.parse_args(arguments)
        if options.action == "submit":
            if options.file is None or options.reference is not None:
                raise Rejected("feedback_arguments")
            result = submit(options.client, bounded_read(options.file, MAX_BYTES))
        else:
            if options.reference is None or options.file is not None:
                raise Rejected("feedback_arguments")
            result = receipt(read(options.client, options.reference))
        print(canonical(result).decode(), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as failure:
        print("feedback_rejected", file=sys.stderr)
        return 130 if isinstance(failure, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
