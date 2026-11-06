"""Fixed private channel between the load probe and the disposable hosted operator."""

import re
import sys
import time
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
    write_json,
)

DIRECTORY = Path("/tmp/mlsecops-load")
MAX_PACKET = 32 * 1024 * 1024
PHASES = ("start", "finish")


def acknowledgement(value):
    require_fields(value, ("phase", "request_sha256", "status", "result"))
    if (
        value["phase"] not in PHASES
        or type(value["request_sha256"]) is not str
        or re.fullmatch("[a-f0-9]{64}", value["request_sha256"]) is None
        or value["status"] not in ("pass", "fail")
        or type(value["result"]) is not dict
    ):
        raise Rejected("load_operator_acknowledgement")
    return value


def send(directory, phase, campaign, payload):
    if (
        phase not in PHASES
        or type(campaign) is not str
        or re.fullmatch("[a-f0-9]{32}", campaign) is None
        or type(payload) is not dict
    ):
        raise Rejected("load_operator_request")
    request = {"phase": phase, "campaign": campaign, "payload": payload}
    content = canonical(request)
    if len(content) > MAX_PACKET:
        raise Rejected("load_operator_packet_limit")
    write_json(directory / "request.json", request)
    path = directory / (phase + "-ack.json")
    deadline = time.monotonic() + 45
    while not path.exists():
        if time.monotonic() >= deadline:
            raise Rejected("load_operator_deadline")
        time.sleep(0.1)
    ack = acknowledgement(decode(bounded_read(path, 16384), 16384))
    if ack["phase"] != phase or ack["request_sha256"] != digest(content) or ack["status"] != "pass":
        raise Rejected("load_operator_refused")
    return ack["result"]


def main():
    if sys.argv[1:] == ["read"]:
        path = DIRECTORY / "request.json"
        value = decode(bounded_read(path, MAX_PACKET), MAX_PACKET) if path.exists() else None
        print(canonical(value).decode(), flush=True)
        return 0
    if sys.argv[1:] == ["ack"]:
        value = acknowledgement(decode(sys.stdin.buffer.read(16385), 16384))
        write_json(DIRECTORY / (value["phase"] + "-ack.json"), value)
        return 0
    raise Rejected("load_operator_command")


if __name__ == "__main__":
    raise SystemExit(main())
