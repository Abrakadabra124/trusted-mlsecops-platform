"""Private, bounded M23 probe/operator exchange with no infrastructure authority."""

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

DIRECTORY = Path("/tmp/mlsecops-security-outage")
PHASES = ("ready", "outage", "attempt", "recover", "finish")
MAX_PACKET = 32 * 1024 * 1024
TIMEOUT = 120


def identity(value, length):
    if type(value) is not str or re.fullmatch("[a-f0-9]{" + str(length) + "}", value) is None:
        raise Rejected("security_exchange_identity")
    return value


def request(value):
    require_fields(value, ("phase", "campaign", "payload"))
    identity(value["campaign"], 32)
    if value["phase"] not in PHASES or type(value["payload"]) is not dict:
        raise Rejected("security_exchange_request")
    if len(canonical(value)) > MAX_PACKET:
        raise Rejected("security_exchange_size")
    return value


def acknowledgement(value):
    require_fields(value, ("phase", "request_sha256", "status", "result"))
    identity(value["request_sha256"], 64)
    if (
        value["phase"] not in PHASES
        or value["status"] not in ("pass", "fail")
        or type(value["result"]) is not dict
    ):
        raise Rejected("security_exchange_ack")
    return value


class Channel:
    """The caller keeps ML observations running between nonblocking poll calls."""

    def __init__(self, directory, campaign, *, clock=time.monotonic):
        self.directory, self.campaign = Path(directory), identity(campaign, 32)
        self.clock, self.index, self.active, self.failed = clock, 0, None, False

    def begin(self, phase, payload):
        if (
            self.failed
            or self.active is not None
            or self.index == len(PHASES)
            or phase != PHASES[self.index]
        ):
            raise Rejected("security_exchange_order")
        value = request({"phase": phase, "campaign": self.campaign, "payload": payload})
        # Include publication time in the budget, not only waiting for the ack.
        deadline = self.clock() + TIMEOUT
        write_json(self.directory / "request.json", value)
        self.active = (phase, digest(canonical(value)), deadline)

    def poll(self):
        if self.active is None or self.failed:
            raise Rejected("security_exchange_not_active")
        phase, reference, deadline = self.active
        try:
            if self.clock() >= deadline:
                raise Rejected("security_exchange_deadline")
            path = self.directory / (phase + "-ack.json")
            if not path.exists():
                return None
            value = acknowledgement(decode(bounded_read(path, 16384), 16384))
            if self.clock() >= deadline:
                raise Rejected("security_exchange_deadline")
            if (
                value["phase"] != phase
                or value["request_sha256"] != reference
                or value["status"] != "pass"
            ):
                raise Rejected("security_exchange_refused")
        except Exception:
            self.failed = True
            raise
        self.active = None
        self.index += 1
        return value["result"]


def main():
    if sys.argv[1:] == ["read"]:
        path = DIRECTORY / "request.json"
        value = (
            request(decode(bounded_read(path, MAX_PACKET), MAX_PACKET)) if path.exists() else None
        )
        print(canonical(value).decode(), flush=True)
        return 0
    if sys.argv[1:] == ["ack"]:
        value = acknowledgement(decode(sys.stdin.buffer.read(16385), 16384))
        write_json(DIRECTORY / (value["phase"] + "-ack.json"), value)
        return 0
    raise Rejected("security_exchange_command")


if __name__ == "__main__":
    raise SystemExit(main())
