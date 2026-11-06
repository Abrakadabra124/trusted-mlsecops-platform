"""Bounded private Pod-to-operator handoff, never a public logging channel."""

import re
import time
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest, read_json, require_fields, write_json

DIRECTORY = Path("/tmp/mlsecops-privacy")
MAX_REQUEST = 2 * 1024 * 1024
PHASES = ("worker", "audit")


def send(directory, phase, campaign, payload):
    if (
        phase not in PHASES
        or type(campaign) is not str
        or re.fullmatch("[a-f0-9]{32}", campaign) is None
        or type(payload) is not dict
    ):
        raise Rejected("privacy_operator_request")
    request = {"phase": phase, "campaign": campaign, "payload": payload}
    content = canonical(request)
    if len(content) > MAX_REQUEST:
        raise Rejected("privacy_operator_request_limit")
    write_json(directory / "request.json", request)
    acknowledgement = directory / (phase + "-ack.json")
    deadline = time.monotonic() + 45
    while not acknowledgement.exists():
        if time.monotonic() >= deadline:
            raise Rejected("privacy_operator_deadline")
        time.sleep(0.1)
    ack = read_json(acknowledgement)
    require_fields(ack, ("phase", "request_sha256", "status", "result"))
    if (
        ack["phase"] != phase
        or ack["request_sha256"] != digest(content)
        or ack["status"] != "pass"
        or type(ack["result"]) is not dict
    ):
        raise Rejected("privacy_operator_refused")
    return ack["result"]
