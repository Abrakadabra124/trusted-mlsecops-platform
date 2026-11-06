"""One private CLI handoff. Actual worker/audit two-phase exchange is unchanged."""

import re
import secrets

from mlsecops import signing
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.controller_api import identifier
from scripts import kube_privacy_exchange as exchange

MAX_REQUEST = 65536


def valid(needles):
    if (
        type(needles) is not tuple
        or len(needles) != 9
        or any(type(v) is not bytes or not 1 <= len(v) <= 4096 for v in needles)
        or len(set(needles)) != 9
    ):
        raise Rejected("cli_privacy_canary_inventory")


def provide(needles, *, directory=exchange.DIRECTORY):
    valid(needles)
    try:
        directory.mkdir(mode=0o700)
    except OSError:
        raise Rejected("cli_privacy_handoff_directory") from None
    try:
        result = exchange.send(
            directory,
            "audit",
            secrets.token_hex(16),
            {
                "needles": [signing.encode64(v) for v in needles],
            },
        )
        if canonical(result) != canonical({"accepted_canaries": 9}):
            raise Rejected("cli_privacy_handoff_ack")
    finally:
        try:
            (directory / "request.json").unlink(missing_ok=True)
            (directory / "audit-ack.json").unlink(missing_ok=True)
            directory.rmdir()
        except OSError:
            raise Rejected("cli_privacy_handoff_cleanup") from None


class Receiver:
    """Called only after invoke verifies the exact owned probe's spec and image."""

    def __init__(self, state):
        self.state, self.identity, self.needles = state, None, None

    def observe(self, pod):
        meta = pod["metadata"]
        name = identifier(meta["name"])
        identity = (meta["namespace"], name, meta["uid"])
        if (
            meta["namespace"] != "ml-serving"
            or type(meta["uid"]) is not str
            or not 1 <= len(meta["uid"]) <= 128
            or self.identity is not None
            and self.identity != identity
        ):
            raise Rejected("cli_privacy_handoff_identity")
        self.identity = identity
        if self.needles is not None:
            return
        program = (
            "import sys; from pathlib import Path; from mlsecops.contracts import bounded_read; "
            f"p=Path('{exchange.DIRECTORY}/request.json'); "
            f"sys.stdout.buffer.write(bounded_read(p,{MAX_REQUEST}) if p.exists() else b'null')"
        )
        response = kubectl(
            self.state,
            ["exec", name, "-n", "ml-serving", "-c", "worker", "--", "python", "-c", program],
            check=False,
        )
        if response.returncode:
            raise Rejected("cli_privacy_handoff_exec")
        request = decode(response.stdout, MAX_REQUEST)
        if request is None:
            return
        require_fields(request, ("phase", "campaign", "payload"))
        if (
            request["phase"] != "audit"
            or type(request["campaign"]) is not str
            or re.fullmatch("[a-f0-9]{32}", request["campaign"]) is None
        ):
            raise Rejected("cli_privacy_handoff_request")
        require_fields(request["payload"], ("needles",))
        values = request["payload"]["needles"]
        if (
            type(values) is not list
            or len(values) != 9
            or any(type(v) is not str or not 1 <= len(v) <= 5464 for v in values)
        ):
            raise Rejected("cli_privacy_canary_encoding")
        needles = tuple(signing.decode64(v) for v in values)
        valid(needles)
        if [signing.encode64(v) for v in needles] != values:
            raise Rejected("cli_privacy_canary_encoding")
        ack = {
            "phase": "audit",
            "request_sha256": digest(canonical(request)),
            "status": "pass",
            "result": {"accepted_canaries": 9},
        }
        program = (
            "import sys; from pathlib import Path; from mlsecops.contracts import decode,write_json; "
            f"write_json(Path('{exchange.DIRECTORY}/audit-ack.json'),decode(sys.stdin.buffer.read(4097),4096))"
        )
        response = kubectl(
            self.state,
            ["exec", "-i", name, "-n", "ml-serving", "-c", "worker", "--", "python", "-c", program],
            ack,
        )
        if response.returncode:
            raise Rejected("cli_privacy_handoff_exec")
        self.needles = needles

    def finish(self, raw):
        valid(self.needles)
        if (
            type(raw) is not bytes
            or not 1 <= len(raw) <= 2 * 1024 * 1024
            or any(v in raw or signing.encode64(v).encode() in raw for v in self.needles)
        ):
            raise Rejected("cli_privacy_handoff_output")
        return self.needles
