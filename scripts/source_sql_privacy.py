"""Owned source-SQL log window for feedback qualification on hosted CI only."""

import re
import secrets
import time
from types import SimpleNamespace

from mlsecops import audit_snapshot, signing, storage_bootstrap, storage_snapshot
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields, safe_child
from scripts import kube_privacy_services as services
from scripts.kube_trust_native import hosted


def admin(state, statement):
    return storage_bootstrap.admin(storage_bootstrap.validate(state)["container_id"], statement)


BACKEND = SimpleNamespace(admin=admin)


def identity(state):
    owner = storage_bootstrap.validate(state)
    container = storage_bootstrap.inspect("container", owner["container_id"])
    if container["State"]["Running"] is not True:
        raise Rejected("feedback_sql_not_running")
    return {
        "container_id": owner["container_id"],
        "image": container["Image"],
        "started_at": container["State"]["StartedAt"],
        "config_digest": owner["config_digest"],
        "settings": services.settings(state, BACKEND),
    }


def capture(state, pinned, needles):
    if identity(state) != pinned:
        raise Rejected("feedback_sql_identity_changed")
    value = storage_snapshot.binary_streams(
        ["docker", "logs", "--timestamps", pinned["container_id"]], output_limit=65536, timeout=10
    )
    # The pinned main container starts postgres directly; log_destination=stderr.
    # Reject another stream instead of concatenating and inventing its ordering.
    if value["returncode"] or value["stdout"] or not value["stderr"]:
        raise Rejected("feedback_sql_log_stream")
    if identity(state) != pinned:
        raise Rejected("feedback_sql_identity_changed")
    if any(needle in value["stderr"] for needle in needles):
        raise Rejected("privacy_log_canary")
    return value["stderr"]


def verified(content, pinned, needles):
    value = decode(content, 262144)
    require_fields(value, ("schema_version", "identity", "before", "after", "start", "end"))
    if (
        canonical(value) != content
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["identity"] != pinned
    ):
        raise Rejected("feedback_sql_packet")
    before, after = (signing.decode64(value[key]) for key in ("before", "after"))
    services.verify_window(before, after, value["start"].encode(), value["end"].encode(), needles)
    return {
        "status": "pass",
        "closed_window": True,
        "leak_control_detected": True,
        "retained_reverified": True,
        "bytes": len(after),
        "sha256": digest(content),
        "release_ready": False,
    }


class Window:
    def __init__(self, state, destination, needles):
        hosted()
        if not state.is_absolute() or state.resolve() != state:
            raise Rejected("feedback_sql_state")
        try:
            if (
                safe_child(state, destination.relative_to(state).as_posix()) != destination
                or destination == state
            ):
                raise ValueError
        except ValueError:
            raise Rejected("feedback_sql_destination") from None
        self.state, self.destination, self.needles = state, destination, needles
        self.pinned = identity(state)
        self.closed = False
        self.start = ("tml-privacy-start-" + secrets.token_hex(16)).encode()
        services.mark(state, BACKEND, self.start)
        self.before = self.wait(self.start, needles)

    def wait(self, marker, needles):
        deadline = time.monotonic() + 5
        while True:
            raw = capture(self.state, self.pinned, needles)
            if raw.count(marker) == 1:
                return raw
            if raw.count(marker) > 1 or time.monotonic() >= deadline:
                raise Rejected("feedback_sql_marker_unobserved")
            time.sleep(0.1)

    def close(self):
        if self.closed:
            raise Rejected("feedback_sql_window_closed")
        self.closed = True
        end = ("tml-privacy-end-" + secrets.token_hex(16)).encode()
        services.mark(self.state, BACKEND, end)
        after = self.wait(end, self.needles)
        services.verify_window(self.before, after, self.start, end, self.needles)
        control = ("tml-privacy-control-" + secrets.token_hex(16)).encode()
        services.mark(self.state, BACKEND, control)
        try:
            self.wait(control, (control,))
        except Rejected as error:
            if str(error) != "privacy_log_canary":
                raise
        else:
            raise Rejected("feedback_sql_control_not_detected")
        content = canonical(
            {
                "schema_version": 1,
                "identity": self.pinned,
                "before": signing.encode64(self.before),
                "after": signing.encode64(after),
                "start": self.start.decode(),
                "end": end.decode(),
            }
        )
        expected = verified(content, self.pinned, self.needles)
        audit_snapshot.store_packet(self.destination, content)
        if (
            verified(audit_snapshot.load_packet(self.destination), self.pinned, self.needles)
            != expected
        ):
            raise Rejected("feedback_sql_retained_changed")
        return expected


def reverify(destination, pinned, needles, expected):
    if (
        type(expected) is not dict
        or re.fullmatch("[a-f0-9]{64}", expected.get("sha256", "")) is None
    ):
        raise Rejected("feedback_sql_receipt")
    result = verified(audit_snapshot.load_packet(destination), pinned, needles)
    if result != expected:
        raise Rejected("feedback_sql_retained_changed")
    return result
