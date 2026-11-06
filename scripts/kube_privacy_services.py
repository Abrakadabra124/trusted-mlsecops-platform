"""Closed, owned SQL log windows for hosted qualification, not process lifetimes."""

import re
import secrets
import time

from mlsecops import audit_snapshot, kube_storage, kube_trust, signing
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest, safe_child
from mlsecops.kube_worker import verify_running_image
from scripts import kube_privacy_logs as logs
from scripts.kube_trust_native import hosted

SETTINGS = {
    "log_destination": "stderr",
    "logging_collector": "off",
    "log_statement": "none",
    "log_min_messages": "warning",
    "log_min_error_statement": "panic",
    "log_error_verbosity": "terse",
    "log_duration": "off",
    "log_min_duration_statement": "-1",
    "log_min_duration_sample": "-1",
    "log_transaction_sample_rate": "0",
    "log_replication_commands": "off",
    "log_parameter_max_length_on_error": "0",
    "debug_print_parse": "off",
    "debug_print_rewritten": "off",
    "debug_print_plan": "off",
    "shared_preload_libraries": "",
    "session_preload_libraries": "",
    "local_preload_libraries": "",
}
MARKER = rb"tml-privacy-(?:start|end|control)-[a-f0-9]{32}"


def settings(state, module):
    names = ",".join("'" + name + "'" for name in sorted(SETTINGS))
    value = decode(
        module.admin(
            state,
            "SELECT json_object_agg(name,setting) FROM pg_settings WHERE name IN (" + names + ");",
        ).encode(),
        65536,
    )
    if (
        value != SETTINGS
        or module.admin(
            state,
            "SELECT count(*) FROM pg_db_role_setting CROSS JOIN LATERAL unnest(setconfig) AS value "
            "WHERE split_part(value,'=',1) IN (" + names + ");",
        )
        != "0"
    ):
        raise Rejected("privacy_service_settings")
    return value


def inspect(state, module):
    marker = module.validate(state)
    document = next(v for v in module.desired(state) if v["kind"] == "StatefulSet")
    namespace = document["metadata"]["namespace"]
    owner = marker["resources"][kube_storage.reference(document)]
    pod = decode(kubectl(state, ["get", "pod", "postgres-0", "-n", namespace, "-o", "json"]).stdout)
    spec = document["spec"]["template"]["spec"]
    image = spec["containers"][0]["image"]
    if (
        namespace not in {"ml-storage", "ml-trust"}
        or pod["metadata"]["namespace"] != namespace
        or not kube_storage.matches(spec, pod["spec"])
        or pod["spec"].get("initContainers")
        or pod["spec"].get("ephemeralContainers")
        or type(image) is not str
        or re.fullmatch(r"[^@]+@sha256:[a-f0-9]{64}", image) is None
    ):
        raise Rejected("privacy_service_identity")
    verify_running_image(pod, image.rsplit("@", 1)[1])
    return {
        "pod": pod,
        "owner": owner,
        "identity": logs.pin(pod, owner, "postgres", False),
        "settings": settings(state, module),
    }


def mark(state, module, marker):
    if type(marker) is not bytes or re.fullmatch(MARKER, marker) is None:
        raise Rejected("privacy_service_marker")
    module.admin(
        state,
        "BEGIN; SET LOCAL client_min_messages=error; DO $window$ BEGIN RAISE WARNING '"
        + marker.decode("ascii")
        + "'; END $window$; COMMIT;",
    )


def verify_window(before, after, start, end, needles):
    if (
        type(needles) is not tuple
        or len(needles) != 9
        or any(type(v) is not bytes or not 1 <= len(v) <= 4096 for v in needles)
        or len(set(needles)) != 9
        or type(start) is not bytes
        or re.fullmatch(rb"tml-privacy-start-[a-f0-9]{32}", start) is None
        or type(end) is not bytes
        or re.fullmatch(rb"tml-privacy-end-[a-f0-9]{32}", end) is None
        or type(before) is not bytes
        or not 1 <= len(before) <= logs.MAX_BYTES
        or type(after) is not bytes
        or not 1 <= len(after) <= logs.MAX_BYTES
    ):
        raise Rejected("privacy_service_window_contract")
    if (
        not after.startswith(before)
        or before.count(start) != 1
        or end in before
        or after.count(start) != 1
        or after.count(end) != 1
        or after.index(start) >= after.index(end)
        or any(v in after for v in needles)
    ):
        raise Rejected("privacy_service_window_incomplete_or_canary")


class Windows:
    def __init__(self, state, destination):
        hosted()
        self.state, self.destination = state, destination
        try:
            if (
                not state.is_absolute()
                or state.resolve() != state
                or not destination.is_absolute()
                or destination.resolve() != destination
                or safe_child(state, destination.relative_to(state).as_posix()) != destination
                or destination == state
            ):
                raise ValueError
        except ValueError:
            raise Rejected("privacy_service_destination") from None
        inspected = [(module, inspect(state, module)) for module in (kube_storage, kube_trust)]
        self.destination.mkdir(mode=0o700, parents=True)
        self.closed = False
        self.entries = []
        for module, observed in inspected:
            start = ("tml-privacy-start-" + secrets.token_hex(16)).encode()
            mark(state, module, start)
            # Input canaries are generated in the probe later. Scan the entire
            # retained prefix again once those exact bytes have been handed off.
            _, before = self.wait(
                observed, start, (b"tml-unused-" + secrets.token_hex(16).encode(),)
            )
            self.entries.append((module, observed, start, before))

    def wait(self, observed, marker, needles):
        deadline = time.monotonic() + 5
        while True:
            receipt, raw = logs.capture(
                self.state,
                observed["pod"],
                owner_uid=observed["owner"],
                container="postgres",
                needles=needles,
            )
            if raw.count(marker) == 1:
                return receipt, raw
            if raw.count(marker) > 1 or time.monotonic() >= deadline:
                raise Rejected("privacy_service_marker_unobserved")
            time.sleep(0.1)

    def close(self, needles):
        if self.closed:
            raise Rejected("privacy_service_already_closed")
        self.closed = True
        result = {}
        for module, initial, start, before in self.entries:
            current = inspect(self.state, module)
            if any(current[k] != initial[k] for k in ("identity", "settings")):
                raise Rejected("privacy_service_changed")
            end = ("tml-privacy-end-" + secrets.token_hex(16)).encode()
            mark(self.state, module, end)
            receipt, after = self.wait(current, end, needles)
            verify_window(before, after, start, end, needles)
            # A separate positive leak control must exercise the real capture
            # rejection path. It runs after the measured request window closes.
            control = ("tml-privacy-control-" + secrets.token_hex(16)).encode()
            mark(self.state, module, control)
            try:
                self.wait(current, control, (control,))
            except Rejected as error:
                if str(error) != "privacy_log_canary":
                    raise
            else:
                raise Rejected("privacy_service_control_not_detected")
            namespace = current["identity"]["namespace"]
            packet = canonical(
                {
                    "schema_version": 1,
                    "identity": current["identity"],
                    "settings": current["settings"],
                    "before": signing.encode64(before),
                    "after": signing.encode64(after),
                    "start": start.decode(),
                    "end": end.decode(),
                    "receipt": receipt,
                }
            )
            path = self.destination / namespace
            audit_snapshot.store_packet(path, packet)
            retained = audit_snapshot.load_packet(path)
            if retained != packet:
                raise Rejected("privacy_service_retained_changed")
            saved = decode(retained)
            verify_window(
                signing.decode64(saved["before"]),
                signing.decode64(saved["after"]),
                saved["start"].encode(),
                saved["end"].encode(),
                needles,
            )
            result[namespace] = {
                "status": "pass",
                "release_ready": False,
                "closed_window": True,
                "leak_control_detected": True,
                "retained_reverified": True,
                "bytes": len(after),
                "sha256": digest(packet),
            }
        return result

    def reverify(self, needles, expected):
        if (
            not self.closed
            or type(expected) is not dict
            or set(expected) != {"ml-storage", "ml-trust"}
        ):
            raise Rejected("privacy_service_retained_inventory")
        for namespace, receipt in expected.items():
            raw = audit_snapshot.load_packet(self.destination / namespace)
            if digest(raw) != receipt["sha256"]:
                raise Rejected("privacy_service_retained_changed")
            saved = decode(raw)
            verify_window(
                signing.decode64(saved["before"]),
                signing.decode64(saved["after"]),
                saved["start"].encode(),
                saved["end"].encode(),
                needles,
            )
        return True
