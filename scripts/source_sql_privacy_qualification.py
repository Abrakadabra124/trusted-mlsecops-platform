"""Closed source SQL evidence with controlled process/owner adapters, no Docker."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import source_sql_privacy as probe


def fixture():
    pin = {
        "container_id": "a" * 64,
        "image": "sha256:" + "b" * 64,
        "started_at": "2026-11-07T00:00:00Z",
        "config_digest": "c" * 64,
        "settings": probe.services.SETTINGS,
    }
    needles = tuple(("private-" + str(index)).encode() for index in range(9))
    start, end = b"tml-privacy-start-" + b"d" * 32, b"tml-privacy-end-" + b"e" * 32
    value = {
        "schema_version": 1,
        "identity": pin,
        "before": signing.encode64(b"prefix\n" + start + b"\n"),
        "after": signing.encode64(b"prefix\n" + start + b"\nnormal\n" + end + b"\n"),
        "start": start.decode(),
        "end": end.decode(),
    }
    return pin, needles, value


class SourceSqlPrivacyContracts(unittest.TestCase):
    def test_identity_requires_owned_running_container_and_exact_log_settings(self):
        pin, _, _ = fixture()
        marker = {key: pin[key] for key in ("container_id", "config_digest")}
        container = {
            "Image": pin["image"],
            "State": {"StartedAt": pin["started_at"], "Running": True},
        }
        with (
            patch.object(probe.storage_bootstrap, "validate", return_value=marker),
            patch.object(probe.storage_bootstrap, "inspect", return_value=container),
            patch.object(probe.services, "settings", return_value=pin["settings"]),
        ):
            self.assertEqual(probe.identity(Path("state")), pin)
            container["State"]["Running"] = False
            with self.assertRaises(Rejected):
                probe.identity(Path("state"))
        with (
            patch.object(probe.storage_bootstrap, "validate", return_value=marker),
            patch.object(probe.storage_bootstrap, "admin", return_value="value") as admin,
        ):
            self.assertEqual(probe.admin(Path("state"), "SELECT 1"), "value")
            admin.assert_called_once_with(pin["container_id"], "SELECT 1")

    def test_capture_checks_identity_both_sides_and_rejects_wrong_stream_or_leak(self):
        pin, needles, _ = fixture()
        for fault in (None, "before", "after", "exit", "stdout", "empty", "canary"):
            result = {"returncode": 0, "stdout": b"", "stderr": b"normal\n"}
            if fault == "exit":
                result["returncode"] = 1
            if fault == "stdout":
                result["stdout"] = b"unexpected"
            if fault == "empty":
                result["stderr"] = b""
            if fault == "canary":
                result["stderr"] += needles[0]
            with (
                self.subTest(fault=fault),
                patch.object(
                    probe,
                    "identity",
                    side_effect=[{} if fault == "before" else pin, {} if fault == "after" else pin],
                ),
                patch.object(
                    probe.storage_snapshot, "binary_streams", return_value=result
                ) as execute,
            ):
                if fault:
                    with self.assertRaises(Rejected):
                        probe.capture(Path("state"), pin, needles)
                else:
                    self.assertEqual(probe.capture(Path("state"), pin, needles), b"normal\n")
                    self.assertEqual(
                        execute.call_args.args[0],
                        ["docker", "logs", "--timestamps", pin["container_id"]],
                    )

    def test_offline_packet_rejects_changed_identity_prefix_marker_canary_and_receipt(self):
        pin, needles, value = fixture()
        expected = probe.verified(canonical(value), pin, needles)
        for fault in ("identity", "version", "extra", "prefix", "end", "canary", "noncanonical"):
            changed = copy.deepcopy(value)
            if fault == "identity":
                changed["identity"]["image"] = "foreign"
            if fault == "version":
                changed["schema_version"] = True
            if fault == "extra":
                changed["private"] = "extra"
            if fault == "prefix":
                changed["after"] = signing.encode64(b"changed")
            if fault == "end":
                changed["end"] = "tml-privacy-end-" + "f" * 32
            if fault == "canary":
                changed["after"] = signing.encode64(signing.decode64(changed["after"]) + needles[0])
            raw = canonical(changed) + (b"\n" if fault == "noncanonical" else b"")
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                probe.verified(raw, pin, needles)
        with patch.object(probe.audit_snapshot, "load_packet", return_value=canonical(value)):
            self.assertEqual(probe.reverify(Path("owned"), pin, needles, expected), expected)
            for bad in ({}, {**expected, "sha256": "f" * 64}):
                with self.assertRaises(Rejected):
                    probe.reverify(Path("owned"), pin, needles, bad)

    def test_window_requires_owned_path_complete_markers_positive_control_and_readback(self):
        pin, needles, _ = fixture()
        for fault in (None, "blind-control", "different-control-error", "retained"):
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary).resolve()
                destination = state / "owned"
                log, retained = [], {}

                def mark(state, backend, marker):
                    log.append(marker + b"\n")

                def capture(state, pinned, values):
                    raw = b"".join(log)
                    if any(value in raw for value in values):
                        if fault == "different-control-error":
                            raise Rejected("unavailable")
                        if fault != "blind-control":
                            raise Rejected("privacy_log_canary")
                    return raw

                def store(path, raw):
                    retained["bytes"] = raw

                with (
                    patch.object(probe, "hosted"),
                    patch.object(probe, "identity", return_value=pin),
                    patch.object(probe.services, "mark", side_effect=mark),
                    patch.object(probe, "capture", side_effect=capture),
                    patch.object(probe.audit_snapshot, "store_packet", side_effect=store),
                    patch.object(
                        probe.audit_snapshot,
                        "load_packet",
                        side_effect=lambda path: (
                            b"{}" if fault == "retained" else retained["bytes"]
                        ),
                    ),
                ):
                    window = probe.Window(state, destination, needles)
                    if fault:
                        with self.assertRaises(Rejected):
                            window.close()
                    else:
                        result = window.close()
                        self.assertEqual(result["sha256"], digest(retained["bytes"]))
                        with self.assertRaises(Rejected):
                            window.close()
                    for bad_state, bad_destination in (
                        (Path("relative"), destination),
                        (state, state),
                        (state, state.parent / "outside"),
                    ):
                        with self.assertRaises(Rejected):
                            probe.Window(bad_state, bad_destination, needles)

    def test_wait_rejects_missing_or_duplicate_markers_and_can_wait_for_a_prefix(self):
        window = object.__new__(probe.Window)
        window.state, window.pinned = Path("state"), {}
        with (
            patch.object(probe, "capture", side_effect=[b"prefix", b"prefix marker"]),
            patch.object(probe.time, "sleep"),
        ):
            self.assertEqual(window.wait(b"marker", (b"private",)), b"prefix marker")
        for raw in (b"no-marker-here", b"marker marker"):
            with (
                patch.object(probe, "capture", return_value=raw),
                patch.object(probe.time, "monotonic", side_effect=[0, 6]),
                self.assertRaises(Rejected),
            ):
                window.wait(b"marker" if raw.startswith(b"marker") else b"absent", (b"private",))


if __name__ == "__main__":
    unittest.main()
