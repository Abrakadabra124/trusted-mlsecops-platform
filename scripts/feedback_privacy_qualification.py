"""Bounded ordinary-CLI capture, without local database or container startup."""

import copy
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import feedback, signing, storage_snapshot
from mlsecops.contracts import Rejected, atomic_write, canonical, digest, write_json
from scripts import feedback_privacy_native as probe
from scripts.feedback_native_qualification import proof as quarantine_fixture
from scripts.source_sql_privacy_qualification import fixture as sql_fixture


def fixture():
    quarantine = quarantine_fixture()
    source = copy.deepcopy(quarantine["input"])
    source["records"] = source["records"][:1]
    record = feedback.document(canonical(source))
    receipt = feedback.receipt(record)
    quarantine.update(
        input=source, stored=record, receipt=receipt, retry=receipt, inspection=receipt
    )
    for key in ("after", "after_retry", "final"):
        quarantine[key]["quarantine"]["bytes"] = len(canonical(record))
    pin, needles, service_packet = sql_fixture()
    value = {
        "input": source,
        "needles": [signing.encode64(item) for item in needles],
        "quarantine": quarantine,
        "outputs": [
            {
                "returncode": 0 if index < 3 else 1,
                "stdout": signing.encode64(canonical(receipt) + b"\n" if index < 3 else b""),
                "stderr": signing.encode64(b"" if index < 3 else b"feedback_rejected\n"),
            }
            for index in range(11)
        ],
        "after_rejections": quarantine["final"],
        "promotion_after_rejections": quarantine["promotion_after"],
        "service_identity": pin,
        "service": probe.source_sql_privacy.verified(canonical(service_packet), pin, needles),
    }
    report = {
        "privacy_campaign_id": "d" * 32,
        "source": {"source_revision": "e" * 40},
        "model_sha256": source["model_sha256"],
        "subject_sha256": source["bundle_sha256"],
    }
    packet = canonical(
        {
            "binding": {"campaign_id": report["privacy_campaign_id"], "source": report["source"]},
            "http_outcomes": [
                {
                    "exchange": 1,
                    "request_id": source["records"][0]["request_id"],
                    "route": "predict",
                    "status": 200,
                    "admitted": True,
                }
            ],
        }
    )
    report["native"] = {"audit": {"packet_sha256": digest(packet)}}
    report["feedback_privacy"] = {
        "summary": dict(probe.SUMMARY),
        "proof_sha256": digest(canonical(value)),
    }
    return source, value, report, packet, canonical(service_packet)


class FeedbackPrivacyContracts(unittest.TestCase):
    def test_source_is_first_actual_admitted_response_bound_to_retained_audit(self):
        source, _, report, packet, _ = fixture()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(probe.audit_snapshot, "load_packet", return_value=packet),
        ):
            state = Path(directory)
            self.assertEqual(probe.source(state, report), source)
            wrong = copy.deepcopy(report)
            wrong["native"]["audit"]["packet_sha256"] = "f" * 64
            with self.assertRaises(Rejected):
                probe.source(state, wrong)
        from mlsecops.contracts import decode

        for field, value in (
            ("exchange", 2),
            ("status", 401),
            ("route", "ready"),
            ("admitted", False),
            ("request_id", "private"),
        ):
            bad = decode(packet)
            bad["http_outcomes"][0][field] = value
            content = canonical(bad)
            changed = copy.deepcopy(report)
            changed["native"]["audit"]["packet_sha256"] = digest(content)
            with (
                self.subTest(field=field),
                patch.object(probe.audit_snapshot, "load_packet", return_value=content),
                self.assertRaises(Rejected),
            ):
                probe.source(Path("state"), changed)
        changed = copy.deepcopy(report)
        changed["source"] = {"source_revision": "f" * 40}
        with (
            patch.object(probe.audit_snapshot, "load_packet", return_value=packet),
            self.assertRaises(Rejected),
        ):
            probe.source(Path("state"), changed)

    def test_exact_output_rejects_canary_extra_warning_nonzero_and_missing_capture(self):
        receipt = {"status": "quarantined"}
        success = {"returncode": 0, "stdout": canonical(receipt) + b"\n", "stderr": b""}
        probe.check_output(success, (b"private",), receipt)
        for field, value in (
            ("returncode", True),
            ("returncode", 1),
            ("stdout", "text"),
            ("stdout", b"private"),
            ("stderr", b"warning"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                probe.check_output({**success, field: value}, (b"private",), receipt)
        with self.assertRaises(Rejected):
            probe.check_output({}, (b"private",), receipt)
        for bad in (
            {},
            {**probe.SUMMARY, "submitted_records": True},
            {**probe.SUMMARY, "private_url": "https://private.invalid"},
        ):
            with self.assertRaises(Rejected):
                probe.checked(bad)

    def test_primary_requires_exact_inputs_eleven_outputs_no_mutation_and_nine_canaries(self):
        source, baseline, _, _, _ = fixture()
        self.assertEqual(len(probe.verify(baseline, source)), 9)
        for fault in (
            "input",
            "needles",
            "duplicate",
            "large-canary",
            "quarantine",
            "after",
            "promotion",
            "output-count",
            "output-shape",
            "output-leak",
        ):
            value = copy.deepcopy(baseline)
            if fault == "input":
                value["input"] = {}
            if fault == "needles":
                value["needles"] = []
            if fault == "duplicate":
                value["needles"][-1] = value["needles"][0]
            if fault == "large-canary":
                value["needles"][-1] = signing.encode64(b"x" * 4097)
            if fault == "quarantine":
                value["quarantine"]["retry"] = {}
            if fault == "after":
                value["after_rejections"] = {}
            if fault == "promotion":
                value["promotion_after_rejections"] = {}
            if fault == "output-count":
                value["outputs"].pop()
            if fault == "output-shape":
                value["outputs"][0]["extra"] = "value"
            if fault == "output-leak":
                value["outputs"][0]["stderr"] = value["needles"][0]
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                probe.verify(value, source)

    def test_retained_primary_and_service_window_reverify_without_live_database(self):
        _, baseline, report, packet, sql_packet = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary).resolve()
            path = probe.directory(state, report) / "privacy.json"
            atomic_write(path, canonical(baseline))

            def load(path):
                return packet if path.name == "audit-evidence" else sql_packet

            with patch.object(probe.audit_snapshot, "load_packet", side_effect=load):
                self.assertEqual(probe.reverify(state, report), probe.SUMMARY)
                changed = copy.deepcopy(report)
                changed["feedback_privacy"]["proof_sha256"] = "f" * 64
                with self.assertRaises(Rejected):
                    probe.reverify(state, changed)
                changed["feedback_privacy"] = {}
                with self.assertRaises(Rejected):
                    probe.reverify(state, changed)
                atomic_write(path, canonical(baseline) + b"\n")
                changed = copy.deepcopy(report)
                changed["feedback_privacy"]["proof_sha256"] = digest(canonical(baseline) + b"\n")
                with self.assertRaises(Rejected):
                    probe.reverify(state, changed)

    def test_hosted_path_executes_three_ordinary_successes_and_eight_rejections(self):
        source, baseline, report, _, _ = fixture()
        receipt = baseline["quarantine"]["receipt"]
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary).resolve()
            destination = probe.directory(state, report)
            destination.parent.mkdir(parents=True)
            count = 0

            def execute(arguments, **options):
                nonlocal count
                self.assertEqual(arguments[:3], [sys.executable, "-m", "mlsecops.feedback"])
                self.assertEqual(options, {"output_limit": 4096, "timeout": 30})
                count += 1
                return {
                    "returncode": 0 if count <= 3 else 1,
                    "stdout": canonical(receipt) + b"\n" if count <= 3 else b"",
                    "stderr": b"" if count <= 3 else b"feedback_rejected\n",
                }

            def qualify_record(state, destination, actual, *, invoke):
                self.assertEqual(actual, source)
                write_json(destination / "submission.json", source)
                for action in ("submit", "submit", "inspect"):
                    self.assertEqual(invoke([action]), receipt)
                return baseline["quarantine"]

            window = Mock(pinned=baseline["service_identity"])
            window.close.return_value = baseline["service"]
            with (
                patch.object(probe, "hosted"),
                patch.object(probe, "source", return_value=source),
                patch.object(probe.source_sql_privacy, "Window", return_value=window),
                patch.object(probe.storage_snapshot, "binary_streams", side_effect=execute),
                patch.object(probe.feedback_native, "qualify_record", side_effect=qualify_record),
                patch.object(
                    probe.feedback_native, "ledger", return_value=baseline["after_rejections"]
                ),
                patch.object(
                    probe.feedback_native,
                    "promotion_snapshot",
                    return_value=baseline["promotion_after_rejections"],
                ),
                patch.object(probe, "reverify", return_value=probe.SUMMARY) as reverify,
            ):
                result = probe.qualify(state, report)
            self.assertEqual(count, 11)
            self.assertEqual(result["summary"], probe.SUMMARY)
            self.assertEqual(
                digest((destination / "privacy.json").read_bytes()), result["proof_sha256"]
            )
            window.close.assert_called_once()
            reverify.assert_called_once()
        with (
            patch.object(probe, "hosted", side_effect=Rejected("not-hosted")),
            patch.object(probe, "source") as read,
            self.assertRaises(Rejected),
        ):
            probe.qualify(Path("state"), {})
        read.assert_not_called()


class FeedbackCaptureContracts(unittest.TestCase):
    def test_both_complete_streams_and_nonzero_exit_are_retained_without_shell(self):
        result = storage_snapshot.binary_streams(
            [
                sys.executable,
                "-c",
                "import os;os.write(1,b'output');os.write(2,b'rejected');raise SystemExit(1)",
            ],
            output_limit=64,
            timeout=5,
        )
        self.assertEqual(result, {"returncode": 1, "stdout": b"output", "stderr": b"rejected"})
        for code in (
            "print('accepted')",
            "raise SystemExit(1)",
            "import os;os.write(2,b'warning')",
        ):
            args = [sys.executable, "-c", code]
            if code.startswith("print"):
                self.assertEqual(
                    storage_snapshot.binary_command(args),
                    b"accepted\r\n" if sys.platform == "win32" else b"accepted\n",
                )
            else:
                with self.assertRaises(Rejected):
                    storage_snapshot.binary_command(args, timeout=5)

    def test_output_limit_timeout_and_partial_reader_start_close_owned_child(self):
        original = subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        for fault in ("limit", "timeout", "thread-start"):
            code = (
                "import time;time.sleep(30)"
                if fault != "limit"
                else "import os;os.write(1,b'x'*10000)"
            )
            count = 0
            start = threading.Thread.start

            def start_thread(thread):
                nonlocal count
                count += 1
                if fault == "thread-start" and count == 2:
                    raise RuntimeError("controlled-thread-start")
                start(thread)

            with (
                self.subTest(fault=fault),
                patch.object(storage_snapshot.subprocess, "Popen", side_effect=spawn),
                patch.object(storage_snapshot.threading.Thread, "start", start_thread),
                self.assertRaises((Rejected, RuntimeError)),
            ):
                storage_snapshot.binary_streams(
                    [sys.executable, "-c", code], output_limit=64, timeout=0.1
                )
            child = children[-1]
            self.assertIsNotNone(child.poll())
            self.assertTrue(
                all(stream.closed for stream in (child.stdin, child.stdout, child.stderr))
            )


if __name__ == "__main__":
    unittest.main()
