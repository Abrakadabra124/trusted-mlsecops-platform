import copy
import hashlib
import io
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from mlsecops import audit_export, audit_snapshot, contracts, process_privacy
from mlsecops.contracts import Rejected, canonical


def context(kind="candidate-qualification", marker="a"):
    value = {
        "schema_version": 1,
        "kind": kind,
        "release_ready": False,
        "bundle_sha256": marker * 64,
        "model_sha256": "b" * 64,
    }
    if kind == "candidate-qualification":
        value.update(permit_sha256="c" * 64, proposal_sha256="d" * 64)
    else:
        value["selection_sha256"] = "e" * 64
    return value


def records(*, request="1" * 32, principal="2" * 32, route="predict", status=200, bound=None):
    bound = context() if status == 200 and bound is None else bound
    return [
        {
            "schema_version": 1,
            "sequence": index + 1,
            "recorded_at_ns": 100 + index,
            "event": {
                "schema_version": 2,
                "request_id": request,
                "principal_id": principal,
                "route": route,
                "stage": stage,
                "status": None if index == 0 else status,
                "context": None if index == 0 or status != 200 else copy.deepcopy(bound),
            },
        }
        for index, stage in enumerate(
            ("request_started", "response_intended", "response_started", "response_completed")
        )
    ]


def encoded(values):
    return b"".join(canonical(value) + b"\n" for value in values)


class PublicProjectionContracts(unittest.TestCase):
    def test_cli_shutdown_is_explicit_after_guarded_work_and_stream_flushes(self):
        for error, expected in (
            (None, 2),
            (SystemExit(0), 0),
            (SystemExit("private"), 1),
            (OSError("private"), 1),
            (KeyboardInterrupt("private"), 130),
        ):
            with (
                patch.object(audit_export, "main", return_value=2, side_effect=error),
                patch.object(audit_export.os, "_exit") as terminate,
                patch.object(sys, "stdout") as output,
                patch.object(sys, "stderr") as diagnostic,
            ):
                audit_export.cli()
                output.flush.assert_called_once_with()
                diagnostic.flush.assert_called_once_with()
                terminate.assert_called_once_with(expected)
        with (
            patch.object(audit_export, "main", return_value=0),
            patch.object(audit_export.os, "_exit") as terminate,
            patch.object(sys, "stdout", Mock(flush=Mock(side_effect=OSError("private")))),
            patch.object(sys, "stderr") as diagnostic,
        ):
            audit_export.cli()
            diagnostic.flush.assert_called_once_with()
            terminate.assert_called_once_with(1)

    def test_dependency_import_failure_is_private_in_a_fresh_cli_process(self):
        script = """
import importlib.abc, runpy, sys
class Broken(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == 'mlsecops.audit_snapshot':
            raise ImportError('PRIVATE-IMPORT-CANARY')
sys.meta_path.insert(0, Broken())
from unittest.mock import patch
from mlsecops import process_privacy
with patch.object(process_privacy, 'enforce'):
    runpy.run_module('mlsecops.audit_export', run_name='__main__')
"""
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, check=False, timeout=15
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr.replace(b"\r\n", b"\n"), b"audit_export_rejected\n")

    def test_deferred_stdout_flush_failure_does_not_leak_at_process_shutdown(self):
        script = """
import io, runpy, sys
from unittest.mock import patch
from mlsecops import audit_snapshot, process_privacy
from scripts.audit_export_qualification import encoded, records
class Broken(io.RawIOBase):
    def writable(self):
        return True
    def write(self, data):
        raise OSError('PRIVATE-FLUSH-CANARY')
sys.stdout = io.TextIOWrapper(io.BufferedWriter(Broken()), encoding='utf-8')
sys.argv = ['export', '--spool', 'unused']
sys.modules.pop('mlsecops.audit_export', None)
with patch.object(process_privacy, 'enforce'), patch.object(audit_snapshot, 'read_closed', return_value=[encoded(records())]):
    runpy.run_module('mlsecops.audit_export', run_name='__main__')
"""
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, check=False, timeout=15
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr.replace(b"\r\n", b"\n"), b"audit_export_rejected\n")

    def test_cli_output_overflow_never_writes_a_successful_summary(self):
        with (
            patch("sys.argv", ["export", "--spool", "unused"]),
            patch.object(process_privacy, "enforce"),
            patch.object(audit_snapshot, "read_closed", return_value=[encoded(records())]),
            patch.object(contracts, "canonical", return_value=b"x" * 4096),
            redirect_stdout(io.StringIO()) as output,
            redirect_stderr(io.StringIO()) as diagnostic,
        ):
            self.assertEqual(audit_export.main(), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(diagnostic.getvalue(), "audit_export_rejected\n")

    def test_cross_segment_sequence_and_record_request_limits_reject(self):
        values = records()
        for record in values[2:]:
            record["sequence"] += 1
        with self.assertRaises(Rejected):
            audit_export.project([encoded(values[:2]), encoded(values[2:])])
        with patch.object(audit_export, "MAX_RECORDS", 3), self.assertRaises(Rejected):
            audit_export.project([encoded(records())])
        values = records() + records(request="3" * 32)
        for index, record in enumerate(values):
            record["sequence"] = index + 1
        with patch.object(audit_export, "MAX_REQUESTS", 1), self.assertRaises(Rejected):
            audit_export.project([encoded(values)])

    def test_cli_guard_parser_io_and_cancellation_do_not_echo_private_values(self):
        for fault in ("guard", "arguments", "read", "cancel"):
            with (
                patch(
                    "sys.argv",
                    [
                        "export",
                        "--spool",
                        "private-path",
                        *(["--private-token"] if fault == "arguments" else []),
                    ],
                ),
                patch.object(
                    process_privacy,
                    "enforce",
                    side_effect=Rejected("private-guard") if fault == "guard" else None,
                ),
                patch.object(
                    audit_snapshot,
                    "read_closed",
                    side_effect=KeyboardInterrupt("private-cancel")
                    if fault == "cancel"
                    else OSError("private-file")
                    if fault == "read"
                    else None,
                    return_value=[encoded(records())],
                ) as read,
                redirect_stdout(io.StringIO()) as output,
                redirect_stderr(io.StringIO()) as diagnostic,
            ):
                self.assertEqual(audit_export.main(), 130 if fault == "cancel" else 1)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(diagnostic.getvalue(), "audit_export_rejected\n")
            if fault in ("guard", "arguments"):
                read.assert_not_called()

    def test_cli_success_and_incomplete_window_have_distinct_exit_codes(self):
        for values, code in ((records(), 0), (records()[:1], 2)):
            with (
                patch("sys.argv", ["export", "--spool", "private-path"]),
                patch.object(process_privacy, "enforce"),
                patch.object(audit_snapshot, "read_closed", return_value=[encoded(values)]),
                redirect_stdout(io.StringIO()) as output,
                redirect_stderr(io.StringIO()) as diagnostic,
            ):
                self.assertEqual(audit_export.main(), code)
            self.assertEqual(diagnostic.getvalue(), "")
            self.assertEqual(
                output.getvalue().encode(),
                canonical(audit_export.project([encoded(values)])) + b"\n",
            )

    def test_fresh_cli_guard_failure_is_constant_before_reading_files(self):
        script = """
import runpy, sys
from unittest.mock import patch
from mlsecops import process_privacy
from mlsecops.contracts import Rejected
sys.argv = ['export', '--spool', 'private-canary']
with patch.object(process_privacy, 'enforce', side_effect=Rejected('private-guard')):
    runpy.run_module('mlsecops.audit_export', run_name='__main__')
"""
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, check=False, timeout=15
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr.replace(b"\r\n", b"\n"), b"audit_export_rejected\n")

    def test_private_values_have_positive_control_and_never_enter_public_summary(self):
        marker = hashlib.sha256(b"synthetic-private-user").hexdigest()
        values = records(request=marker[:32], principal="f" * 32, bound=context(marker=marker[0]))
        source = encoded(values)
        summary = audit_export.project([source])
        public = canonical(summary)
        for private in (marker[:32], "f" * 32, marker[0] * 64, "b" * 64, "c" * 64, "d" * 64):
            self.assertIn(private.encode(), source)
            self.assertNotIn(private.encode(), public)
        self.assertEqual(
            summary,
            {
                "schema_version": 1,
                "scope": "serving-audit-public-window-not-full-M13",
                "status": "pass",
                "release_ready": False,
                "events": 4,
                "requests": {"completed": 1, "aborted": 0, "unresolved": 0},
                "routes": {"predict": 1, "ready": 0},
                "context_kinds": {"release-selection": 0, "candidate-qualification": 1, "none": 0},
            },
        )

    def test_private_identifiers_hashes_and_times_do_not_affect_projection(self):
        original = records()
        changed = records(request="e" * 32, principal="f" * 32, bound=context(marker="9"))
        for record in changed:
            record["recorded_at_ns"] += 1000000000
            record["sequence"] += 100
        self.assertEqual(
            audit_export.project([encoded(original)]), audit_export.project([encoded(changed)])
        )

    def test_concurrent_requests_and_segment_boundaries_preserve_accounting(self):
        first = records(bound=context("release-selection"))
        second = records(request="3" * 32, route="ready", status=503)
        interleaved = [item for pair in zip(first, second, strict=True) for item in pair]
        for index, record in enumerate(interleaved):
            record["sequence"] = index + 1
        summary = audit_export.project([encoded(interleaved[:3]), encoded(interleaved[3:])])
        self.assertEqual(summary["events"], 8)
        self.assertEqual(summary["requests"], {"completed": 2, "aborted": 0, "unresolved": 0})
        self.assertEqual(summary["routes"], {"predict": 1, "ready": 1})
        self.assertEqual(
            summary["context_kinds"],
            {"release-selection": 1, "candidate-qualification": 0, "none": 1},
        )

    def test_partial_retained_prefix_and_tail_are_not_complete(self):
        for selected in (records()[1:], records()[:-1]):
            for index, record in enumerate(selected):
                record["sequence"] = index + 50
            summary = audit_export.project([encoded(selected)])
            self.assertEqual(summary["status"], "inconclusive")
            self.assertEqual(summary["requests"], {"completed": 0, "aborted": 0, "unresolved": 1})

    def test_missing_start_without_retention_or_observed_interior_stage_is_rejected(self):
        for selected in (records()[1:], [records()[0], records()[2], records()[3]]):
            for index, record in enumerate(selected):
                record["sequence"] = index + 1
            with self.assertRaises(Rejected):
                audit_export.project([encoded(selected)])

    def test_retained_request_suffix_can_start_inside_the_window(self):
        selected = records(request="3" * 32) + records()[-1:]
        for index, record in enumerate(selected):
            record["sequence"] = index + 101
        summary = audit_export.project([encoded(selected)])
        self.assertEqual(summary["requests"], {"completed": 1, "aborted": 0, "unresolved": 1})

    def test_abort_and_fail_closed_response_replacement_are_not_approval(self):
        values = records()[:2]
        aborted = copy.deepcopy(values[-1])
        aborted["sequence"] += 1
        aborted["event"].update(stage="aborted", status=None, context=None)
        summary = audit_export.project([encoded([*values, aborted])])
        self.assertEqual(summary["requests"]["aborted"], 1)
        replaced = records()
        for record in replaced[2:]:
            record["event"].update(status=503, context=None)
        self.assertEqual(audit_export.project([encoded(replaced)])["requests"]["completed"], 1)

    def test_unknown_schema_payload_private_urls_and_invalid_order_reject(self):
        for field, value in (
            ("private_url", "https://private.invalid/secret"),
            ("schema_version", 99),
            ("principal_id", "private-email@example.invalid"),
        ):
            values = records()
            values[1]["event"][field] = value
            with self.assertRaises(Rejected):
                audit_export.project([encoded(values)])
        for mutation in (
            "principal",
            "route",
            "context",
            "status",
            "duplicate",
            "reverse",
            "sequence",
            "record-field",
        ):
            values = records()
            if mutation == "principal":
                values[2]["event"]["principal_id"] = "9" * 32
            elif mutation == "route":
                values[2]["event"]["route"] = "ready"
            elif mutation == "context":
                values[2]["event"]["context"]["model_sha256"] = "9" * 64
            elif mutation == "status":
                values[3]["event"].update(status=503, context=None)
            elif mutation == "duplicate":
                values[2]["event"] = copy.deepcopy(values[1]["event"])
            elif mutation == "reverse":
                values[1]["event"], values[2]["event"] = values[2]["event"], values[1]["event"]
            elif mutation == "sequence":
                values[2]["sequence"] += 1
            else:
                values[2]["raw_features"] = {"change_size": 0.314159}
            with self.subTest(mutation=mutation), self.assertRaises(Rejected):
                audit_export.project([encoded(values)])

    def test_empty_truncated_noncanonical_and_unbounded_sources_reject(self):
        good = encoded(records())
        for chunks in (
            [],
            [b""],
            [good[:-1]],
            [b" " + good],
            [good] * 65,
            iter([good]),
            ["private"],
        ):
            with self.assertRaises(Rejected):
                audit_export.project(chunks)


if __name__ == "__main__":
    unittest.main()
