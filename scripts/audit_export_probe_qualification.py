import copy
import subprocess
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import audit_export_probe
from scripts.audit_correlation_qualification import trace
from scripts.audit_export_probe import scan
from scripts.audit_export_qualification import encoded, records


def public():
    return {
        "schema_version": 1,
        "scope": "serving-audit-public-window-not-full-M13",
        "status": "pass",
        "release_ready": False,
        "events": 4,
        "requests": {"completed": 1, "aborted": 0, "unresolved": 0},
        "routes": {"predict": 1, "ready": 0},
        "context_kinds": {"release-selection": 0, "candidate-qualification": 1, "none": 0},
    }


class PublicProbeContracts(unittest.TestCase):
    def test_nested_private_lineage_values_are_positive_control_canaries(self):
        source = [encoded(records(bound=asdict(trace("candidate"))))]
        with (
            patch.object(audit_export_probe.audit_snapshot, "read_closed", return_value=source),
            patch.object(
                audit_export_probe.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, canonical(public()) + b"\n", b""),
            ),
            patch.object(audit_export_probe, "scan", wraps=scan) as observed,
        ):
            self.assertEqual(audit_export_probe.exercise(Path("unused")), public())
        for value in asdict(trace("candidate").lineage).values():
            self.assertIn(value.encode(), source[0])
            self.assertIn(value.encode(), observed.call_args.kwargs["private"])

    def test_context_on_two_event_abort_and_four_event_unresolved_are_impossible(self):
        for incomplete in (False, True):
            value = public()
            value["events"] = 4 if incomplete else 2
            value["status"] = "inconclusive" if incomplete else "pass"
            value["requests"] = {
                "completed": 0,
                "aborted": 0 if incomplete else 1,
                "unresolved": 1 if incomplete else 0,
            }
            with self.subTest(incomplete=incomplete), self.assertRaises(Rejected):
                scan(canonical(value) + b"\n")

    def test_closed_cli_probe_compares_independent_source_counts_and_fails_closed(self):
        for fault in (None, "exit", "stderr", "source-count", "source-changed", "incomplete"):
            source = [encoded(records())]
            after = source if fault != "source-changed" else [encoded(records(principal="f" * 32))]
            report = public()
            if fault == "source-count":
                report["context_kinds"] = {
                    "release-selection": 1,
                    "candidate-qualification": 0,
                    "none": 0,
                }
            elif fault == "incomplete":
                report.update(status="inconclusive", events=1)
                report["requests"].update(completed=0, unresolved=1)
            result = subprocess.CompletedProcess(
                [],
                1 if fault == "exit" else 0,
                canonical(report) + b"\n",
                b"private-error" if fault == "stderr" else b"",
            )
            with (
                patch.object(
                    audit_export_probe.audit_snapshot, "read_closed", side_effect=[source, after]
                ),
                patch.object(audit_export_probe.subprocess, "run", return_value=result),
            ):
                if fault is None:
                    self.assertEqual(audit_export_probe.exercise(Path("unused")), public())
                else:
                    with self.subTest(fault=fault), self.assertRaises(Rejected):
                        audit_export_probe.exercise(Path("unused"))

    def test_probe_accepts_observed_intent_with_abort_without_claiming_inference(self):
        values = records()[:2]
        values.append(copy.deepcopy(values[-1]))
        values[-1]["sequence"] = 3
        values[-1]["event"].update(stage="aborted", status=None, context=None)
        report = public()
        report.update(events=3)
        report["requests"].update(completed=0, aborted=1)
        with (
            patch.object(
                audit_export_probe.audit_snapshot, "read_closed", return_value=[encoded(values)]
            ),
            patch.object(
                audit_export_probe.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, canonical(report) + b"\n", b""),
            ),
        ):
            self.assertEqual(audit_export_probe.exercise(Path("unused")), report)

    def test_exact_schema_and_complete_or_partial_counters(self):
        for incomplete in (False, True):
            value = public()
            if incomplete:
                value.update(status="inconclusive", events=1)
                value["requests"].update(completed=0, unresolved=1)
            self.assertEqual(scan(canonical(value) + b"\n"), value)

    def test_unknown_fields_private_values_false_approval_and_count_mutations_reject(self):
        mutations = [
            ("private_url", "https://private.invalid/value"),
            ("schema_version", True),
            ("scope", "full-M13"),
            ("release_ready", True),
            ("release_ready", 0),
            ("events", True),
            ("events", 0),
            ("events", 5),
            ("events", 65537),
            ("status", "inconclusive"),
            ("routes", {"predict": 2, "ready": 0}),
            ("routes", {"predict": -1, "ready": 2}),
            ("routes", {"predict": True, "ready": 0}),
            ("routes", {"predict": 1, "ready": 0, "private-id": 1}),
            ("requests", {"completed": 16385, "aborted": 0, "unresolved": 0}),
            ("context_kinds", []),
        ]
        for key, replacement in mutations:
            value = copy.deepcopy(public())
            value[key] = replacement
            with self.subTest(key=key, replacement=replacement), self.assertRaises(Rejected):
                scan(canonical(value) + b"\n")

    def test_bytes_canonical_size_and_canary_boundaries(self):
        value = canonical(public()) + b"\n"
        for payload in (b"", b" " * 4097, value[:-1], b" " + value, value + b"\n", b"[]\n", "x"):
            with self.assertRaises(Rejected):
                scan(payload)
        with self.assertRaises(Rejected):
            scan(value, private=(b"candidate-qualification",))
        self.assertEqual(scan(value, private=(b"secret-canary",)), public())


if __name__ == "__main__":
    unittest.main()
