import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import audit_snapshot
from mlsecops.contracts import Rejected
from scripts import audit_evidence_probe, audit_export_probe
from scripts.audit_evidence_qualification import binding, check, expected, fixture, packet


class AuditEvidenceProbeContracts(unittest.TestCase):
    def test_closed_source_and_exact_export_are_retained_and_read_back(self):
        manifest, chunks, outcomes, public = fixture()
        written = []

        def export(path, *, observer):
            observer(tuple(chunks), public)
            return check(packet())["public"]

        with (
            patch.object(audit_snapshot, "capture_closed", return_value=(manifest, tuple(chunks))),
            patch.object(audit_export_probe, "exercise", side_effect=export),
            patch.object(
                audit_snapshot,
                "store_packet",
                side_effect=lambda path, content: written.append(content),
            ),
            patch.object(audit_snapshot, "load_packet", side_effect=lambda path: written[-1]),
        ):
            result = audit_evidence_probe.retain(
                Path("source"),
                Path("destination"),
                Mock(snapshot=Mock(return_value=outcomes)),
                binding=binding(),
                expected_context=expected(),
            )
        self.assertEqual(written, [packet()])
        self.assertEqual(result, check(packet()))

    def test_changed_source_missing_or_wrong_export_and_storage_faults_reject(self):
        manifest, chunks, outcomes, public = fixture()
        for fault in ("source", "missing", "snapshot", "twice", "export", "store", "readback"):

            def export(path, *, observer):
                if fault != "missing":
                    observer((b"changed",) if fault == "snapshot" else tuple(chunks), public)
                if fault == "twice":
                    observer(tuple(chunks), public)
                result = check(packet())["public"]
                return {**result, "events": 8} if fault == "export" else result

            with (
                self.subTest(fault=fault),
                patch.object(
                    audit_snapshot,
                    "capture_closed",
                    side_effect=[
                        (manifest, tuple(chunks)),
                        (b"changed", tuple(chunks))
                        if fault == "source"
                        else (manifest, tuple(chunks)),
                    ],
                ),
                patch.object(audit_export_probe, "exercise", side_effect=export),
                patch.object(
                    audit_snapshot,
                    "store_packet",
                    side_effect=OSError("private") if fault == "store" else None,
                ),
                patch.object(
                    audit_snapshot,
                    "load_packet",
                    return_value=b"changed" if fault == "readback" else packet(),
                ),
                self.assertRaises((Rejected, OSError)),
            ):
                audit_evidence_probe.retain(
                    Path("source"),
                    Path("destination"),
                    Mock(snapshot=Mock(return_value=outcomes)),
                    binding=binding(),
                    expected_context=expected(),
                )


if __name__ == "__main__":
    unittest.main()
