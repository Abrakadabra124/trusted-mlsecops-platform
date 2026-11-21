import copy
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import image_coredns_pair as pair
from scripts.image_audit_qualification import fixtures
from scripts.image_package_observation_qualification import coredns_observation


def finding(advisory, name, version, severity="Critical"):
    return {
        "id": advisory,
        "package": name,
        "installed": version,
        "severity": severity,
        "type": "go-module",
    }


class PairTests(unittest.TestCase):
    def setUp(self):
        self.old = [
            finding("GO-2026-6612", "stdlib", "go1.26.6"),
            finding("GO-2026-6612", "golang.org/x/net", "v0.57.0"),
            finding("GO-2026-6604", "stdlib", "go1.26.6"),
        ]

    def test_gate_requires_all_original_critical_bindings(self):
        for i in range(3):
            with self.subTest(i=i):
                self.assertFalse(pair.target_removed(self.old[:i] + self.old[i + 1 :], []))
        wrong = copy.deepcopy(self.old)
        wrong[0]["severity"] = "High"
        self.assertFalse(pair.target_removed(wrong, []))

    def test_target_ids_at_critical_anywhere_block_only_the_scoped_claim(self):
        other = finding("OTHER", "stdlib", "go1.27.3")
        downgraded = finding("GO-2026-6612", "stdlib", "go1.27.3", "High")
        remaining = [other, downgraded, copy.deepcopy(other)]
        before = copy.deepcopy(remaining)
        self.assertTrue(pair.target_removed(self.old, remaining))
        self.assertEqual(remaining, before)
        for advisory in ("GO-2026-6612", "GO-2026-6604"):
            self.assertFalse(pair.target_removed(self.old, [finding(advisory, "other", "v1")]))

    def test_paired_scans_share_one_cache_and_detect_byte_drift(self):
        for drift in (None, 1, 2):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as root:
                inputs = []

                def scanner(run, name, image, args, mounts, network=False):
                    self.assertEqual(
                        (name, image, args, network),
                        ("db-update", pair.audit.GRYPE_IMAGE, ["db", "update"], True),
                    )
                    ((cache, target, writable),) = mounts
                    self.assertEqual((target, writable), ("/cache", True))
                    (cache / "6").mkdir()
                    (cache / "6/vulnerability.db").write_bytes(b"base")
                    return 0, None

                def scan(run, cache, label, reference, config):
                    inputs.append((cache, reference, config))
                    if len(inputs) == drift:
                        (cache / "6/vulnerability.db").write_bytes(b"changed")
                    return {
                        "database": {"built": "same"},
                        "findings": self.old if label == "old" else [],
                        "status": "fail",
                        "severity_counts": {"High": 2},
                    }

                with (
                    patch.object(pair.audit, "command"),
                    patch.object(pair.audit, "inspect_image"),
                    patch.object(pair.audit, "scanner", side_effect=scanner),
                    patch.object(pair, "scan_image", side_effect=scan),
                ):
                    if drift:
                        with self.assertRaisesRegex(Rejected, "database_changed"):
                            pair.compare(Path(root))
                        self.assertEqual(len(inputs), drift)
                    else:
                        result = pair.compare(Path(root))
                        self.assertTrue(result["target_criticals_removed"])
                        self.assertEqual(result["new"]["status"], "fail")
                        self.assertEqual(result["db_sha256_before"], result["db_sha256_after"])
                        self.assertEqual(inputs[0][0], inputs[1][0])
                        self.assertNotEqual(inputs[0][1:], inputs[1][1:])

    def test_scan_binds_original_bytes_and_preserves_all_matches(self):
        observation = coredns_observation()
        sbom, report, _, _, _ = fixtures()
        sbom["source"]["metadata"]["imageID"] = report["source"]["target"]["imageID"] = (
            pair.COREDNS_CONFIG
        )
        sbom["distro"] = observation["distro"]
        sbom["artifacts"] = [
            {**p, "id": str(i), "locations": [{"path": path} for path in p["paths"]]}
            for i, p in enumerate(observation["packages"])
        ]
        report["descriptor"]["db"]["status"]["built"] = datetime.now(UTC).isoformat()
        package = next(p for p in sbom["artifacts"] if p["name"] == "golang.org/x/net")
        report["matches"] = [
            {
                "artifact": {k: package[k] for k in ("id", "name", "type", "version")},
                "vulnerability": {"id": "OTHER", "severity": "High"},
            }
        ] * 2
        with tempfile.TemporaryDirectory() as root:
            run = Path(root)
            cache = run / "cache"

            def scanner(run, name, image, args, mounts):
                path = run / (name + ".json")
                is_sbom = image == pair.audit.SYFT_IMAGE
                if not is_sbom:
                    self.assertEqual(
                        args, ["sbom:/input/sbom.json", "--fail-on", "high", "-o", "json"]
                    )
                    self.assertEqual(
                        mounts,
                        [
                            (cache, "/cache", False),
                            (run / "new-sbom.json", "/input/sbom.json", False),
                        ],
                    )
                path.write_text(json.dumps(sbom if is_sbom else report), encoding="utf-8")
                return (0 if is_sbom else 2), path

            with (
                patch.object(pair.audit, "inspect_image", return_value={"Id": pair.COREDNS_CONFIG}),
                patch.object(pair.audit, "identity", return_value=pair.COREDNS_CONFIG),
                patch.object(pair.audit, "command"),
                patch.object(pair.audit, "scanner", side_effect=scanner),
            ):
                args = (run, cache, "new", pair.COREDNS_REFERENCE, pair.COREDNS_CONFIG)
                result = pair.scan_image(*args)
                self.assertEqual(
                    (result["status"], result["matches"], len(result["findings"])), ("fail", 2, 2)
                )
                for key, suffix in (("sbom_sha256", "sbom"), ("report_sha256", "scan")):
                    self.assertEqual(result[key], pair.audit.file_hash(run / f"new-{suffix}.json"))
                report["source"]["target"]["imageID"] = pair.OLD_CONFIG
                with self.assertRaises(Rejected):
                    pair.scan_image(*args)
                sbom["artifacts"].pop()
                with self.assertRaisesRegex(Rejected, "inventory"):
                    pair.scan_image(*args)
