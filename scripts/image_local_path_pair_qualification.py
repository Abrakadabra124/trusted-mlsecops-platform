import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import image_local_path_pair as pair
from scripts.image_package_observation_qualification import local_path_observation


def observation(candidate=False):
    obs = local_path_observation()
    if not candidate:
        return obs
    # Changes independently read from the proposal ELF relative to the stock fixture.
    modules = {p["name"]: p["version"] for p in obs["packages"] if p["type"] == "go-module"}
    for name in (
        "github.com/cpuguy83/go-md2man/v2",
        "github.com/russross/blackfriday/v2",
        "github.com/urfave/cli",
    ):
        del modules[name]
    modules.update(
        {
            "stdlib": "go1.26.5",
            pair.APP: "v0.0.37",
            "github.com/sirupsen/logrus": "v1.9.4",
            "github.com/urfave/cli/v3": "v3.10.1",
            "golang.org/x/net": "v0.56.0",
            "golang.org/x/sys": "v0.46.0",
            "golang.org/x/term": "v0.44.0",
            "golang.org/x/text": "v0.39.0",
        }
    )
    return {
        "image_id": pair.PROPOSAL[1],
        "distro": {"id": None, "versionID": None},
        "packages": [
            {
                "name": n,
                "version": v,
                "type": "go-module",
                "foundBy": "go-module-binary-cataloger",
                "paths": ["/usr/bin/local-path-provisioner"],
            }
            for n, v in modules.items()
        ],
    }


def finding(identifier, package, severity, installed="v1.0.0"):
    return {
        "id": identifier,
        "package": package,
        "installed": installed,
        "severity": severity,
        "type": "go-module",
        "fix": {"state": "fixed", "versions": ["0.0.36"]},
    }


def result(rows, config):
    counts = {s: sum(f["severity"] == s for f in rows) for s in pair.SEVERITIES}
    code = 2 if counts["Critical"] + counts["High"] else 0
    return {
        "image_id": config,
        "findings": rows,
        "matches": len(rows),
        "unique_vulnerabilities": len({r["id"] for r in rows}),
        "severity_counts": counts,
        "database": {"schema_version": "v6.1.0", "built": "same"},
        "sbom_sha256": "a" * 64,
        "grype_sha256": "b" * 64,
        "scanner_exit_code": code,
        "status": "fail" if code else "inconclusive",
    }


class PairQualification(unittest.TestCase):
    def setUp(self):
        self.control = finding(pair.ADVISORY, pair.APP, "High", "v0.0.34")
        self.db = {"6/vulnerability.db": "c" * 64}

    def test_full_inventory_path_and_distro_on_both(self):
        for spec, obs in ((pair.STOCK, observation()), (pair.PROPOSAL, observation(True))):
            self.assertTrue(pair.inventory_matches(spec, obs))
            for mutation in (
                "delete",
                "duplicate",
                "path",
                "type",
                "cataloger",
                "version",
                "distro",
                "id",
            ):
                with self.subTest(spec=spec, mutation=mutation):
                    changed = copy.deepcopy(obs)
                    packages = changed["packages"]
                    go = next(p for p in packages if p["name"] == "stdlib")
                    if mutation == "delete":
                        packages.pop()
                    elif mutation == "duplicate":
                        packages.append(packages[0])
                    elif mutation == "path":
                        go["paths"].append("/other")
                    elif mutation == "cataloger":
                        go["foundBy"] = "other"
                    elif mutation == "type":
                        go["type"] = "binary"
                    elif mutation == "version":
                        go["version"] = "go1.26.11"
                    elif mutation == "id":
                        changed["image_id"] = (
                            pair.STOCK[1] if spec == pair.PROPOSAL else pair.PROPOSAL[1]
                        )
                    else:
                        changed["distro"] = {"id": "alpine", "versionID": "3.22"}
                    self.assertFalse(pair.inventory_matches(spec, changed))

    def compare(self, old, new):
        return pair.compare(
            observation(),
            result(old, pair.STOCK[1]),
            observation(True),
            result(new, pair.PROPOSAL[1]),
            self.db,
        )

    def test_delta_keeps_duplicates_packages_and_severity_changes(self):
        same = finding("A", "x", "Medium")
        lower = finding("A", "x", "Low")
        other = finding("A", "y", "Medium")
        measured = self.compare([self.control, same, same, other], [same, lower])
        self.assertEqual(measured["status"], "diagnostic-clear")
        self.assertFalse(measured["release_ready"])
        self.assertEqual(
            measured["retained"], [{"id": "A", "package": "x", "severity": "Medium", "count": 1}]
        )
        self.assertEqual(len(measured["removed"]), 3)
        self.assertEqual(
            measured["added"], [{"id": "A", "package": "x", "severity": "Low", "count": 1}]
        )
        self.assertEqual(self.compare([self.control], [lower, lower])["added"][0]["count"], 2)

    def test_nonzero_conditions_even_when_app_advisory_disappears(self):
        for severity in ("Critical", "High", "Unknown"):
            with self.subTest(severity=severity):
                self.assertNotEqual(
                    self.compare([self.control], [finding("OTHER", "x", severity)])["status"],
                    "diagnostic-clear",
                )
        for old, new in (
            ([], []),
            ([{**self.control, "installed": "v0.0.35"}], []),
            ([{**self.control, "fix": {"state": "unknown", "versions": []}}], []),
            ([{**self.control, "fix": {"state": "fixed", "versions": "0.0.36"}}], []),
            ([self.control], [self.control]),
            ([self.control, finding("UNKNOWN", "x", "Unknown")], []),
        ):
            self.assertNotEqual(self.compare(old, new)["status"], "diagnostic-clear")

    def test_mismatched_database_and_coverage(self):
        before = result([self.control], pair.STOCK[1])
        after = result([], pair.PROPOSAL[1])
        self.assertRaises(
            Rejected,
            pair.compare,
            observation(),
            before,
            observation(True),
            {**after, "database": {"built": "other"}},
            self.db,
        )
        with self.assertRaises(Rejected):
            pair.compare(observation(), before, observation(True), after, {})
        broken = observation(True)
        broken["packages"].pop()
        report = pair.compare(observation(), before, broken, after, self.db)
        self.assertEqual(report["status"], "inconclusive")
        self.assertFalse(report["proposal"]["inventory_verified"])

    def test_qualify_pulls_only_pins_and_uses_one_cache(self):
        def inspect(argv, **kwargs):
            if argv[1] == "pull":
                self.assertIn("@sha256:", argv[-1])
                return ""
            return dict((ref, cfg) for ref, cfg in (pair.STOCK, pair.PROPOSAL))[argv[-1]]

        scan_results = [
            ({}, observation(), result([self.control], pair.STOCK[1])),
            ({}, observation(True), result([finding("OTHER", "x", "High")], pair.PROPOSAL[1])),
        ]
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(pair, "command", side_effect=inspect),
            patch.object(pair.audit, "scanner", return_value=(0, None)) as updater,
            patch.object(pair.audit, "snapshot", return_value=self.db),
            patch.object(pair, "measure", side_effect=scan_results) as meter,
            redirect_stdout(io.StringIO()) as log,
        ):
            self.assertEqual(pair.qualify(Path(tmp)), 1)
            self.assertEqual(updater.call_count, 1)
            self.assertEqual(updater.call_args.args[3], ["db", "update"])
            self.assertEqual(
                [c.args[1:3] for c in meter.call_args_list], [(Path(tmp) / "cache", self.db)] * 2
            )
            self.assertEqual(json.loads(log.getvalue())["status"], "fail")
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(pair, "command", return_value="wrong"),
            patch.object(pair.audit, "scanner") as update,
            self.assertRaises(Rejected),
        ):
            pair.qualify(Path(tmp))
        update.assert_not_called()

    def test_report_identity_and_finding_counts(self):
        original = result([self.control], pair.STOCK[1])
        for mismatch in ({"image_id": pair.PROPOSAL[1]}, {"matches": 0}, {"severity_counts": {}}):
            with self.subTest(mismatch=mismatch), self.assertRaises(Rejected):
                pair.compare(
                    observation(),
                    {**original, **mismatch},
                    observation(True),
                    result([], pair.PROPOSAL[1]),
                    self.db,
                )

    def test_cli_refuses_local_and_emits_nonzero_reason_on_technical_refusal(self):
        with (
            patch.dict(pair.os.environ, {"GITHUB_ACTIONS": "false"}),
            patch.object(pair, "qualify") as run,
        ):
            with self.assertRaises(SystemExit):
                pair.main()
            run.assert_not_called()
        with (
            patch.dict(
                pair.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
            ),
            patch.object(pair.platform, "system", return_value="Linux"),
            patch.object(pair.platform, "machine", return_value="x86_64"),
            patch.object(pair, "qualify", side_effect=Rejected("local_path_db_update_failed")),
            redirect_stdout(io.StringIO()) as log,
        ):
            self.assertEqual(pair.main(), 1)
            self.assertEqual(json.loads(log.getvalue())["reason"], "local_path_db_update_failed")


if __name__ == "__main__":
    unittest.main()
