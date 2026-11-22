"""Offline rebuild checks with a controlled scanner and upstream inventory fixtures."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, digest
from scripts import image_local_path_pair as pair
from scripts import image_local_path_rebuild as rebuild
from scripts.image_local_path_pair_qualification import finding, observation, result

IID = "sha256:" + "a" * 64
REV = "49b2be8e26d6d34c9afaa21fa33108d2e82f8955"
PATH = "/usr/local/bin/local-path-provisioner"


class RebuildTests(unittest.TestCase):
    def setUp(self):
        self.stock = observation()
        self.new = copy.deepcopy(observation(True))
        self.mods = {p["name"]: p["version"] for p in self.new["packages"]}
        self.mods.update(rebuild.PATCHED_MODULES)
        self.mods.update({"golang.org/x/sys": "v0.49.0", "golang.org/x/term": "v0.47.0"})
        self.mods.update({pair.APP: "v0.0.37+dirty", "stdlib": "go1.27.4"})
        self.new.update(image_id=IID, distro=self.stock["distro"])
        for p in self.new["packages"]:
            p.update(paths=[PATH], version=self.mods[p["name"]])
        self.new["packages"].extend(p for p in self.stock["packages"] if p["type"] == "deb")
        self.info = [
            "binary: go1.27.4",
            "path\t" + pair.APP,
            "mod\t" + pair.APP + "\tv0.0.37+dirty",
            "build\tvcs=git",
            "build\tvcs.revision=" + REV,
            "build\tvcs.modified=true",
            "build\tGOOS=linux",
            "build\tGOARCH=amd64",
            *[
                f"dep\t{name}\t{version}\th1:fixture"
                for name, version in self.mods.items()
                if name not in (pair.APP, "stdlib")
            ],
        ]
        dep_rows = sorted(
            s[4:].replace("\t", " ") + "\n" for s in self.info if s.startswith("dep\t")
        )
        self.enterContext(
            patch.object(rebuild, "DEPENDENCIES_SHA256", digest("".join(dep_rows).encode()))
        )
        self.db = {"6/vulnerability.db": "c" * 64}
        self.base = {"config": {"User": "0"}, "rootfs": {"type": "layers", "diff_ids": [IID]}}
        self.config = copy.deepcopy(self.base)
        self.config["rootfs"]["diff_ids"].extend(["sha256:" + "b" * 64, "sha256:" + "c" * 64])
        control = finding(pair.ADVISORY, pair.APP, "High", "v0.0.34")
        self.source = result([control], pair.STOCK[1])
        self.candidate = result([], IID)
        self.binary = (
            52_174_972,
            "e424baa965649565de70a5e4549fa88a1fa4242c39dfda32aaadd557c2e41612",
        )

    def metadata(self):
        return rebuild.check_inventory(self.stock, self.new, "\n".join(self.info))

    def test_binary_and_sbom_bind_all_named_modules_and_truthful_dirty_state(self):
        self.assertEqual(self.metadata()["modules"], self.mods)
        for old, new in (
            ("go1.27.4", "go1.26.11"),
            (REV, "0" * 40),
            ("modified=true", "modified=false"),
            ("v0.0.37+dirty", "(devel)"),
            ("path\t" + pair.APP, "path\texample.org/other"),
            ("GOARCH=amd64", "GOARCH=arm64"),
        ):
            with self.subTest(new=new), self.assertRaises(Rejected):
                rebuild.check_inventory(
                    self.stock, self.new, "\n".join(self.info).replace(old, new)
                )
        for change in ("missing", "extra", "duplicate", "wrong-path", "wrong-deb", "both-missing"):
            with self.subTest(change=change), self.assertRaises(Rejected):
                obs = copy.deepcopy(self.new)
                lines = list(self.info)
                row = next(p for p in obs["packages"] if p["name"] == "k8s.io/api")
                if change in ("missing", "both-missing"):
                    obs["packages"].remove(row)
                    if change == "both-missing":
                        lines = [s for s in lines if not s.startswith("dep\tk8s.io/api\t")]
                elif change == "extra":
                    obs["packages"].append({**row, "name": "foreign.test/pkg"})
                    lines.append("dep\tforeign.test/pkg\t" + row["version"])
                elif change == "duplicate":
                    obs["packages"].append(row)
                elif change == "wrong-path":
                    row["paths"] = ["/elsewhere"]
                else:
                    next(p for p in obs["packages"] if p["type"] == "deb")["version"] = "changed"
                rebuild.check_inventory(self.stock, obs, "\n".join(lines))

    def test_rejects_ref_or_stock_before_daemon_access(self):
        for value in ("tag:latest", "sha256:123", pair.STOCK[1], IID.upper()):
            with self.subTest(value=value), patch.object(rebuild, "command") as cmd:
                with self.assertRaises(Rejected):
                    rebuild.qualify(Path("."), value)
                cmd.assert_not_called()
        with (
            patch.object(rebuild, "command", return_value=pair.STOCK[1]),
            patch.object(pair, "pull_verified") as pull,
            self.assertRaisesRegex(Rejected, "identity_mismatch"),
        ):
            rebuild.qualify(Path("."), IID)
        pull.assert_not_called()

    def test_static_copy_checks_image_state_and_proves_cleanup_after_copy_failure(self):
        cid = "d" * 64
        content = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\x00"
        for fault in ("none", "foreign", "copy", "cleanup"):
            calls = []

            def command(args, **kwargs):
                calls.append(args)
                if args[1] == "create":
                    self.assertEqual(args[-1], IID)
                    Path(args[args.index("--cidfile") + 1]).write_text(cid, encoding="ascii")
                elif args[1] == "inspect":
                    return IID + (" running" if fault == "foreign" else " created")
                elif args[1] == "cp":
                    self.assertEqual(args[2], cid + ":" + PATH)
                    if fault == "copy":
                        raise Rejected("copy_failed")
                    Path(args[-1]).write_bytes(content)
                elif args[1] == "rm":
                    self.assertEqual(args, ["docker", "rm", "-v", cid])
                elif args[:3] == ["go", "version", "-m"]:
                    return "offline metadata"
                else:
                    self.fail(args)

            with (
                self.subTest(fault=fault),
                tempfile.TemporaryDirectory() as tmp,
                patch.object(rebuild, "command", command),
                patch.object(
                    rebuild,
                    "confirm_absent",
                    side_effect=Rejected("cleanup_failed") if fault == "cleanup" else None,
                ) as absent,
            ):
                if fault == "none":
                    self.assertEqual(
                        rebuild.binary_readback(Path(tmp), IID), (len(content), digest(content))
                    )
                else:
                    with self.assertRaises(Rejected):
                        rebuild.binary_readback(Path(tmp), IID)
                    self.assertFalse(any(args[0] == "go" for args in calls))
                self.assertIn(["docker", "rm", "-v", cid], calls)
                absent.assert_called_once_with(Path(tmp) / "readback.cid")

    def test_branch_specific_thresholds_cannot_use_an_older_branch_or_an_unknown_fix(self):
        for versions, state, classification in (
            (["1.26.11", "1.27.4"], "fixed", "threshold_met"),
            (["1.26.10", "1.27.5"], "fixed", "below_threshold"),
            (["1.26.9"], "fixed", "no_comparable_threshold"),
            (["1.27.3", "unparseable"], "fixed", "unverified_fix"),
            ([], "unknown", "unverified_fix"),
        ):
            row = finding("stdlib-control", "stdlib", "High")
            row["fix"] = {"state": state, "versions": versions}
            self.source = result([*self.source["findings"][:1], row], pair.STOCK[1])
            with self.subTest(versions=versions):
                report = self.run_fake()
                verified = classification == "threshold_met"
                self.assertEqual(report["fixed_thresholds"][-1]["classification"], classification)
                self.assertEqual(report["fixed_thresholds"][-1]["verified"], verified)
                self.assertEqual(report["stock"]["findings"], self.source["findings"])
                self.assertEqual(report["proposal"]["findings"], [])
                self.assertTrue(report["app_advisory"]["verified"])
                self.assertEqual(
                    report["status"], "diagnostic-clear" if verified else "inconclusive"
                )

    def test_cli_returns_diagnostic_exit_and_requires_hosted_runner(self):
        with (
            patch.dict(rebuild.os.environ, {"GITHUB_ACTIONS": "false"}),
            patch.object(rebuild, "qualify") as qualify,
        ):
            with self.assertRaises(SystemExit):
                rebuild.main(["--image-id", IID])
            qualify.assert_not_called()
        with (
            patch.dict(
                rebuild.os.environ, GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted"
            ),
            patch.object(rebuild.platform, "machine", return_value="x86_64"),
            patch.object(rebuild.platform, "system", return_value="Linux"),
            patch.object(rebuild, "qualify", side_effect=Rejected("refused")),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(rebuild.main(["--image-id", IID]), 1)
            self.assertFalse(json.loads(output.getvalue())["release_ready"])

    def test_reviewed_go_alternative_requires_exact_advisory_package_and_scanner_fix(self):
        for suffix in ("6603", "6610", "6611", "6612", "6617", "9999"):
            row = finding("GO-2026-" + suffix, "stdlib", "High", "go1.26.7")
            row["fix"]["versions"] = ["1.26.9"]
            for name, versions, state in (
                ("stdlib", ["1.26.9"], "fixed"),
                ("stdlib", ["1.26.8"], "fixed"),
                ("stdlib", ["1.26.9", "1.27.5"], "fixed"),
                ("stdlib", ["1.26.9"], "unknown"),
                ("golang.org/x/net", ["1.26.9"], "fixed"),
            ):
                change = {**row, "package": name, "fix": {"state": state, "versions": versions}}
                (check,) = rebuild.fixed_thresholds(self.mods, [change])
                reviewed = suffix != "9999" and change == row
                with self.subTest(advisory=suffix, name=name, versions=versions, state=state):
                    self.assertEqual("upstream" in check, reviewed)
                    self.assertEqual(check["verified"], reviewed)
                    self.assertEqual(check["stock_fix"], change["fix"])
                    if reviewed:
                        self.assertEqual(
                            check["upstream"]["url"], f"https://vuln.go.dev/ID/{row['id']}.json"
                        )
                        self.assertEqual(check["upstream"]["fixed"], "1.27.2")
                        self.assertRegex(check["upstream"]["sha256"], "^[a-f0-9]{64}$")

    def run_fake(self, *, retain=False):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                rebuild,
                "command",
                side_effect=lambda args: IID if args[0] == "docker" else "\n".join(self.info),
            ),
            patch.object(pair, "pull_verified"),
            patch.object(pair, "scanner_database", return_value=(Path(tmp), self.db)),
            patch.object(
                rebuild,
                "measure",
                side_effect=[
                    (self.base, self.stock, self.source),
                    (self.config, self.new, self.candidate),
                ],
            ) as scan,
            patch.object(
                rebuild,
                "binary_readback",
                side_effect=[self.binary, (1, rebuild.delivery.STOCK_BINARY_SHA256)],
            ) as binary,
            patch.object(rebuild.delivery, "archive_hash", return_value="d" * 64),
            patch.object(rebuild.delivery, "retain") as stage,
        ):
            report = rebuild.qualify(Path(tmp), IID, retain_archive=retain)
            if retain and report["status"] == "diagnostic-clear":
                stage.assert_called_once_with(Path(tmp), report, "d" * 64)
                self.assertEqual(
                    binary.call_args.args, (Path(tmp) / "stock-readback", pair.STOCK[1])
                )
            else:
                stage.assert_not_called()
            self.assertEqual(
                [c.args[1:] for c in scan.call_args_list],
                [
                    (Path(tmp), self.db, "source", pair.STOCK[1]),
                    (Path(tmp), self.db, "candidate", IID),
                ],
            )
            return report

    def test_optional_retention_requires_a_clear_pair_and_stock_binary_readback(self):
        self.assertEqual(
            self.run_fake(retain=True)["stock_binary_sha256"], rebuild.delivery.STOCK_BINARY_SHA256
        )
        for severity in ("Unknown", "High", "Critical"):
            self.candidate = result([finding("new", "stdlib", severity)], IID)
            self.assertNotEqual(self.run_fake(retain=True)["status"], "diagnostic-clear")

    def test_readback_mismatch_reports_measured_size_and_hash_and_keeps_findings(self):
        for size, sha in ((52_174_971, self.binary[1]), (52_174_972, "f" * 64)):
            with self.subTest(size=size), patch.object(self, "binary", (size, sha)):
                report = self.run_fake()
                self.assertEqual(report["reason"], "local_path_binary_mismatch")
                self.assertEqual(report["status"], "inconclusive")
                self.assertEqual((report["binary_size"], report["binary_sha256"]), (size, sha))
                self.assertEqual(report["removed_blocking"][0]["id"], pair.ADVISORY)

    def test_bound_configs_layers_control_and_all_blocking_deltas(self):
        report = self.run_fake()
        self.assertEqual(report["status"], "diagnostic-clear")
        self.assertIs(report["release_ready"], False)
        self.assertTrue(report["app_advisory"]["verified"])
        for severity in ("Unknown", "High", "Critical"):
            with self.subTest(severity=severity):
                self.candidate = result([finding("new", "stdlib", severity)] * 2, IID)
                report = self.run_fake()
                self.assertEqual(
                    report["status"], "inconclusive" if severity == "Unknown" else "fail"
                )
                self.assertEqual(report["added_blocking"][0]["count"], 2)
                self.assertEqual(report["removed_blocking"][0]["id"], pair.ADVISORY)
        self.candidate = result([], IID)
        self.source = result([], pair.STOCK[1])
        self.assertEqual(self.run_fake()["status"], "inconclusive")

    def test_wrong_config_layer_database_or_stock_inventory_cannot_clear(self):
        for field, value in (
            ("config", {**self.config, "config": {"User": "1000"}}),
            ("config", {**self.config, "rootfs": {"type": "layers", "diff_ids": [IID]}}),
            (
                "config",
                {
                    **self.config,
                    "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "0" * 64, IID, IID]},
                },
            ),
            ("source", {**self.source, "image_id": IID}),
            ("candidate", {**self.candidate, "image_id": pair.STOCK[1]}),
            ("candidate", {**self.candidate, "database": {}}),
            ("stock", {**self.stock, "packages": self.stock["packages"][:-1]}),
        ):
            with self.subTest(field=field, value=value), patch.object(self, field, value):
                try:
                    report = self.run_fake()
                except Rejected:
                    continue
                self.assertNotEqual(report["status"], "diagnostic-clear")
