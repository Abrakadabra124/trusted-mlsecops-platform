"""CLI pin wiring, real M23 replay, and independent signed M18 freeze tests.

The two existing signed fixture families have different candidates. Test each
ordinary verifier with its own original bytes, mocking only their join/checkout.
No native operation, report replacement or reviewer evidence in production.
"""

import contextlib
import copy
import io
import os
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, decode, digest, write_json
from scripts import final_evidence_qualification as frozen_fixtures
from scripts import m18_security_driver as driver
from scripts import m18_security_retention as retention
from scripts import m18_security_retention_qualification as security_fixtures

ROOT = Path(__file__).resolve().parents[1]


class SecurityDriver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        security_fixtures.RetentionContract.setUpClass()
        cls.addClassCleanup(security_fixtures.RetentionContract.doClassCleanups)

    def setUp(self):
        self.fixture = security_fixtures.RetentionContract()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.state = self.fixture.state
        self.receipt = dict(
            schema_version=1,
            **self.fixture.source,
            image_id=self.fixture.values["image_id"],
            freeze={retention.candidate.PROPOSAL: self.fixture.pins["proposal"]},
            policy_reference="a" * 64,
        )
        self.freeze_pin = self.fixture.put(driver.freeze.RECEIPT, self.receipt)
        self.enterContext(
            patch.object(retention, "case_inventory", return_value=self.fixture.expected_cases)
        )
        self.frozen = self.enterContext(
            patch.object(retention.final, "frozen", return_value=(self.fixture.values, {}, {}))
        )

    def run_driver(self, mode="capture", **changes):
        args = dict(
            freeze_pin=self.freeze_pin,
            pins=self.fixture.pins,
            owner=self.fixture.owner,
            expected_cases=self.fixture.expected_cases,
        )
        return driver.run(ROOT, self.state, mode, **(args | changes))

    def test_capture_keeps_original_and_replays_without_M23_stage_and_authority_files(self):
        original = (self.state / "evidence/M23.json").read_bytes()
        result = self.run_driver()
        index = result["index_sha256"]
        self.assertEqual(result["frozen_inputs_sha256"], self.freeze_pin)
        self.assertEqual(result["expected_cases_sha256"], self.fixture.expected_cases)
        self.assertEqual(result["artifact_count"], 20)
        self.assertIs(result["release_ready"], False)
        self.assertEqual(original, (self.state / "evidence/M23.json").read_bytes())
        record = decode(retention.object_bytes(self.state, index))
        for name in record["files"]:
            # The proposal is shared with final.frozen, whose original inputs remain.
            if name != retention.candidate.PROPOSAL:
                (self.state / name).unlink()
        replayed = self.run_driver("replay", index_pin=index)
        self.assertEqual(replayed, {k: v for k, v in result.items() if k != "object_count"})
        self.assertEqual(original, retention.object_bytes(self.state, self.fixture.pins["report"]))
        self.assertFalse((self.state / "evidence/M23.json").exists())

    def test_missing_corrupt_and_foreign_index_cannot_replay(self):
        result = self.run_driver()
        pin = result["index_sha256"]
        path = self.state / "evidence/M18-objects" / pin
        original = path.read_bytes()
        for raw in (None, b"corrupt"):
            if raw is None:
                path.unlink()
            else:
                path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(Rejected):
                self.run_driver("replay", index_pin=pin)
        path.write_bytes(original)
        with self.assertRaises(Rejected):
            self.run_driver("replay", index_pin="0" * 64)

    def test_independent_cases_seven_pins_and_original_owner_are_required(self):
        for changes in (
            {"expected_cases": "0" * 64},
            {"pins": {k: v for k, v in self.fixture.pins.items() if k != "workspace"}},
            {"pins": self.fixture.pins | {"workspace": "0" * 64}},
            {"pins": self.fixture.pins | {"report": True}},
            {"owner": self.fixture.owner | {"GITHUB_RUN_ATTEMPT": "3"}},
            {"owner": self.fixture.owner | {"GITHUB_RUN_ID": "012345"}},
            {"owner": self.fixture.owner | {"extra": "1"}},
            {"index_pin": "a" * 64},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.run_driver(**changes)
        self.assertFalse((self.state / "evidence/M18-objects").exists())
        for mode in ("replay", "unsupported"):
            with self.assertRaises(Rejected):
                self.run_driver(mode)

    def test_all_original_capture_pins_are_enforced_by_driver(self):
        for key in retention.PIN_FIELDS:
            with self.subTest(pin=key), self.assertRaises(Rejected):
                self.run_driver(pins=self.fixture.pins | {key: "0" * 64})
        self.assertFalse((self.state / "evidence/M18-objects").exists())

    def test_original_freeze_candidate_is_used_by_ordinary_report_verifier(self):
        for field, value in (
            ("candidate_reference", "0" * 64),
            ("evaluation_reference", "0" * 64),
            ("model_sha256", "0" * 64),
            ("model", "0" * 64),
            ("release_subject", "0" * 64),
            ("source_revision", "0" * 40),
        ):
            self.frozen.return_value = (self.fixture.values | {field: value}, {}, {})
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.run_driver()
        self.assertFalse((self.state / "evidence/M18-objects").exists())


class OriginalFreeze(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        frozen_fixtures.FinalEvidenceContracts.setUpClass()
        cls.addClassCleanup(frozen_fixtures.FinalEvidenceContracts.tearDownClass)

    def setUp(self):
        self.fixture = frozen_fixtures.FinalEvidenceContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.build()
        self.root, self.state = self.fixture.root, self.fixture.state
        self.receipt = {
            k: v
            for k, v in self.fixture.index.items()
            if k
            in (
                "schema_version",
                "source_revision",
                "source_fingerprint",
                "image_id",
                "freeze",
                "policy_reference",
            )
        }
        self.freeze_pin = self.fixture.pinfile(driver.freeze.RECEIPT, self.receipt)
        self.expected_cases = retention.case_inventory(ROOT)
        self.enterContext(
            patch.object(retention, "case_inventory", return_value=self.expected_cases)
        )
        self.clean = self.enterContext(patch.object(retention.final, "clean"))
        self.collect = self.enterContext(
            patch.object(retention, "collect", return_value={"release_ready": False})
        )
        self.enterContext(
            patch.object(driver.freeze.release_bundle, "load", side_effect=AssertionError("no SQL"))
        )
        self.pins = dict.fromkeys(retention.PIN_FIELDS, "b" * 64)
        self.pins["proposal"] = self.fixture.freeze[retention.candidate.PROPOSAL]
        self.owner = dict(GITHUB_RUN_ID="12345", GITHUB_RUN_ATTEMPT="2")

    def run_driver(self, **changes):
        args = dict(
            freeze_pin=self.freeze_pin,
            pins=self.pins,
            owner=self.owner,
            expected_cases=self.expected_cases,
        )
        return driver.run(self.root, self.state, "capture", **(args | changes))

    def test_original_signed_package_provides_exact_values_offline(self):
        self.run_driver()
        self.clean.assert_called_once_with(
            self.root,
            self.fixture.source["source_revision"],
            self.fixture.source["source_fingerprint"],
        )
        self.collect.assert_called_once_with(
            self.root,
            self.state,
            values=self.fixture.values,
            pins=self.pins,
            owner=self.owner,
            expected_cases=self.expected_cases,
        )

    def test_freeze_receipt_requires_exact_pin_schema_version_and_original_proposal(self):
        path = self.state / driver.freeze.RECEIPT
        raw = path.read_bytes()
        for changes in (
            {"schema_version": True},
            {"extra": "canary"},
            {"freeze": {}},
            {"freeze": self.receipt["freeze"] | {retention.candidate.PROPOSAL: "0" * 64}},
            {"source_revision": "0" * 40},
            {"image_id": "sha256:" + "0" * 64},
        ):
            write_json(path, self.receipt | changes)
            with self.subTest(changes=changes), self.assertRaises((Rejected, KeyError)):
                self.run_driver(freeze_pin=digest(path.read_bytes()))
        path.write_bytes(raw + b" ")
        with self.assertRaises(Rejected):
            self.run_driver()
        path.unlink()
        with self.assertRaises(Rejected):
            self.run_driver()
        self.collect.assert_not_called()

    def test_every_shared_freeze_file_and_signed_material_is_required_and_unchanged(self):
        paths = [self.state / name for name in self.receipt["freeze"]]
        paths += [
            self.state / "evidence/M18-objects" / pin
            for pin in (
                self.receipt["policy_reference"],
                self.fixture.proposal["proposal_reference"],
            )
        ]
        for path in paths:
            raw = path.read_bytes()
            for content in (b"corrupt", None):
                if content is None:
                    path.unlink()
                else:
                    path.write_bytes(content)
                with (
                    self.subTest(file=path.name, missing=content is None),
                    self.assertRaises(Rejected),
                ):
                    self.run_driver()
            path.write_bytes(raw)
        self.collect.assert_not_called()

    def test_rehashed_foreign_candidate_in_shared_demo_is_refused(self):
        name = "storage-demo.json"
        demo = decode((self.state / name).read_bytes())
        demo["candidate"]["candidate_reference"] = "0" * 64
        receipt = copy.deepcopy(self.receipt)
        receipt["freeze"][name] = self.fixture.pinfile(name, demo)
        pin = self.fixture.pinfile(driver.freeze.RECEIPT, receipt)
        with self.assertRaises(Rejected):
            self.run_driver(freeze_pin=pin)
        self.collect.assert_not_called()


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.output = self.directory / "output"
        self.env = dict(
            M18_FREEZE_SHA256="a" * 64,
            M18_SECURITY_CASES_SHA256="b" * 64,
            M18_SECURITY_INDEX_SHA256="c" * 64,
            M23_RUN_ID="12345",
            M23_RUN_ATTEMPT="2",
            GITHUB_RUN_ID="99999",
            GITHUB_RUN_ATTEMPT="9",
            GITHUB_OUTPUT=str(self.output),
        )
        self.env.update(
            {
                "M23_" + key.upper() + "_SHA256": f"{n:064x}"
                for n, key in enumerate(retention.PIN_FIELDS, 1)
            }
        )
        self.enterContext(patch.dict(os.environ, self.env, clear=True))

    def test_capture_and_replay_bind_all_seven_external_pins_and_original_run(self):
        result = dict(
            schema_version=1,
            scope=driver.SCOPE,
            index_sha256="c" * 64,
            artifact_count=20,
            release_ready=False,
        )
        for mode in ("capture", "replay"):
            with (
                patch.object(driver, "run", return_value=result) as run,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                driver.main([mode])
            run.assert_called_once_with(
                ROOT,
                ROOT / ".runtime",
                mode,
                freeze_pin="a" * 64,
                pins={
                    key: self.env["M23_" + key.upper() + "_SHA256"] for key in retention.PIN_FIELDS
                },
                owner=dict(GITHUB_RUN_ID="12345", GITHUB_RUN_ATTEMPT="2"),
                expected_cases="b" * 64,
                index_pin="c" * 64 if mode == "replay" else None,
            )
            self.assertEqual(decode(output.getvalue().encode()), result)
        self.assertIn("release_ready=false\n", self.output.read_text(encoding="utf-8"))

    def test_prerun_inventory_needs_no_freeze_reports_owner_or_runtime(self):
        expected = retention.case_inventory(ROOT)
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(driver, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            driver.main(["case-inventory"])
        result = decode(output.getvalue().encode())
        self.assertEqual(result["expected_cases_sha256"], expected)
        self.assertIs(result["release_ready"], False)

    def test_missing_original_owner_never_falls_back_to_current_GitHub_run(self):
        del os.environ["M23_RUN_ID"]
        with patch.object(driver, "run") as run, self.assertRaises(KeyError):
            driver.main(["capture"])
        run.assert_not_called()

    def test_cli_invalid_arguments_and_failures_emit_no_private_details(self):
        for args in ([], ["unknown"], ["capture", "extra"]):
            with self.assertRaises(Rejected):
                driver.main(args)
        for error in (Rejected, OSError, KeyError, TypeError, ValueError):
            with (
                patch.object(driver, "main", side_effect=error("PRIVATE-CANARY")),
                self.assertRaises(SystemExit) as result,
            ):
                driver.cli()
            self.assertEqual(str(result.exception), "M18 security primary verification failed")

    def test_module_entry_point_outputs_source_inventory(self):
        with (
            patch("sys.argv", ["m18_security_driver", "case-inventory"]),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            runpy.run_path(str(ROOT / "scripts/m18_security_driver.py"), run_name="__main__")
        self.assertEqual(
            decode(output.getvalue().encode())["expected_cases_sha256"],
            retention.case_inventory(ROOT),
        )


if __name__ == "__main__":
    unittest.main()
