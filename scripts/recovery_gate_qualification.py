"""Ordinary M17 CLI with controlled post-cleanup replay and no infrastructure."""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import acceptance
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import m17_recovery_native as native


def pin(label):
    return digest(label.encode())


class Gate(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(TemporaryDirectory()))
        self.output = self.state / "evidence/M17.json"
        runner = dict(GITHUB_RUN_ID="10", GITHUB_RUN_ATTEMPT="2")
        owner = dict(
            source_revision="1" * 40,
            source_fingerprint=pin("source"),
            methods=pin("methods"),
            pins={k: pin(k) for k in ("demo", "keys", "proposal")},
            runner=runner,
        )
        self.env = {
            **runner,
            "RUNNER_TEMP": str(self.state.parent),
            **{"M17_" + k.upper() + "_SHA256": v for k, v in owner["pins"].items()},
            "M17_PRIMARY_SHA256": pin("primary"),
        }
        self.enterContext(patch.dict(os.environ, self.env))
        self.enterContext(
            patch.object(acceptance, "command", return_value=owner["source_revision"])
        )
        self.enterContext(
            patch.object(acceptance, "source_fingerprint", return_value=owner["source_fingerprint"])
        )
        self.enterContext(
            patch.object(
                sys,
                "argv",
                [
                    "acceptance",
                    "--gate",
                    "M17",
                    "--state",
                    str(self.state),
                    "--output",
                    str(self.output),
                ],
            )
        )
        self.enterContext(redirect_stdout(io.StringIO()))
        for file in (
            native.PACKET,
            "storage.json",
            native.TARGET + "/storage.json",
            "storage-demo.json",
            "trusted-keys.json",
            "evidence/release-native.json",
        ):
            write_json(self.state / file, {})
        self.schedule = dict(
            unit="mlsecops-daily-backup-" + "a" * 32 + ".timer",
            calendar="*-*-* 02:00:00 UTC",
            trigger="controlled-on-active",
            runtime_units_removed=True,
            daily_cadence_observed=False,
            last_trigger_utc="2026-01-01T04:00:00+00:00",
            service_started_at="2026-01-01T04:00:01+00:00",
            service_exited_at="2026-01-01T04:00:12+00:00",
            next_elapse_utc="2026-01-02T02:00:00+00:00",
            exit_status=0,
            backup_id=pin("backup"),
            inventory_sha256=pin("inventory"),
        )
        refs = dict(
            candidate_reference=pin("candidate"),
            evaluation_reference=pin("evaluation"),
            model_sha256=pin("model"),
        )
        self.sql = dict(
            scope="source-offline-sql-evaluated-candidate",
            release_ready=False,
            backup_id=pin("backup"),
            dataset_reference=pin("dataset"),
            **refs,
            features_sha256=pin("features"),
            image_id="sha256:" + pin("image"),
            golden_rows=1000,
            max_error=0.000001,
            rto_seconds=8.5,
            wall_elapsed_seconds=8.5,
            rpo_seconds=86399,
        )
        self.proposal = dict(
            **refs,
            subject_sha256=pin("subject"),
            proposal_reference=pin("proposal-ref"),
            target_workspace="a" * 32,
            release_ready=False,
            status="verified-proposal-requires-assurance",
        )
        self.control = dict(
            scope="controlled-approvals-in-shared-v2-snapshot",
            status="pass",
            release_ready=False,
            backup_id=pin("backup"),
            campaign="b" * 32,
            image=self.sql["image_id"],
            approved_sequences=[1, 2],
            selected_request_sha256=pin("selection"),
            approval_sha256=pin("approval"),
            release_subject=pin("controlled subject"),
            model_sha256=refs["model_sha256"],
            revoked_approver_sha256=pin("revoked"),
            healthy_status=200,
            cold_ready_status=503,
            cold_predict_status=503,
            target_workspace=self.proposal["target_workspace"],
            source_workspace="c" * 32,
            archive_refusals={k: "backup_archive_integrity_failed" for k in ("missing", "corrupt")},
            verified_clock=dict(before_ns=1, monotonic_ns=1, after_ns=2),
        )
        self.result = dict(
            started_at="2026-01-02T01:00:12+00:00",
            schedule=self.schedule,
            sql=self.sql,
            timing=dict(rto_seconds=900, rpo_seconds=86400),
            control=self.control,
            proposal=self.proposal,
            owner=owner,
        )
        self.replay = self.enterContext(patch.object(native, "replay", return_value=self.result))

    def check(self, code, status):
        write_json(self.output, dict(status="pass", stale=True))
        self.assertEqual(acceptance.main(), code)
        result = read_json(self.output)
        self.assertEqual((result["status"], result["exit_code"]), (status, code))
        self.assertIs(result["release_ready"], False)
        self.assertNotIn("stale", result)
        self.assertNotIn(b"PRIVATE-M17", canonical(result))
        return result

    def test_missing_prerequisites_replace_stale_pass_without_replay(self):
        for name in self.env:
            with self.subTest(name=name), patch.dict(os.environ):
                del os.environ[name]
                self.check(2, "inconclusive")
        (self.state / native.PACKET).unlink()
        self.check(2, "inconclusive")
        self.replay.assert_not_called()

    def test_owner_rejection_or_stopped_store_unavailable(self):
        for error, code, status in (
            (Rejected("PRIVATE-M17"), 1, "fail"),
            (Rejected("storage_resource_missing:container"), 2, "inconclusive"),
        ):
            self.replay.side_effect = error
            self.assertEqual(self.check(code, status)["cases"], [])

    def test_foreign_owner_attempt_source_and_different_subject_fail_closed(self):
        for part, change in (
            (self.result["owner"]["runner"], dict(GITHUB_RUN_ATTEMPT="1")),
            (self.result["owner"]["pins"], dict(demo=pin("foreign"))),
            (self.result["owner"], dict(source_revision="0" * 40)),
            (self.result["owner"], dict(source_fingerprint="0" * 64)),
            (self.proposal, dict(candidate_reference=pin("other"))),
            (self.control, dict(target_workspace="e" * 32)),
            (self.control, dict(model_sha256=pin("other-trained-model"))),
            (self.control, dict(release_subject=self.proposal["subject_sha256"])),
            (self.schedule, dict(backup_id=pin("other"))),
        ):
            with self.subTest(change=change), patch.dict(part, change):
                self.check(1, "fail")

    def test_actual_rto_includes_serving_and_rpo_uses_signed_point(self):
        for field, value in (
            ("rto_seconds", 900.000001),
            ("rpo_seconds", 86400.000001),
            ("rpo_seconds", True),
            ("rto_seconds", float("nan")),
        ):
            with (
                self.subTest(field=field, value=value),
                patch.dict(self.result["timing"], {field: value}),
            ):
                self.check(1, "fail")

    def test_incomplete_drills_and_false_cadence_claim_cannot_pass(self):
        for part, change in (
            (self.schedule, dict(next_elapse_utc="2026-01-03T02:00:00+00:00")),
            (self.schedule, dict(daily_cadence_observed=True)),
            (self.schedule, dict(exit_status=False)),
            (self.sql, dict(golden_rows=999)),
            (self.sql, dict(max_error=0.01)),
            (self.proposal, dict(release_ready=True)),
            (self.control, dict(cold_ready_status=200)),
            (self.control, dict(approved_sequences=[True, 2])),
            (self.control, dict(archive_refusals={"missing": "backup_archive_integrity_failed"})),
        ):
            with self.subTest(change=change), patch.dict(part, change):
                self.check(1, "fail")

    def test_bounded_lab_pass_uses_verified_summary_and_redacts_private_data(self):
        for part in (self.proposal, self.schedule, self.control, self.sql):
            part["private"] = "PRIVATE-M17"
        result = self.check(0, "pass")
        self.replay.assert_called_once()
        self.assertEqual(result["metrics"]["rto_seconds"], 900)
        self.assertEqual(result["metrics"]["rpo_seconds"], 86400)
        self.assertFalse(result["metrics"]["daily_cadence_observed"])
        self.assertEqual(
            result["input_digests"]["candidate_reference"], self.sql["candidate_reference"]
        )
        self.assertNotIn("release_subject", result["input_digests"])
        self.assertEqual(
            result["artifact_hashes"]["recovery_packet"], self.env["M17_PRIMARY_SHA256"]
        )
        self.assertEqual(len({case["id"] for case in result["cases"]}), result["metrics"]["checks"])

    def test_schedule_can_have_next_elapse_on_the_same_utc_date(self):
        with patch.dict(
            self.schedule,
            dict(
                last_trigger_utc="2026-01-01T01:00:00+00:00",
                service_started_at="2026-01-01T01:00:01+00:00",
                service_exited_at="2026-01-01T01:00:12+00:00",
                next_elapse_utc="2026-01-01T02:00:00+00:00",
            ),
        ):
            self.check(0, "pass")

    def test_garbage_owner_pin_is_a_rejection_before_replay(self):
        with patch.dict(os.environ, M17_PRIMARY_SHA256="PRIVATE-M17"):
            self.check(1, "fail")
        self.replay.assert_not_called()
