"""Controlled ordinary M16 acceptance. Exercise the packet/owner boundary without services."""

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
from scripts import canary_rollback_native as rollback
from scripts import canary_rollout_native as native


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(TemporaryDirectory()))
        self.output = self.state / "evidence/M16.json"
        source = dict(source_revision="1" * 40, source_fingerprint="2" * 64)
        self.owner = dict(
            source=source,
            methods="3" * 64,
            runner=dict(GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="1"),
            proposal_pin="4" * 64,
        )
        self.packet = dict(
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:01:00+00:00",
            campaign="a" * 32,
            source=source,
            methods=self.owner["methods"],
            proposal_sha256=self.owner["proposal_pin"],
            runner=self.owner["runner"],
            candidate=dict(
                candidate_reference="5" * 64,
                evaluation_reference="6" * 64,
                model_sha256="7" * 64,
                subject_sha256="8" * 64,
                proposal_reference="9" * 64,
                permit_sha256="a" * 64,
                image_id="sha256:" + "b" * 64,
                source_evidence_sha256="0" * 64,
            ),
            stable=dict(model_sha256="c" * 64, subject_sha256="d" * 64, request_sha256="e" * 64),
            traffic=dict(primary_sha256="1" * 64),
            journals=dict(stable="d" * 64, candidate="e" * 64),
            private="PRIVATE-CANARY",
        )
        self.traffic = dict(
            stages=[
                dict(
                    candidate_percent=p,
                    attempts=200,
                    valid=200,
                    errors=0,
                    candidate_attempts=p * 2,
                    p95_ms=200.0,
                    p99_ms=500.0,
                    passed=True,
                    checks=dict(
                        valid_observations=True,
                        golden_responses=True,
                        latency=True,
                        error_delta=True,
                    ),
                )
                for p in (0, 10, 50, 100)
            ],
            requests=800,
            audit_completed=dict(stable=481, candidate=321),
            route_recovery_seconds=120,
            primary_traffic_sha256="1" * 64,
            candidate="5" * 64,
            model="7" * 64,
            release_subject="8" * 64,
        )
        self.durable = dict(
            scope=rollback.SCOPE,
            campaign=self.packet["campaign"],
            release_ready=False,
            recovery_ns=120_000_000_000,
            refusal_statuses=[503, 503],
            refusal_attempts=[1, 2],
            **{
                k: digest(k.encode())
                for k in (
                    "from_request_sha256",
                    "target_request_sha256",
                    "restored_request_sha256",
                    "restored_bundle",
                    "restored_model",
                    "rejected_rollback_event",
                    "pending_case_sha256",
                )
            },
        )
        self.record = dict(
            schema_version=1,
            owner=self.owner,
            started_at=self.packet["finished_at"],
            finished_at="2026-01-01T00:02:00+00:00",
            drill=dict(
                campaign=self.packet["campaign"],
                image=self.packet["candidate"]["image_id"],
                features=[[0.1]],
            ),
        )
        write_json(self.state / "storage.json", {})
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    **self.owner["runner"],
                    "T19_PROPOSAL_SHA256": self.owner["proposal_pin"],
                },
            )
        )
        self.seal()
        self.enterContext(
            patch.object(acceptance, "command", return_value=source["source_revision"])
        )
        self.enterContext(
            patch.object(
                acceptance, "source_fingerprint", return_value=source["source_fingerprint"]
            )
        )
        self.enterContext(patch.object(native, "hosted"))
        self.enterContext(patch.object(native, "capture_inputs", return_value=self.owner))
        self.enterContext(patch.object(native, "validate", return_value={"container_id": "owned"}))
        self.inspect = self.enterContext(
            patch.object(native, "inspect", return_value={"State": {"Running": False}})
        )
        self.enterContext(patch.object(native, "probe_features", return_value=[[0.1]]))
        self.traffic_replay = self.enterContext(
            patch.object(native.canary_native_evidence, "replay", return_value=self.traffic)
        )
        self.durable_replay = self.enterContext(
            patch.object(rollback, "replay", return_value=self.durable)
        )
        self.enterContext(
            patch.object(
                sys,
                "argv",
                [
                    "acceptance",
                    "--gate",
                    "M16",
                    "--state",
                    str(self.state),
                    "--output",
                    str(self.output),
                ],
            )
        )
        self.enterContext(redirect_stdout(io.StringIO()))

    def seal(self):
        for filename, variable, record in (
            (native.PACKET, "T19_PRIMARY_SHA256", self.packet),
            (native.ROLLBACK_PACKET, "T19_ROLLBACK_SHA256", self.record),
        ):
            if variable == "T19_ROLLBACK_SHA256":
                record["traffic_sha256"] = os.environ["T19_PRIMARY_SHA256"]
            path = self.state / filename
            write_json(path, record)
            os.environ[variable] = digest(path.read_bytes())

    def run_gate(self, code, status):
        write_json(self.output, {"status": "pass", "stale": True})
        self.assertEqual(acceptance.main(), code)
        result = read_json(self.output)
        self.assertEqual((result["status"], result["exit_code"]), (status, code))
        self.assertIs(result["release_ready"], False)
        self.assertNotIn("stale", result)
        self.assertNotIn(b"PRIVATE-CANARY", canonical(result))
        return result

    def test_summary_alone_and_missing_pin_invalidate_stale_pass(self):
        with patch.dict(os.environ):
            del os.environ["T19_ROLLBACK_SHA256"]
            self.run_gate(2, "inconclusive")
        (self.state / native.ROLLBACK_PACKET).unlink()
        write_json(self.state / "evidence/canary-gate.json", self.durable)
        self.run_gate(2, "inconclusive")
        self.traffic_replay.assert_not_called()

    def test_stopped_owner_and_original_bytes_required_before_reporting(self):
        self.inspect.return_value["State"]["Running"] = True
        self.run_gate(1, "fail")
        self.traffic_replay.assert_not_called()
        self.inspect.return_value["State"]["Running"] = False
        path = self.state / native.PACKET
        path.write_bytes(path.read_bytes().rstrip())
        self.run_gate(1, "fail")
        self.durable_replay.assert_not_called()

    def test_rehashed_durable_capture_from_another_attempt_is_rejected(self):
        self.record["owner"] = {
            **self.owner,
            "runner": {**self.owner["runner"], "GITHUB_RUN_ATTEMPT": "2"},
        }
        self.seal()
        self.run_gate(1, "fail")
        self.durable_replay.assert_not_called()

    def test_replay_rejection_is_redacted(self):
        self.durable_replay.side_effect = Rejected("PRIVATE-CANARY")
        self.run_gate(1, "fail")

    def test_gate_rejects_inconsistent_replay_results(self):
        for summary, change in (
            (self.traffic, {"model": "0" * 64}),
            (self.traffic, {"stages": self.traffic["stages"][:-1]}),
            (self.traffic["stages"][1], {"passed": False}),
            (self.traffic["stages"][1], {"valid": 99}),
            (self.traffic, {"route_recovery_seconds": 120.001}),
            (self.durable, {"campaign": "0" * 32}),
            (self.durable, {"scope": "production-approval"}),
            (self.durable, {"recovery_ns": 120_000_000_001}),
            (self.durable, {"refusal_statuses": [503, 200]}),
            (self.durable, {"release_ready": True}),
            (self.durable, {"pending_case_sha256": None}),
            (self.durable, {"raw": "PRIVATE-CANARY"}),
        ):
            with self.subTest(field=next(iter(change))), patch.dict(summary, change):
                self.run_gate(1, "fail")

    def test_capture_owner_is_rechecked_after_both_replays(self):
        foreign = {**self.owner, "runner": {**self.owner["runner"], "GITHUB_RUN_ATTEMPT": "3"}}
        with patch.object(native, "capture_inputs", side_effect=[self.owner, foreign]):
            self.run_gate(1, "fail")
        self.durable_replay.assert_called_once()

    def test_current_acceptance_source_must_match_capture(self):
        with patch.object(acceptance, "command", return_value="0" * 40):
            self.run_gate(1, "fail")

    def test_complete_replay_publishes_bounded_lab_cases_and_distinct_authorities(self):
        result = self.run_gate(0, "pass")
        self.assertEqual(result["metrics"]["stages"], self.traffic["stages"])
        self.assertEqual(result["metrics"]["requests"], 800)
        self.assertEqual(result["metrics"]["controlled_rollback"], self.durable)
        self.assertEqual(result["metrics"]["route_recovery_seconds"], 120)
        self.assertEqual(
            result["input_digests"]["qualified_candidate_subject"], self.traffic["release_subject"]
        )
        self.assertNotIn("release_subject", result["input_digests"])
        self.assertEqual(
            result["artifact_hashes"]["traffic_packet"], os.environ["T19_PRIMARY_SHA256"]
        )
        self.assertEqual(
            result["artifact_hashes"]["rollback_packet"], os.environ["T19_ROLLBACK_SHA256"]
        )
        self.assertEqual(result["metrics"]["checks"], len({case["id"] for case in result["cases"]}))
        self.assertTrue(result["residual_risks"])
        self.traffic_replay.assert_called_once()
        self.durable_replay.assert_called_once()
