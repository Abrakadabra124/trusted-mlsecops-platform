import base64
import copy
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import (
    contracts,
    inventory,
    process_privacy,
    release_bundle,
    sandbox,
    storage_bootstrap,
    storage_pki,
    worker_transport,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json, write_json
from scripts import candidate_serving_native, release_bundle_qualification
from scripts import serving_output_native as native
from scripts import serving_output_probe as probe
from scripts.privacy_evidence_qualification import END, START, SUBJECT, fixture
from scripts.serving_output_qualification import NEEDLES, expected, operation, report


def evidence_child(value=None):
    receipt = copy.deepcopy(value if value is not None else fixture())
    receipt["cases"].remove("full-lifecycle-output-privacy")
    del receipt["runtime"]["output_privacy"]

    def exercise(observer):
        observer(NEEDLES)
        return receipt

    return {
        "schema_version": 1,
        "output": probe.produce(exercise),
        "diagnostics": {
            "bytes": 0,
            "gpu_discovery_warning": False,
            "raw_output_retained": False,
        },
    }


class OutputNativeContracts(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(
            os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        )
        environment.start()
        self.addCleanup(environment.stop)
        campaign = patch("uuid.uuid4", return_value=SimpleNamespace(hex="d" * 32))
        campaign.start()
        self.addCleanup(campaign.stop)

    def test_guard_and_explicit_confirmation_precede_state_access(self):
        for arguments, error in (
            ([], None),
            (["--state", "private", "--confirm-disposable", "--child"], None),
            (["--state", "private", "--confirm-disposable", "--campaign", "invalid"], None),
            (["--state", "private", "--confirm-disposable"], Rejected("private-guard")),
        ):
            with (
                patch.object(process_privacy, "enforce", side_effect=error),
                patch.object(storage_pki, "workspace_id") as ownership,
                redirect_stderr(io.StringIO()) as diagnostic,
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(native.main(arguments), 1)
            ownership.assert_not_called()
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(diagnostic.getvalue(), "serving_output_rejected\n")

    def test_failed_child_diagnostics_project_only_fixed_operational_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            campaign = "d" * 32
            destination = state / "serving-qualifications" / campaign
            secret = "private-input-and-credential-canary"
            write_json(
                destination / "http-outage.json",
                {
                    "status": "fail",
                    "identity": secret,
                    "assessment": {
                        "first_503_seconds": 60.02,
                        "failures": ["first_http_503_exceeds_60_seconds", secret],
                    },
                },
            )
            write_json(
                destination / "http-paused-query.json",
                {
                    "status": "inconclusive",
                    "private": secret,
                    "denial": {
                        "http_status": 503,
                        "libpq_query_active_at_denial": True,
                        "read_finished_at_denial": False,
                        "response_valid": True,
                        "generation_fenced": True,
                    },
                },
            )
            report = native.failure_diagnostic(state, campaign)
            self.assertEqual(report["status"], "fail")
            self.assertFalse(report["release_ready"])
            self.assertNotIn(secret, canonical(report).decode())
            self.assertEqual(report["outage"]["first_503_seconds"], 60.02)
            self.assertEqual(report["outage"]["failures"], ["first_http_503_exceeds_60_seconds"])
            self.assertEqual(report["paused"]["http_status"], 503)
            self.assertEqual(report["expiry"]["status"], "unavailable")

    def test_failed_child_diagnostics_handle_missing_malformed_and_oversized_traces(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            campaign = "d" * 32
            destination = state / "serving-qualifications" / campaign
            for value in (
                {"status": "secret", "assessment": []},
                [],
                {
                    "status": "pass",
                    "assessment": {"first_503_seconds": "secret", "failures": "secret"},
                },
                {"status": "pass", "denial": []},
            ):
                for filename in (
                    "http-outage.json",
                    "http-paused-query.json",
                    "http-expiring-query.json",
                ):
                    write_json(destination / filename, value)
                report = native.failure_diagnostic(state, campaign)
                self.assertNotIn("secret", canonical(report).decode())
            (destination / "http-outage.json").write_bytes(b"x" * 262145)
            report = native.failure_diagnostic(state, campaign)
            self.assertEqual(report["outage"]["status"], "unavailable")
            report = native.failure_diagnostic(state, "../private")
            self.assertTrue(
                all(
                    report[name]["status"] == "unavailable"
                    for name in ("outage", "paused", "expiry")
                )
            )

    def test_child_failure_records_only_allowlisted_code_locations(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with (
                patch.object(process_privacy, "enforce"),
                patch.object(storage_pki, "workspace_id"),
                patch.object(storage_bootstrap, "validate"),
                patch.object(native, "qualified", side_effect=Rejected("credential-canary")),
                redirect_stdout(io.StringIO()) as output,
                redirect_stderr(io.StringIO()) as diagnostic,
            ):
                self.assertEqual(
                    native.main(
                        [
                            "--state",
                            str(state),
                            "--confirm-disposable",
                            "--child",
                            "--campaign",
                            "d" * 32,
                        ]
                    ),
                    1,
                )
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(diagnostic.getvalue(), "serving_output_rejected\n")
            report = native.failure_diagnostic(state, "d" * 32)
            self.assertTrue(report["locations"])
            self.assertEqual(report["locations"][0]["module"], "scripts.serving_output_native")
            self.assertNotIn("credential-canary", canonical(report).decode())
            self.assertNotIn(str(state), canonical(report).decode())

    def test_failure_location_projection_rejects_private_or_unbounded_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            path = state / "serving-qualifications" / ("d" * 32) / "failure-location.json"
            valid = {"module": "scripts.serving_output_native", "line": 10}
            for value in (
                {"private": "credential-canary"},
                [valid] * 17,
                [
                    None,
                    {"module": "credential-canary", "line": 1},
                    {**valid, "line": -1},
                    {**valid, "line": True},
                    {**valid, "line": 100001},
                    {**valid, "private": "credential-canary"},
                ],
            ):
                write_json(path, value)
                report = native.failure_diagnostic(state, "d" * 32)
                self.assertEqual(report["locations"], [])
                self.assertNotIn("credential-canary", canonical(report).decode())
            self.assertEqual(native.failure_locations(Rejected("credential-canary")), [])

    def test_failure_location_write_failure_does_not_expose_the_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(process_privacy, "enforce"),
                patch.object(storage_pki, "workspace_id"),
                patch.object(storage_bootstrap, "validate"),
                patch.object(native, "qualified", side_effect=Rejected("credential-canary")),
                patch.object(contracts, "write_json", side_effect=OSError("private-path")),
                redirect_stdout(io.StringIO()) as output,
                redirect_stderr(io.StringIO()) as diagnostic,
            ):
                self.assertEqual(
                    native.main(
                        [
                            "--state",
                            directory,
                            "--confirm-disposable",
                            "--child",
                            "--campaign",
                            "d" * 32,
                        ]
                    ),
                    1,
                )
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(diagnostic.getvalue(), "serving_output_rejected\n")

    def test_parent_verification_failure_exposes_only_code_locations(self):
        with (
            patch.object(native, "source", return_value=expected()),
            patch.object(native, "verified_subject", return_value=SUBJECT),
            patch.object(worker_transport, "capture", return_value=evidence_child()),
            patch.object(probe, "observe", side_effect=Rejected("credential-canary")),
            redirect_stdout(io.StringIO()) as output,
        ):
            with self.assertRaises(Rejected):
                native.run(Path("root"), Path("state"), "image", 15446)
        self.assertTrue(output.getvalue())
        report = decode(output.getvalue())
        self.assertTrue(report["locations"])
        self.assertNotIn("credential-canary", output.getvalue())
        self.assertEqual(report["status"], "fail")

    def test_non_hosted_environment_is_rejected_before_private_access(self):
        with (
            patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}),
            patch.object(process_privacy, "enforce"),
            patch.object(storage_pki, "workspace_id") as owner,
            redirect_stderr(io.StringIO()) as diagnostic,
        ):
            self.assertEqual(native.main(["--state", "private", "--confirm-disposable"]), 1)
        owner.assert_not_called()
        self.assertEqual(diagnostic.getvalue(), "serving_output_rejected\n")

    def test_source_is_clean_pinned_and_child_cannot_publish_campaign_report(self):
        with (
            patch.object(inventory, "command", side_effect=["", "b" * 40]),
            patch.object(inventory, "source_fingerprint", return_value="c" * 64),
            patch.object(sandbox, "resolve_image", return_value="sha256:" + "a" * 64),
        ):
            self.assertEqual(native.source(Path("root"), "alias"), expected())
        with (
            patch.object(inventory, "command", return_value="changed"),
            self.assertRaisesRegex(Rejected, "serving_output_source_dirty"),
        ):
            native.source(Path("root"), "alias")
        observer = object()
        with patch.object(candidate_serving_native, "qualify", return_value=report()) as action:
            self.assertEqual(
                native.qualified(Path("root"), Path("state"), "image", 15446, observer), report()
            )
        action.assert_called_once_with(
            Path("root"),
            Path("state"),
            "image",
            trust_port=15446,
            privacy_observer=observer,
            publish_report=False,
        )
        with patch.object(candidate_serving_native, "qualify", return_value=report()) as action:
            native.qualified(Path("root"), Path("state"), "image", 15446, observer, "d" * 32)
        self.assertEqual(action.call_args.kwargs["campaign_id"], "d" * 32)

    def test_parent_only_publishes_verified_result_and_constant_failure(self):
        for failure in (None, Rejected("private-canary"), KeyboardInterrupt()):
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                write_json(
                    state / "evidence/candidate-serving.json", {"status": "pass", "old": True}
                )
                with (
                    patch.object(process_privacy, "enforce"),
                    patch.object(storage_pki, "workspace_id"),
                    patch.object(storage_bootstrap, "validate"),
                    patch.object(native, "run", return_value=report(), side_effect=failure),
                    redirect_stdout(io.StringIO()) as output,
                    redirect_stderr(io.StringIO()) as diagnostic,
                ):
                    code = native.main(["--state", str(state), "--confirm-disposable"])
                if failure is None:
                    self.assertEqual(code, 0)
                    self.assertEqual(decode(output.getvalue()), report())
                    self.assertEqual(read_json(state / "evidence/candidate-serving.json"), report())
                    self.assertEqual(diagnostic.getvalue(), "")
                else:
                    self.assertEqual(code, 130 if isinstance(failure, KeyboardInterrupt) else 1)
                    self.assertEqual(output.getvalue(), "")
                    self.assertNotIn("private", diagnostic.getvalue())
                    self.assertEqual(
                        read_json(state / "evidence/candidate-serving.json")["status"],
                        "inconclusive",
                    )

    def test_child_does_not_claim_fd_observation_or_write_final_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with (
                patch.object(process_privacy, "enforce"),
                patch.object(storage_pki, "workspace_id"),
                patch.object(storage_bootstrap, "validate"),
                patch.object(
                    native,
                    "qualified",
                    side_effect=lambda root, location, image, port, observer, campaign: operation(
                        observer
                    ),
                ),
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(
                    native.main(
                        [
                            "--state",
                            str(state),
                            "--confirm-disposable",
                            "--child",
                            "--campaign",
                            "d" * 32,
                        ]
                    ),
                    0,
                )
            value = decode(output.getvalue())
            self.assertEqual(value["observation"]["status"], "inconclusive")
            self.assertFalse((state / "evidence/candidate-serving.json").exists())

    def test_run_uses_fixed_owned_child_and_rejects_changed_source_or_failed_transport(self):
        child = evidence_child()
        for failure in (None, "changed", "timeout", "cleanup", "cancel", "packet"):
            error = {
                "timeout": Rejected("worker_transport_deadline"),
                "cleanup": Rejected("worker_cleanup_incomplete"),
                "cancel": KeyboardInterrupt(),
            }.get(failure)
            with (
                patch.object(native, "verified_subject", return_value=SUBJECT),
                patch.object(
                    native,
                    "verify_packet",
                    side_effect=Rejected("invalid-packet") if failure == "packet" else None,
                ),
                patch.object(contracts, "now", side_effect=[START, END]),
                patch.object(
                    native,
                    "source",
                    side_effect=[expected(), {} if failure == "changed" else expected()],
                ),
                patch.object(
                    worker_transport, "capture", return_value=child, side_effect=error
                ) as captured,
            ):
                if failure is None:
                    result = native.run(Path("root"), Path("state"), "image", 15446)
                    self.assertEqual(result["runtime"]["output_privacy"]["status"], "pass")
                    self.assertIn("current-private-receipt-admitted", result["cases"])
                    self.assertIn("closed-audit-primary-packet-reverified", result["cases"])
                    self.assertFalse(result["release_ready"])
                else:
                    with self.assertRaises(KeyboardInterrupt if failure == "cancel" else Rejected):
                        native.run(Path("root"), Path("state"), "image", 15446)
            arguments = captured.call_args.args[0]
            self.assertEqual(arguments[1:3], ["-m", "scripts.serving_output_native"])
            self.assertIn("--child", arguments)
            self.assertEqual(arguments[arguments.index("--campaign") + 1], "d" * 32)
            self.assertEqual(captured.call_args.kwargs["timeout"], 570)
            self.assertIs(captured.call_args.kwargs["canonical_output"], True)

    def test_unverified_primary_materials_cannot_start_the_child(self):
        with (
            patch.object(native, "source", return_value=expected()),
            patch.object(native, "verified_subject", side_effect=Rejected("invalid-primary")),
            patch.object(worker_transport, "capture") as captured,
            self.assertRaises(Rejected),
        ):
            native.run(Path("root"), Path("state"), "image", 15446)
        captured.assert_not_called()

    def test_parent_rejects_replayed_campaign_despite_fresh_report_timestamps(self):
        value = fixture()
        value["campaign_id"] = "f" * 32
        with (
            patch.object(native, "source", return_value=expected()),
            patch.object(native, "verified_subject", return_value=SUBJECT),
            patch.object(native, "verify_packet", return_value={}),
            patch("uuid.uuid4", return_value=SimpleNamespace(hex="d" * 32)),
            patch.object(contracts, "now", side_effect=[START, END]),
            patch.object(worker_transport, "capture", return_value=evidence_child(value)),
            self.assertRaisesRegex(Rejected, "campaign"),
        ):
            native.run(Path("root"), Path("state"), "image", 15446)

    def test_observed_child_must_match_independent_subject_freshness_and_accounting(self):
        variants = [(name, "f" * 64) for name in SUBJECT] + [
            ("started_at", "2026-10-20T11:59:59+00:00"),
            ("finished_at", "2026-10-20T12:06:00+00:00"),
            ("cases", list(fixture()["cases"])[1:]),
            ("cases", [*fixture()["cases"], "current-private-receipt-admitted"]),
        ]
        for field, replacement in variants:
            value = fixture()
            value[field] = replacement
            with (
                self.subTest(field=field),
                patch.object(native, "source", return_value=expected()),
                patch.object(native, "verified_subject", return_value=SUBJECT),
                patch.object(contracts, "now", side_effect=[START, END]),
                patch.object(worker_transport, "capture", return_value=evidence_child(value)),
                self.assertRaises(Rejected),
            ):
                native.run(Path("root"), Path("state"), "image", 15446)


class OutputSubjectContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        release_bundle_qualification.ReleaseBundleContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        release_bundle_qualification.ReleaseBundleContracts.tearDownClass()

    def test_subject_is_derived_from_real_signed_materials_and_rejects_tampering(self):
        bundle = release_bundle_qualification.ReleaseBundleContracts()
        bundle.setUp()
        self.addCleanup(bundle.doCleanups)
        package = bundle.create()
        verified = bundle.check(package)
        context = bundle.materials.context
        subject = {
            "proposal_reference": digest(canonical(package["envelope"])),
            "subject_sha256": verified["subject_sha256"],
            "model_sha256": digest(verified["model"]),
            "candidate_reference": context["candidate_reference"],
            "evaluation_reference": context["evaluation_reference"],
        }
        receipt = {
            "scope": "release-proposal-and-authorization-denial-not-full-M10",
            "status": "pass",
            "source_dirty": False,
            "release_ready": False,
            "source": context["expected"],
            **subject,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            write_json(root / "policies/local-cpu.json", context["policy"])
            write_json(state / "storage-trust.json", context["trust"])
            write_json(state / "trusted-keys.json", {"approver": bundle.materials.public})
            for fault in (None, "source", "model", "expiry", "capsule", "document"):
                primary, loaded = copy.deepcopy(receipt), copy.deepcopy(package)
                if fault == "source":
                    primary["source"] = {}
                if fault == "model":
                    primary["model_sha256"] = "0" * 64
                if fault == "capsule":
                    signature = loaded["capsule"]["envelope"]["signatures"][0]
                    content = bytearray(base64.b64decode(signature["sig"], validate=True))
                    content[0] ^= 1
                    signature["sig"] = base64.b64encode(content).decode()
                if fault == "document":
                    loaded["documents"]["dependency-lock"] = b"tampered"
                write_json(state / "evidence/release-native.json", primary)
                with (
                    self.subTest(fault=fault),
                    patch.object(release_bundle, "load", return_value=loaded) as load,
                    patch(
                        "time.time", return_value=bundle.clock + (1801 if fault == "expiry" else 0)
                    ),
                ):
                    if fault is None:
                        self.assertEqual(
                            native.verified_subject(root, state, context["expected"]), subject
                        )
                    else:
                        with self.assertRaisesRegex(
                            Rejected, "invalid_signature" if fault == "capsule" else ".+"
                        ):
                            native.verified_subject(root, state, context["expected"])
                load.assert_called_once_with(
                    (state / "storage-clients/serving").resolve(),
                    subject["proposal_reference"],
                    publisher_public=bundle.materials.public,
                )


if __name__ == "__main__":
    unittest.main()
