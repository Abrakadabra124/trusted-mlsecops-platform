"""Entry-point contracts with signed controlled fixtures, never actual ML approval."""

import contextlib
import copy
import io
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psycopg

from mlsecops import process_privacy, release_bundle, signing, storage, trust
from mlsecops import promotion_controller as controller
from mlsecops.contracts import Rejected, canonical, digest, write_json
from scripts import promotion_qualification as fixtures


class SubmissionContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.PromotionAdmissionContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.PromotionAdmissionContracts.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.PromotionAdmissionContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.values = f.values
        self.config = {
            "schema_version": 1,
            "storage_client": str(Path.cwd() / "controlled-model-promoter"),
            "trust_client": str(Path.cwd() / "controlled-trust-promoter"),
            **{
                k: f.arguments[k]
                for k in ("context", "trusted_root", "expected_policy", "expected_serving_image")
            },
            "trust_root": f.trust_fixture.public,
            "minimum_trust_version": 1,
        }
        with f.fixture.bundle.memory_storage(self.values):
            proposal = release_bundle.publish(
                "promoter",
                f.arguments["package"],
                context=f.arguments["context"],
                publisher_public=f.fixture.policy["identities"]["publisher"]["public_key"],
                expected_serving_image=f.arguments["expected_serving_image"],
                clock=f.clock,
            )
        self.request = {"schema_version": 1, "proposal_reference": proposal}
        for kind in ("policy", "assurance", "approval"):
            content = canonical(f.arguments[kind + "_envelope"])
            self.values[digest(content)] = content
            self.request[kind + "_reference"] = digest(content)
        for content in f.arguments["reports"].values():
            self.values[digest(content)] = content
        self.initial = dict(self.values)
        self.reads, self.writes = [], []
        self.enterContext(
            patch.object(storage, "connection_parameters", return_value={"user": "ml_promoter"})
        )
        self.enterContext(patch.object(storage, "connect", return_value=f.connection))
        self.enterContext(patch.object(storage, "get", side_effect=self.get))
        self.enterContext(patch.object(storage, "put", side_effect=self.put))
        self.enterContext(
            patch.object(
                controller.trust_authority, "read", side_effect=lambda *a: f.trust_fixture.read()
            )
        )

    def get(self, client, table, reference):
        self.assertEqual(table, "releases")
        self.reads.append(reference)
        if reference not in self.values:
            raise Rejected("storage_object_missing")
        content = self.values[reference]
        if digest(content) != reference:
            raise Rejected("storage_object_integrity_failed")
        return content

    def put(self, client, table, content):
        self.assertEqual((client, table), (self.config["storage_client"], "releases"))
        self.writes.append(digest(content))
        self.values[digest(content)] = content
        return digest(content)

    def submit(self, config=None, request=None):
        return controller.submit(config or self.config, request or self.request)

    def test_signed_references_reach_existing_admission_and_exact_retry(self):
        first = self.submit()
        second = self.submit()
        self.assertEqual(first, second)
        self.assertEqual(first["state"], "recorded-not-activated")
        self.assertFalse(first["release_ready"])
        self.assertEqual(first["request_sha256"], self.fixture.head)
        self.assertEqual(first["proposal_reference"], self.request["proposal_reference"])

    def test_missing_assurance_approval_or_report_cannot_write_selection(self):
        for kind, reason in [
            ("assurance", "release_assurance_required"),
            ("approval", "release_approval_required"),
        ]:
            request = {**self.request, kind + "_reference": None}
            with self.subTest(kind=kind), self.assertRaisesRegex(Rejected, reason):
                self.submit(request=request)
            self.assertFalse(self.writes)
        reference = next(iter(self.fixture.fixture.assurance["reports"].values()))
        del self.values[reference]
        with self.assertRaisesRegex(Rejected, "storage_object_missing"):
            self.submit()
        self.assertFalse(self.writes)
        self.assertIsNone(self.fixture.head)

    def test_pins_and_request_schema_cannot_be_overridden(self):
        for key, value in [
            ("clock", self.fixture.clock),
            ("storage_client", "attacker"),
            ("expected_policy", "0" * 64),
            ("schema_version", True),
            ("proposal_reference", "../outside"),
        ]:
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.submit(request={**self.request, key: value})
        for key, value in [
            ("expected_policy", "0" * 64),
            ("expected_serving_image", "sha256:" + "0" * 64),
            ("minimum_trust_version", True),
            ("storage_client", "relative"),
            ("schema_version", 2),
        ]:
            with self.subTest(config_key=key), self.assertRaises(Rejected):
                self.submit(config={**self.config, key: value})
        self.assertFalse(self.writes)

    def test_non_promoter_credentials_are_denied_before_any_cas_read(self):
        with patch.object(storage, "connection_parameters", return_value={"user": "ml_serving"}):
            with self.assertRaisesRegex(Rejected, "promotion_controller_identity"):
                self.submit()
        self.assertFalse(self.reads)
        self.assertFalse(self.writes)

    def test_untrusted_or_noncanonical_envelopes_are_not_authority(self):
        for kind in ("policy", "assurance", "approval"):
            original = self.request[kind + "_reference"]
            content = b" " + self.values[original]
            self.values[digest(content)] = content
            with self.subTest(kind=kind), self.assertRaises(Rejected):
                self.submit(request={**self.request, kind + "_reference": digest(content)})
        forged = copy.deepcopy(self.fixture.arguments["assurance_envelope"])
        forged["signatures"][0]["sig"] = "A" * 86 + "=="
        content = canonical(forged)
        self.values[digest(content)] = content
        with self.assertRaises(Rejected):
            self.submit(request={**self.request, "assurance_reference": digest(content)})
        self.assertFalse(self.writes)

    def test_revocation_and_unavailable_trust_never_record_a_selection(self):
        for failure in (True, False):
            if failure:
                self.fixture.trust_fixture.failure = trust.Unavailable("controlled outage")
            else:
                self.fixture.trust_fixture.failure = None
                self.fixture.trust_fixture.payload["revoked_artifacts"] = [
                    digest(self.fixture.fixture.bundle.materials.fixture.model)
                ]
            with self.subTest(outage=failure), self.assertRaises(Rejected):
                self.submit()
            self.assertFalse(self.writes)
            self.assertIsNone(self.fixture.head)

    def test_malformed_context_and_sql_clock_errors_are_structured_refusals(self):
        with self.assertRaisesRegex(Rejected, "promotion_controller_shape"):
            self.submit(config={**self.config, "context": None})
        self.fixture.connection.execute.side_effect = psycopg.OperationalError("private connection")
        with self.assertRaisesRegex(Rejected, "promotion_controller_clock_unavailable"):
            self.submit()
        self.assertFalse(self.writes)

    def test_report_integrity_and_total_transport_budget_are_enforced_before_write(self):
        target = next(iter(self.fixture.fixture.assurance["reports"].values()))
        for content in (None, b"foreign", b"X" * (1024 * 1024 + 1)):
            with patch.object(
                storage,
                "get",
                side_effect=lambda c, t, r: content if r == target else self.get(c, t, r),
            ):
                with (
                    self.subTest(content_type=type(content)),
                    self.assertRaisesRegex(Rejected, "report_integrity"),
                ):
                    self.submit()
        assurance = copy.deepcopy(self.fixture.fixture.assurance)
        content = b"X" * (1024 * 1024)
        reference = digest(content)
        self.values[reference] = content
        assurance["reports"] = {gate: reference for gate in assurance["reports"]}
        envelope = signing.sign(
            assurance, "release-assurance", self.fixture.fixture.authorities.keys["assessor"]
        )
        content = canonical(envelope)
        self.values[digest(content)] = content
        with self.assertRaisesRegex(Rejected, "promotion_controller_reports_size"):
            self.submit(request={**self.request, "assurance_reference": digest(content)})
        self.assertFalse(self.writes)
        self.assertIsNone(self.fixture.head)


class CliContracts(unittest.TestCase):
    def test_sequence_conflict_has_exact_public_code_without_echoing_arbitrary_errors(self):
        for failure, expected in (
            (Rejected("promotion_commit_unconfirmed:P1004"), "promotion_sequence_conflict"),
            (Rejected("promotion_commit_unconfirmed:P1003"), "promotion_rejected"),
            (Rejected("promotion_commit_unconfirmed:P1004 private"), "promotion_rejected"),
            (RuntimeError("promotion_commit_unconfirmed:P1004"), "promotion_rejected"),
        ):
            with (
                self.subTest(error=type(failure).__name__, expected=expected),
                patch.object(controller, "enforce_privacy"),
                patch.object(controller, "configured", side_effect=failure),
                contextlib.redirect_stdout(io.StringIO()) as out,
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(controller.main(["--config", "config", "--request", "request"]), 1)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), expected + "\n")

    def test_cli_success_and_module_entrypoint_have_bounded_constant_diagnostics(self):
        result = {"state": "recorded-not-activated", "release_ready": False}
        with (
            patch.object(controller, "enforce_privacy"),
            patch.object(controller, "configured", return_value=result),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(controller.main(["--config", "config", "--request", "request"]), 0)
        self.assertEqual(out.getvalue(), canonical(result).decode() + "\n")
        with (
            patch.object(process_privacy, "enforce"),
            patch("sys.argv", ["promotion"]),
            contextlib.redirect_stderr(io.StringIO()) as err,
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_module("mlsecops.promotion_controller", run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertTrue(err.getvalue().endswith("promotion_rejected\n"))

    def test_private_failures_and_interrupt_never_echo_config_or_credentials(self):
        for failure, expected in [
            (RuntimeError("private-config-secret"), 1),
            (KeyboardInterrupt(), 130),
        ]:
            with (
                patch.object(controller, "enforce_privacy"),
                patch.object(controller, "configured", side_effect=failure),
                contextlib.redirect_stdout(io.StringIO()) as out,
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                code = controller.main(
                    ["--config", "private-config", "--request", "private-request"]
                )
            self.assertEqual(code, expected)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), "promotion_rejected\n")

    def test_bounded_separate_files_are_passed_once_and_cannot_embed_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            config, request = (Path(temporary) / name for name in ("config.json", "request.json"))
            write_json(config, {"external": "pin"})
            write_json(request, {"submitted": "reference"})
            with patch.object(
                controller, "submit", return_value={"release_ready": False}
            ) as submit:
                self.assertEqual(controller.configured(config, request), {"release_ready": False})
                submit.assert_called_once_with({"external": "pin"}, {"submitted": "reference"})
            request.write_bytes(b"x" * (65536 + 1))
            with self.assertRaises(Rejected):
                controller.configured(config, request)
