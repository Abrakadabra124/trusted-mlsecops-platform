import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import audit_correlation_probe_qualification as correlation
from scripts import audit_evidence_qualification as packets
from scripts import kube_cli_privacy_native as native
from scripts import kube_cli_privacy_probe as probe
from scripts import serving_privacy_probe
from scripts.audit_export_qualification import encoded, records


class CLIPrivacyContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        correlation.CorrelationProbeContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        correlation.CorrelationProbeContracts.tearDownClass()

    def fixture(self):
        factory = correlation.CorrelationProbeContracts()
        self.addCleanup(factory.doCleanups)
        _, context, _ = factory.release()
        manifest, _, outcomes, _ = packets.fixture()
        chunk = encoded(records(bound=context))
        saved = decode(manifest)
        saved["segments"][0].update(size=len(chunk), sha256=digest(chunk))
        snapshot = {
            "manifest": probe.signing.encode64(canonical(saved)),
            "segments": [probe.signing.encode64(chunk)],
        }
        http = [{k: v for k, v in row.items() if k != "admitted"} for row in outcomes]
        return snapshot, context, http

    def test_closed_snapshot_binds_release_context_and_real_http_without_claiming_admission(self):
        snapshot, context, http = self.fixture()
        result = probe.verify_snapshot(snapshot, context, http)
        self.assertEqual(result["correlation"]["completed_200"], 1)
        self.assertIs(result["independent_admission_observed"], False)
        self.assertIs(result["release_ready"], False)

    def test_snapshot_tampering_foreign_context_and_http_mismatch_refuse(self):
        snapshot, context, http = self.fixture()
        for mutation in ("segment", "manifest", "extra", "context", "http", "missing"):
            value, expected, responses = (
                copy.deepcopy(snapshot),
                copy.deepcopy(context),
                copy.deepcopy(http),
            )
            if mutation == "segment":
                value["segments"][0] = probe.signing.encode64(b"changed")
            if mutation == "manifest":
                value["manifest"] = probe.signing.encode64(b"{}")
            if mutation == "extra":
                value["private"] = "unexpected"
            if mutation == "context":
                expected["approval_sha256"] = "f" * 64
            if mutation == "http":
                responses[0]["status"] = 422
            if mutation == "missing":
                responses = []
            with self.subTest(mutation=mutation), self.assertRaises(Rejected):
                probe.verify_snapshot(value, expected, responses)

    def test_shared_matrix_has_twelve_cases_and_six_distinct_input_needles(self):
        from mlsecops.datasets import FEATURES

        body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
        cases, response_needles, private_needles = serving_privacy_probe.inputs(body, "a" * 64)
        self.assertEqual(len(cases), 12)
        self.assertEqual(len(response_needles), 5)
        self.assertEqual(len(set(private_needles)), 6)
        self.assertIn(b"a" * 64, private_needles)

    def test_lost_observation_or_missing_fence_cannot_publish_a_closed_window(self):
        observer = probe.Privacy()
        with self.assertRaises(Rejected):
            observer.observe("/v1/predict", 200, [], b"[]")
        with self.assertRaises(Rejected):
            observer.observe("/livez", 200, [], b"{}")
        observer.needles = (b"private",) * 9
        observer.metrics = {"series": 69}
        with self.assertRaises(Rejected):
            observer.closed(Path("unused"), b"", {})
        observer.failed = False
        with self.assertRaises(Rejected):
            observer.closed(Path("unused"), b"", {})

    def test_parent_reloads_digest_bound_selection_and_signed_authorization(self):
        factory = correlation.CorrelationProbeContracts()
        self.addCleanup(factory.doCleanups)
        fixture, expected, _ = factory.release()
        selected, authorization = canonical(fixture.selection), canonical(fixture.authorization)
        with patch.object(
            native.kube_storage, "admin", side_effect=[selected.hex(), authorization.hex()]
        ) as read:
            self.assertEqual(
                native.primary(
                    Path("unused"), fixture.arguments, {"request_sha256": digest(selected)}
                ),
                expected,
            )
        self.assertEqual(read.call_count, 2)
        for raw in ("", "00", selected.hex()):
            with (
                patch.object(native.kube_storage, "admin", return_value=raw),
                self.assertRaises(Rejected),
            ):
                native.primary(Path("unused"), fixture.arguments, {"request_sha256": "f" * 64})

    def test_hosted_guard_prevents_fixture_or_infrastructure_work(self):
        with (
            patch.object(native, "hosted", side_effect=Rejected("hosted")),
            patch.object(native.promotion_qualification, "PromotionAdmissionContracts") as fixture,
        ):
            with self.assertRaises(Rejected), native.controlled(None, None, None, {}):
                pass
            fixture.assert_not_called()

    def test_principals_and_metrics_use_distinct_private_files(self):
        observer = probe.Privacy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {"token_file": "old"}
            observer.configure(root, config, "a" * 64)
            self.assertNotIn("token_file", config)
            clients = probe.read_json(Path(config["principals_file"]))["clients"]
            self.assertEqual(len({v["token"] for v in clients} | {observer.metrics_token}), 4)
            self.assertEqual([v["burst"] for v in clients], [40, 1, 1])

    def test_complete_native_lifecycle_retains_bytes_and_cleans_fixture(self):
        snapshot, context, http = self.fixture()
        privacy = {
            "snapshot": snapshot,
            "http": http,
            "audit": probe.verify_snapshot(snapshot, context, http),
        }
        fixture = Mock()
        fixture.arguments = {
            key: {}
            for key in (
                "package",
                "policy_envelope",
                "assurance_envelope",
                "approval_envelope",
                "reports",
            )
        }
        fixture.trust_fixture.key = Path("authority-key")
        fixture.trust_fixture.public = "public"
        fixtures = Mock(return_value=fixture)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(native, "hosted"),
            patch.object(native.promotion_qualification, "PromotionAdmissionContracts", fixtures),
            patch.object(native.serving_native, "bind_real_runtime", return_value=([[0.5]], [0.7])),
            patch.object(
                native,
                "configuration",
                return_value={"schema_version": 1, "expected_policy": "policy"},
            ),
            patch.object(native.kube_promotion, "configure"),
            patch.object(native.trust_authority, "install"),
            patch.object(native.trust_authority, "update"),
            patch.object(native, "stage"),
            patch.object(
                native.kube_promotion,
                "invoke",
                return_value={
                    "status": "recorded-not-activated",
                    "receipt": {"reference": "owned"},
                },
            ),
            patch.object(native, "primary", return_value=context) as primary,
            patch.object(native, "snapshot", return_value={"immutable": True}),
            patch.object(native, "invoke", return_value={"privacy": privacy}) as invoke,
            patch.object(native.audit_snapshot, "store_packet") as store,
            patch.object(native.audit_snapshot, "load_packet", return_value=canonical(privacy)),
        ):
            with native.controlled(
                Path(directory), Path(directory), "image", {"image_id": "image"}
            ) as (result, key):
                self.assertTrue(result["post_cleanup_primary_reverified"])
                self.assertFalse(result["independent_admission_observed"])
                self.assertEqual(key, Path("authority-key"))
            self.assertEqual(primary.call_count, 2)
            self.assertTrue(invoke.call_args.kwargs["cli_privacy"])
            store.assert_called_once()
            fixture.doCleanups.assert_called_once()
            fixtures.tearDownClass.assert_called_once()


if __name__ == "__main__":
    unittest.main()
