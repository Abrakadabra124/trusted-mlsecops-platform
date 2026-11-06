import copy
import io
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
        for mutation in (
            "segment",
            "manifest",
            "extra",
            "context",
            "http",
            "missing",
            "segment-count",
            "sequence",
            "unfinished",
            "kind",
            "duplicate",
            "ordinal",
        ):
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
            if mutation == "segment-count":
                value["segments"] = []
            if mutation == "kind":
                expected["kind"] = "candidate-qualification"
            if mutation == "duplicate":
                responses[1]["request_id"] = responses[0]["request_id"]
            if mutation == "ordinal":
                responses[1]["exchange"] = 1
            if mutation in {"sequence", "unfinished"}:
                saved = decode(probe.signing.decode64(value["manifest"]))
                saved["sequence"] += 1
                if mutation == "unfinished":
                    chunk = (
                        b"\n".join(probe.signing.decode64(value["segments"][0]).splitlines()[:-1])
                        + b"\n"
                    )
                    saved["segments"][0].update(size=len(chunk), sha256=digest(chunk))
                    saved["sequence"] = 3
                    value["segments"] = [probe.signing.encode64(chunk)]
                value["manifest"] = probe.signing.encode64(canonical(saved))
            with self.subTest(mutation=mutation), self.assertRaises(Rejected):
                probe.verify_snapshot(value, expected, responses)
        http.append({"exchange": 3, "request_id": None, "route": "other", "status": 404})
        self.assertEqual(probe.verify_snapshot(snapshot, context, http)["observed_responses"], 3)

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
        arguments = {
            **fixture.arguments,
            "package": {**fixture.arguments["package"], "envelope": {}},
        }
        with (
            patch.object(
                native.kube_storage, "admin", side_effect=[selected.hex(), authorization.hex()]
            ),
            self.assertRaisesRegex(Rejected, "cli_privacy_proposal_changed"),
        ):
            native.primary(Path("unused"), arguments, {"request_sha256": digest(selected)})
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

    @staticmethod
    def wire(status, path, index=1):
        value = {"schema_version": 1, "request_id": f"{index:032x}"}
        if status == 404:
            value = {"detail": "Not Found"}
        elif status == 200:
            value.update(model_sha256="a" * 64, bundle_sha256="b" * 64)
            if path.startswith("/readyz"):
                value.pop("schema_version")
                value["ready"] = True
            else:
                value["predictions"] = [{"decision": "score", "reason": None, "score": 0.7}]
        else:
            value["error"] = {
                "code": {
                    401: "unauthorized",
                    413: "body_too_large",
                    422: "invalid_request",
                    429: "client_limited",
                    503: "not_ready" if path == "/readyz" else "model_unavailable",
                }[status]
            }
        content = canonical(value)
        headers = [
            ("content-type", "application/json"),
            ("content-length", str(len(content))),
            ("date", "Fri, 06 Nov 2026 13:00:00 GMT"),
            ("cache-control", "no-store"),
        ]
        return status, headers, content

    def test_http_matrix_quota_refill_metrics_and_fence_negative_controls(self):
        from mlsecops.datasets import FEATURES

        body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
        for fault in (None, "status", "echo", "quota", "slow", "refill", "metrics", "fence"):
            with self.subTest(fault=fault):
                observer = probe.Privacy()
                observer.token, observer.quotas, observer.metrics_token = (
                    "0" * 64,
                    ["c" * 64, "d" * 64],
                    "e" * 64,
                )
                statuses = iter(
                    [
                        200,
                        200,
                        422,
                        422,
                        422,
                        422,
                        422,
                        401,
                        404,
                        404,
                        413,
                        200,
                        422,
                        429,
                        422,
                        429,
                        200,
                        200,
                        503,
                        503,
                    ]
                )
                calls = []

                def request(path, payload=None, *, raw=False, **options):
                    index = len(calls)
                    status = next(statuses)
                    if fault == "status" and index == 0:
                        status = 422
                    if fault == "quota" and index == 13:
                        status = 200
                    if fault == "fence" and index == 18:
                        status = 200
                    code, headers, content = self.wire(status, path, index + 1)
                    if fault == "echo" and index == 0:
                        value = decode(content)
                        value["private"] = observer.needles[0].decode()
                        content = canonical(value)
                        headers[1] = ("content-length", str(len(content)))
                    if fault == "refill" and index == 16:
                        value = decode(content)
                        value["model_sha256"] = "f" * 64
                        content = canonical(value)
                    calls.append((path, options))
                    observer.observe(path, code, headers, content)
                    return (code, headers, content) if raw else (code, decode(content))

                with (
                    patch.object(
                        probe.time, "monotonic", side_effect=[0, 2 if fault == "slow" else 0.1]
                    ),
                    patch.object(probe.time, "sleep") as sleep,
                    patch.object(
                        probe.serving_metrics_probe,
                        "scan",
                        side_effect=Rejected("metrics") if fault == "metrics" else None,
                        return_value={"series": 69},
                    ) as metrics,
                ):
                    if fault is None:
                        observer.exercise(request, body, {"model": "a" * 64})
                        observer.fenced(request, body)
                        self.assertEqual(len(calls), 20)
                        self.assertEqual(len(observer.needles), 9)
                        self.assertTrue(observer.fence_complete)
                        self.assertEqual(request.metrics_credential, observer.metrics_token)
                        sleep.assert_called_once_with(1.05)
                        metrics.assert_called_once()
                    else:
                        with self.assertRaises(Rejected):
                            observer.exercise(request, body, {"model": "a" * 64})
                            observer.fenced(request, body)

    def test_closed_snapshot_and_full_output_bounds_reject_even_after_http_success(self):
        snapshot, context, http = self.fixture()
        manifest = probe.signing.decode64(snapshot["manifest"])
        chunks = tuple(probe.signing.decode64(v) for v in snapshot["segments"])
        for fault in (None, "canary", "size", "stderr"):
            observer = probe.Privacy()
            observer.needles = tuple(f"private-{i}".encode() for i in range(9))
            observer.metrics, observer.http, observer.fence_complete = {"series": 69}, http, True
            if fault == "canary":
                observer.outputs = [observer.needles[0]]
            with (
                self.subTest(fault=fault),
                patch.object(probe.serving_privacy_probe, "scan_owned_audit"),
                patch.object(probe.cli_exchange, "provide"),
                patch.object(
                    probe.audit_snapshot, "capture_closed", return_value=(manifest, chunks)
                ),
                patch.object(probe, "MAX_BYTES", 1 if fault == "size" else 1024 * 1024),
            ):
                if fault is None:
                    result = observer.closed(Path("owned"), b"", {"audit_context": context})
                    self.assertEqual(result["snapshot"], snapshot)
                    self.assertFalse(result["audit"]["independent_admission_observed"])
                else:
                    with self.assertRaises(Rejected):
                        observer.closed(
                            Path("owned"),
                            b"private-stderr" if fault == "stderr" else b"",
                            {"audit_context": context},
                        )
        observer = probe.Privacy()
        observer.observe("/livez", 200, [], b"{}")
        observer.observe("/metrics", 200, [], b"metrics")
        self.assertEqual(observer.http, [])
        with patch.object(probe, "MAX_BYTES", 1), self.assertRaises(Rejected):
            observer.observe("/livez", 200, [], b"{}")
        self.assertTrue(observer.failed)

    def test_cli_entrypoint_exports_only_fixed_failure_and_preserves_process_boundary(self):
        from types import SimpleNamespace

        for fail in (False, True):
            with (
                self.subTest(fail=fail),
                patch.object(probe, "enforce"),
                patch.object(probe, "Arguments") as parser,
                patch.object(probe, "read_json", return_value={"configured": True}),
                patch.object(
                    probe.kube_serving_probe,
                    "qualify",
                    side_effect=Rejected("PRIVATE-CANARY") if fail else None,
                    return_value={"status": "pass"},
                ) as run,
                patch("sys.stdout", io.StringIO()) as output,
            ):
                parser.return_value.parse_args.return_value = SimpleNamespace(
                    config=Path("config"), request=Path("request")
                )
                self.assertEqual(probe.main([]), 1 if fail else 0)
                self.assertNotIn("PRIVATE-CANARY", output.getvalue())
                self.assertIsInstance(run.call_args.kwargs["privacy"], probe.Privacy)

    def test_complete_native_lifecycle_retains_bytes_and_cleans_fixture(self):
        for fault in (None, "promotion", "primary", "ledger", "receipt", "bytes", "verifier"):
            with self.subTest(fault=fault):
                self.native_lifecycle(fault)

    def native_lifecycle(self, fault):
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
            ) as promotion,
            patch.object(native, "primary", return_value=context) as primary,
            patch.object(native, "snapshot", return_value={"immutable": True}) as ledger,
            patch.object(native, "Windows") as windows,
            patch.object(
                native,
                "invoke",
                return_value={
                    "privacy": privacy,
                    "_privacy_needles": tuple(f"private-{i}".encode() for i in range(9)),
                },
            ) as invoke,
            patch.object(native.audit_snapshot, "store_packet") as store,
            patch.object(
                native.audit_snapshot, "load_packet", return_value=canonical(privacy)
            ) as load,
            patch.object(native, "verify_snapshot", wraps=probe.verify_snapshot) as verify,
        ):
            windows.return_value.close.return_value = {"ml-storage": {}, "ml-trust": {}}
            if fault == "promotion":
                promotion.return_value = {"status": "rejected", "receipt": None}
            if fault == "primary":
                primary.side_effect = [context, {}]
            if fault == "ledger":
                ledger.side_effect = [{"immutable": True}, {"changed": True}]
            if fault == "receipt":
                privacy["audit"] = {"changed": True}
            if fault == "bytes":
                load.return_value = b"changed"
            if fault == "verifier":
                verify.side_effect = [privacy["audit"], {}]
            if fault is None:
                with native.controlled(
                    Path(directory), Path(directory), "image", {"image_id": "image"}
                ) as (result, key):
                    self.assertTrue(result["post_cleanup_primary_reverified"])
                    self.assertFalse(result["independent_admission_observed"])
                    self.assertEqual(key, Path("authority-key"))
                self.assertEqual(primary.call_count, 2)
                self.assertTrue(invoke.call_args.kwargs["cli_privacy"])
                windows.return_value.close.assert_called_once()
                self.assertNotIn("_privacy_needles", result["native"])
                store.assert_called_once()
            else:
                with (
                    self.assertRaises(Rejected),
                    native.controlled(
                        Path(directory), Path(directory), "image", {"image_id": "image"}
                    ),
                ):
                    pass
            fixture.doCleanups.assert_called_once()
            fixtures.tearDownClass.assert_called_once()


if __name__ == "__main__":
    unittest.main()
