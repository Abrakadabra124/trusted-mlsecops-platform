import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import kube_promotion_native as target


class KubernetesPromotionNativeContracts(unittest.TestCase):
    def test_campaign_uses_existing_pinned_workspace_authority_without_generating_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            key = state / "keys/trust.pem"
            public = signing.create_key(key)
            write_json(state / "trusted-keys.json", {"trust": public})
            with patch.object(signing, "create_key", side_effect=AssertionError("implicit rekey")):
                self.assertEqual(target.campaign_authority(state), (key.resolve(), public))
                write_json(state / "trusted-keys.json", {"trust": "changed"})
                with self.assertRaisesRegex(Rejected, "campaign_authority_pin"):
                    target.campaign_authority(state)
                key.unlink()
                with self.assertRaises(Rejected):
                    target.campaign_authority(state)

    def test_campaign_bootstrap_orders_authority_before_audit_and_preserves_current_policy(self):
        order = []
        for existing in (False, True):
            order.clear()
            with (
                patch.object(target, "hosted"),
                patch.object(target, "campaign_authority", return_value=(Path("key"), "root")),
                patch.object(
                    target.trust_authority,
                    "install",
                    side_effect=lambda *a, **k: order.append("install"),
                ),
                patch.object(
                    target.trust_authority,
                    "current",
                    side_effect=lambda *a, **k: (None, {"envelope": {} if existing else None}),
                ),
                patch.object(
                    target.trust_authority,
                    "update",
                    side_effect=lambda *a, **k: order.append("seed"),
                ) as update,
                patch.object(target, "workspace_id", return_value="a" * 32),
                patch.object(
                    target, "initialize_audit", side_effect=lambda *a, **k: order.append("audit")
                ),
            ):
                self.assertEqual(
                    target.initialize_campaign("root", "state", "image"), (Path("key"), "root")
                )
                self.assertEqual(
                    order, ["install", "audit"] if existing else ["install", "seed", "audit"]
                )
                self.assertEqual(update.call_count, 0 if existing else 1)
        with (
            patch.object(target, "hosted", side_effect=Rejected("hosted_only")),
            patch.object(target, "campaign_authority") as authority,
            self.assertRaisesRegex(Rejected, "hosted_only"),
        ):
            target.initialize_campaign("root", "state", "image")
        authority.assert_not_called()

    def test_foreign_authority_stops_campaign_before_policy_or_audit_mutation(self):
        with (
            patch.object(target, "hosted"),
            patch.object(target, "campaign_authority", return_value=(Path("key"), "root")),
            patch.object(
                target.trust_authority,
                "install",
                side_effect=Rejected("trust_configuration_conflict"),
            ),
            patch.object(target.trust_authority, "update") as update,
            patch.object(target, "initialize_audit") as audit,
            self.assertRaisesRegex(Rejected, "trust_configuration_conflict"),
        ):
            target.initialize_campaign("root", "state", "image")
        update.assert_not_called()
        audit.assert_not_called()

    def package(self):
        return {
            "capsule": {
                "objects": {("candidates", digest(b"model")): b"model"},
                "envelope": {"capsule": 1},
            },
            "documents": {"model-card": b"description"},
            "envelope": {"release": 1},
        }

    def test_staging_retains_exact_references_and_requires_readback(self):
        values = [
            b"model",
            canonical({"capsule": 1}),
            b"description",
            canonical({"release": 1}),
            canonical({"policy": 1}),
            canonical({"assurance": 1}),
            canonical({"approval": 1}),
            b"report",
        ]
        with patch.object(
            target.kube_storage, "admin", side_effect=[f"{digest(v)}:{len(v)}" for v in values]
        ) as execute:
            request = target.stage(
                "state",
                self.package(),
                {"policy": 1},
                {"assurance": 1},
                {"approval": 1},
                {"M01": b"report"},
            )
            self.assertEqual(request["proposal_reference"], digest(canonical({"release": 1})))
            self.assertEqual(request["approval_reference"], digest(canonical({"approval": 1})))
            self.assertEqual(execute.call_count, len(values))
            self.assertTrue(
                all("ON CONFLICT DO NOTHING" in call.args[1] for call in execute.call_args_list)
            )
        with patch.object(
            target.kube_storage, "admin", side_effect=[f"{digest(v)}:{len(v)}" for v in values[:5]]
        ):
            request = target.stage("state", self.package(), {"policy": 1})
            self.assertIsNone(request["assurance_reference"])
        with (
            patch.object(target.kube_storage, "admin", return_value="changed"),
            self.assertRaisesRegex(Rejected, "stage_readback"),
        ):
            target.stage("state", self.package(), {"policy": 1})

    def test_oversized_or_invalid_content_never_starts_sql_writes(self):
        for content in (b"", "not-bytes"):
            package = self.package()
            package["documents"]["model-card"] = content
            with (
                patch.object(target.kube_storage, "admin") as execute,
                self.assertRaisesRegex(Rejected, "stage_limit"),
            ):
                target.stage("state", package, {"policy": 1})
            execute.assert_not_called()
        with (
            patch.object(target, "MAX_BYTES", 1),
            patch.object(target.kube_storage, "admin") as execute,
            self.assertRaisesRegex(Rejected, "stage_limit"),
        ):
            target.stage("state", self.package(), {"policy": 1})
        execute.assert_not_called()

    def test_hosted_guard_precedes_storage_access_and_failure_invalidates_old_report(self):
        with (
            patch.object(target, "hosted", side_effect=Rejected("hosted-only")),
            patch.object(target.storage_bootstrap, "validate") as validate,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(target.main(["--state", "private"]), 1)
            validate.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            output = state / "evidence/kubernetes-promotion.json"
            write_json(output, {"status": "pass"})

            def failed(*args):
                self.assertEqual(read_json(output)["status"], "inconclusive")
                raise Rejected("private configuration")

            with (
                patch.object(target, "hosted"),
                patch.object(target.storage_bootstrap, "validate"),
                patch.object(target, "qualify", side_effect=failed),
                redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(target.main(["--state", directory]), 1)
            self.assertEqual(read_json(output), {"status": "fail", "release_ready": False})
            self.assertEqual(errors.getvalue(), "kubernetes_promotion_native_rejected\n")
            with (
                patch.object(target, "hosted"),
                patch.object(target.storage_bootstrap, "validate"),
                patch.object(target, "qualify", return_value={"status": "pass"}),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(target.main(["--state", directory]), 0)
            with (
                patch.object(target, "hosted"),
                patch.object(target.storage_bootstrap, "validate"),
                patch.object(target, "qualify", side_effect=KeyboardInterrupt()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(target.main(["--state", directory]), 130)
            self.assertEqual(read_json(output)["status"], "inconclusive")
            with (
                patch.object(target, "hosted"),
                patch.object(target.storage_bootstrap, "validate"),
                patch.object(target, "write_json", side_effect=OSError("private path")),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(target.main(["--state", directory]), 1)


if __name__ == "__main__":
    unittest.main()
