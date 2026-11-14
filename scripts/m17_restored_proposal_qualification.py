import copy
import shutil
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from mlsecops import storage, storage_bootstrap, storage_pki
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import m17_restored_proposal as restored
from scripts import release_authorization_qualification as fixtures


class RestoredProposal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ReleaseAuthorizationContracts.setUpClass()
        cls.addClassCleanup(fixtures.ReleaseAuthorizationContracts.tearDownClass)
        cls.fx = fixtures.ReleaseAuthorizationContracts()
        cls.fx.setUp()
        cls.addClassCleanup(cls.fx.doCleanups)

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.root = Path(stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.origin, self.target = self.root / "origin", self.root / "target"
        fx = self.fx
        ctx = fx.bundle.materials.context
        self.public = dict(
            curator=ctx["trust"]["curator"],
            evaluator=ctx["trust"]["evaluator"],
            approver=fx.bundle.materials.public,
            trust=fx.authorities.public["root"],
        )
        write_json(self.target / "recovered-public-keys.json", self.public)
        self.report = dict(
            scope="release-proposal-and-authorization-denial-not-full-M10",
            status="pass",
            source_dirty=False,
            release_ready=False,
            source=ctx["expected"],
            proposal_reference=digest(canonical(fx.package["envelope"])),
            model_sha256=digest(fx.release["model"]),
            subject_sha256=fx.release["subject_sha256"],
            campaign_id=fx.release["manifest"]["release_id"],
            policy_sha256=fx.policy_hash,
        )
        path = self.origin / "evidence/release-native.json"
        write_json(path, self.report)
        self.demo = dict(
            candidate=dict(
                candidate_reference=ctx["candidate_reference"],
                metadata=dict(model_digest=self.report["model_sha256"]),
            ),
            evaluation_reference=ctx["evaluation_reference"],
            dataset=dict(source_approval_digest=ctx["trust"]["source_approval_digest"]),
        )
        self.demo_path = self.origin / "storage-demo.json"
        write_json(self.demo_path, self.demo)
        write_json(self.root / "policies/local-cpu.json", ctx["policy"])
        write_json(
            self.origin / "release-proposals" / self.report["campaign_id"] / "policy-envelope.json",
            fx.policy_envelope,
        )
        self.pins = dict(
            proposal_pin=digest(path.read_bytes()),
            keys_pin=digest(canonical(self.public)),
            demo_pin=digest(self.demo_path.read_bytes()),
        )
        self.markers = {
            s: {k: s.name for k in ("container_id", "network_id", "port", "volume", "workspace_id")}
            for s in (self.origin, self.target)
        }
        for i, directory in enumerate((self.origin, self.target), start=1):
            marker = self.markers[directory]
            marker.update(workspace_id=str(i) * 32, port=15439 + i)
            write_json(
                directory / "workspace.json",
                dict(
                    schema_version=1,
                    product="trusted-mlsecops",
                    workspace_id=marker["workspace_id"],
                ),
            )
            storage_pki.initialize(directory)
            storage_bootstrap.export_clients(directory, marker["port"])
        stack.enter_context(patch.object(restored, "hosted"))
        stack.enter_context(patch.object(restored, "source", return_value=ctx["expected"]))
        stack.enter_context(
            patch.object(restored, "validate", side_effect=self.markers.__getitem__)
        )
        self.inspect = stack.enter_context(
            patch.object(
                restored,
                "inspect",
                side_effect=lambda _, identity: {"State": {"Running": identity == "target"}},
            )
        )
        self.load = stack.enter_context(
            patch.object(restored.release_bundle, "load", return_value=copy.deepcopy(fx.package))
        )

    def verify(self):
        return restored.verify(self.root, self.origin, self.target, "controlled", **self.pins)

    def test_only_restored_client_can_verify_original_bundle_and_enforce_ordinary_denial(self):
        exported = self.target / "storage-clients/serving"

        def load(client, reference, *, publisher_public):
            expected = storage.connection_materials(exported)[1]
            # The underlying loader reconnects for every object. Substitution of
            # the mutable export after the checks must not redirect those reads.
            shutil.copytree(self.origin / "storage-clients/serving", exported, dirs_exist_ok=True)
            params, materials = storage.connection_materials(client)
            self.assertEqual(materials, expected)
            self.assertEqual(params["port"], self.markers[self.target]["port"])
            self.assertEqual(
                (reference, publisher_public),
                (self.report["proposal_reference"], self.public["approver"]),
            )
            return self.load.return_value

        self.load.side_effect = load
        result = self.verify()
        self.load.assert_called_once()
        self.assertFalse(self.load.call_args.args[0].exists())
        self.assertEqual(result["status"], "verified-proposal-requires-assurance")
        self.assertIs(result["release_ready"], False)
        self.assertEqual(result["model_sha256"], self.report["model_sha256"])

    def test_foreign_serving_credentials_port_or_promoter_role_refuse_before_read(self):
        exported = self.target / "storage-clients/serving"
        for source, port in (
            (self.origin / "storage-clients/serving", self.markers[self.target]["port"]),
            (self.target / "storage-clients/promoter", self.markers[self.target]["port"]),
            (self.origin / "storage-clients/serving", self.markers[self.origin]["port"]),
        ):
            shutil.copytree(source, exported, dirs_exist_ok=True)
            settings = read_json(exported / "connection.json")
            write_json(exported / "connection.json", {**settings, "port": port})
            with (
                self.subTest(source=source, port=port),
                self.assertRaisesRegex(Rejected, "serving_client"),
            ):
                self.verify()
        self.load.assert_not_called()

    def test_exported_password_file_is_refused_before_loading(self):
        (self.target / "storage-clients/serving/.no-passwords").touch()
        with self.assertRaisesRegex(Rejected, "serving_client"):
            self.verify()
        self.load.assert_not_called()

    def test_equal_storage_online_origin_or_foreign_pins_stop_before_open(self):
        self.markers[self.target]["volume"] = "origin"
        with self.assertRaisesRegex(Rejected, "storage_identity"):
            self.verify()
        self.markers[self.target]["volume"] = "target"
        with (
            patch.object(restored, "inspect", return_value={"State": {"Running": True}}),
            self.assertRaisesRegex(Rejected, "storage_identity"),
        ):
            self.verify()
        for field in self.pins:
            with (
                patch.dict(self.pins, {field: "f" * 64}),
                self.assertRaisesRegex(Rejected, "recovered_proposal_pin"),
            ):
                self.verify()
        self.load.assert_not_called()

    def test_rebound_demo_changed_package_or_wrong_refusal_never_prove_recovery(self):
        self.demo["evaluation_reference"] = "9" * 64
        write_json(self.demo_path, self.demo)
        with (
            patch.dict(self.pins, demo_pin=digest(self.demo_path.read_bytes())),
            self.assertRaisesRegex(Rejected, "wrong_candidate"),
        ):
            self.verify()
        self.demo["evaluation_reference"] = self.fx.bundle.materials.context["evaluation_reference"]
        write_json(self.demo_path, self.demo)
        with (
            patch.object(
                restored.release_authorization, "verify", side_effect=Rejected("invalid_policy")
            ),
            self.assertRaisesRegex(Rejected, "invalid_policy"),
        ):
            self.verify()
        with (
            patch.object(restored.release_authorization, "verify", return_value={}),
            self.assertRaisesRegex(Rejected, "unapproved_admission"),
        ):
            self.verify()
        self.load.return_value["documents"]["dependency-lock"] = b"altered"
        with self.assertRaises(Rejected):
            self.verify()
