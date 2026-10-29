import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import (
    kube_promotion,
    kube_storage,
    kube_storage_resources,
    kube_trust,
    storage,
    storage_pki,
)
from mlsecops.contracts import Rejected, read_json, write_json
from mlsecops.storage_bootstrap import export_clients
from mlsecops.trust_targets import Target, select
from scripts import kube_serving_faults, kube_serving_native
from scripts import kube_trust_qualification as fixtures


class TrustTargetContracts(unittest.TestCase):
    def test_combined_storage_and_authorities_fit_namespace_secret_quotas(self):
        documents = kube_storage_resources.resources(
            "a" * 32, {}, {role: {} for role in storage_pki.ROLES}
        )
        for target in Target:
            documents.extend(
                kube_trust.resources(
                    "a" * 32, {}, {role: {} for role in kube_trust.READERS}, target=target
                )
            )
        for quota in (d for d in documents if d["kind"] == "ResourceQuota"):
            namespace = quota["metadata"]["namespace"]
            count = sum(
                d["kind"] == "Secret" and d["metadata"]["namespace"] == namespace for d in documents
            )
            limit = int(quota["spec"]["hard"]["count/secrets"])
            with self.subTest(namespace=namespace):
                self.assertLessEqual(count, limit)
                self.assertEqual(limit, 3 if namespace in ("ml-serving", "ml-promoter") else 2)

    def test_alternate_fault_coordinator_only_allows_irreversible_model_revoke(self):
        for fault in ("outage", "key-revocation", "policy-change", "blackhole"):
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(Rejected, "serving_fault_target"),
            ):
                kube_serving_faults.Coordinator(
                    "state", fault, "a" * 64, "key", "b" * 64, target=Target.MODEL_REVOCATION
                )
        with patch.object(kube_serving_faults.trust_authority, "update") as update:
            with kube_serving_faults.Coordinator(
                "state", "revocation", "a" * 64, "key", "b" * 64, target=Target.MODEL_REVOCATION
            ) as coordinator:
                coordinator("ready")
                coordinator("denied")
            update.assert_called_once()
            self.assertEqual(update.call_args.kwargs["revoked_artifacts"], ["b" * 64])
            self.assertEqual(
                update.call_args.kwargs["backend"].keywords, {"target": Target.MODEL_REVOCATION}
            )

    def test_non_candidate_or_mismatched_job_cannot_select_alternate_target(self):
        with patch.object(kube_serving_native.kube_promotion, "configuration_map") as create:
            for candidate, config in ((False, {"trust_target": "model-revocation"}), (True, {})):
                with self.assertRaisesRegex(Rejected, "candidate_authority_target"):
                    kube_serving_native.invoke(
                        "state",
                        {},
                        config,
                        {},
                        candidate_probe=candidate,
                        trust_target=Target.MODEL_REVOCATION,
                    )
            create.assert_not_called()

    def test_independent_bootstrap_is_idempotent_and_primary_uid_change_rejects(self):
        fixture = fixtures.KubernetesTrustContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.cluster()
        with patch.object(
            kube_trust,
            "live",
            side_effect=lambda state, marker, *, target: {
                "volume_uid": target.namespace + "-pv",
                "pod_uid": target.namespace + "-pod",
            },
        ):
            kube_trust.bootstrap(fixture.state)
            original = read_json(kube_trust.directory(fixture.state) / "resources.json")
            kube_trust.bootstrap(fixture.state, target=Target.MODEL_REVOCATION)
            model = read_json(
                kube_trust.directory(fixture.state, target=Target.MODEL_REVOCATION)
                / "resources.json"
            )
            self.assertNotEqual(original["volume_uid"], model["volume_uid"])
            self.assertEqual(
                read_json(kube_trust.directory(fixture.state) / "resources.json"), original
            )
            count = len(fixture.created)
            kube_trust.bootstrap(fixture.state, target=Target.MODEL_REVOCATION)
            self.assertEqual(len(fixture.created), count)
            primary_resource = next(iter(original["resources"]))
            fixture.objects[primary_resource]["metadata"]["uid"] = "foreign"
            with self.assertRaisesRegex(Rejected, "resource_identity_changed"):
                kube_trust.validate(fixture.state)
            kube_trust.validate(fixture.state, target=Target.MODEL_REVOCATION)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.workspace = {
            "schema_version": 1,
            "product": "trusted-mlsecops",
            "workspace_id": "a" * 32,
        }
        write_json(self.state / "workspace.json", self.workspace)

    def provision_files(self, target):
        local = kube_trust.directory(self.state, target=target)
        write_json(local / "workspace.json", self.workspace)
        storage_pki.initialize(local, target.host)
        export_clients(local, 5432, target.host)
        return local

    def test_only_two_exact_targets_are_selectable(self):
        for target in Target:
            self.assertIs(select(target), target)
            self.assertIs(select(target.value), target)
        for value in (None, True, {}, "ml-trust", "postgres.evil.example", "PRIMARY", "../primary"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(Rejected, "trust_target_invalid"),
            ):
                select(value)

    def test_model_endpoint_requires_explicit_exact_host_pin(self):
        model = self.provision_files(Target.MODEL_REVOCATION)
        client = model / "storage-clients/serving"
        with self.assertRaises(Rejected):
            storage.connection_parameters(client)
        with self.assertRaises(Rejected):
            storage.connection_parameters(client, expected_host=Target.PRIMARY.host)
        params = storage.connection_parameters(client, expected_host=Target.MODEL_REVOCATION.host)
        self.assertEqual(params["host"], Target.MODEL_REVOCATION.host)
        self.assertEqual(params["dbname"], "mlsecops")
        self.assertEqual(params["sslmode"], "verify-full")
        self.assertEqual(params["ssl_min_protocol_version"], "TLSv1.3")
        self.assertEqual(params["user"], "ml_serving")
        with patch.object(storage.psycopg, "connect") as connect:
            storage.connect(client, expected_host=Target.MODEL_REVOCATION.host)
            self.assertEqual(connect.call_args.kwargs, params)
        for host in ("evil.example", "127.0.0.1", True):
            with self.subTest(host=host), self.assertRaises(Rejected):
                storage.connection_parameters(client, expected_host=host)

    def test_primary_client_is_not_rebound_by_selecting_model_target(self):
        local = self.provision_files(Target.PRIMARY)
        client = local / "storage-clients/serving"
        self.assertEqual(storage.connection_parameters(client)["host"], Target.PRIMARY.host)
        with self.assertRaises(Rejected):
            storage.connection_parameters(client, expected_host=Target.MODEL_REVOCATION.host)

    def test_ca_dns_and_storage_directories_are_independent(self):
        primary = self.provision_files(Target.PRIMARY)
        model = self.provision_files(Target.MODEL_REVOCATION)
        self.assertNotEqual(primary, model)
        self.assertNotEqual(
            (primary / "storage-pki/ca.crt").read_bytes(),
            (model / "storage-pki/ca.crt").read_bytes(),
        )
        with self.assertRaisesRegex(Rejected, "storage_certificate_host_mismatch"):
            storage_pki.validate(model, Target.PRIMARY.host)
        with self.assertRaisesRegex(Rejected, "storage_certificate_host_mismatch"):
            storage_pki.validate(primary, Target.MODEL_REVOCATION.host)

    def test_targets_share_no_managed_resource_identity(self):
        sets = []
        for target in Target:
            documents = kube_trust.resources(
                "a" * 32, {}, {role: {} for role in kube_trust.READERS}, target=target
            )
            sets.append({kube_storage.reference(d) for d in documents})
            server = next(d for d in documents if d["kind"] == "StatefulSet")
            self.assertEqual(server["metadata"]["namespace"], target.namespace)
            for role in kube_trust.READERS:
                secret = next(
                    d
                    for d in documents
                    if d["kind"] == "Secret" and d["metadata"]["namespace"] == "ml-" + role
                )
                self.assertEqual(secret["metadata"]["name"], target.secret)
        self.assertFalse(sets[0] & sets[1])

    def test_pod_mounts_only_the_selected_target_secret(self):
        profile = {"image": "image@sha256:" + "b" * 64}
        for target in Target:
            spec = kube_promotion.pod_spec(profile, "config", "request", trust_target=target)
            volume = next(v for v in spec["volumes"] if v["name"] == "trust-credentials")
            self.assertEqual(volume["secret"]["secretName"], target.secret)
            direct = kube_trust.client_spec(profile["image"], "serving", [], target=target)
            self.assertEqual(
                [v["secret"]["secretName"] for v in direct["volumes"] if "secret" in v],
                [target.secret],
            )

    def test_changed_connection_or_ca_is_rejected(self):
        local = self.provision_files(Target.MODEL_REVOCATION)
        client = local / "storage-clients/serving"
        original = read_json(client / "connection.json")
        for change in (
            {"host": Target.PRIMARY.host},
            {"port": 15445},
            {"host": "postgres.ml-trust-model"},
        ):
            write_json(client / "connection.json", {**original, **change})
            with self.assertRaises(Rejected):
                storage.connection_parameters(client, expected_host=Target.MODEL_REVOCATION.host)
        write_json(client / "connection.json", original)
        (client / "ca.crt").write_bytes(b"wrong CA")
        with self.assertRaisesRegex(Rejected, "storage_client_certificate_changed"):
            storage.connection_parameters(client, expected_host=Target.MODEL_REVOCATION.host)

    def test_admin_execution_is_pinned_to_selected_namespace(self):
        with patch.object(kube_trust, "binary_command", return_value=b"1\n") as command:
            self.assertEqual(
                kube_trust.admin(self.state, "SELECT 1;", target=Target.MODEL_REVOCATION), "1"
            )
            arguments = command.call_args.args[0]
            self.assertEqual(
                arguments[arguments.index("-n") + 1], Target.MODEL_REVOCATION.namespace
            )

    def test_wrong_target_marker_cannot_validate_even_with_matching_resources(self):
        self.provision_files(Target.MODEL_REVOCATION)
        with patch.object(kube_trust, "validate_cluster"), patch.object(kube_trust, "live") as live:
            write_json(
                kube_trust.directory(self.state, target=Target.MODEL_REVOCATION) / "resources.json",
                {"authority_target": "primary"},
            )
            with self.assertRaisesRegex(Rejected, "trust_resources_incomplete_or_changed"):
                kube_trust.validate(self.state, target=Target.MODEL_REVOCATION)
            live.assert_not_called()


if __name__ == "__main__":
    unittest.main()
