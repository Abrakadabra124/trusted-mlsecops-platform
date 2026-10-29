import copy
import io
import runpy
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509

from mlsecops import kube_storage, kube_trust, storage, storage_pki, trust_authority
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.kube_storage_resources import CLASS, WORKSPACE, postgres
from mlsecops.storage_bootstrap import export_clients


class KubernetesTrustContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        write_json(
            self.state / "workspace.json",
            {
                "schema_version": 1,
                "product": "trusted-mlsecops",
                "workspace_id": "a" * 32,
            },
        )

    def test_separate_exact_endpoint_and_own_ca_preserve_tls_contract(self):
        storage_pki.initialize(self.state, storage_pki.TRUST_HOST)
        export_clients(self.state, 5432, storage_pki.TRUST_HOST)
        client = self.state / "storage-clients/promoter"
        observed = storage.connection_parameters(client)
        self.assertEqual(observed["host"], "postgres.ml-trust.svc.cluster.local")
        self.assertEqual(observed["sslmode"], "verify-full")
        self.assertEqual(observed["ssl_min_protocol_version"], "TLSv1.3")
        self.assertEqual(observed["user"], "ml_promoter")
        self.assertEqual(
            storage_pki.server_names(storage_pki.TRUST_HOST), [x509.DNSName(storage_pki.TRUST_HOST)]
        )
        original = __import__("json").loads((client / "connection.json").read_text())
        for change in ({"host": "evil.example"}, {"port": 15445}, {"host": "postgres.ml-trust"}):
            write_json(client / "connection.json", {**original, **change})
            with self.assertRaisesRegex(Rejected, "storage_client_config_invalid"):
                storage.connection_parameters(client)
        with self.assertRaisesRegex(Rejected, "storage_certificate_host_mismatch"):
            storage_pki.validate(self.state, storage_pki.CLUSTER_HOST)

    def test_resources_separate_service_credentials_and_allow_only_two_readers(self):
        documents = kube_trust.resources(
            "a" * 32,
            {"server.key": b"private"},
            {
                "promoter": {"client.key": b"promoter"},
                "serving": {"client.key": b"serving"},
            },
        )
        self.assertTrue(all(d["metadata"]["labels"][WORKSPACE] == "a" * 32 for d in documents))
        self.assertEqual(
            [d["metadata"]["name"] for d in documents if d["kind"] == "Namespace"], ["ml-trust"]
        )
        secrets = [d for d in documents if d["kind"] == "Secret"]
        self.assertEqual(
            {(d["metadata"]["namespace"], d["metadata"]["name"]) for d in secrets},
            {
                ("ml-trust", "postgres-tls"),
                ("ml-promoter", "trust-client"),
                ("ml-serving", "trust-client"),
            },
        )
        self.assertFalse(
            any(
                d["kind"] in {"RoleBinding", "ClusterRoleBinding", "StorageClass"}
                for d in documents
            )
        )
        network = next(
            d
            for d in documents
            if d["kind"] == "CiliumNetworkPolicy" and d["metadata"]["namespace"] == "ml-trust"
        )
        peers = network["spec"]["ingress"][0]["fromEndpoints"]
        self.assertEqual(
            {p["matchLabels"]["io.cilium.k8s.policy.serviceaccount"] for p in peers},
            {"promoter", "serving"},
        )
        self.assertEqual(network["spec"]["egressDeny"], [{"toEntities": ["all"]}])
        server = next(d for d in documents if d["kind"] == "StatefulSet")
        self.assertFalse(server["spec"]["template"]["spec"]["automountServiceAccountToken"])
        self.assertEqual(
            server["spec"]["template"]["spec"]["containers"][0]["image"], kube_trust.IMAGE
        )

    def test_trust_client_pod_has_no_signer_api_token_or_host_mount(self):
        spec = kube_trust.client_spec("image@sha256:" + "b" * 64, "promoter", ["module"])
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(
            [v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v], ["trust-client"]
        )
        self.assertFalse(any("hostPath" in v for v in spec["volumes"]))
        self.assertEqual(
            spec["containers"][0]["volumeMounts"][-1],
            {"name": "client", "mountPath": "/client", "readOnly": True},
        )
        with self.assertRaisesRegex(Rejected, "trust_reader_role"):
            kube_trust.client_spec("image", "publisher", ["module"])

    def test_backend_routes_only_through_verified_separate_database(self):
        checksum = digest(trust_authority.migration_sql().encode())
        public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        with (
            patch.object(kube_trust, "validate") as validate,
            patch.object(
                kube_trust, "admin", side_effect=["", "", f"1:{checksum}", f"local-cpu:{public}"]
            ) as admin,
            patch.object(trust_authority, "admin") as docker_admin,
        ):
            self.assertEqual(
                trust_authority.install(
                    self.state, "local-cpu", public, backend=kube_trust.binding
                ),
                checksum,
            )
            validate.assert_called_once_with(self.state, target=kube_trust.Target.PRIMARY)
            self.assertIn("trust_requires_separate_empty_storage", admin.call_args_list[1].args[1])
            docker_admin.assert_not_called()
        with (
            patch.object(kube_trust, "validate", side_effect=Rejected("changed")),
            patch.object(kube_trust, "admin") as admin,
        ):
            with self.assertRaisesRegex(Rejected, "changed"):
                trust_authority.install(self.state, "local-cpu", public, backend=kube_trust.binding)
            admin.assert_not_called()

    def cluster(self):
        self.objects = {}
        self.created = []

        def get(state, document):
            return copy.deepcopy(self.objects.get(kube_storage.reference(document)))

        def kubectl(state, arguments, document=None, **kwargs):
            if arguments[0] == "create":
                key = kube_storage.reference(document)
                value = copy.deepcopy(document)
                value["metadata"]["uid"] = f"uid-{len(self.created)}"
                self.objects[key] = value
                self.created.append(key)
                return SimpleNamespace(stdout=canonical(value))
            self.assertEqual(arguments[:3], ["rollout", "status", "statefulset/postgres"])
            return SimpleNamespace(stdout=b"")

        for target, name, replacement in (
            (kube_storage, "validate", lambda state: {}),
            (kube_storage, "get", get),
            (kube_trust, "kubectl", kubectl),
            (kube_trust, "validate_cluster", lambda state: {}),
            (kube_trust, "migrate", lambda state, **kwargs: {"version": 1}),
            (kube_trust, "admin", lambda *args, **kwargs: ""),
            (
                kube_trust,
                "live",
                lambda *args, **kwargs: {"volume_uid": "owned-volume", "pod_uid": "owned-pod"},
            ),
        ):
            self.enterContext(patch.object(target, name, replacement))

    def test_bootstrap_twice_preserves_uids_and_never_adopts_foreign_resources(self):
        self.cluster()
        first = kube_trust.bootstrap(self.state)
        created = self.created.copy()
        self.assertEqual(first, kube_trust.bootstrap(self.state))
        self.assertEqual(self.created, created)
        self.assertEqual(first["status"], "ready")
        local = kube_trust.directory(self.state)
        write_json(
            local / "resources.json", {**read_json(local / "resources.json"), "ready": False}
        )
        with self.assertRaisesRegex(Rejected, "trust_resources_incomplete"):
            kube_trust.validate(self.state)
        (local / "resources.json").unlink()
        with self.assertRaisesRegex(Rejected, "trust_unowned_resources"):
            kube_trust.bootstrap(self.state)

    def test_interruption_can_resume_only_recorded_resources_and_rejects_drift(self):
        self.cluster()
        original = kube_trust.kubectl
        count = 0

        def interrupted(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 3:
                raise Rejected("controlled-interruption")
            return original(*args, **kwargs)

        with (
            patch.object(kube_trust, "kubectl", side_effect=interrupted),
            self.assertRaisesRegex(Rejected, "controlled-interruption"),
        ):
            kube_trust.bootstrap(self.state)
        partial = read_json(kube_trust.directory(self.state) / "resources.json")
        self.assertFalse(partial["ready"])
        self.assertEqual(len(partial["resources"]), 2)
        kube_trust.bootstrap(self.state)
        key = next(iter(self.objects))
        self.objects[key]["metadata"]["uid"] = "foreign"
        with self.assertRaisesRegex(Rejected, "resource_identity_changed"):
            kube_trust.bootstrap(self.state)
        with self.assertRaisesRegex(Rejected, "resource_identity_changed"):
            kube_trust.validate(self.state)

    def test_changed_workspace_spec_or_missing_resource_inventory_cannot_be_accepted(self):
        self.cluster()
        kube_trust.bootstrap(self.state)
        local = kube_trust.directory(self.state)
        original = read_json(local / "resources.json")
        for change in ({"spec_digest": "changed"}, {"resources": {}}):
            write_json(local / "resources.json", {**original, **change})
            with self.assertRaisesRegex(Rejected, "trust_resources_incomplete"):
                kube_trust.validate(self.state)
        with self.assertRaisesRegex(Rejected, "trust_change_requires_migration"):
            write_json(local / "resources.json", {**original, "spec_digest": "changed"})
            kube_trust.bootstrap(self.state)
        write_json(
            local / "workspace.json",
            {**read_json(self.state / "workspace.json"), "workspace_id": "b" * 32},
        )
        for operation in (kube_trust.desired, kube_trust.bootstrap):
            with self.assertRaisesRegex(Rejected, "trust_workspace_mismatch"):
                operation(self.state)

    def test_resource_appearing_between_inventory_and_create_is_not_adopted(self):
        self.cluster()
        existing = kube_storage.get
        calls = 0

        def race(state, document):
            nonlocal calls
            calls += 1
            if calls == 14:
                return {**document, "metadata": {**document["metadata"], "uid": "foreign"}}
            return existing(state, document)

        # There are 13 initial resource lookups before the create loop starts.
        with (
            patch.object(kube_storage, "get", side_effect=race),
            self.assertRaisesRegex(Rejected, "trust_unowned_resource"),
        ):
            kube_trust.bootstrap(self.state)
        self.assertEqual(self.created, [])

    def live_fixture(self):
        claim = {
            "metadata": {"uid": "pvc"},
            "spec": {"volumeName": "volume"},
            "status": {"phase": "Bound"},
        }
        volume = {
            "metadata": {"uid": "pv"},
            "spec": {
                "persistentVolumeReclaimPolicy": "Retain",
                "storageClassName": CLASS,
                "claimRef": {"uid": "pvc", "namespace": "ml-trust", "name": "postgres-data"},
            },
        }
        pod = {
            "metadata": {"uid": "pod"},
            "spec": postgres("a" * 32)["spec"]["template"]["spec"],
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        }
        return claim, volume, pod

    def test_live_validation_requires_bound_owned_volume_restricted_ready_pod_and_sql(self):
        baseline = self.live_fixture()
        with (
            patch.object(kube_storage, "get", side_effect=copy.deepcopy(baseline)),
            patch.object(kube_trust, "admin", side_effect=["180006:on", "0", "f"]),
        ):
            self.assertEqual(
                kube_trust.live(self.state, {"volume_uid": "pv"}),
                {"volume_uid": "pv", "pod_uid": "pod"},
            )
        for index, mutate, code in (
            (0, lambda d: d["status"].update(phase="Pending"), "trust_volume_unbound"),
            (0, lambda d: d["spec"].update(volumeName=None), "trust_volume_unbound"),
            (
                1,
                lambda d: d["spec"].update(persistentVolumeReclaimPolicy="Delete"),
                "trust_volume_binding_changed",
            ),
            (
                1,
                lambda d: d["spec"]["claimRef"].update(uid="foreign"),
                "trust_volume_binding_changed",
            ),
            (1, lambda d: d["metadata"].update(uid="foreign"), "trust_volume_binding_changed"),
            (
                2,
                lambda d: d["spec"].update(automountServiceAccountToken=True),
                "trust_pod_not_ready",
            ),
            (2, lambda d: d["spec"].update(initContainers=[{}]), "trust_pod_not_ready"),
            (
                2,
                lambda d: d["status"]["conditions"][0].update(status="False"),
                "trust_pod_not_ready",
            ),
        ):
            documents = copy.deepcopy(baseline)
            mutate(documents[index])
            with (
                patch.object(kube_storage, "get", side_effect=documents),
                self.assertRaisesRegex(Rejected, code),
            ):
                kube_trust.live(self.state, {"volume_uid": "pv"})
        for responses, code in (
            (["170000:off"], "trust_server_version"),
            (["180006:on", "1"], "trust_hba_invalid"),
            (["180006:on", "0", "t"], "trust_reader_has_model_storage_access"),
        ):
            with (
                patch.object(kube_storage, "get", side_effect=copy.deepcopy(baseline)),
                patch.object(kube_trust, "admin", side_effect=responses),
                self.assertRaisesRegex(Rejected, code),
            ):
                kube_trust.live(self.state, {})

    def test_operator_execution_uses_only_trust_namespace_and_constant_cli_errors(self):
        with patch.object(kube_trust, "binary_command", return_value=b"1\n") as execute:
            self.assertEqual(kube_trust.admin(self.state, "SELECT 1;"), "1")
            args = execute.call_args.args[0]
            self.assertEqual(args[args.index("-n") + 1], "ml-trust")
            self.assertEqual(execute.call_args.kwargs["content"], b"SELECT 1;")
        with (
            patch.object(kube_trust, "bootstrap", return_value={"status": "ready"}),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(kube_trust.main(["--state", str(self.state)]), 0)
        for error, code in ((Rejected("private-value"), 1), (KeyboardInterrupt(), 130)):
            output = io.StringIO()
            with patch.object(kube_trust, "bootstrap", side_effect=error), redirect_stderr(output):
                self.assertEqual(kube_trust.main(["--state", str(self.state)]), code)
            self.assertEqual(output.getvalue(), "kubernetes_trust_rejected\n")
        with (
            patch("sys.argv", ["kube-trust"]),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            runpy.run_module("mlsecops.kube_trust", run_name="__main__")
        self.assertEqual(error.exception.code, 1)
        with (
            patch.object(
                trust_authority,
                "current",
                return_value=(
                    self.state,
                    {"environment": "local-cpu", "version": 1, "sha256": "a" * 64},
                ),
            ) as current,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                trust_authority.main(
                    ["show", "--state", str(self.state), "--backend", "kubernetes"]
                ),
                0,
            )
            self.assertIs(current.call_args.kwargs["backend"], kube_trust.binding)


if __name__ == "__main__":
    unittest.main()
