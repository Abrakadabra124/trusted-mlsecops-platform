"""Boundary-only native orchestration and real-file recovery contracts; no infrastructure."""

import importlib.util
import io
import os
import runpy
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    digest,
    read_json,
    write_json,
)


def workspace(path, identity):
    write_json(
        path / "workspace.json",
        dict(schema_version=1, product="trusted-mlsecops", workspace_id=identity),
    )


class NativeDriverTests(unittest.TestCase):
    def test_driver_and_shared_recovery_are_available(self):
        self.assertIsNotNone(importlib.util.find_spec("scripts.ci_consumer_native"))
        self.assertIsNotNone(importlib.util.find_spec("scripts.ci_consumer_recovery"))

    def test_nonhosted_refuses_without_proposal_or_cleanup_claim(self):
        from scripts import ci_consumer_native as driver

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(driver, "hosted", side_effect=Rejected("private-host")):
                with patch.object(driver.release_native, "qualify") as proposal:
                    result = driver.execute(root)
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["stage"], "preflight")
            self.assertEqual(result["cleanup"], {"sql": False, "cluster": False})
            self.assertNotIn("private-host", str(result))
            proposal.assert_not_called()

    def test_missing_recovery_witness_is_not_empty_baseline(self):
        from scripts import ci_consumer_native as driver

        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(driver, "hosted"):
                result = driver.execute(Path(temporary), cleanup=True)
            self.assertEqual(result["status"], "fail")
            self.assertFalse(any(result["cleanup"].values()))

    def test_cleanup_attempts_cluster_after_sql_failure(self):
        from scripts import ci_consumer_recovery as recovery

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            workspace(state, "a" * 32)
            record = {"workspace_id": "a" * 32, "sql": None, "cluster": None}
            write_json(state / recovery.RECORD, record)
            witness = recovery.Recovery(state)
            attempts = []

            def sql():
                attempts.append("sql")
                raise Rejected("private-resource")

            def cluster():
                attempts.append("cluster")

            with (
                patch.object(witness, "stop_sql", sql),
                patch.object(witness, "delete_cluster", cluster),
            ):
                self.assertEqual(witness.cleanup(), {"sql": False, "cluster": True})
            self.assertEqual(attempts, ["sql", "cluster"])
            self.assertEqual(
                read_json(state / recovery.RECORD)["cleanup"], {"sql": False, "cluster": True}
            )

    def test_invalid_cli_emits_only_closed_json(self):
        from scripts import ci_consumer_native as driver

        output = io.StringIO()
        with redirect_stdout(output):
            code = driver.main(["private-argument"])
        self.assertEqual(code, 1)
        self.assertNotIn("private-argument", output.getvalue())
        self.assertIn('"cause":"arguments"', output.getvalue())

    def test_main_entrypoints_print_closed_result_and_return_exit_status(self):
        from scripts import ci_consumer_native as driver

        for arguments, status, expected in (([], "pass", 0), (["cleanup"], "fail", 1)):
            output = io.StringIO()
            value = driver.projection() | {"status": status}
            with patch.object(driver, "execute", return_value=value) as execute:
                with redirect_stdout(output):
                    code = driver.main(arguments)
            self.assertEqual(code, expected)
            self.assertEqual(output.getvalue(), canonical(value).decode() + "\n")
            self.assertEqual(execute.call_args.kwargs, {"cleanup": bool(arguments)})

    def test_module_cli_error_has_no_raw_traceback(self):
        from scripts import ci_consumer_native as driver

        output = io.StringIO()
        with patch.object(sys, "argv", ["ci_consumer_native", "private-invalid"]):
            with redirect_stdout(output), self.assertRaises(SystemExit) as result:
                runpy.run_path(driver.__file__, run_name="__main__")
        self.assertEqual(result.exception.code, 1)
        self.assertNotIn("private-invalid", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_delayed_helpers_receive_independent_pins_and_replay_is_required(self):
        from scripts import ci_consumer_native as driver
        from scripts import consumer_candidate_storage as importer
        from scripts import m18_shared_retention as retainer

        seen = []

        def imported(root, state, **args):
            seen.append(("import", root, state, args))
            return {"status": "pass"}

        def retain(root, state, destination, **args):
            seen.append(("retain", root, state, destination, args))
            return "d" * 64

        def replay(root, destination, *, index_pin, **args):
            seen.append(("replay", root, destination, index_pin, args))
            return {"release_ready": False}

        # Patch the real module attributes: earlier tests may already have cached
        # these modules on the scripts package, independently of sys.modules.
        with (
            patch.object(importer, "import_candidate", imported),
            patch.object(retainer, "retain", retain),
            patch.object(retainer, "replay", replay),
        ):
            owner = {"freeze_pin": "a" * 64, "freeze": {"original": "pin"}}
            self.assertEqual(driver.import_candidate("root", "state", **owner), {"status": "pass"})
            result = driver.retain("root", "state", "destination", **owner)
            self.assertEqual(result["index_pin"], "d" * 64)
            self.assertEqual(
                seen,
                [
                    ("import", "root", "state", owner),
                    ("retain", "root", "state", "destination", owner),
                    ("replay", "root", "destination", "d" * 64, owner),
                ],
            )
            retainer.replay = lambda *args, **kwargs: {"release_ready": True}
            with self.assertRaises(Rejected):
                driver.retain("root", "state", "destination", **owner)


class DockerBoundary:
    """Model Docker's read/stop/remove boundary; no orchestration methods are replaced."""

    def __init__(self):
        self.rows = {}
        self.volumes = set()
        self.volume_info = {}
        self.networks = set()
        self.mutations = []
        self.fail_stop = False
        self.fail_remove = False
        self.bad_query = False

    def add(self, handle, name, labels):
        self.rows[handle] = dict(
            Id=handle,
            Name="/" + name,
            Config={"Labels": labels},
            State=dict(Running=True, Status="running", StartedAt="start", FinishedAt=""),
            RestartCount=0,
            Mounts=[],
        )

    def docker(self, args, **kwargs):

        if self.bad_query:
            raise Rejected("private-daemon")
        out, code = b"", 0
        if args[0] == "ps":
            rows = self.rows.copy()
            for i, value in enumerate(args):
                if value != "--filter":
                    continue
                kind, _, wanted = args[i + 1].partition("=")
                if kind == "label":
                    label, _, expected = wanted.partition("=")
                    rows = {
                        k: v
                        for k, v in rows.items()
                        if v["Config"]["Labels"].get(label) == expected
                    }
                elif kind == "volume":
                    rows = {
                        k: v
                        for k, v in rows.items()
                        if wanted in [m["Name"] for m in v["Mounts"] if m["Type"] == "volume"]
                    }
                else:
                    rows = {
                        k: v
                        for k, v in rows.items()
                        if v["Name"] == wanted.removeprefix("^").removesuffix("$")
                    }
            out = "\n".join(rows).encode()
        elif args[:2] == ["container", "inspect"]:
            row = self.rows.get(args[2])
            if row is None:
                row = next((v for v in self.rows.values() if v["Name"] == "/" + args[2]), None)
            out, code = (canonical([row]), 0) if row else (b"", 1)
        elif args[:2] == ["volume", "inspect"]:
            out = canonical([self.volume_info[args[2]]])
        elif args[:2] == ["volume", "rm"]:
            self.mutations.append(tuple(args))
            self.volumes.remove(args[2])
            self.volume_info.pop(args[2])
        elif args[0] in ("volume", "network"):
            inventory = self.volumes if args[0] == "volume" else self.networks
            out = "\n".join(
                v
                for v in inventory
                if "--filter" not in args or v == args[-1].removeprefix("name=")
            ).encode()
        elif args[0] == "stop":
            self.mutations.append(tuple(args))
            if self.fail_stop:
                raise OSError("private-sql")
            row = self.rows[args[-1]]
            row["State"].update(Running=False, Status="exited", FinishedAt="finish")
        elif args[0] == "rm":
            self.mutations.append(tuple(args))
            if self.fail_remove:
                raise OSError("private-cluster")
            del self.rows[args[-1]]
        else:
            raise AssertionError(args)
        if kwargs.get("check", True) and code:
            raise Rejected("missing")
        return SimpleNamespace(stdout=out, stderr=b"", returncode=code)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        from scripts import ci_consumer_recovery as recovery

        self.r = recovery
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.producer, self.view = self.root / "producer", self.root / "consumer"
        workspace(self.producer, "a" * 32)
        workspace(self.view, "b" * 32)
        self.docker = DockerBoundary()
        self.enterContext(patch.object(recovery.sql, "docker", self.docker.docker))
        self.enterContext(patch.object(recovery.cluster, "command", self.kind))
        self.enterContext(patch.object(recovery.storage_pki, "initialize"))
        self.spec = dict(
            workspace_id="b" * 32,
            config_digest="c" * 64,
            name="consumer",
            volume="consumer-data",
            network="consumer-net",
            port=15440,
        )
        self.enterContext(patch.object(recovery.sql, "specification", return_value=(self.spec, {})))
        self.w = recovery.Recovery.begin(self.producer, {"job": 1}, {"source_revision": "d" * 40})

    def kind(self, args):
        self.assertEqual(args, ["kind", "get", "clusters"])
        return (
            self.r.cluster.NAME
            if any(
                v["Config"]["Labels"].get(self.r.KIND_LABEL) == self.r.cluster.NAME
                for v in self.docker.rows.values()
            )
            else ""
        )

    def sql_row(self, handle="1" * 64):
        self.docker.add(
            handle,
            "consumer",
            {self.r.sql.WORKSPACE_LABEL: "b" * 32, self.r.sql.CONFIG_LABEL: "c" * 64},
        )

    def cluster_row(self, handle="2" * 64):
        self.docker.add(
            handle,
            self.r.cluster.NODE,
            {self.r.KIND_LABEL: self.r.cluster.NAME, "io.x-k8s.kind.role": "control-plane"},
        )

    def armed(self):
        self.w.arm_sql(self.view)
        self.sql_row()
        self.w.observe_sql()
        self.w.arm_cluster()
        self.cluster_row()
        atomic_write(self.view / "kubeconfig", b"private-kubeconfig")
        self.w.observe_cluster(self.view)

    def node_volume(self, name="node-private"):
        self.docker.volumes.add(name)
        self.docker.volume_info[name] = dict(
            Name=name, Driver="local", CreatedAt="created", Labels=None, Options=None
        )
        self.docker.rows["2" * 64]["Mounts"].append(dict(Type="volume", Name=name))

    def test_node_private_volume_deleted_after_exact_node_and_no_references(self):
        self.w.arm_cluster()
        self.cluster_row()
        self.node_volume()
        self.w.observe_cluster(self.view)
        result = self.w.cleanup()
        self.assertEqual(result, {"sql": True, "cluster": True})
        self.assertNotIn("node-private", self.docker.volumes)
        self.assertEqual(
            self.docker.mutations, [("rm", "--force", "2" * 64), ("volume", "rm", "node-private")]
        )
        self.assertEqual(self.w.cleanup(), result)

    def test_shared_or_preexisting_node_volume_is_never_adopted(self):
        for preexisting in (True, False):
            with self.subTest(preexisting=preexisting):
                self.w.record["cluster"] = None
                self.docker.rows.clear()
                self.docker.volumes.clear()
                if preexisting:
                    self.docker.volumes.add("node-private")
                self.w.arm_cluster()
                self.cluster_row()
                self.node_volume()
                if not preexisting:
                    self.docker.add("3" * 64, "foreign", {})
                    self.docker.rows["3" * 64]["Mounts"] = [
                        dict(Type="volume", Name="node-private")
                    ]
                with self.assertRaises(Rejected):
                    self.w.observe_cluster(self.view)
                self.assertEqual(self.w.cleanup(), {"sql": True, "cluster": False})
                self.assertFalse(self.docker.mutations)

    def test_replaced_or_newly_shared_volume_refuses_deletion(self):
        self.w.arm_cluster()
        self.cluster_row()
        self.node_volume()
        self.w.observe_cluster(self.view)
        self.docker.volume_info["node-private"]["CreatedAt"] = "replacement"
        self.assertFalse(self.w.cleanup()["cluster"])
        self.assertFalse(self.docker.mutations)
        self.docker.volume_info["node-private"]["CreatedAt"] = "created"
        self.docker.add("3" * 64, "foreign", {})
        self.docker.rows["3" * 64]["Mounts"] = [dict(Type="volume", Name="node-private")]
        self.assertFalse(self.w.cleanup()["cluster"])
        self.assertFalse(self.docker.mutations)

    def test_empty_baseline_and_no_creation_are_verified(self):
        self.assertEqual(self.w.cleanup(), {"sql": True, "cluster": True})
        self.assertFalse(self.docker.mutations)

    def test_exact_ids_stop_sql_delete_cluster_and_survive_view_deletion(self):
        self.armed()
        shutil.rmtree(self.view)
        recovered = self.r.Recovery(self.producer)
        self.assertEqual(recovered.cleanup(), {"sql": True, "cluster": True})
        self.assertFalse(self.docker.rows["1" * 64]["State"]["Running"])
        self.assertNotIn("2" * 64, self.docker.rows)
        self.assertEqual(
            self.docker.mutations, [("stop", "--time", "20", "1" * 64), ("rm", "--force", "2" * 64)]
        )
        self.assertEqual(bounded_read(self.producer / self.r.KUBE), b"private-kubeconfig")
        self.assertEqual(recovered.cleanup(), {"sql": True, "cluster": True})

    def test_partial_bootstrap_without_storage_or_cluster_marker(self):
        self.armed()
        self.assertFalse((self.view / "storage.json").exists())
        self.assertFalse((self.view / "cluster.json").exists())
        self.assertEqual(self.w.cleanup(), {"sql": True, "cluster": True})

    def test_missing_observation_refuses_even_when_current_inventory_empty(self):
        self.w.arm_sql(self.view)
        self.w.arm_cluster()
        self.assertEqual(self.w.cleanup(), {"sql": False, "cluster": False})
        self.assertFalse(self.docker.mutations)

    def test_replaced_container_is_never_stopped_or_deleted(self):
        self.armed()
        self.docker.rows.pop("1" * 64)
        self.docker.rows.pop("2" * 64)
        self.sql_row("3" * 64)
        self.cluster_row("4" * 64)
        self.assertEqual(self.w.cleanup(), {"sql": False, "cluster": False})
        self.assertFalse(self.docker.mutations)

    def test_changed_label_rejects_foreign_resources(self):
        self.armed()
        self.docker.rows["1" * 64]["Config"]["Labels"][self.r.sql.CONFIG_LABEL] = "foreign"
        self.docker.rows["2" * 64]["Config"]["Labels"][self.r.KIND_LABEL] = "foreign"
        self.assertEqual(self.w.cleanup(), {"sql": False, "cluster": False})
        self.assertFalse(self.docker.mutations)

    def test_each_cleanup_failure_still_attempts_other_resource(self):
        for fail_sql, fail_cluster in ((True, False), (False, True), (True, True)):
            with self.subTest(sql=fail_sql, cluster=fail_cluster):
                self.docker.rows.clear()
                self.w.record.update(sql=None, cluster=None)
                self.armed()
                self.docker.mutations.clear()
                self.docker.fail_stop, self.docker.fail_remove = fail_sql, fail_cluster
                self.assertEqual(
                    self.w.cleanup(), {"sql": not fail_sql, "cluster": not fail_cluster}
                )
                self.assertEqual(len(self.docker.mutations), 2)

    def test_daemon_query_failure_cannot_be_absence(self):
        self.docker.bad_query = True
        self.assertEqual(self.w.cleanup(), {"sql": True, "cluster": False})

    def test_nonempty_sql_baselines_refuse_before_arming(self):
        for resource in ("container", "volume", "network"):
            with self.subTest(resource=resource):
                if resource == "container":
                    self.sql_row()
                elif resource == "volume":
                    self.docker.volumes.add("consumer-data")
                else:
                    self.docker.networks.add("consumer-net")
                with self.assertRaises(Rejected):
                    self.w.arm_sql(self.view)
                self.assertIsNone(self.w.record["sql"])
                self.docker.rows.clear()
                self.docker.volumes.clear()
                self.docker.networks.clear()

    def test_existing_cluster_and_wrong_workspace_refuse(self):
        self.cluster_row()
        with self.assertRaises(Rejected):
            self.w.arm_cluster()
        with self.assertRaises(Rejected):
            self.r.Recovery.begin(self.producer, {}, {})
        workspace(self.producer, "e" * 32)
        with self.assertRaises(Rejected):
            self.r.Recovery(self.producer)

    def test_two_kind_nodes_or_wrong_role_refuse(self):
        self.cluster_row()
        self.docker.rows["2" * 64]["Config"]["Labels"]["io.x-k8s.kind.role"] = "worker"
        with self.assertRaises(Rejected):
            self.r.cluster_inventory()
        self.cluster_row()
        self.cluster_row("3" * 64)
        with self.assertRaises(Rejected):
            self.r.cluster_inventory()

    def test_disappeared_filter_does_not_hide_live_recorded_cluster_id(self):
        self.armed()
        self.docker.rows["2" * 64]["Name"] = "/renamed-foreign"
        self.docker.rows["2" * 64]["Config"]["Labels"] = {}
        result = self.w.cleanup()
        self.assertFalse(result["cluster"])
        self.assertIn("2" * 64, self.docker.rows)
        self.assertNotIn(("rm", "--force", "2" * 64), self.docker.mutations)

    def test_new_sql_after_stop_is_not_unchecked_cleanup_success(self):
        self.armed()
        original = self.docker.docker

        def concurrent(args, **kwargs):
            result = original(args, **kwargs)
            if args[0] == "stop":
                self.sql_row("3" * 64)
            return result

        with patch.object(self.r.sql, "docker", concurrent):
            result = self.w.cleanup()
        self.assertFalse(result["sql"])
        self.assertTrue(result["cluster"])
        self.assertTrue(self.docker.rows["3" * 64]["State"]["Running"])


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        from scripts import ci_consumer_native as driver

        self.d = driver
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.producer = self.root / ".runtime"
        workspace(self.producer, "a" * 32)
        self.events, self.failure, self.primary = [], None, Rejected("private-primary")
        self.cleanup_sql_failure = self.cleanup_cluster_failure = False
        self.docker = DockerBoundary()
        self.expected_source = dict(
            source_revision="d" * 40, source_fingerprint="e" * 64, image_id="sha256:" + "f" * 64
        )
        self.expected = dict(
            self.expected_source,
            candidate_reference="1" * 64,
            evaluation_reference="2" * 64,
            proposal_reference="3" * 64,
            subject_sha256="4" * 64,
            model_sha256="5" * 64,
        )
        self.marker = dict(workspace_id="a" * 32, container_id="a" * 64, port=15439)
        write_json(self.producer / "storage.json", self.marker)
        self.docker.add("a" * 64, "producer", {})
        for name in ("storage-demo.json", "storage-trust.json", "trusted-keys.json"):
            write_json(self.producer / name, {"private": name})
        atomic_write(self.producer / "keys/trust.pem", b"original-private-key")
        self.spec = dict(
            workspace_id="b" * 32,
            config_digest="c" * 64,
            name="consumer",
            volume="consumer-data",
            network="consumer-net",
            port=15440,
        )
        self.enterContext(
            patch.dict(
                os.environ,
                dict(
                    GITHUB_REPOSITORY=driver.ci_transfer.REPOSITORY,
                    GITHUB_RUN_ID="17",
                    GITHUB_RUN_ATTEMPT="2",
                    GITHUB_JOB="consumer",
                    M12_EARLY_SHA256="old-pin",
                ),
            )
        )
        self.enterContext(patch.object(driver, "hosted", lambda: self.event("hosted")))
        self.enterContext(patch.object(driver, "source", self.source))
        self.enterContext(patch.object(driver.storage_bootstrap, "docker", self.docker.docker))
        self.enterContext(patch.object(driver.cluster, "command", self.kind))
        self.enterContext(patch.object(driver.recovery.storage_pki, "initialize"))
        self.enterContext(
            patch.object(driver.storage_bootstrap, "specification", return_value=(self.spec, {}))
        )
        self.enterContext(
            patch.object(
                driver.storage_bootstrap,
                "validate",
                lambda state: read_json(state / "storage.json"),
            )
        )
        self.enterContext(patch.object(driver.release_native, "qualify", self.proposal))
        self.enterContext(patch.object(driver.m18_delivery_freeze, "capture", self.freeze))
        self.enterContext(patch.object(driver.transfer.delivery, "frozen", self.frozen))
        self.enterContext(patch.object(driver.bridge, "seal", self.seal))
        self.enterContext(
            patch.object(driver.consumer_candidate_state, "materialize", self.materialize)
        )
        self.enterContext(patch.object(driver.storage_bootstrap, "bootstrap", self.sql))
        self.enterContext(patch.object(driver, "import_candidate", self.imported))
        self.enterContext(patch.object(driver.cluster, "bootstrap", self.cluster))
        self.enterContext(
            patch.object(
                driver.cluster, "validate_cluster", lambda state: self.event("cluster_validate")
            )
        )
        self.enterContext(
            patch.object(driver.kube_storage, "bootstrap", lambda state: self.event("kube_storage"))
        )
        self.enterContext(patch.object(driver.bridge, "_fresh", self.fresh))
        self.enterContext(
            patch.object(driver.bridge, "_window", lambda *args: self.event("window"))
        )
        self.enterContext(patch.object(driver.shared, "capture", self.actual))
        self.enterContext(patch.object(driver.shared, "late", self.late))
        self.enterContext(patch.object(driver.acceptance, "report", self.report))
        self.enterContext(patch.object(driver.shared_serving_receipt, "receipt", self.receipt))
        self.retention_patch = None
        if hasattr(driver, "retain"):
            self.retention_patch = self.enterContext(patch.object(driver, "retain", self.retain))
        self.view = None
        self.receipt_count = 0

    def event(self, name):
        self.events.append(name)
        print("nested-private-" + name)
        print("nested-private-error-" + name, file=__import__("sys").stderr)
        if name == self.failure:
            self.docker.fail_stop = self.cleanup_sql_failure
            self.docker.fail_remove = self.cleanup_cluster_failure
            raise self.primary

    def source(self, root, image):
        self.assertEqual((root, image), (self.root, "trusted-mlsecops:dev"))
        self.event("source")
        return self.expected_source.copy()

    def kind(self, args):
        self.assertEqual(args, ["kind", "get", "clusters"])
        return self.d.cluster.NAME if "c" * 64 in self.docker.rows else ""

    def proposal(self, root, state, image):
        self.assertEqual((root, state, image), (self.root, self.producer, self.d.IMAGE))
        self.event("proposal")
        report = dict(
            status="pass",
            source=self.expected_source,
            source_dirty=False,
            campaign_id="6" * 32,
            proposal_reference="3" * 64,
        )
        write_json(state / "release-proposals" / ("6" * 32) / "report.json", report)
        return report

    def freeze(self, root, state, freeze, revision):
        self.event("freeze")
        self.assertEqual(revision, "d" * 40)
        self.assertEqual(
            freeze, {p: digest(bounded_read(state / p)) for p in self.d.transfer.delivery.FILES}
        )
        return self.d.put(
            state, self.d.transfer.RECEIPT, dict(freeze=freeze, **self.expected_source)
        )

    def frozen(self, root, state, index):
        self.event("frozen")
        return self.expected.copy(), {}, {}

    def seal(self, root, state, **args):
        self.event("seal")
        self.assertEqual(args["expected"], self.expected)
        self.assertEqual(args["phase"], "M11-M12")
        self.assertEqual(len(args["key"]), 32)
        self.key = args["key"]
        return dict(
            envelope=b"private-ciphertext",
            context={"private": "context"},
            ciphertext_sha256="7" * 64,
            manifest_sha256="8" * 64,
        )

    @contextmanager
    def materialize(self, root, envelope, **args):
        self.event("materialize")
        self.assertFalse(self.docker.rows["a" * 64]["State"]["Running"])
        self.assertEqual(args["key"], self.key)
        self.assertEqual(envelope, b"private-ciphertext")
        self.assertEqual(args["trust_key_path"], self.producer / "keys/trust.pem")
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            self.view = Path(temporary)
            workspace(self.view, "b" * 32)
            for name in self.d.transfer.delivery.FILES:
                atomic_write(self.view / name, bounded_read(self.producer / name))
            atomic_write(self.view / "keys/trust.pem", b"original-private-key")
            try:
                yield (
                    self.view,
                    dict(workspace_id="b" * 32, storage_imported=False, campaign_id="6" * 32),
                )
            finally:
                # Assert before the fixture owns deletion. Recovery data must already exist.
                witness = read_json(self.producer / self.d.recovery.RECORD)
                self.assertIn("cleanup", witness)
                self.assertTrue((self.view / "keys/trust.pem").exists())
                self.event("view_exit")

    def sql(self, state, *, port):
        self.assertEqual((state, port), (self.view, 15440))
        self.assertFalse(self.docker.rows["a" * 64]["State"]["Running"])
        self.docker.add(
            "b" * 64,
            "consumer",
            {
                self.d.recovery.sql.WORKSPACE_LABEL: "b" * 32,
                self.d.recovery.sql.CONFIG_LABEL: "c" * 64,
            },
        )
        self.event("sql_partial")
        write_json(state / "storage.json", dict(self.spec, container_id="b" * 64))
        self.event("sql_ready")

    def imported(self, root, state, **args):
        self.event("import")
        self.assertEqual(args["expected"], self.expected)
        self.assertEqual(args["expected_workspace_id"], "b" * 32)
        self.assertEqual(args["storage_pin"], digest(bounded_read(state / "storage.json")))
        record = read_json(self.producer / self.d.recovery.RECORD)
        self.assertEqual(record["storage_pin"], args["storage_pin"])
        return dict(
            status="pass",
            proposal_reference="3" * 64,
            workspace_id="b" * 32,
            storage_pin=args["storage_pin"],
        )

    def cluster(self, state):
        self.docker.add(
            "c" * 64,
            self.d.cluster.NODE,
            {
                self.d.recovery.KIND_LABEL: self.d.cluster.NAME,
                "io.x-k8s.kind.role": "control-plane",
            },
        )
        atomic_write(state / "kubeconfig", b"private-kubeconfig")
        self.event("cluster_partial")
        write_json(state / "cluster.json", {"workspace_id": "b" * 32})
        self.event("cluster_ready")

    def fresh(self, root, state, owner):
        self.event("fresh")
        self.assertEqual(owner["expected"], self.expected)
        return {"original": "window"}, 100

    def actual(self, root, state, image):
        self.event("actual")
        self.assertNotIn("M12_EARLY_SHA256", os.environ)
        self.assertEqual(
            os.environ["M11_PROPOSAL_SHA256"],
            digest(bounded_read(state / "evidence/release-native.json")),
        )
        self.assertTrue(self.docker.rows["b" * 64]["State"]["Running"])
        return {"actual": "private-actual-packet"}

    def late(self, root, state, image, early_pin):
        self.event("late")
        self.assertFalse(self.docker.rows["b" * 64]["State"]["Running"])
        self.assertEqual(early_pin, digest(bounded_read(state / self.d.shared.EARLY)))
        return {"early_sha256": early_pin, "controlled": "private-controlled"}

    def report(self, gate, profile, root, *, state):
        self.event(gate)
        self.assertEqual((profile, root, state), ("local-cpu", self.root, self.view))
        self.assertEqual(
            os.environ[self.d.shared.PIN], digest(bounded_read(state / self.d.shared.FULL))
        )
        return dict(gate=gate, status="pass", exit_code=0, metrics={"checks": 7})

    def receipt(self, state, env):
        self.receipt_count += 1
        self.event("receipt")
        self.assertEqual(state, self.view)
        self.assertTrue((state / "evidence/M11.json").exists())
        self.assertTrue((state / "evidence/M12.json").exists())
        return dict(reports={g: {"checks": 7} for g in ("M11", "M12")}, private="receipt")

    def retain(self, root, state, destination, **args):
        self.event("retain")
        self.assertNotIn("c" * 64, self.docker.rows)
        self.assertFalse(self.docker.rows["b" * 64]["State"]["Running"])
        self.assertTrue(state.exists())
        self.assertEqual(
            args["report_pins"],
            {g: digest(bounded_read(state / ("evidence/" + g + ".json"))) for g in ("M11", "M12")},
        )
        write_json(destination / "private-index.json", {"retained": True})
        return {
            "index_pin": "9" * 64,
            "replay": {
                "release_ready": False,
                "receipt": dict(
                    reports={g: {"checks": 7} for g in ("M11", "M12")}, private="receipt"
                ),
            },
        }

    def result(self):
        return self.d.execute(self.root)

    def test_entire_original_path_and_retention_precede_context_exit(self):
        result = self.result()
        self.assertEqual(
            result["status"],
            "pass",
            bounded_read(self.producer / "evidence/ci-consumer-native-run.log").decode(),
        )
        self.assertEqual(result["gate_counts"], {"M11": 7, "M12": 7})
        self.assertEqual(result["cleanup"], {"sql": True, "cluster": True})
        self.assertEqual(
            self.events,
            [
                "hosted",
                "source",
                "proposal",
                "freeze",
                "frozen",
                "seal",
                "materialize",
                "sql_partial",
                "sql_ready",
                "import",
                "cluster_partial",
                "cluster_ready",
                "cluster_validate",
                "kube_storage",
                "fresh",
                "window",
                "source",
                "actual",
                "late",
                "M11",
                "M12",
                "receipt",
                "receipt",
                "retain",
                "view_exit",
            ],
        )
        self.assertFalse(self.view.exists())
        self.assertEqual(os.environ["M12_EARLY_SHA256"], "old-pin")
        packet = read_json(self.producer / self.d.PRIVATE_PACKET)
        self.assertIn("receipt", packet)
        self.assertIn("retention", packet)
        self.assertEqual(packet["reports"]["M11"]["status"], "pass")
        public = bounded_read(self.producer / self.d.PUBLIC_REPORT)
        for secret in (b"private", b"pin", b"ciphertext", self.key):
            self.assertNotIn(secret, public)
        self.assertIn(
            b"nested-private", bounded_read(self.producer / "evidence/ci-consumer-native-run.log")
        )

    def test_partial_sql_failure_cleanup_happens_before_context_deletion(self):
        self.failure = "sql_partial"
        result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "consumer_sql")
        self.assertEqual(result["cleanup"], {"sql": True, "cluster": True})
        self.assertFalse(self.docker.rows["b" * 64]["State"]["Running"])
        self.assertNotIn("import", self.events)
        self.assertFalse(self.view.exists())

    def test_partial_cluster_failure_uses_exact_ids_and_private_kubeconfig(self):
        self.failure = "cluster_partial"
        result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["cleanup"], {"sql": True, "cluster": True})
        self.assertNotIn("c" * 64, self.docker.rows)
        self.assertEqual(bounded_read(self.producer / self.d.recovery.KUBE), b"private-kubeconfig")
        self.assertNotIn("actual", self.events)

    def test_primary_error_survives_observation_failure(self):
        self.failure = "sql_partial"
        with patch.object(
            self.d.recovery.Recovery, "observe_sql", side_effect=OSError("secondary")
        ):
            result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertIn("consumer_cleanup_incomplete", getattr(self.primary, "__notes__", []))
        self.assertFalse(result["cleanup"]["sql"])

    def test_sql_cleanup_failure_does_not_skip_cluster_or_become_pass(self):
        self.failure, self.cleanup_sql_failure = "actual", True
        result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "actual")
        self.assertEqual(result["cleanup"], {"sql": False, "cluster": True})
        self.assertNotIn("c" * 64, self.docker.rows)
        self.assertTrue(self.docker.rows["b" * 64]["State"]["Running"])
        self.assertIn("consumer_cleanup_incomplete", self.primary.__notes__)

    def test_cluster_cleanup_failure_does_not_skip_sql(self):
        self.failure, self.cleanup_cluster_failure = "actual", True
        result = self.result()
        self.assertEqual(result["cleanup"], {"sql": True, "cluster": False})
        self.assertFalse(self.docker.rows["b" * 64]["State"]["Running"])
        self.assertIn("c" * 64, self.docker.rows)
        self.assertEqual(result["status"], "fail")

    def test_missing_retention_never_claims_component_success(self):
        if not hasattr(self.d, "retain"):
            self.fail("mandatory retained primary evidence is not implemented")
        with patch.object(self.d, "retain", side_effect=ImportError("private-helper")):
            result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "retention")
        self.assertEqual(result["cause"], "dependency")
        self.assertFalse((self.producer / self.d.PRIVATE_PACKET).exists())

    def test_offline_retained_receipt_must_match_original_full_gate_receipt(self):
        with patch.object(
            self.d,
            "retain",
            return_value={
                "index_pin": "9" * 64,
                "replay": {"release_ready": False, "receipt": {"other": "model"}},
            },
        ):
            result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "retention")
        self.assertFalse((self.producer / self.d.PRIVATE_PACKET).exists())

    def test_gate_refusal_keeps_original_report_and_prevents_next_gate(self):
        with patch.object(
            self.d.acceptance,
            "report",
            return_value={
                "gate": "M11",
                "status": "inconclusive",
                "exit_code": 2,
            },
        ):
            result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "M11")
        self.assertEqual(
            read_json(self.producer / self.d.recovery.DIRECTORY / "M11.json")["status"],
            "inconclusive",
        )
        self.assertNotIn("M12", self.events)
        self.assertNotIn("retain", self.events)

    def test_changed_receipt_after_cluster_cleanup_refuses(self):
        original = self.receipt

        def changed(*args):
            value = original(*args)
            if self.receipt_count == 2:
                value["private"] = "changed"
            return value

        with patch.object(self.d.shared_serving_receipt, "receipt", changed):
            result = self.result()
        self.assertEqual(result["stage"], "recheck")
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("retain", self.events)

    def test_missing_importer_is_not_import_only_success(self):
        with patch.object(self.d, "import_candidate", side_effect=ImportError("missing-private")):
            result = self.result()
        self.assertEqual(
            (result["status"], result["stage"], result["cause"]), ("fail", "import", "dependency")
        )
        self.assertNotIn("cluster_partial", self.events)
        self.assertFalse(self.docker.rows["b" * 64]["State"]["Running"])

    def test_duplicate_producer_invocation_never_creates_second_proposal(self):
        self.assertEqual(self.result()["status"], "pass")
        result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self.events.count("proposal"), 1)

    def test_cleanup_cli_rechecks_run_binding_and_saved_ids_without_consumer_files(self):
        self.assertEqual(self.result()["status"], "pass")
        result = self.d.execute(self.root, cleanup=True)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["cleanup"], {"sql": True, "cluster": True})
        with patch.dict(os.environ, GITHUB_RUN_ATTEMPT="3"):
            result = self.d.execute(self.root, cleanup=True)
        self.assertEqual(result["status"], "fail")
        self.assertFalse(any(result["cleanup"].values()))

    def test_successful_cleanup_cannot_overwrite_failed_native_outcome(self):
        self.failure = "actual"
        self.assertEqual(self.result()["status"], "fail")
        original = bounded_read(self.producer / self.d.PUBLIC_REPORT)
        self.assertEqual(self.d.execute(self.root, cleanup=True)["status"], "pass")
        self.assertEqual(bounded_read(self.producer / self.d.PUBLIC_REPORT), original)
        self.assertEqual(
            read_json(self.producer / "evidence/ci-consumer-native-cleanup-public.json")["status"],
            "pass",
        )

    def test_interruption_is_closed_failure_and_cleanup_still_runs(self):
        self.failure, self.primary = "actual", KeyboardInterrupt("private-interrupt")
        result = self.result()
        self.assertEqual(result["cause"], "interrupted")
        self.assertEqual(result["cleanup"], {"sql": True, "cluster": True})
        self.assertFalse(self.view.exists())

    def test_cleanup_record_write_failure_preserves_primary_and_cannot_claim_success(self):
        self.failure = "actual"
        with patch.object(self.d.recovery.Recovery, "cleanup", side_effect=OSError("private-io")):
            result = self.result()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "actual")
        self.assertIn("consumer_cleanup_unverified", self.primary.__notes__)
        self.assertFalse(any(result["cleanup"].values()))

    def test_stdout_stderr_file_descriptors_are_private(self):
        with self.d.private_output(self.producer, "probe"):
            os.write(1, b"fd-private-out\n")
            os.write(2, b"fd-private-err\n")
            print("python-private-out")
        content = bounded_read(self.producer / "evidence/ci-consumer-native-probe.log")
        for expected in (b"fd-private-out", b"fd-private-err", b"python-private-out"):
            self.assertIn(expected, content)

    def test_public_report_write_failure_is_not_success(self):
        original = self.d.put

        def refused(state, name, value):
            if name == self.d.PUBLIC_REPORT:
                raise OSError("private-report-path")
            return original(state, name, value)

        with patch.object(self.d, "put", refused):
            result = self.result()
        self.assertEqual((result["status"], result["cause"]), ("fail", "local_io"))


class PrivateOutputCleanupTests(unittest.TestCase):
    def check_fault(self, fault):
        from scripts import ci_consumer_native as driver

        class Log(io.StringIO):
            def fileno(self):
                return 77

            def flush(self):
                if fault == "flush":
                    raise OSError("controlled-private-flush")
                return super().flush()

        copies, redirects, closes = [], [], []

        def duplicate(descriptor):
            if fault == "second_dup" and descriptor == 2:
                raise OSError("controlled-second-dup")
            copies.append(descriptor + 100)
            return descriptor + 100

        def redirect(original, descriptor):
            redirects.append((original, descriptor))
            if fault == "restore_stderr" and original == 102:
                raise OSError("controlled-restore-stderr")

        def close(descriptor):
            closes.append(descriptor)
            if fault == "close_stdout" and descriptor == 101:
                raise OSError("controlled-close-stdout")

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(driver, "atomic_write"),
            patch.object(Path, "open", return_value=Log()),
            patch.object(driver.os, "dup", side_effect=duplicate),
            patch.object(driver.os, "dup2", side_effect=redirect),
            patch.object(driver.os, "close", side_effect=close),
            self.assertRaises(OSError),
        ):
            with driver.private_output(Path(temporary), "controlled"):
                pass
        self.assertEqual(sorted(closes), sorted(copies))
        for descriptor in copies:
            self.assertIn((descriptor, descriptor - 100), redirects)

    def test_flush_failure_still_restores_and_closes_both_descriptors(self):
        self.check_fault("flush")

    def test_second_dup_failure_closes_the_first_saved_descriptor(self):
        self.check_fault("second_dup")

    def test_restore_failure_still_attempts_other_descriptor_and_closes_both(self):
        self.check_fault("restore_stderr")

    def test_close_failure_still_restores_and_closes_other_descriptor(self):
        self.check_fault("close_stdout")


def failure_case(event, stage):
    def test(self):
        self.failure = event
        result = self.result()
        self.assertEqual((result["status"], result["stage"]), ("fail", stage))
        self.assertNotIn("private", canonical(result).decode())
        if self.view is not None:
            self.assertFalse(self.view.exists())
        if event != "view_exit":
            self.assertNotIn("retention", result)

    return test


for _event, _stage in (
    ("source", "preflight"),
    ("proposal", "proposal"),
    ("freeze", "freeze"),
    ("frozen", "freeze"),
    ("seal", "seal"),
    ("materialize", "materialize"),
    ("sql_ready", "consumer_sql"),
    ("import", "import"),
    ("cluster_ready", "consumer_cluster"),
    ("cluster_validate", "consumer_cluster"),
    ("kube_storage", "consumer_cluster"),
    ("fresh", "window"),
    ("window", "window"),
    ("actual", "actual"),
    ("late", "controlled"),
    ("M11", "M11"),
    ("M12", "M12"),
    ("receipt", "receipt"),
    ("retain", "retention"),
    ("view_exit", "retention"),
):
    setattr(OrchestrationTests, "test_failure_at_" + _event, failure_case(_event, _stage))


if __name__ == "__main__":
    unittest.main()
