"""Real witnesses/Recovery with strict Docker boundaries; no infrastructure."""

import copy
import importlib
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import cluster, kube_storage, storage_bootstrap, storage_pki
from mlsecops.contracts import Rejected, bounded_read, digest, read_json, write_json
from scripts import ci_consumer_recovery as recovery
from scripts import serving_campaign as campaign
from scripts.ci_consumer_native_qualification import DockerBoundary, workspace
from scripts.ci_producer_cluster_qualification import OWNER, SOURCE

PHASES = ("M13", "M14", "M15")
SQL_ID = "1" * 64
IDS = {phase: str(i + 2) * 64 for i, phase in enumerate(PHASES)}


class ServingRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("scripts.ci_serving_recovery"), "lifecycle missing"
        )
        self.module = importlib.import_module("scripts.ci_serving_recovery")
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.producer, self.state = self.root / "producer", self.root / "consumer"
        workspace(self.producer, "a" * 32)
        workspace(self.state, "b" * 32)
        self.docker = DockerBoundary()
        self.spec = dict(
            workspace_id="b" * 32,
            config_digest="c" * 64,
            name="consumer",
            volume="consumer-data",
            network="consumer-net",
            port=15440,
        )
        self.enterContext(patch.object(storage_bootstrap, "docker", self.docker.docker))
        self.enterContext(
            patch.object(storage_bootstrap, "specification", return_value=(self.spec, {}))
        )
        self.enterContext(patch.object(storage_pki, "initialize"))
        self.enterContext(patch.object(storage_pki, "validate", return_value={}))
        self.enterContext(
            patch.object(
                storage_bootstrap,
                "validate",
                side_effect=lambda state: read_json(state / "storage.json"),
            )
        )
        self.sql_boot = self.enterContext(
            patch.object(storage_bootstrap, "bootstrap", side_effect=self.sql)
        )
        self.cluster_boot = self.enterContext(
            patch.object(cluster, "bootstrap", side_effect=self.node)
        )
        self.kube_boot = self.enterContext(
            patch.object(kube_storage, "bootstrap", side_effect=self.kube)
        )
        self.enterContext(patch.object(cluster, "command", side_effect=self.command))
        self.enterContext(patch.object(campaign, "command", side_effect=self.command))
        self.enterContext(
            patch.object(
                cluster,
                "validate_cluster",
                side_effect=lambda state: read_json(state / "cluster.json"),
            )
        )
        self.enterContext(
            patch.object(
                kube_storage,
                "validate",
                side_effect=lambda state: read_json(state / "kubernetes-storage/marker.json"),
            )
        )
        self.enterContext(patch.object(campaign, "owned_node", side_effect=self.owned_node))
        for target in ("subprocess.run", "subprocess.Popen", "socket.socket"):
            self.enterContext(patch(target, side_effect=AssertionError("no infrastructure")))
        self.life = self.module.Lifecycle.begin(
            self.producer, self.state, run_owner=OWNER, source=SOURCE
        )

    def record(self, name):
        return read_json(self.producer / self.module.DIRECTORY / name / recovery.RECORD)

    def load(self, **changes):
        return self.module.Lifecycle.load(
            self.producer, **(dict(run_owner=OWNER, source=SOURCE) | changes)
        )

    def command(self, args):
        if args == ["kind", "get", "clusters"]:
            return (
                cluster.NAME
                if any(
                    row["Config"]["Labels"].get(recovery.KIND_LABEL) == cluster.NAME
                    for row in self.docker.rows.values()
                )
                else ""
            )
        if args == ["docker", "ps", "-aq", "--no-trunc"]:
            return "\n".join(self.docker.rows)
        if args == ["docker", "volume", "ls", "--format", "{{.Name}}"]:
            return "\n".join(self.docker.volumes)
        raise AssertionError(args)

    def sql(self, state, *, port):
        self.assertEqual(state, self.state)
        self.assertEqual(port, 15440)
        self.assertFalse(self.record("SQL")["sql"]["observed"])
        self.docker.add(
            SQL_ID,
            self.spec["name"],
            {storage_bootstrap.WORKSPACE_LABEL: "b" * 32, storage_bootstrap.CONFIG_LABEL: "c" * 64},
        )
        write_json(state / "storage.json", self.spec | dict(container_id=SQL_ID))

    def node(self, state):
        self.assertEqual(state, self.state)
        self.assertTrue(self.docker.rows[SQL_ID]["State"]["Running"])
        armed = [
            g
            for g in PHASES
            if (entry := self.record(g)["cluster"]) is not None and entry["observed"] is False
        ]
        self.assertEqual(len(armed), 1)
        phase = armed[0]
        self.docker.add(
            IDS[phase],
            cluster.NODE,
            {recovery.KIND_LABEL: cluster.NAME, "io.x-k8s.kind.role": "control-plane"},
        )
        name = phase + "-volume"
        self.docker.volumes.add(name)
        self.docker.volume_info[name] = dict(
            Name=name, Driver="local", CreatedAt=phase, Labels=None, Options=None
        )
        self.docker.rows[IDS[phase]]["Mounts"] = [dict(Type="volume", Name=name)]
        write_json(state / "cluster.json", dict(workspace_id="b" * 32, namespace_uid=phase))
        (state / "kubeconfig").write_bytes(b"private-fixture-kubeconfig")

    def kube(self, state):
        phase = read_json(state / "cluster.json")["namespace_uid"]
        write_json(state / "kubernetes-storage/marker.json", dict(volume_uid=phase))

    def owned_node(self, state):
        phase = read_json(state / "cluster.json")["namespace_uid"]
        return dict(container=IDS[phase], namespace=phase, volumes=[phase + "-volume"])

    def active(self):
        pin = self.life.bootstrap_sql(self.state)
        self.life.start(self.state, pin)
        return pin

    def test_wrong_run_source_and_producer_workspace_refuse_without_actions(self):
        for changes in (
            dict(run_owner=OWNER | {"run_attempt": 2}),
            dict(source=SOURCE | {"image_id": "sha256:" + "f" * 64}),
        ):
            with self.assertRaises(Rejected):
                self.load(**changes)
        path = self.producer / "workspace.json"
        path.write_bytes(bounded_read(path) + b" ")
        with self.assertRaises(Rejected):
            self.life.cleanup()
        self.assertFalse(self.docker.mutations)

    def test_missing_record_and_foreign_child_witness_are_not_absence(self):
        self.active()
        directory = self.producer / self.module.DIRECTORY
        (directory / "M15" / recovery.RECORD).unlink()
        record = self.record("M13")
        record["run_owner"]["run_id"] += 1
        write_json(directory / "M13" / recovery.RECORD, record)
        result = self.load().cleanup()
        self.assertFalse(result["M15"] or result["M13"])
        self.assertTrue(result["SQL"])
        self.assertIn(IDS["M13"], self.docker.rows)

    def test_foreign_ids_labels_and_shared_volume_are_never_deleted(self):
        self.active()
        original = copy.deepcopy(self.docker.rows)
        for kind in ("id", "label", "shared"):
            self.docker.rows = copy.deepcopy(original)
            if kind == "id":
                self.docker.rows["f" * 64] = self.docker.rows.pop(IDS["M13"])
                self.docker.rows["f" * 64]["Id"] = "f" * 64
            elif kind == "label":
                self.docker.rows[IDS["M13"]]["Config"]["Labels"]["foreign"] = "owner"
            else:
                self.docker.add("f" * 64, "foreign", {})
                self.docker.rows["f" * 64]["Mounts"] = [dict(Type="volume", Name="M13-volume")]
            result = self.load().cleanup()
            self.assertFalse(result["M13"])
            self.assertFalse(any(action[0] == "rm" for action in self.docker.mutations))

    def test_out_of_order_duplicate_and_unknown_phases_fail_closed(self):
        with self.assertRaises(Rejected):
            self.life.start(self.state, "f" * 64)
        pin = self.active()
        for phase in ("M14", "M15", "../M13", "M11-M12", None):
            with self.assertRaises(Rejected):
                self.life.transition(self.state, phase, pin)
        with self.assertRaises(Rejected):
            self.life.start(self.state, pin)
        with self.assertRaises(Rejected):
            self.life.bootstrap_sql(self.state)
        self.assertFalse(self.docker.mutations)

    def test_partial_sql_and_cluster_bootstrap_observed_in_finally(self):
        def failed_sql(*args, **kwargs):
            self.sql(*args, **kwargs)
            raise Rejected("partial")

        self.sql_boot.side_effect = failed_sql
        with self.assertRaises(Rejected):
            self.life.bootstrap_sql(self.state)
        self.assertTrue(self.record("SQL")["sql"]["observed"])
        self.assertTrue(all(self.load().cleanup().values()))

    def test_partial_cluster_bootstrap_can_cleanup_after_view_deletion(self):
        pin = self.life.bootstrap_sql(self.state)

        def failed(state):
            self.node(state)
            (state / "cluster.json").unlink()
            raise Rejected("partial-kind")

        self.cluster_boot.side_effect = failed
        with self.assertRaises(Rejected):
            self.life.start(self.state, pin)
        self.assertTrue(self.record("M13")["cluster"]["observed"])
        shutil.rmtree(self.state)
        with patch.object(cluster, "validate_cluster", side_effect=AssertionError("no API")):
            self.assertTrue(all(self.load().cleanup().values()))
        self.assertFalse(self.docker.rows[SQL_ID]["State"]["Running"])
        self.assertEqual(self.docker.volumes, set())

    def test_observation_failure_prevents_adoption_or_retry(self):
        pin = self.life.bootstrap_sql(self.state)
        with patch.object(
            recovery.Recovery, "observe_cluster", side_effect=Rejected("observation")
        ):
            with self.assertRaises(Rejected):
                self.life.start(self.state, pin)
        with self.assertRaises(Rejected):
            self.load().start(self.state, pin)
        result = self.load().cleanup()
        self.assertFalse(result["M13"])
        self.assertTrue(result["SQL"])
        self.assertIn(IDS["M13"], self.docker.rows)

    def test_all_phases_preserve_sql_pin_and_archive_before_bootstrap(self):
        pin = self.active()
        packets = []
        for phase in ("M13", "M14"):
            packets.append(self.life.transition(self.state, phase, pin))
            self.assertTrue(self.docker.rows[SQL_ID]["State"]["Running"])
            self.assertEqual(digest(bounded_read(self.state / "storage.json")), pin)
            retired = self.state / "ci-serving-retired" / phase
            self.assertEqual(read_json(retired / "cluster.json")["namespace_uid"], phase)
        self.assertEqual(len(campaign.chain(packets, pin)), 3)
        directory = self.producer / self.module.DIRECTORY
        for name in ("SQL", *PHASES):
            owner = self.producer if name == "SQL" else self.state
            self.assertEqual(
                bounded_read(directory / name / "workspace.json"),
                bounded_read(owner / "workspace.json"),
            )
            self.assertEqual(
                {
                    str(p.relative_to(directory / name)).replace("\\", "/")
                    for p in (directory / name).rglob("*")
                    if p.is_file()
                },
                {"workspace.json", recovery.RECORD},
            )
        self.assertTrue(all(self.load().cleanup().values()))
        self.assertTrue(all(self.load().cleanup().values()))
        with self.assertRaises(Rejected):
            self.load().transition(self.state, "M14", pin)

    def test_reverse_cleanup_attempts_sql_after_cluster_failure(self):
        self.active()
        self.docker.fail_remove = True
        order = []
        original = self.life._witness

        def observed(name):
            order.append(name)
            return original(name)

        with patch.object(self.life, "_witness", observed):
            result = self.life.cleanup()
        self.assertEqual(order, ["M15", "M14", "M13", "SQL"])
        self.assertFalse(result["M13"])
        self.assertTrue(result["SQL"])

    def test_transition_failure_blocks_retry_and_preserves_sql_for_cleanup(self):
        pin = self.active()
        self.kube_boot.side_effect = Rejected("storage bootstrap failed")
        with self.assertRaises(Rejected):
            self.life.transition(self.state, "M13", pin)
        self.assertTrue(self.record("M14")["cluster"]["observed"])
        self.assertTrue(self.docker.rows[SQL_ID]["State"]["Running"])
        with self.assertRaises(Rejected):
            self.load().transition(self.state, "M13", pin)
        self.assertTrue(all(self.load().cleanup().values()))

    def test_marker_archive_failure_blocks_next_phase_without_adoption(self):
        pin = self.active()
        with patch.object(Path, "rename", side_effect=OSError("archive")):
            with self.assertRaises(OSError):
                self.life.transition(self.state, "M13", pin)
        self.assertIsNone(self.record("M14")["cluster"])
        self.assertTrue(self.docker.rows[SQL_ID]["State"]["Running"])
        with self.assertRaises(Rejected):
            self.load().transition(self.state, "M13", pin)
        self.assertTrue(all(self.load().cleanup().values()))

    def test_changed_sql_pin_workspace_or_live_identity_blocks_transition(self):
        pin = self.active()
        with self.assertRaises(Rejected):
            self.life.transition(self.state, "M13", "f" * 64)
        path = self.state / "workspace.json"
        raw = bounded_read(path)
        path.write_bytes(raw + b" ")
        with self.assertRaises(Rejected):
            self.life.transition(self.state, "M13", pin)
        path.write_bytes(raw)
        self.docker.rows[SQL_ID]["Config"]["Labels"]["foreign"] = "owner"
        with self.assertRaises(Rejected):
            self.life.transition(self.state, "M13", pin)
        self.assertFalse(self.docker.mutations)

    def test_exclusive_begin_and_state_inside_witness_are_refused(self):
        with self.assertRaises(FileExistsError):
            self.module.Lifecycle.begin(self.producer, self.state, run_owner=OWNER, source=SOURCE)
        with self.assertRaises(Rejected):
            self.module.Lifecycle.begin(self.state, self.state, run_owner=OWNER, source=SOURCE)

    def test_noop_delete_never_advances_phase(self):
        pin = self.active()
        with patch.object(recovery.Recovery, "delete_cluster", return_value=None):
            with self.assertRaises(Rejected):
                self.life.transition(self.state, "M13", pin)
        self.assertIsNone(self.record("M14")["cluster"])
        self.assertTrue(self.docker.rows[SQL_ID]["State"]["Running"])

    def test_missing_phase_directory_does_not_skip_independent_sql_cleanup(self):
        self.active()
        shutil.rmtree(self.producer / self.module.DIRECTORY / "M15")
        result = self.load().cleanup()
        self.assertFalse(result["M15"])
        self.assertTrue(result["M13"] and result["SQL"])

    def test_incomplete_or_foreign_future_witness_blocks_new_resources(self):
        pin = self.life.bootstrap_sql(self.state)
        path = self.producer / self.module.DIRECTORY / "M15" / recovery.RECORD
        raw = bounded_read(path)
        for fault in ("missing", "foreign"):
            with self.subTest(fault=fault):
                if fault == "missing":
                    path.unlink()
                else:
                    record = read_json(path)
                    record["source"]["source_revision"] = "f" * 40
                    write_json(path, record)
                with self.assertRaises((Rejected, FileNotFoundError)):
                    self.load().start(self.state, pin)
                self.cluster_boot.assert_not_called()
                path.write_bytes(raw)

    def test_sql_failure_is_reported_after_all_cluster_removal(self):
        pin = self.active()
        self.docker.fail_stop = True
        result = self.life.cleanup()
        self.assertTrue(all(result[g] for g in PHASES))
        self.assertFalse(result["SQL"])
        self.assertTrue(self.docker.rows[SQL_ID]["State"]["Running"])
        with self.assertRaises(Rejected):
            self.load().transition(self.state, "M13", pin)
        self.docker.fail_stop = False
        self.assertTrue(all(self.load().cleanup().values()))

    def test_missing_prepared_pki_cannot_create_keys_or_sql(self):
        with patch.object(storage_pki, "validate", side_effect=Rejected("missing PKI")):
            with self.assertRaises(Rejected):
                self.life.bootstrap_sql(self.state)
        self.sql_boot.assert_not_called()
        self.assertIsNone(self.record("SQL")["sql"])

    def test_malformed_external_bindings_and_missing_owner_manifest_refuse(self):
        for changes in (
            dict(run_owner=OWNER | {"run_id": True}),
            dict(run_owner=OWNER | {"repository": "foreign/repo"}),
            dict(run_owner=OWNER | {"producer_job": "../bad"}),
            dict(source=SOURCE | {"image_id": "tag:latest"}),
            dict(source=SOURCE | {"extra": "field"}),
        ):
            with self.assertRaises(Rejected):
                self.load(**changes)
        (self.producer / self.module.DIRECTORY / "lifecycle.json").unlink()
        with self.assertRaises((Rejected, FileNotFoundError)):
            self.load()
        self.assertFalse(self.docker.mutations)

    def test_cleanup_record_write_failure_cannot_return_success(self):
        self.active()
        with patch.object(self.module, "write_json", side_effect=OSError("record")):
            with self.assertRaises(OSError):
                self.life.cleanup()
        self.assertNotIn(IDS["M13"], self.docker.rows)
        self.assertFalse(self.docker.rows[SQL_ID]["State"]["Running"])


if __name__ == "__main__":
    unittest.main()
