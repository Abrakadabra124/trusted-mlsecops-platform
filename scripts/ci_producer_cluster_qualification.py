"""Real recovery/files/output capture with simulated Docker; no infrastructure."""

import copy
import io
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, bounded_read, canonical, read_json, write_json
from scripts import ci_consumer_recovery as recovery

SOURCE = {
    "source_revision": "a" * 40,
    "source_fingerprint": "b" * 64,
    "image_id": "sha256:" + "c" * 64,
}
OWNER = dict(
    repository="Abrakadabra124/trusted-mlsecops-platform",
    run_id=123,
    run_attempt=1,
    producer_job="producer",
)
HANDLE, VOLUME = "d" * 64, "owned-kind-volume"
PRIVATE = "private-owner-and-pin-must-never-escape"


class DockerFixture:
    def __init__(self, root):
        self.root = root
        self.producer = root / ".runtime"
        self.witness = self.producer / "producer-cluster-witness"
        self.nodes, self.volumes, self.calls = {}, {}, []
        self.ignore_removal = False
        write_json(
            self.producer / "workspace.json",
            dict(schema_version=1, product="trusted-mlsecops", workspace_id="e" * 32),
        )

    def create_node(self):
        self.nodes[HANDLE] = dict(
            Id=HANDLE,
            Name="/" + recovery.cluster.NODE,
            Config={
                "Labels": {
                    recovery.KIND_LABEL: recovery.cluster.NAME,
                    "io.x-k8s.kind.role": "control-plane",
                }
            },
            Mounts=[dict(Type="volume", Name=VOLUME)],
        )
        self.volumes[VOLUME] = dict(
            Name=VOLUME, CreatedAt="2026-11-20T00:00:00Z", Driver="local", Labels={}, Options={}
        )

    def bootstrap(self, producer):
        assert producer == self.producer
        record = self.record()
        assert record["cluster"]["observed"] is False
        assert record["cluster"]["containers"] == {}
        assert record["sql"] is None
        self.create_node()
        (producer / "kubeconfig").write_bytes(b"private-fixture-kubeconfig")

    def record(self):
        return read_json(self.witness / recovery.RECORD)

    def inspect(self, kind, name):
        return copy.deepcopy((self.nodes if kind == "container" else self.volumes)[name])

    def command(self, args):
        assert args == ["kind", "get", "clusters"], args
        return recovery.cluster.NAME if self.nodes else ""

    def docker(self, args):
        self.calls.append(args)
        output = []
        if args[:4] == ["ps", "--all", "--quiet", "--no-trunc"]:
            rows = self.nodes.copy()
            for flag, value in zip(args[4::2], args[5::2], strict=True):
                assert flag == "--filter"
                category, _, expected = value.partition("=")
                if category == "label":
                    key, _, label = expected.partition("=")
                    rows = {
                        k: v for k, v in rows.items() if v["Config"]["Labels"].get(key) == label
                    }
                elif category == "name":
                    rows = {k: v for k, v in rows.items() if v["Name"] == expected[1:-1]}
                elif category == "volume":
                    rows = {k: v for k, v in rows.items() if expected in recovery.node_volumes(v)}
                else:
                    raise AssertionError(value)
            output = list(rows)
        elif args == ["volume", "ls", "--quiet"]:
            output = list(self.volumes)
        elif args[:2] == ["rm", "--force"]:
            assert len(args) == 3 and args[2] == HANDLE
            if not self.ignore_removal:
                del self.nodes[args[2]]
        elif args[:2] == ["volume", "rm"]:
            assert len(args) == 3 and args[2] == VOLUME
            if not self.ignore_removal:
                del self.volumes[args[2]]
        else:
            raise AssertionError(args)
        return SimpleNamespace(stdout="\n".join(output).encode())

    def mutations(self):
        return [args for args in self.calls if args[0] == "rm" or args[:2] == ["volume", "rm"]]


class ProducerClusterTests(unittest.TestCase):
    def setUp(self):
        from scripts import ci_producer_cluster

        self.helper = ci_producer_cluster

    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            fixture = DockerFixture(Path(temporary).resolve())
            environment = {
                "GITHUB_REPOSITORY": OWNER["repository"],
                "GITHUB_RUN_ID": str(OWNER["run_id"]),
                "GITHUB_RUN_ATTEMPT": str(OWNER["run_attempt"]),
                "GITHUB_JOB": OWNER["producer_job"],
            }
            stack.enter_context(patch.dict(os.environ, environment))
            fixture.hosted = stack.enter_context(patch.object(self.helper.driver, "hosted"))
            fixture.source = stack.enter_context(
                patch.object(self.helper.driver, "source", return_value=SOURCE)
            )
            stack.enter_context(patch.object(recovery.sql, "docker", side_effect=fixture.docker))
            stack.enter_context(patch.object(recovery.sql, "inspect", side_effect=fixture.inspect))
            stack.enter_context(
                patch.object(recovery.cluster, "command", side_effect=fixture.command)
            )
            fixture.bootstrap_mock = stack.enter_context(
                patch.object(recovery.cluster, "bootstrap", side_effect=fixture.bootstrap)
            )
            fixture.storage = stack.enter_context(
                patch.object(self.helper.kube_storage, "bootstrap")
            )
            fixture.controllers = stack.enter_context(
                patch.object(self.helper.controller_bootstrap, "bootstrap")
            )
            for module, function in (
                (recovery.sql, "bootstrap"),
                (recovery.sql, "specification"),
                (recovery.storage_pki, "initialize"),
                (recovery, "sql_inventory"),
                (recovery.cluster, "kubectl"),
                (recovery.cluster, "validate_cluster"),
            ):
                stub = stack.enter_context(
                    patch.object(
                        module, function, side_effect=AssertionError("forbidden runtime action")
                    )
                )
                stack.callback(stub.assert_not_called)
            yield fixture

    def result(self, fixture, action, status):
        result = self.helper.execute(fixture.root, action)
        self.assertEqual(
            result,
            dict(
                stage=action,
                status=status,
                cleanup_counts=dict(
                    required=1, verified=int(action == "cleanup" and status == "pass")
                ),
            ),
        )
        return result

    def test_missing_witness_or_record_never_claims_clean(self):
        for partial in (False, True):
            with self.subTest(partial=partial), self.fixture() as fixture:
                if partial:
                    fixture.witness.mkdir()
                    (fixture.witness / "workspace.json").write_bytes(
                        bounded_read(fixture.producer / "workspace.json")
                    )
                self.result(fixture, "cleanup", "fail")
                self.assertEqual(fixture.calls, [])

    def test_partial_cluster_bootstrap_is_observed_and_cleaned_by_exact_id(self):
        for failure in (Rejected(PRIVATE), KeyboardInterrupt(PRIVATE)):
            with self.subTest(failure=type(failure)), self.fixture() as fixture:

                def partial(producer):
                    fixture.bootstrap(producer)
                    raise failure

                fixture.bootstrap_mock.side_effect = partial
                self.result(fixture, "start", "fail")
                self.assertTrue(fixture.record()["cluster"]["observed"])
                self.assertFalse((fixture.producer / "cluster.json").exists())
                fixture.storage.assert_not_called()
                fixture.controllers.assert_not_called()
                self.result(fixture, "cleanup", "pass")
                self.assertEqual(
                    fixture.mutations(), [["rm", "--force", HANDLE], ["volume", "rm", VOLUME]]
                )
                self.assertFalse(fixture.nodes or fixture.volumes)

    def test_bootstrap_fails_before_creation_and_absence_is_verified(self):
        with self.fixture() as fixture:
            fixture.bootstrap_mock.side_effect = Rejected(PRIVATE)
            self.result(fixture, "start", "fail")
            self.assertTrue(fixture.record()["cluster"]["observed"])
            self.result(fixture, "cleanup", "pass")
            self.assertFalse(fixture.mutations())

    def test_observation_failure_refuses_blind_cleanup(self):
        with self.fixture() as fixture:
            with patch.object(recovery.Recovery, "observe_cluster", side_effect=Rejected(PRIVATE)):
                self.result(fixture, "start", "fail")
            self.assertFalse(fixture.record()["cluster"]["observed"])
            self.result(fixture, "cleanup", "fail")
            self.assertTrue(fixture.nodes and fixture.volumes)
            self.assertFalse(fixture.mutations())
            fixture.storage.assert_not_called()

    def test_foreign_ids_labels_and_volumes_are_never_deleted(self):
        for change in ("id", "labels", "volume", "volume-user"):
            with self.subTest(change=change), self.fixture() as fixture:
                self.result(fixture, "start", "pass")
                if change == "id":
                    fixture.nodes["f" * 64] = fixture.nodes.pop(HANDLE)
                    fixture.nodes["f" * 64]["Id"] = "f" * 64
                elif change == "labels":
                    fixture.nodes[HANDLE]["Config"]["Labels"]["foreign"] = "owner"
                elif change == "volume":
                    fixture.volumes[VOLUME]["CreatedAt"] = "2026-11-21T00:00:00Z"
                else:
                    fixture.nodes["f" * 64] = dict(
                        Id="f" * 64,
                        Name="/foreign",
                        Config={"Labels": {}},
                        Mounts=[dict(Type="volume", Name=VOLUME)],
                    )
                self.result(fixture, "cleanup", "fail")
                self.assertFalse(fixture.mutations())

    def test_successful_delete_command_without_absence_is_not_clean(self):
        with self.fixture() as fixture:
            self.result(fixture, "start", "pass")
            fixture.ignore_removal = True
            self.result(fixture, "cleanup", "fail")
            self.assertTrue(fixture.nodes)

    def test_run_owner_mismatch_refuses_before_cleanup(self):
        for key, value in (
            ("run_id", 456),
            ("run_attempt", 2),
            ("producer_job", "other"),
            ("repository", "foreign/repo"),
            ("run_attempt", True),
        ):
            with self.subTest(key=key, value=value), self.fixture() as fixture:
                self.result(fixture, "start", "pass")
                record = fixture.record()
                record["run_owner"][key] = value
                write_json(fixture.witness / recovery.RECORD, record)
                fixture.calls.clear()
                self.result(fixture, "cleanup", "fail")
                self.assertEqual(fixture.calls, [])

    def test_workspace_identity_and_exact_original_bytes_required(self):
        for target, content in (("witness", b" "), ("producer", b" "), ("record", None)):
            with self.subTest(target=target), self.fixture() as fixture:
                self.result(fixture, "start", "pass")
                if target == "record":
                    record = fixture.record()
                    record["workspace_id"] = "f" * 32
                    write_json(fixture.witness / recovery.RECORD, record)
                else:
                    path = getattr(fixture, target) / "workspace.json"
                    path.write_bytes(bounded_read(path) + content)
                fixture.calls.clear()
                self.result(fixture, "cleanup", "fail")
                self.assertEqual(fixture.calls, [])

    def test_sql_state_in_cluster_witness_is_refused(self):
        with self.fixture() as fixture:
            self.result(fixture, "start", "pass")
            record = fixture.record()
            record["sql"] = {"foreign": "state"}
            write_json(fixture.witness / recovery.RECORD, record)
            fixture.calls.clear()
            self.result(fixture, "cleanup", "fail")
            self.assertEqual(fixture.calls, [])

    def test_start_preconditions_fail_before_bootstrap(self):
        for failure in ("hosted", "dirty", "image", "workspace", "existing-cluster", "arm"):
            with self.subTest(failure=failure), self.fixture() as fixture, ExitStack() as stack:
                if failure == "hosted":
                    fixture.hosted.side_effect = Rejected(PRIVATE)
                elif failure in ("dirty", "image"):
                    fixture.source.side_effect = Rejected(PRIVATE)
                elif failure == "workspace":
                    (fixture.producer / "workspace.json").unlink()
                elif failure == "existing-cluster":
                    fixture.create_node()
                else:
                    stack.enter_context(
                        patch.object(
                            recovery.Recovery, "arm_cluster", side_effect=Rejected(PRIVATE)
                        )
                    )
                self.result(fixture, "start", "fail")
                fixture.bootstrap_mock.assert_not_called()
                self.assertFalse(fixture.mutations())

    def test_start_exclusively_creates_witness_and_preserves_original(self):
        with self.fixture() as fixture:
            original = bounded_read(fixture.producer / "workspace.json")
            self.result(fixture, "start", "pass")
            fixture.source.assert_called_once_with(fixture.root, self.helper.driver.IMAGE)
            fixture.storage.assert_called_once_with(fixture.producer)
            fixture.controllers.assert_called_once_with(
                fixture.root, fixture.producer, self.helper.driver.IMAGE
            )
            self.assertEqual(bounded_read(fixture.witness / "workspace.json"), original)
            self.assertEqual(bounded_read(fixture.producer / "workspace.json"), original)
            self.assertEqual(fixture.record()["source"], SOURCE)
            self.assertEqual(fixture.record()["run_owner"], OWNER)
            self.assertIsNone(fixture.record()["sql"])
            self.assertEqual(
                {
                    str(p.relative_to(fixture.witness)).replace("\\", "/")
                    for p in fixture.witness.rglob("*")
                    if p.is_file()
                },
                {"workspace.json", recovery.RECORD, recovery.KUBE},
            )
            record = bounded_read(fixture.witness / recovery.RECORD)
            self.result(fixture, "start", "fail")
            self.assertEqual(bounded_read(fixture.witness / recovery.RECORD), record)
            fixture.bootstrap_mock.assert_called_once()

    def test_storage_and_controller_failures_leave_observed_cluster_cleanable(self):
        for stage in ("storage", "controllers"):
            with self.subTest(stage=stage), self.fixture() as fixture:

                def failed(*args):
                    self.assertTrue(fixture.record()["cluster"]["observed"])
                    raise Rejected(PRIVATE)

                getattr(fixture, stage).side_effect = failed
                self.result(fixture, "start", "fail")
                self.result(fixture, "cleanup", "pass")

    def test_cleanup_needs_no_image_source_or_kubernetes_api_and_is_repeatable(self):
        with self.fixture() as fixture:
            self.result(fixture, "start", "pass")
            fixture.source.side_effect = Rejected("image and source unavailable")
            self.result(fixture, "cleanup", "pass")
            self.result(fixture, "cleanup", "pass")
            fixture.source.assert_called_once()
            self.assertEqual(fixture.record()["cleanup"], {"sql": True, "cluster": True})

    def test_cleanup_still_requires_hosted_runner(self):
        with self.fixture() as fixture:
            self.result(fixture, "start", "pass")
            fixture.hosted.side_effect = Rejected(PRIVATE)
            fixture.calls.clear()
            self.result(fixture, "cleanup", "fail")
            self.assertFalse(fixture.calls)

    def test_cleanup_requires_exact_true_results(self):
        for result in (
            {"sql": True, "cluster": False},
            {"sql": True},
            {"sql": 1, "cluster": 1},
            {"sql": True, "cluster": True, "extra": True},
        ):
            with self.subTest(result=result), self.fixture() as fixture:
                self.result(fixture, "start", "pass")
                with patch.object(recovery.Recovery, "cleanup", return_value=result):
                    self.result(fixture, "cleanup", "fail")

    def test_python_child_fd_and_exception_output_stays_private_for_both_actions(self):
        def noisy():
            print(PRIVATE + "-stdout")
            print(PRIVATE + "-stderr", file=sys.stderr)
            os.write(1, (PRIVATE + "-fd1\n").encode())
            os.write(2, (PRIVATE + "-fd2\n").encode())
            subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    "import os; os.write(1, b'"
                    + PRIVATE
                    + "-child1\\n'); os.write(2, b'"
                    + PRIVATE
                    + "-child2\\n')",
                ],
                check=True,
            )

        for action in ("start", "cleanup"):
            with self.subTest(action=action), self.fixture() as fixture, ExitStack() as stack:
                if action == "start":

                    def fail(producer):
                        fixture.bootstrap(producer)
                        noisy()
                        raise Rejected(PRIVATE)

                    fixture.bootstrap_mock.side_effect = fail
                else:
                    self.result(fixture, "start", "pass")
                    original = recovery.Recovery.cleanup

                    def fail(witness):
                        noisy()
                        original(witness)
                        raise Rejected(PRIVATE)

                    stack.enter_context(patch.object(recovery.Recovery, "cleanup", fail))
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.result(fixture, action, "fail")
                self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
                log = bounded_read(
                    fixture.producer
                    / ("evidence/ci-consumer-native-producer-cluster-" + action + ".log")
                ).decode()
                for suffix in ("stdout", "stderr", "fd1", "fd2", "child1", "child2"):
                    self.assertIn(PRIVATE + "-" + suffix, log)
                self.assertIn("Traceback", log)

    def test_output_capture_failure_never_claims_success(self):
        with self.fixture() as fixture:
            with patch.object(self.helper.driver, "private_output", side_effect=OSError(PRIVATE)):
                self.result(fixture, "start", "fail")
                self.result(fixture, "cleanup", "fail")
            fixture.bootstrap_mock.assert_not_called()

    def test_output_capture_exit_failure_discards_success(self):
        original = self.helper.driver.private_output

        @contextmanager
        def fail_on_exit(producer, action):
            with original(producer, action):
                yield
            raise OSError(PRIVATE)

        for action in ("start", "cleanup"):
            with self.subTest(action=action), self.fixture() as fixture:
                if action == "cleanup":
                    self.result(fixture, "start", "pass")
                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    patch.object(self.helper.driver, "private_output", fail_on_exit),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    self.result(fixture, action, "fail")
                self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
                if action == "cleanup":
                    self.assertFalse(fixture.nodes or fixture.volumes)

    def test_cli_emits_closed_projection_and_exit_status(self):
        with self.fixture() as fixture:
            execute = self.helper.execute
            for action, status, code in (
                ("start", "pass", 0),
                ("cleanup", "pass", 0),
                ("start", "fail", 1),
            ):
                output = io.StringIO()
                with patch.object(
                    self.helper,
                    "execute",
                    side_effect=lambda root, action: execute(fixture.root, action),
                ):
                    with redirect_stdout(output):
                        self.assertEqual(self.helper.main([action]), code)
                expected = dict(
                    stage=action,
                    status=status,
                    cleanup_counts=dict(required=1, verified=int(action == "cleanup")),
                )
                self.assertEqual(output.getvalue(), canonical(expected).decode() + "\n")

    def test_invalid_arguments_and_module_entrypoint_do_not_echo_input(self):
        for arguments in ([], [PRIVATE], ["start", PRIVATE]):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(self.helper.main(arguments), 1)
            self.assertEqual(
                output.getvalue(),
                canonical(
                    dict(
                        stage="arguments",
                        status="fail",
                        cleanup_counts=dict(required=1, verified=0),
                    )
                ).decode()
                + "\n",
            )
        with (
            patch.object(sys, "argv", [self.helper.__file__, PRIVATE]),
            redirect_stdout(io.StringIO()) as output,
        ):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(self.helper.__file__, run_name="__main__")
        self.assertEqual(result.exception.code, 1)
        self.assertNotIn(PRIVATE, output.getvalue())


if __name__ == "__main__":
    unittest.main()
