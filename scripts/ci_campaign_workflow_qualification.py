"""Offline entry and failure contracts for the manual hosted campaign."""

import io
import os
import re
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, write_json

ROOT = Path(__file__).resolve().parents[1]
FLOW = ROOT / ".github/workflows/candidate-cross-job.yml"
ACTION = ROOT / ".github/actions/campaign-image-receive/action.yml"
JOBS = ("image", "producer", "shared", "serving", "image_cleanup")


def job(text, name):
    match = re.search(rf"^  {name}:\n(.+?)(?=^  \w+:|\Z)", text, re.M | re.S)
    if not match:
        raise AssertionError(f"Missing job {name}")
    return match[1]


def step(text, title):
    return text.split("      - name: " + title + "\n", 1)[1].split("\n      - ", 1)[0]


def definitions(block):
    """Run the workflow's own embedded definitions, omitting its invocation."""
    script = block.split("<<'PY'", 1)[1].split("\n          PY", 1)[0]
    source = textwrap.dedent(script).split("\ntry:\n", 1)[0]
    scope = {}
    exec(compile(source, str(FLOW), "exec"), scope)
    return scope


class CampaignWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flow = FLOW.read_text(encoding="utf-8")

    def test_dispatch_graph_and_closed_permissions(self):
        self.assertIn("          - run-original-campaign\n", self.flow)
        image = job(self.flow, "image")
        condition = next(line for line in image.splitlines() if "if: &campaign" in line)
        for guard in (
            "github.ref_protected",
            "github.event_name == 'workflow_dispatch'",
            "inputs.operation == 'run-original-campaign'",
            "github.repository == 'Abrakadabra124/trusted-mlsecops-platform'",
            "github.repository_id == '1407811916'",
            "!github.event.repository.private",
            "!github.event.repository.fork",
            "github.ref == 'refs/heads/qualify/candidate-cross-job'",
        ):
            self.assertIn(guard, condition)
            self.assertIn(guard, job(self.flow, "image_cleanup"))
        self.assertIn("needs: contracts", image)
        for name in ("producer", "shared", "serving"):
            body = job(self.flow, name)
            self.assertIn("if: *campaign", body)
            self.assertIn("environment: candidate-store-write", body)
            self.assertIn(
                "needs: " + ("image" if name == "producer" else "[image, producer]"), body
            )
            self.assertIn("permissions: *campaign_read", body)
        cleanup = job(self.flow, "image_cleanup")
        self.assertIn("needs: [image, producer, shared, serving]", cleanup)
        self.assertIn("always() && needs.image.result != 'skipped'", cleanup)
        self.assertIn("actions: write", cleanup)
        self.assertEqual(self.flow.count("actions: write"), 1)
        self.assertIn("needs: probe_upload", job(self.flow, "probe_reader"))
        self.assertIn("candidate-store-read", job(self.flow, "probe_reader"))
        self.assertNotIn("run-original-campaign", job(self.flow, "probe_upload"))

    def test_artifact_paths_order_and_action_pins(self):
        action = ACTION.read_text(encoding="utf-8")
        positions = [
            action.index(term)
            for term in (
                "ci_campaign_image precheck",
                "actions/download-artifact@",
                "ci_campaign_image receive",
                "ci_campaign_image local-cleanup",
            )
        ]
        self.assertEqual(positions, sorted(positions))
        reference = (ROOT / ".github/workflows/source-image-transfer.yml").read_text()
        upload = re.compile(
            r"uses: actions/upload-artifact@[^\n]+(?:\n        with:)(?:\n          [^\n]+)+"
        )
        self.assertEqual(upload.findall(self.flow), upload.findall(reference))
        self.assertIn("artifact-ids: " + "$" + "{{ inputs.artifact }}", action)
        self.assertIn("path: .runtime/source-image", action)
        for use in re.findall(r"uses: (\S+)", self.flow + action):
            if not use.startswith("./"):
                self.assertRegex(use, r"^[\w/-]+@[a-f0-9]{40}$")
        for forbidden in (
            "actions/cache",
            "upload-pages",
            "ci_campaign_terminal cleanup",
            "secrets: inherit",
        ):
            self.assertNotIn(forbidden, self.flow + action)

    def test_secret_and_key_routing(self):
        producer = job(self.flow, "producer")
        shared = job(self.flow, "shared")
        self.assertIn("steps: *receiver_steps", job(self.flow, "serving"))
        capture = step(shared, "Capture original receiver evidence")
        publish = step(shared, "Publish verified receiver evidence")
        for body, own, other in ((capture, "READ", "WRITE"), (publish, "WRITE", "READ")):
            self.assertIn(
                "CANDIDATE_STORE_" + own + ": " + "$" + "{{ secrets.CANDIDATE_STORE_" + own + " }}",
                body,
            )
            self.assertNotIn("CANDIDATE_STORE_" + other, body)
        self.assertIn("needs.producer.outputs.producer_public", capture)
        self.assertIn("steps.capture.outputs.receiver_public", publish)
        self.assertNotIn(
            "CANDIDATE_STORE_", step(producer, "Prepare the original producer").split("run:")[0]
        )
        self.assertIn("CANDIDATE_STORE_WRITE:", step(producer, "Publish the original producer"))
        self.assertIn("steps.issue.outputs.producer_public", producer)
        for role in ("shared", "serving"):
            self.assertIn("steps.capture.outputs.receiver_public", job(self.flow, role))
        for name in ("image", "image_cleanup"):
            self.assertNotIn("secrets.", job(self.flow, name))
        for name in JOBS:
            self.assertNotIn("continue-on-error", job(self.flow, name))

    def test_output_parser_requires_exact_success_single_canonical_key(self):
        scope = definitions(step(job(self.flow, "producer"), "Prepare the original producer"))
        key = "A" * 43 + "="
        valid = b"original_publish=pass\nproducer_public=" + key.encode() + b"\n"
        self.assertEqual(scope["public_output"](valid, "original_publish", "producer_public"), key)
        for bad in (
            valid + b"\n",
            b"debug\n" + valid,
            valid.rstrip(),
            valid.replace(b"pass", b"fail"),
            valid.replace(b"producer_public", b"other"),
            valid.replace(b"AA=", b"AB="),
        ):
            with self.subTest(bad=bad), self.assertRaises(Exception):
                scope["public_output"](bad, "original_publish", "producer_public")

    def test_protected_preflight_sees_only_pat_presence_and_cleanup_is_owned(self):
        producer = job(self.flow, "producer")
        preflight = step(producer, "Validate private configuration")
        for key in ("CANDIDATE_STORE_READ", "CANDIDATE_STORE_WRITE"):
            self.assertEqual(preflight.count(key), 1)
            self.assertIn("secrets." + key + " != ''", preflight)
        self.assertIn('("READER_PRESENT", "WRITER_PRESENT", "TRUST_PRESENT")', preflight)
        self.assertLess(
            producer.index("Validate private configuration"), producer.index("id: prepare")
        )
        clean = producer.split("      - &clean_keys\n", 1)[1]
        self.assertIn("always() && steps.keys.outcome == 'success'", clean)
        self.assertIn("stat -c '%d:%i' -- \"$dir\"", clean)
        self.assertIn('rmdir -- "$dir"', clean)
        self.assertIn('! -e "$dir" && ! -L "$dir"', clean)
        self.assertNotIn("rm -r", clean)
        self.assertIn("- *clean_keys", job(self.flow, "shared"))
        self.assertIn("ci_producer_cluster cleanup", producer)
        for name in JOBS:
            self.assertNotIn("ci_origin_backup cleanup", job(self.flow, name))

    def test_stale_and_foreign_descriptors_refuse_before_prepare(self):
        producer = job(self.flow, "producer")
        self.assertLess(
            producer.index("Validate private configuration"), producer.index("id: prepare")
        )
        check = definitions(step(producer, "Validate private configuration"))["descriptors"]
        base = dict(repository_id=1465012664, target_commitish="d" * 40)
        rows = [
            base | dict(release_id=i, name=n)
            for i, n in enumerate(("ci-journal-test", "ci-primary-101-2", "ci-origin-101-2"), 1)
        ]
        check(*rows, 101, 2)
        for index, override in (
            (0, {"name": "ci-other"}),
            (0, {"target_commitish": "main"}),
            (1, {"name": "ci-primary-101-1"}),
            (2, {"name": "ci-origin-102-2"}),
            (2, {"repository_id": 1407811916}),
            (2, {"release_id": 2}),
            (1, {"release_id": True}),
            (0, {"extra": "private"}),
        ):
            changed = [row.copy() for row in rows]
            changed[index].update(override)
            with self.subTest(index=index, override=override), self.assertRaises(Exception):
                check(*changed, 101, 2)

    def test_privilege_proof_requires_exact_attempt_and_each_measured_job(self):
        block = step(
            job(self.flow, "contracts"), "Require a completed operator-pinned store privilege proof"
        )
        verify = definitions(block)["verify"]
        pin = dict(run_id=123, run_attempt=2, head_sha="a" * 40)
        repo = dict(
            id=1407811916,
            full_name="Abrakadabra124/trusted-mlsecops-platform",
            private=False,
            fork=False,
        )
        base = dict(
            head_sha=pin["head_sha"], run_attempt=2, status="completed", conclusion="success"
        )
        run = base | dict(
            id=123,
            repository=repo,
            head_repository=repo,
            event="workflow_dispatch",
            head_branch="qualify/store-access-v1",
            path=".github/workflows/candidate-cross-job.yml",
        )
        jobs = [
            base | dict(run_id=123, id=i, name=name)
            for i, name in enumerate(
                ("contracts", "probe_upload", "probe_reader", "probe_cleanup"), 1
            )
        ]
        root = "repos/" + repo["full_name"] + "/actions/runs/123"
        routes = {
            root: run,
            root + "/attempts/2": run.copy(),
            root + "/attempts/2/jobs?per_page=100": dict(total_count=4, jobs=jobs),
        }

        def api(method, path):
            self.assertEqual(method, "GET")
            return routes[path]

        verify(api, pin)
        with patch.dict(run, head_branch="qualify/store-access-v2"):
            with self.assertRaises(Exception):
                verify(api, pin)
            with patch.dict(routes[root + "/attempts/2"], head_branch="qualify/store-access-v2"):
                verify(api, pin)
        for row, changes in (
            (run, {"run_attempt": 3}),
            (run, {"head_branch": "main"}),
            (run, {"event": "push"}),
            (repo, {"fork": True}),
            (routes[root + "/attempts/2"], {"head_sha": "b" * 40}),
            (jobs[3], {"conclusion": "cancelled"}),
            (jobs[2], {"conclusion": "skipped"}),
            (jobs[2], {"conclusion": "failure"}),
            (jobs[1], {"conclusion": "failure"}),
            (jobs[2], {"name": "probe_upload"}),
            (jobs[2], {"name": "other"}),
            (jobs[0], {"run_attempt": 1}),
            (routes[root + "/attempts/2/jobs?per_page=100"], {"total_count": 5}),
        ):
            with (
                self.subTest(changes=changes),
                patch.dict(row, changes),
                self.assertRaises(Exception),
            ):
                verify(api, pin)

    def test_actual_command_boundary_and_key_removal(self):
        block = step(job(self.flow, "producer"), "Prepare the original producer")
        scope = definitions(block)
        temp = Path(self.enterContext(TemporaryDirectory())).resolve()
        folder = temp / "campaign-keys"
        folder.mkdir(mode=0o700)
        checkout = temp / "repo"
        checkout.mkdir()
        self.enterContext(patch.object(Path, "cwd", return_value=checkout))
        info = folder.stat()
        folder.with_suffix(".owner").write_text(f"{info.st_dev}:{info.st_ino}\n")
        output = temp / "out"
        public = "A" * 43 + "="
        original_lstat = Path.lstat

        def mode(path):
            st = original_lstat(path)
            if os.name == "nt" and (path == folder or path.parent == folder):
                parts = list(st)
                parts[0] = (st.st_mode & ~0o777) | (0o700 if path == folder else 0o600)
                return os.stat_result(parts)
            return st

        self.enterContext(patch.object(Path, "lstat", mode))
        self.enterContext(patch.object(os, "geteuid", return_value=info.st_uid, create=True))
        tests = (
            (
                "scripts.ci_original_bootstrap prepare",
                "original_bootstrap=pass\n",
                "CANDIDATE_TRUST_FILE",
                None,
            ),
            (
                "scripts.ci_original_publish publish",
                "original_publish=pass\nproducer_public=" + public + "\n",
                "CANDIDATE_JOURNAL_KEY_FILE",
                "WRITE",
            ),
            (
                "scripts.ci_primary_job capture",
                "primary_capture=pass\nreceiver_public=" + public + "\n",
                "CANDIDATE_TRUST_FILE",
                "READ",
            ),
            ("scripts.ci_primary_job publish", "primary_publish=pass\n", None, "WRITE"),
        )
        inputs = (
            "CANDIDATE_PUBLIC_TOKEN CANDIDATE_STORE_READ CANDIDATE_STORE_WRITE CANDIDATE_TRANSFER_KEY "
            "CANDIDATE_RECEIVER_PUBLIC CANDIDATE_PRODUCER_PUBLIC SOURCE_IMAGE_RECEIPT "
            "CANDIDATE_PRIMARY_RELEASE CANDIDATE_ORIGIN_RELEASE CANDIDATE_JOURNAL_PUBLIC CANDIDATE_JOURNAL_RELEASE"
        )
        for command, status, keyfile, role in tests:
            env = dict.fromkeys(inputs.split(), "fixture")
            env.update(
                CAMPAIGN_COMMAND=command,
                RUNNER_TEMP=str(temp),
                PATH="fixture-tools",
                PRIVATE_OTHER="unused",
                CANDIDATE_TRUST_PEM="fixture-pem",
                CANDIDATE_JOURNAL_SIGNER_PEM="fixture-pem",
                GITHUB_OUTPUT=str(output),
            )

            def run(args, *, env, stdout, stderr, check):
                self.assertEqual(args[1:], ["-B", "-W", "error", "-m", *command.split()])
                self.assertTrue(check)
                self.assertEqual(stderr, scope["subprocess"].DEVNULL)
                self.assertEqual(stdout, scope["subprocess"].PIPE)
                self.assertEqual(env["GITHUB_OUTPUT"], os.devnull)
                self.assertNotIn("PRIVATE_OTHER", env)
                self.assertFalse(any(k.endswith("_PEM") for k in env))
                self.assertEqual(
                    {k for k in env if k.startswith("CANDIDATE_STORE_")},
                    {"CANDIDATE_STORE_" + role} if role else set(),
                )
                if keyfile:
                    self.assertEqual(Path(env[keyfile]).read_bytes(), b"fixture-pem")
                    self.assertEqual(Path(env[keyfile]).parent, folder)
                return SimpleNamespace(stdout=status.encode())

            with (
                self.subTest(command=command),
                patch.dict(os.environ, env, clear=True),
                patch.object(scope["subprocess"], "run", run),
                redirect_stdout(io.StringIO()) as logged,
            ):
                scope["invoke"]()
                self.assertEqual(list(folder.iterdir()), [])
                self.assertEqual(set(logged.getvalue().splitlines()), set(status.splitlines()))
            if keyfile:
                with (
                    patch.dict(os.environ, env, clear=True),
                    patch.object(scope["subprocess"], "run", side_effect=RuntimeError),
                    self.assertRaises(RuntimeError),
                ):
                    scope["invoke"]()
                self.assertEqual(list(folder.iterdir()), [])
        self.assertEqual(
            output.read_text().splitlines(),
            ["producer_public=" + public, "receiver_public=" + public],
        )

    def test_sql_stop_validates_original_owner_even_if_publish_never_started(self):
        producer = job(self.flow, "producer")
        block = step(
            producer, "Stop and verify the owned producer SQL independently of publication"
        )
        self.assertIn("always() && (steps.prepare.outcome", block)
        self.assertNotIn("steps.issue", block)
        scope = definitions(block)
        state = Path(self.enterContext(TemporaryDirectory())).resolve()
        marker = dict(workspace_id="workspace", container_id="container", port=15439)
        source = dict(
            source_revision="a" * 40, source_fingerprint="b" * 64, image_id="sha256:" + "c" * 64
        )
        owner = dict(repository="public", run_id=17, run_attempt=2, producer_job="producer")
        record = dict(
            workspace_id="workspace",
            run_owner=owner.copy(),
            baseline_empty=True,
            sql=None,
            source=source,
        )
        for module, method, value in (
            ("image", "owner_record", "observed"),
            ("image", "receipt", source),
            ("ci_campaign_producer", "run_owner", owner),
            ("storage_pki", "workspace_id", "workspace"),
            ("storage_bootstrap", "validate", marker),
        ):
            self.enterContext(patch.object(scope[module], method, return_value=value))
        self.enterContext(
            patch.object(
                scope["ci_producer_cluster"].recovery,
                "Recovery",
                return_value=SimpleNamespace(record=record),
            )
        )
        stop = Mock()
        offline = Mock()
        self.enterContext(patch.object(scope["m17_recovery_native"], "stop_owned", stop))
        self.enterContext(patch.object(scope["shared_serving_receipt"], "offline_pin", offline))
        with self.assertRaises(Rejected):
            scope["stop"](state, "{}", True)
        stop.assert_not_called()
        scope["stop"](state, "{}", False)
        stop.assert_called_once_with(state / ".runtime")
        offline.assert_called_once_with(state / ".runtime")
        for row, mutation in (
            (record, {"source": {}}),
            (record, {"workspace_id": "foreign"}),
            (record["run_owner"], {"run_attempt": 1}),
            (marker, {"workspace_id": "foreign"}),
            (marker, {"port": 15440}),
        ):
            with patch.dict(row, mutation), self.assertRaises(Exception):
                scope["stop"](state, "{}", False)
        stop.assert_called_once()
        ready = state / ".runtime/evidence/storage-bootstrap.json"
        write_json(ready, dict(status="ready", container_id="foreign"))
        with self.assertRaises(Rejected):
            scope["stop"](state, "{}", True)
        stop.assert_called_once()
        write_json(ready, dict(status="ready", container_id=marker["container_id"]))
        scope["stop"](state, "{}", True)
        self.assertEqual(stop.call_count, 2)
        self.assertEqual(offline.call_count, 2)
