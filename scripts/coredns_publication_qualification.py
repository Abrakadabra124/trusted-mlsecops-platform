import io
import os
import re
import unittest
from contextlib import redirect_stdout
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from mlsecops.contracts import Rejected, canonical
from scripts import coredns_publication as core
from scripts import etcd_publication as etcd
from scripts.etcd_publication_qualification import PublicationContractCases

ENV = {
    "GITHUB_REPOSITORY": "Abrakadabra124/trusted-mlsecops-platform",
    "GITHUB_REPOSITORY_ID": "1407811916",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "QUALIFIED_RUN_ID": "1234",
}

# Historical negative control only. This attempt failed before rollout and produced no archive.
FAILED_PRODUCER = {
    "EXPECTED_SOURCE": "153cb11e5f26f561ba4ea9f85f21b8f8ccaeca5c",
    "WORKFLOW_SHA256": "5a3637fcd3e64f49eb76d077d33b1a2ca57c640c0f0eea98fd79f2f3c6fdb15e",
    "RECIPE": "1d7bde1eaa8639468a9e6ed2d7a71033e6536e7f0b1ae2915b58770ddeb61b3a",
    "RUN_ID": 45026873329,
    "JOB_ID": 137221714846,
    "JOB_NAME": "qualify",
    "STEPS": (
        "Set up job",
        "Read exact public source and check the recipe pin",
        "Run astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7",
        "Test the inventory, capability and finding gates",
        "Build twice offline and export the agreed executable hash",
        "Compare the original findings and inspect the archived executables",
        "Query the candidate on UDP port 53 in its own network namespace",
        "Prepare the project workspace and pinned kind tools",
        "Verify both running CoreDNS replicas, switch and roll back",
        "Delete the owned disposable cluster and verify absence",
        "Bind the scanned archive to the verified running CoreDNS config",
        "Upload the scanned CoreDNS archive and its receipt",
        "Post Run astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7",
        "Complete job",
    ),
}


class CoreAuthorityTests(unittest.TestCase):
    def test_terminal_failure_is_rejected_even_if_pins_match(self):
        pub = core.PUBLISHER
        for key in ("EXPECTED_SOURCE", "RUN_ID", "JOB_ID"):
            self.assertNotEqual(getattr(pub, key), FAILED_PRODUCER[key])
        self.enterContext(patch.multiple(pub, **FAILED_PRODUCER))
        self.assertEqual(len(pub.STEPS), 14)
        self.assertEqual(
            sha256(("\n".join(pub.STEPS) + "\n").encode()).hexdigest(),
            "cce4c76885172727fbc899874521c02371326861e67e6659834c4346a6edac29",
        )
        repo = {"id": 1407811916, "full_name": ENV["GITHUB_REPOSITORY"], "private": False}
        run = {
            "repository": repo,
            "head_repository": repo,
            "id": pub.RUN_ID,
            "workflow_id": 1,
            "path": pub.WORKFLOW,
            "head_branch": pub.BRANCH,
            "head_sha": pub.EXPECTED_SOURCE,
            "event": "push",
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "failure",
        }
        with patch.object(pub, "body", return_value=canonical(run)) as request:
            with self.assertRaisesRegex(Rejected, "run_invalid"):
                pub.preflight({**ENV, "QUALIFIED_RUN_ID": str(pub.RUN_ID)})
            request.assert_called_once_with(
                "https://api.github.com/repos/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45026873329",
                None,
            )
        with self.assertRaisesRegex(Rejected, "artifact_count"):
            pub.select_artifact({"total_count": 0, "artifacts": []}, pub.RUN_ID)

    def test_workflow_dispatch_and_job_permissions(self):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/coredns-publication.yml"
        workflow = path.read_text(encoding="utf-8")
        trigger = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"^  (\w+):$", trigger, re.M), ["workflow_dispatch"])
        self.assertEqual(re.findall(r"^      (\w+):$", trigger, re.M), ["run_id"])
        self.assertIn("\npermissions: {}\n", workflow)
        authority, publish = workflow.split("\n  publish:\n", 1)
        self.assertIn("github.ref == 'refs/heads/main'", authority)
        self.assertIn("PUBLISHER.preflight(os.environ)", authority)
        self.assertIn("    needs: authority", publish.splitlines())
        self.assertNotIn("github.token", authority)
        for job, expected in (
            (authority, ["contents: read"]),
            (publish, ["contents: read", "actions: read", "packages: write"]),
        ):
            block = job.split("\n    permissions:\n", 1)[1].split("\n    steps:", 1)[0]
            self.assertEqual([line.strip() for line in block.splitlines()], expected)
            self.assertIn("persist-credentials: false", job)
        self.assertEqual(workflow.count("${{ github.token }}"), 1)

    def test_unconfigured_dispatch_and_direct_publication_stop_before_io(self):
        pub = core.PUBLISHER
        with (
            patch.object(pub, "EXPECTED_SOURCE", None),
            patch.object(pub, "evidence", side_effect=AssertionError("network")),
            patch.dict(os.environ, ENV, clear=True),
            redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(pub.main(), 1)
            self.assertIn("coredns_publication_producer_pins_unset", out.getvalue())
            with self.assertRaisesRegex(Rejected, "producer_pins_unset"):
                pub.publish(1234, "synthetic", "actor", Path("."))

    def test_fixed_namespaces_and_registry_grants(self):
        for pub, name, branch, workflow in (
            (
                core.PUBLISHER,
                "coredns",
                "qualify/r1-coredns-kind-candidate",
                "coredns-dependency-candidate.yml",
            ),
            (etcd.PUBLISHER, "etcd", "qualify/r1-etcd-delivery", "etcd-candidate.yml"),
        ):
            package = f"abrakadabra124/trusted-mlsecops-platform/{name}"
            self.assertEqual(pub.REGISTRY, "ghcr.io/" + package)
            self.assertEqual(pub.V2, "https://ghcr.io/v2/" + package)
            self.assertEqual(pub.BRANCH, branch)
            self.assertEqual(pub.WORKFLOW, ".github/workflows/" + workflow)
            for basic, operations in (("Basic synthetic", "pull,push"), (None, "pull")):
                with patch.object(
                    pub, "body", return_value=canonical({"token": "synthetic"})
                ) as get:
                    pub.registry_auth(basic)
                    url, grant = get.call_args.args
                    self.assertEqual(grant, basic)
                    endpoint = urlsplit(url)
                    self.assertEqual(
                        (endpoint.scheme, endpoint.hostname, endpoint.path),
                        ("https", "ghcr.io", "/token"),
                    )
                    self.assertEqual(
                        parse_qs(endpoint.query),
                        {"service": ["ghcr.io"], "scope": [f"repository:{package}:{operations}"]},
                    )


class CoreDNSPublicationTests(PublicationContractCases, unittest.TestCase):
    pub = core.PUBLISHER
    module = core
    public_required = True
    asset = "coredns-qualified-1234-1"
    tag_prefix = "1.15.0-deps-r1-"

    def setUp(self):
        for key, value in {
            "RECIPE": "b" * 64,
            "WORKFLOW_SHA256": "c" * 64,
            "JOB_ID": 123456,
            "RUN_ID": 1234,
            "JOB_NAME": "reviewed job",
            "STEPS": ("setup", "verify", "upload", "cleanup"),
        }.items():
            self.enterContext(patch.object(self.pub, key, value))
        super().setUp()
        self.job["id"] = 123456

    @staticmethod
    def image_config():
        return {"User": "65532:65532", "Entrypoint": ["/coredns"], "Labels": {}}

    def test_partial_pins_fail_before_credential_or_archive_access(self):
        for field, invalid in (
            ("EXPECTED_SOURCE", ""),
            ("EXPECTED_SOURCE", "A" * 40),
            ("WORKFLOW_SHA256", "0" * 64),
            ("WORKFLOW_SHA256", "a" * 63),
            ("RECIPE", None),
            ("RECIPE", "sha256:" + "a" * 64),
            ("JOB_ID", True),
            ("JOB_ID", 0),
            ("RUN_ID", True),
            ("JOB_NAME", " "),
            ("STEPS", ()),
            ("STEPS", ("",)),
            ("STEPS", "not a step list"),
        ):
            with self.subTest(field=field, invalid=invalid), patch.object(self.pub, field, invalid):
                with self.assertRaisesRegex(Rejected, "producer_pins_unset"):
                    self.pub.dispatch(ENV, str(self.run_id))

    def test_foreign_run_rejected_before_reading_evidence(self):
        with patch.object(self.pub, "evidence", side_effect=AssertionError("network")):
            with self.assertRaisesRegex(Rejected, "run_id_invalid"):
                self.pub.dispatch(ENV, "1235")
            with self.assertRaisesRegex(Rejected, "run_id_invalid"):
                self.pub.publish(1235, "synthetic", "owner", self.temp)

    def test_reject_other_successful_job_or_extra_step(self):
        for override in (
            {"id": True},
            {"id": 123455},
            {"name": "qualify"},
            {
                "steps": self.steps
                + [{"name": "unreviewed", "status": "completed", "conclusion": "success"}]
            },
        ):
            with self.subTest(override=override), self.assertRaises(Rejected):
                self.pub.verify_jobs(
                    {"total_count": 1, "jobs": [{**self.job, **override}]}, self.run_id
                )

    def test_reject_etcd_artifact_and_producer(self):
        other = etcd.PUBLISHER
        with self.assertRaises(Rejected):
            self.pub.select_artifact(
                {"total_count": 1, "artifacts": [{**self.art, "name": "etcd-qualified-1234-1"}]},
                self.run_id,
            )
        for override in (
            {"path": other.WORKFLOW},
            {"head_branch": other.BRANCH},
            {"head_sha": other.EXPECTED_SOURCE},
        ):
            with self.subTest(override=override), self.assertRaises(Rejected):
                self.pub.verify_run({**self.run, **override}, self.run_id)

    def test_reject_another_workload(self):
        config = self.image_config()
        for change in ({"Entrypoint": ["/usr/local/bin/etcd"]}, {"User": "0"}):
            with self.assertRaisesRegex(Rejected, "image_config_invalid"):
                self.pub.verify_image({"Config": {**config, **change}})

    def test_incomplete_anonymous_readback_cannot_pass(self):
        env = {
            **ENV,
            "RUNNER_TEMP": str(self.temp),
            "GITHUB_TOKEN": "synthetic",
            "GITHUB_ACTOR": "owner",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            redirect_stdout(io.StringIO()),
            patch.object(self.pub, "publish", return_value={"anonymous_adoption": "inconclusive"}),
        ):
            self.assertEqual(self.pub.main(), 1)
