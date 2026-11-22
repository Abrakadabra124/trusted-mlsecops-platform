"""Verify and publish the archive bound to a component-specific, reviewed producer."""

import base64
import hashlib
import os
import re
import stat
import subprocess
import tempfile
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts.image_archive import identity

REPOSITORY = "Abrakadabra124/trusted-mlsecops-platform"
REPO_ID = 1407811916
API = f"https://api.github.com/repos/{REPOSITORY}"
MANIFEST_TYPES = ", ".join(
    (
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v1+prettyjws",
    )
)
LIMIT = 512 * 1024**2


def positive(n):
    return type(n) is int and n > 0


def is_digest(value):
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def file_sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class HTTPSRedirect(HTTPRedirectHandler):
    def __init__(self, require):
        self.require = require

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.require(urlsplit(newurl).scheme == "https", "redirect_invalid")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def repo_matches(repo):
    return repo["id"] == REPO_ID and repo["full_name"] == REPOSITORY and repo["private"] is False


class QualifiedPublisher(ABC):
    JOB_NAME = "qualify"
    REQUIRE_PUBLIC = False

    @property
    def PACKAGE(self):
        return f"abrakadabra124/trusted-mlsecops-platform/{self.COMPONENT}"

    @property
    def REGISTRY(self):
        return "ghcr.io/" + self.PACKAGE

    @property
    def V2(self):
        return "https://ghcr.io/v2/" + self.PACKAGE

    def verify_pins(self, run_id):
        self.require(
            re.fullmatch("[0-9a-f]{40}", self.EXPECTED_SOURCE) and self.EXPECTED_SOURCE != "0" * 40,
            "source_pin_unset",
        )

    def job_matches(self, job):
        return job["name"] == self.JOB_NAME

    @abstractmethod
    def verify_image(self, details):
        """Check the specific image before granting registry access."""

    def require(self, condition, reason):
        if not condition:
            raise Rejected(f"{self.COMPONENT}_publication_" + reason)

    def dispatch(self, env, value):
        self.require(
            env.get("GITHUB_REPOSITORY") == REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(REPO_ID)
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and re.fullmatch("[1-9][0-9]{0,18}", value),
            "dispatch_invalid",
        )
        run_id = int(value)
        self.verify_pins(run_id)
        return run_id

    def open_url(self, url, auth=None, accept="application/json"):
        req = Request(
            url, headers={"Accept": accept, "User-Agent": f"{self.COMPONENT}-component-publisher"}
        )
        if auth:
            # urllib drops unredirected headers on redirects to signed artifact/blob storage.
            req.add_unredirected_header("Authorization", auth)
        return build_opener(HTTPSRedirect(self.require)).open(req, timeout=90)

    def body(self, url, auth=None, accept="application/json"):
        with self.open_url(url, auth, accept) as response:
            content = response.read(2 * 1024**2 + 1)
        self.require(len(content) <= 2 * 1024**2, "metadata_too_large")
        return content

    def verify_run(self, run, run_id):
        self.require(
            repo_matches(run["repository"])
            and repo_matches(run["head_repository"])
            and run["id"] == run_id
            and positive(run["workflow_id"])
            and run["path"] == self.WORKFLOW
            and run["head_branch"] == self.BRANCH
            and run["head_sha"] == self.EXPECTED_SOURCE
            and run["event"] == "push"
            and positive(run["run_attempt"])
            and run["run_attempt"] == 1
            and run["status"] == "completed"
            and run["conclusion"] == "success",
            "run_invalid",
        )

    def verify_jobs(self, document, run_id):
        self.require(document["total_count"] == len(document["jobs"]) == 1, "job_count")
        job = document["jobs"][0]
        self.require(
            self.job_matches(job)
            and job["run_id"] == run_id
            and positive(job["run_attempt"])
            and job["run_attempt"] == 1
            and job["head_branch"] == self.BRANCH
            and job["head_sha"] == self.EXPECTED_SOURCE
            and job["status"] == "completed"
            and job["conclusion"] == "success",
            "job_invalid",
        )
        names = [s["name"] for s in job["steps"]]
        self.require(
            tuple(n for n in names if n in self.STEPS) == self.STEPS
            and all(
                s["status"] == "completed" and s["conclusion"] == "success" for s in job["steps"]
            ),
            "steps_invalid",
        )

    def select_artifact(self, document, run_id):
        self.require(
            document["total_count"] == len(document["artifacts"]), "artifact_page_incomplete"
        )
        matches = [
            a
            for a in document["artifacts"]
            if a["name"] == f"{self.COMPONENT}-qualified-{run_id}-1"
        ]
        self.require(len(matches) == 1, "artifact_count")
        a = matches[0]
        parent = a["workflow_run"]
        self.require(
            positive(a["id"])
            and a["expired"] is False
            and is_digest(a["digest"])
            and positive(a["size_in_bytes"])
            and a["size_in_bytes"] <= LIMIT
            and parent["id"] == run_id
            and parent["repository_id"] == parent["head_repository_id"] == REPO_ID
            and parent["head_branch"] == self.BRANCH
            and parent["head_sha"] == self.EXPECTED_SOURCE,
            "artifact_invalid",
        )
        return a

    def evidence(self, run_id, auth):
        def api(path):
            return decode(self.body(API + path, auth))

        path = f"/actions/runs/{run_id}"
        run = api(path)
        self.verify_run(run, run_id)
        workflow = api(f"/actions/workflows/{run['workflow_id']}")
        self.require(
            workflow["id"] == run["workflow_id"] and workflow["path"] == self.WORKFLOW,
            "workflow_invalid",
        )
        self.verify_jobs(api(path + "/attempts/1/jobs?per_page=100"), run_id)
        return self.select_artifact(api(path + "/artifacts?per_page=100"), run_id)

    def copy_exact(self, source, destination, size):
        left = size
        with destination.open("xb") as stream:
            while left:
                data = source.read(min(left, 1024**2))
                self.require(data, "short_file")
                stream.write(data)
                left -= len(data)
            self.require(not source.read(1), "oversized_file")

    def validate_receipt(self, raw, run_id, size):
        receipt = decode(raw, 8192)
        expected = {
            "schema_version": 1,
            "repository": REPOSITORY,
            "source_revision": self.EXPECTED_SOURCE,
            "run_id": run_id,
            "run_attempt": 1,
            "archive_size": size,
            "recipe_sha256": self.RECIPE,
        }
        self.require(
            type(receipt) is dict
            and receipt.keys() == expected.keys() | {"config_id", "archive_sha256"}
            and all(type(receipt[k]) is type(v) and receipt[k] == v for k, v in expected.items())
            and is_digest(receipt["config_id"])
            and type(receipt["archive_sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", receipt["archive_sha256"]),
            "receipt_invalid",
        )
        return receipt

    def unpack(self, path, artifact, run_id, target):
        self.require(
            path.stat().st_size == artifact["size_in_bytes"]
            and "sha256:" + file_sha(path) == artifact["digest"],
            "zip_digest_mismatch",
        )
        with zipfile.ZipFile(path) as z:
            self.require(sorted(z.namelist()) == ["candidate.tar", "receipt.json"], "zip_members")
            for i in z.infolist():
                self.require(
                    i.orig_filename == i.filename
                    and not i.flag_bits & 1
                    and stat.S_IFMT(i.external_attr >> 16) in (0, stat.S_IFREG)
                    and not i.external_attr & 0x410
                    and i.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "zip_member_type",
                )
            size = z.getinfo("candidate.tar").file_size
            self.require(
                0 < size <= LIMIT and 0 < z.getinfo("receipt.json").file_size <= 8192, "member_size"
            )
            receipt = self.validate_receipt(z.read("receipt.json"), run_id, size)
            with z.open("candidate.tar") as source:
                self.copy_exact(source, target, size)
        self.require(file_sha(target) == receipt["archive_sha256"], "archive_digest_mismatch")
        return receipt

    def registry_auth(self, basic=None):
        query = urlencode(
            {
                "service": "ghcr.io",
                "scope": f"repository:{self.PACKAGE}:" + ("pull,push" if basic else "pull"),
            }
        )
        grant = decode(self.body("https://ghcr.io/token?" + query, basic))
        token = grant.get("token")
        self.require(
            isinstance(token, str) and token and not any(c.isspace() for c in token),
            "registry_token_invalid",
        )
        return "Bearer " + token

    def require_absent(self, tag, auth):
        try:
            self.body(f"{self.V2}/manifests/{tag}", auth, MANIFEST_TYPES)
        except HTTPError as error:
            if error.code == 404:
                problem = decode(error.read(16385), 16384)
                errors = problem["errors"]
                self.require(
                    isinstance(errors, list)
                    and errors
                    and all(e["code"] in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN") for e in errors),
                    "ambiguous_tag_lookup",
                )
                return
            raise
        raise Rejected(f"{self.COMPONENT}_publication_tag_exists")

    def readback(self, tag, expected_digest, config, auth):
        raw = self.body(f"{self.V2}/manifests/{tag}", auth, MANIFEST_TYPES)
        self.require("sha256:" + digest(raw) == expected_digest, "tag_digest_mismatch")
        raw_by_digest = self.body(f"{self.V2}/manifests/{expected_digest}", auth, MANIFEST_TYPES)
        self.require(raw == raw_by_digest, "manifest_digest_mismatch")
        m = decode(raw)
        self.require(
            m["schemaVersion"] == 2 and m["config"]["digest"] == config, "manifest_config_mismatch"
        )
        blob = self.body(f"{self.V2}/blobs/{config}", auth, "application/octet-stream")
        self.require(
            len(blob) == m["config"]["size"] and "sha256:" + digest(blob) == config,
            "config_blob_mismatch",
        )

    def anonymous_readback(self, tag, manifest, config):
        try:
            self.readback(tag, manifest, config, self.registry_auth())
        except HTTPError as error:
            if error.code not in (401, 403, 404):
                raise
            return "blocked"
        return "verified"

    def publish(self, run_id, token, actor, work):
        self.verify_pins(run_id)
        gh = "Bearer " + token
        artifact = self.evidence(run_id, gh)
        for path, pin in (
            (self.WORKFLOW, self.WORKFLOW_SHA256),
            (f"images/candidates/{self.COMPONENT}/Dockerfile", self.RECIPE),
        ):
            raw = self.body(
                f"{API}/contents/{path}?ref={self.EXPECTED_SOURCE}",
                gh,
                "application/vnd.github.raw+json",
            )
            self.require(digest(raw) == pin, "source_file_mismatch")
        archive = work / "candidate.tar"
        zip_path = work / "artifact.zip"
        with self.open_url(
            f"{API}/actions/artifacts/{artifact['id']}/zip", gh, "application/vnd.github+json"
        ) as source:
            self.copy_exact(source, zip_path, artifact["size_in_bytes"])
        receipt = self.unpack(zip_path, artifact, run_id, archive)
        config = receipt["config_id"]
        docker_config = work / "docker"
        docker_config.mkdir(mode=0o700)

        def docker(*args, password=None):
            return subprocess.run(
                ["docker", "--config", str(docker_config), *args],
                input=password,
                capture_output=True,
                check=True,
                timeout=600,
            ).stdout

        docker("load", "--input", str(archive))
        (details,) = decode(docker("image", "inspect", config))
        self.require(
            details["Id"] == config and identity(archive, details) == config,
            "loaded_image_mismatch",
        )
        self.verify_image(details)

        tag = self.TAG_PREFIX + self.EXPECTED_SOURCE
        target = self.REGISTRY + ":" + tag
        docker("tag", config, target)
        self.require(self.evidence(run_id, gh) == artifact, "evidence_changed")
        basic = "Basic " + base64.b64encode(f"{actor}:{token}".encode()).decode()
        auth = self.registry_auth(basic)
        docker("login", "ghcr.io", "--username", actor, "--password-stdin", password=token.encode())
        self.require_absent(tag, auth)
        output = docker("push", "--platform", "linux/amd64", target).decode()
        match = re.search(
            r"(?m)^" + re.escape(tag) + r": digest: (sha256:[0-9a-f]{64}) size: [0-9]+\s*$", output
        )
        self.require(match is not None, "push_digest_missing")
        manifest = match[1]
        self.readback(tag, manifest, config, auth)
        public = self.anonymous_readback(tag, manifest, config)
        return {
            "scope": f"{self.COMPONENT}-platform-component-publication",
            "release_ready": False,
            "published": True,
            "target": target,
            "reference": self.REGISTRY + "@" + manifest,
            "authenticated_readback": "verified",
            "anonymous_adoption": public,
            "producer": receipt,
            "artifact_id": artifact["id"],
            "zip_digest": artifact["digest"],
        }

    def main(self):
        try:
            run_id = self.dispatch(os.environ, os.environ.get("QUALIFIED_RUN_ID", ""))
            token = os.environ.pop("GITHUB_TOKEN")
            with tempfile.TemporaryDirectory(
                prefix=f"{self.COMPONENT}-publication-", dir=os.environ["RUNNER_TEMP"]
            ) as tmp:
                result = self.publish(run_id, token, os.environ["GITHUB_ACTOR"], Path(tmp))
            print(canonical(result).decode())
            if result["anonymous_adoption"] == "blocked":
                print("Published and authenticated readback verified. Anonymous adoption blocked.")
            if self.REQUIRE_PUBLIC and result["anonymous_adoption"] != "verified":
                return 1
        except Rejected as error:
            print(str(error))
            return 1
        except HTTPError as error:
            print(f"{self.COMPONENT}_publication_http_failure status={error.code}")
            return 1
        except (
            OSError,
            URLError,
            ValueError,
            KeyError,
            TypeError,
            zipfile.BadZipFile,
            subprocess.SubprocessError,
        ) as error:
            print(f"{self.COMPONENT}_publication_failed " + type(error).__name__)
            return 1
        return 0
