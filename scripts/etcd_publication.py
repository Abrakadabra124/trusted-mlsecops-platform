"""Publish one qualified Docker archive. All authority and destinations are fixed here."""

import base64
import hashlib
import os
import re
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts.image_archive import identity

REPOSITORY = "Abrakadabra124/trusted-mlsecops-platform"
REPO_ID = 1407811916
WORKFLOW = ".github/workflows/etcd-candidate.yml"
BRANCH = "qualify/r1-etcd-delivery"
EXPECTED_SOURCE = "13ef78c65cf212706b1bbb4495a33ef6437d1fc2"
WORKFLOW_SHA256 = "d17df170a0e8f7e39b8444c0bb4b5b4a04082355e25904be403ec55441e6ec6e"
RECIPE = "2c2ef58b4f8eeb484d24c0bb1d55b91d9d26fd2e49a1185153bbe8511a2f5f2d"
API = f"https://api.github.com/repos/{REPOSITORY}"
PACKAGE = "abrakadabra124/trusted-mlsecops-platform/etcd"
REGISTRY = "ghcr.io/" + PACKAGE
V2 = f"https://ghcr.io/v2/{PACKAGE}"
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
STEPS = (
    "Build twice and compare files extracted from both final images",
    "Scan both Docker archives and the three extracted candidate executables",
    "Check native versions and run a disposable single-member server",
    "Apply the candidate gates to the unmodified reports",
    "Prepare project workspace and pinned kind tools",
    "Replace and roll back the etcd static Pod on the owned kind node",
    "Remove and verify the disposable kind cluster and node",
    "Bind the original scanned archive to the verified running config",
    "Upload the qualified archive and its receipt",
)


def require(condition, reason):
    if not condition:
        raise Rejected("etcd_publication_" + reason)


def positive(n):
    return type(n) is int and n > 0


def is_digest(value):
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def dispatch(env, value):
    require(
        re.fullmatch("[0-9a-f]{40}", EXPECTED_SOURCE) and EXPECTED_SOURCE != "0" * 40,
        "source_pin_unset",
    )
    require(
        env.get("GITHUB_REPOSITORY") == REPOSITORY
        and env.get("GITHUB_REPOSITORY_ID") == str(REPO_ID)
        and env.get("GITHUB_REF") == "refs/heads/main"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and re.fullmatch("[1-9][0-9]{0,18}", value),
        "dispatch_invalid",
    )
    return int(value)


class HTTPSRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(urlsplit(newurl).scheme == "https", "redirect_invalid")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(url, auth=None, accept="application/json"):
    req = Request(url, headers={"Accept": accept, "User-Agent": "etcd-component-publisher"})
    if auth:
        # urllib drops unredirected headers on redirects to signed artifact/blob storage.
        req.add_unredirected_header("Authorization", auth)
    return build_opener(HTTPSRedirect()).open(req, timeout=90)


def body(url, auth=None, accept="application/json"):
    with open_url(url, auth, accept) as response:
        content = response.read(2 * 1024**2 + 1)
    require(len(content) <= 2 * 1024**2, "metadata_too_large")
    return content


def repo_matches(repo):
    return repo["id"] == REPO_ID and repo["full_name"] == REPOSITORY and repo["private"] is False


def verify_run(run, run_id):
    require(
        repo_matches(run["repository"])
        and repo_matches(run["head_repository"])
        and run["id"] == run_id
        and positive(run["workflow_id"])
        and run["path"] == WORKFLOW
        and run["head_branch"] == BRANCH
        and run["head_sha"] == EXPECTED_SOURCE
        and run["event"] == "push"
        and positive(run["run_attempt"])
        and run["run_attempt"] == 1
        and run["status"] == "completed"
        and run["conclusion"] == "success",
        "run_invalid",
    )


def verify_jobs(document, run_id):
    require(document["total_count"] == len(document["jobs"]) == 1, "job_count")
    job = document["jobs"][0]
    require(
        job["name"] == "qualify"
        and job["run_id"] == run_id
        and positive(job["run_attempt"])
        and job["run_attempt"] == 1
        and job["head_branch"] == BRANCH
        and job["head_sha"] == EXPECTED_SOURCE
        and job["status"] == "completed"
        and job["conclusion"] == "success",
        "job_invalid",
    )
    names = [s["name"] for s in job["steps"]]
    require(
        tuple(n for n in names if n in STEPS) == STEPS
        and all(s["status"] == "completed" and s["conclusion"] == "success" for s in job["steps"]),
        "steps_invalid",
    )


def select_artifact(document, run_id):
    require(document["total_count"] == len(document["artifacts"]), "artifact_page_incomplete")
    matches = [a for a in document["artifacts"] if a["name"] == f"etcd-qualified-{run_id}-1"]
    require(len(matches) == 1, "artifact_count")
    a = matches[0]
    parent = a["workflow_run"]
    require(
        positive(a["id"])
        and a["expired"] is False
        and is_digest(a["digest"])
        and positive(a["size_in_bytes"])
        and a["size_in_bytes"] <= LIMIT
        and parent["id"] == run_id
        and parent["repository_id"] == parent["head_repository_id"] == REPO_ID
        and parent["head_branch"] == BRANCH
        and parent["head_sha"] == EXPECTED_SOURCE,
        "artifact_invalid",
    )
    return a


def evidence(run_id, auth):
    def api(path):
        return decode(body(API + path, auth))

    path = f"/actions/runs/{run_id}"
    run = api(path)
    verify_run(run, run_id)
    workflow = api(f"/actions/workflows/{run['workflow_id']}")
    require(
        workflow["id"] == run["workflow_id"] and workflow["path"] == WORKFLOW, "workflow_invalid"
    )
    verify_jobs(api(path + "/attempts/1/jobs?per_page=100"), run_id)
    return select_artifact(api(path + "/artifacts?per_page=100"), run_id)


def copy_exact(source, destination, size):
    left = size
    with destination.open("xb") as stream:
        while left:
            data = source.read(min(left, 1024**2))
            require(data, "short_file")
            stream.write(data)
            left -= len(data)
        require(not source.read(1), "oversized_file")


def file_sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unpack(path, artifact, run_id, target):
    require(
        path.stat().st_size == artifact["size_in_bytes"]
        and "sha256:" + file_sha(path) == artifact["digest"],
        "zip_digest_mismatch",
    )
    with zipfile.ZipFile(path) as z:
        require(sorted(z.namelist()) == ["candidate.tar", "receipt.json"], "zip_members")
        for i in z.infolist():
            require(
                i.orig_filename == i.filename
                and not i.flag_bits & 1
                and stat.S_IFMT(i.external_attr >> 16) in (0, stat.S_IFREG)
                and not i.external_attr & 0x410
                and i.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                "zip_member_type",
            )
        size = z.getinfo("candidate.tar").file_size
        require(
            0 < size <= LIMIT and 0 < z.getinfo("receipt.json").file_size <= 8192, "member_size"
        )
        receipt = decode(z.read("receipt.json"), 8192)
        expected = {
            "schema_version": 1,
            "repository": REPOSITORY,
            "source_revision": EXPECTED_SOURCE,
            "run_id": run_id,
            "run_attempt": 1,
            "archive_size": size,
            "recipe_sha256": RECIPE,
        }
        require(
            type(receipt) is dict
            and receipt.keys() == expected.keys() | {"config_id", "archive_sha256"}
            and all(type(receipt[k]) is type(v) and receipt[k] == v for k, v in expected.items())
            and is_digest(receipt["config_id"])
            and type(receipt["archive_sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", receipt["archive_sha256"]),
            "receipt_invalid",
        )
        with z.open("candidate.tar") as source:
            copy_exact(source, target, size)
    require(file_sha(target) == receipt["archive_sha256"], "archive_digest_mismatch")
    return receipt


def registry_auth(basic=None):
    query = urlencode(
        {
            "service": "ghcr.io",
            "scope": f"repository:{PACKAGE}:" + ("pull,push" if basic else "pull"),
        }
    )
    grant = decode(body("https://ghcr.io/token?" + query, basic))
    token = grant.get("token")
    require(
        isinstance(token, str) and token and not any(c.isspace() for c in token),
        "registry_token_invalid",
    )
    return "Bearer " + token


def require_absent(tag, auth):
    try:
        body(f"{V2}/manifests/{tag}", auth, MANIFEST_TYPES)
    except HTTPError as error:
        if error.code == 404:
            problem = decode(error.read(16385), 16384)
            errors = problem["errors"]
            require(
                isinstance(errors, list)
                and errors
                and all(e["code"] in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN") for e in errors),
                "ambiguous_tag_lookup",
            )
            return
        raise
    raise Rejected("etcd_publication_tag_exists")


def readback(tag, expected_digest, config, auth):
    raw = body(f"{V2}/manifests/{tag}", auth, MANIFEST_TYPES)
    require("sha256:" + digest(raw) == expected_digest, "tag_digest_mismatch")
    raw_by_digest = body(f"{V2}/manifests/{expected_digest}", auth, MANIFEST_TYPES)
    require(raw == raw_by_digest, "manifest_digest_mismatch")
    m = decode(raw)
    require(m["schemaVersion"] == 2 and m["config"]["digest"] == config, "manifest_config_mismatch")
    blob = body(f"{V2}/blobs/{config}", auth, "application/octet-stream")
    require(
        len(blob) == m["config"]["size"] and "sha256:" + digest(blob) == config,
        "config_blob_mismatch",
    )


def anonymous_readback(tag, manifest, config):
    try:
        readback(tag, manifest, config, registry_auth())
    except HTTPError as error:
        if error.code not in (401, 403, 404):
            raise
        return "blocked"
    return "verified"


def publish(run_id, token, actor, work):
    gh = "Bearer " + token
    artifact = evidence(run_id, gh)
    for path, pin in ((WORKFLOW, WORKFLOW_SHA256), ("images/candidates/etcd/Dockerfile", RECIPE)):
        raw = body(
            f"{API}/contents/{path}?ref={EXPECTED_SOURCE}", gh, "application/vnd.github.raw+json"
        )
        require(digest(raw) == pin, "source_file_mismatch")
    archive = work / "candidate.tar"
    zip_path = work / "artifact.zip"
    with open_url(
        f"{API}/actions/artifacts/{artifact['id']}/zip", gh, "application/vnd.github+json"
    ) as source:
        copy_exact(source, zip_path, artifact["size_in_bytes"])
    receipt = unpack(zip_path, artifact, run_id, archive)
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
    require(
        details["Id"] == config and identity(archive, details) == config, "loaded_image_mismatch"
    )
    labels = details["Config"]["Labels"]
    require(
        labels.get("org.opencontainers.image.source") == "https://github.com/" + REPOSITORY
        and labels.get("org.opencontainers.image.version") == "3.6.17"
        and labels.get("org.trusted-mlsecops-platform.etcd.patch") == "x-crypto-v0.59.0-r1"
        and labels.get("org.trusted-mlsecops-platform.etcd.upstream-revision")
        == "0689586e360e2c6b46f95ad5634c25d5fa1683db",
        "image_labels_invalid",
    )

    tag = "3.6.17-xcrypto-v0.59.0-r1-" + EXPECTED_SOURCE
    target = REGISTRY + ":" + tag
    docker("tag", config, target)
    require(evidence(run_id, gh) == artifact, "evidence_changed")
    basic = "Basic " + base64.b64encode(f"{actor}:{token}".encode()).decode()
    auth = registry_auth(basic)
    docker("login", "ghcr.io", "--username", actor, "--password-stdin", password=token.encode())
    require_absent(tag, auth)
    output = docker("push", "--platform", "linux/amd64", target).decode()
    match = re.search(
        r"(?m)^" + re.escape(tag) + r": digest: (sha256:[0-9a-f]{64}) size: [0-9]+\s*$", output
    )
    require(match is not None, "push_digest_missing")
    manifest = match[1]
    readback(tag, manifest, config, auth)
    public = anonymous_readback(tag, manifest, config)
    return {
        "scope": "etcd-platform-component-publication",
        "release_ready": False,
        "published": True,
        "target": target,
        "reference": REGISTRY + "@" + manifest,
        "authenticated_readback": "verified",
        "anonymous_adoption": public,
        "producer": receipt,
        "artifact_id": artifact["id"],
        "zip_digest": artifact["digest"],
    }


def main():
    try:
        run_id = dispatch(os.environ, os.environ.get("QUALIFIED_RUN_ID", ""))
        token = os.environ.pop("GITHUB_TOKEN")
        with tempfile.TemporaryDirectory(
            prefix="etcd-publication-", dir=os.environ["RUNNER_TEMP"]
        ) as tmp:
            result = publish(run_id, token, os.environ["GITHUB_ACTOR"], Path(tmp))
        print(canonical(result).decode())
        if result["anonymous_adoption"] == "blocked":
            print("Published and authenticated readback verified. Anonymous adoption blocked.")
    except Rejected as error:
        print(str(error))
        return 1
    except HTTPError as error:
        print(f"etcd_publication_http_failure status={error.code}")
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
        print("etcd_publication_failed " + type(error).__name__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
