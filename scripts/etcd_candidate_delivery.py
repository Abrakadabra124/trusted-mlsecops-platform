"""Bind the original scanned Docker save archive to its successful kind qualification."""

import hashlib
import os
import re
import subprocess
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts.image_archive import identity

RECIPE = "images/candidates/etcd/Dockerfile"
REPOSITORY = "Abrakadabra124/trusted-mlsecops-platform"
DELIVERY_REF = "refs/heads/qualify/r1-etcd-delivery"


def prepare(work, env):
    revision = env["GITHUB_SHA"]
    if not (
        env["GITHUB_REPOSITORY"] == REPOSITORY
        and env["GITHUB_REF"] == DELIVERY_REF
        and re.fullmatch(r"[0-9a-f]{40}", revision)
        and all(
            re.fullmatch(r"[1-9][0-9]*", env[k]) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
        )
    ):
        raise Rejected("invalid_delivery_run")

    recipe = subprocess.check_output(
        ["git", "-C", str(work / "source"), "cat-file", "blob", f"{revision}:{RECIPE}"]
    )
    recipe_hash = digest(recipe)
    if (
        recipe_hash != env["ETCD_RECIPE_SHA256"]
        or (work / "context/Dockerfile").read_bytes() != recipe
    ):
        raise Rejected("delivery_recipe_mismatch")

    scans = work / "scans"
    archive = scans / "candidate.tar"
    if archive.is_symlink() or not archive.is_file():
        raise Rejected("missing_candidate_archive")
    with archive.open("rb") as stream:
        archive_size = os.fstat(stream.fileno()).st_size
        archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    if archive_hash != env["ETCD_ARCHIVE_SHA256"]:
        raise Rejected("archive_changed_since_scan")

    [inspect] = decode((scans / "candidate.inspect.json").read_bytes())
    sbom = decode((scans / "candidate.sbom.json").read_bytes())
    grype = decode((scans / "candidate.grype.json").read_bytes())
    config = env["ETCD_LIVE_CONFIG"]
    if not (
        re.fullmatch(r"sha256:[0-9a-f]{64}", config)
        and config
        == (work / "first/id").read_text().strip()
        == inspect["Id"]
        == sbom["source"]["metadata"]["imageID"]
        == grype["source"]["target"]["imageID"]
        == identity(archive, inspect)
    ):
        raise Rejected("delivery_config_mismatch")

    receipt = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "source_revision": revision,
        "run_id": int(env["GITHUB_RUN_ID"]),
        "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "config_id": config,
        "archive_sha256": archive_hash,
        "archive_size": archive_size,
        "recipe_sha256": recipe_hash,
    }
    path = scans / "receipt.json"
    with path.open("xb") as output:
        output.write(canonical(receipt) + b"\n")
    print(
        f"etcd-qualified-{receipt['run_id']}-{receipt['run_attempt']} receipt_sha256={digest(path.read_bytes())} archive_sha256={archive_hash} archive_size={archive_size} config_id={config} recipe_sha256={recipe_hash}"
    )


if __name__ == "__main__":
    prepare(Path(os.environ["RUNNER_TEMP"]) / "etcd-qualification", os.environ)
