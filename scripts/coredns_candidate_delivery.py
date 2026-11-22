"""Emit a receipt for the original CoreDNS archive only after the hosted rollout and cleanup."""

import os
import re
import subprocess
from pathlib import Path

from mlsecops.ci_transfer import REPOSITORY
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from scripts import image_audit as audit

RECIPE = "images/candidates/coredns/Dockerfile"
REF = "refs/heads/qualify/r1-coredns-kind-candidate"


def prepare(work, env):
    revision = env["GITHUB_SHA"]
    if not (
        env["GITHUB_REPOSITORY"] == REPOSITORY
        and env["GITHUB_REF"] == REF
        and env["GITHUB_RUN_ATTEMPT"] == "1"
        and re.fullmatch(r"[1-9][0-9]*", env["GITHUB_RUN_ID"])
        and re.fullmatch(r"[0-9a-f]{40}", revision)
    ):
        raise Rejected("invalid_coredns_delivery_run")
    recipe = subprocess.check_output(["git", "cat-file", "blob", f"{revision}:{RECIPE}"])
    recipe_hash = digest(recipe)
    if (
        recipe_hash != env["QUALIFIED_RECIPE_SHA256"]
        or (work / "context/Dockerfile").read_bytes() != recipe
    ):
        raise Rejected("coredns_delivery_recipe_mismatch")
    archive = work / "candidate.tar"
    archive_sha = audit.file_hash(archive)
    if archive_sha != env["QUALIFIED_ARCHIVE_SHA256"]:
        raise Rejected("coredns_archive_changed_since_scan")
    config = env["LIVE_CONFIG"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", config) or config != env["QUALIFIED_CONFIG"]:
        raise Rejected("coredns_delivery_live_config_mismatch")
    inspect = audit.inspect_image(config)
    sbom = decode(bounded_read(work / "candidate-sbom.json", audit.LIMIT), audit.LIMIT)
    grype = decode(bounded_read(work / "candidate-scan.json", audit.LIMIT), audit.LIMIT)
    if not (
        config
        == (work / "candidate.id").read_text().strip()
        == inspect["Id"]
        == sbom["source"]["metadata"]["imageID"]
        == grype["source"]["target"]["imageID"]
        == audit.identity(archive, inspect)
    ):
        raise Rejected("coredns_delivery_config_mismatch")
    size = archive.stat().st_size
    run_id = int(env["GITHUB_RUN_ID"])
    receipt = dict(
        schema_version=1,
        repository=REPOSITORY,
        source_revision=revision,
        run_id=run_id,
        run_attempt=1,
        config_id=config,
        archive_sha256=archive_sha,
        archive_size=size,
        recipe_sha256=recipe_hash,
    )
    path = work / "receipt.json"
    with path.open("xb") as stream:
        stream.write(canonical(receipt) + b"\n")
    print(
        f"coredns-qualified-{run_id}-1 receipt_sha256={digest(path.read_bytes())} "
        f"archive_sha256={archive_sha} archive_size={size} config_id={config} recipe_sha256={recipe_hash}"
    )


if __name__ == "__main__":
    prepare(Path(os.environ["RUNNER_TEMP"]) / "coredns-dependency", os.environ)
