"""Compare an official signed runc patch on the stock node, without starting a cluster."""

import json
import os
import tarfile
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath

from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.inventory import command
from scripts import image_audit as audit
from scripts import image_node_openssl as node
from scripts.image_audit_contract import exact_observation_matches

PATH = "usr/local/sbin/runc"
MODULE = "github.com/opencontainers/runc"
LOCAL = "trusted-mlsecops:stock-node-runc-144"
BASE_URL = "https://github.com/opencontainers/runc/releases/download/v1.4.4/"
KEY_SOURCE = "bb14dabeb7185bb72c8c86735d090dcb20f36587"
REVISION = "6d1032fdfb7d3432125806826b50b37ac42b6b23"
SIGNER = "C2428CD75720FACDCF76B6EA17DE5ECB75A1100E"
BINARY = (11670920, "378e4c545dee19f310bf470fae5b4d1362d740f3f10a5eb6f788ca392c4592de")
ASSETS = {
    "runc.amd64": BINARY,
    "runc.amd64.asc": (488, "d38aac0c020776dbe654ad51dd75bd4b54e888ce3cbda11477beaa7d165c2c6c"),
    "runc.sha256sum": (1233, "a4c96487ef8b84e7c81ec485c8b213a44b03ef862ed619be8ee50708143a6941"),
}


def prepare(run, context):
    key = node.fetch(
        f"https://raw.githubusercontent.com/opencontainers/runc/{KEY_SOURCE}/runc.keyring",
        (8507, "9bd9742cb79b215cf5f7f71ea71a51a2a95ab573412d54c2905be072d8fcab7c"),
    )
    armor = run / "keys.asc"
    armor.write_bytes(key)
    ring = run / "keys.gpg"
    command(
        [
            "gpg",
            "--batch",
            "--no-options",
            "--homedir",
            str(run),
            "--dearmor",
            "-o",
            str(ring),
            str(armor),
        ]
    )
    for name, pin in ASSETS.items():
        (run / name).write_bytes(node.fetch(BASE_URL + name, pin))
    for args in (["runc.amd64.asc", "runc.amd64"], ["runc.sha256sum"]):
        status = command(
            [
                "gpgv",
                "--homedir",
                str(run),
                "--keyring",
                str(ring),
                "--status-fd",
                "1",
                *[str(run / arg) for arg in args],
            ]
        )
        if [
            line.split()[2] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")
        ] != [SIGNER]:
            raise Rejected("runc_signer_changed")
    sums = (run / "runc.sha256sum").read_text("ascii").splitlines()
    if [line.split() for line in sums if line.split()[-1:] == ["runc.amd64"]] != [
        [BINARY[1], "runc.amd64"]
    ]:
        raise Rejected("runc_checksum_manifest_changed")
    binary = run / "runc.amd64"
    info = command(["go", "version", "-m", str(binary)]).splitlines()
    fields = [line.strip().split() for line in info[1:]]
    if (
        not info
        or not info[0].endswith(": go1.26.11")
        or ["path", MODULE] not in fields
        or ["mod", MODULE, "v1.4.4"] not in fields
        or ["build", "vcs.revision=" + REVISION] not in fields
    ):
        raise Rejected("runc_release_buildinfo_changed")
    binary.rename(context / "runc.amd64")


def check_layer(layer, base):
    parents = {str(p) for p in PurePosixPath(PATH).parents if str(p) != "."}
    if any(base.get(p, ({}, {}))[0].get("type") != "directory" for p in parents) or base.get(
        PATH, ({}, {})
    )[0].get("type") not in ("0", "\x00"):
        raise Rejected("runc_base_path_changed")
    seen = set()
    with tarfile.open(fileobj=layer, mode="r|*") as tar:
        for member in tar:
            name = str(PurePosixPath(member.name))
            if name in seen:
                raise Rejected("runc_layer_duplicate")
            seen.add(name)
            if (
                name in parents
                and member.isdir()
                and node.directory_record(member)[0] == base[name][0]
            ):
                continue
            if (
                name != PATH
                or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                or member.size != BINARY[0]
                or member.mode != 0o755
                or member.linkname
                or (member.uid, member.gid) != (0, 0)
                or set(member.pax_headers) - {"path", "mtime", "atime", "ctime"}
            ):
                raise Rejected("runc_layer_contains_unexpected_change")
            if digest(tar.extractfile(member).read(BINARY[0] + 1)) != BINARY[1]:
                raise Rejected("runc_file_readback_failed")
    if PATH not in seen:
        raise Rejected("runc_file_missing")


def check_archive(path, config, *, base_layers=node.LAYERS):
    ids = config["rootfs"]["diff_ids"]
    with tarfile.open(path, "r:") as archive:
        (manifest,) = json.load(archive.extractfile("manifest.json"))
        layers = manifest["Layers"]
        if ids[:-1] != list(base_layers) or len(layers) != len(ids):
            raise Rejected("runc_archive_layer_set_changed")
        base = {}
        for name, diff in zip(layers[:-1], base_layers, strict=True):
            with node.verified_layer(archive, name, diff) as layer:
                node.apply_base_layer(base, layer)
        with node.verified_layer(archive, layers[-1], ids[-1]) as layer:
            check_layer(layer, base)


def compare_inventory(before, after):
    foreign_rows = []
    scoped_count = []
    for obs, main, go in ((before, "v1.4.3", "go1.26.7"), (after, "v1.4.4", "go1.26.11")):
        local, foreign = [], []
        for row in obs["packages"]:
            if "/" + PATH in row["paths"]:
                if row["paths"] != ["/" + PATH]:
                    raise Rejected("runc_package_path_ambiguous")
                local.append(row)
            else:
                foreign.append(canonical(row))
        foreign_rows.append(sorted(foreign))
        scoped_count.append(len(local))
        for name, version in ((MODULE, main), ("stdlib", go)):
            if [(r["type"], r["version"]) for r in local if r["name"] == name] != [
                ("go-module", version)
            ]:
                raise Rejected("runc_module_identity_changed")
    if foreign_rows[0] != foreign_rows[1]:
        raise Rejected("runc_other_packages_changed")
    return {
        "unchanged_other_rows": len(foreign_rows[0]),
        "unchanged_other_sha256": digest(b"[" + b",".join(foreign_rows[0]) + b"]"),
        "runc_rows_before_after": scoped_count,
    }


def qualify(run):
    context, cache = run / "context", run / "cache"
    context.mkdir()
    cache.mkdir()
    prepare(run, context)
    for image in (node.AMD64, audit.SYFT_IMAGE, audit.GRYPE_IMAGE):
        command(["docker", "pull", "--platform", "linux/amd64", image], timeout=360)
    if audit.inspect_image(node.AMD64)["Id"] != node.CONFIG:
        raise Rejected("runc_node_baseline_mismatch")
    recipe = Path(__file__).resolve().parents[1] / "images/candidates/node-runc/Dockerfile"
    command(
        [
            "docker",
            "buildx",
            "build",
            "--load",
            "--provenance=false",
            "--network=none",
            "--platform=linux/amd64",
            "--no-cache",
            "-f",
            str(recipe),
            "-t",
            LOCAL,
            str(context),
        ],
        timeout=600,
    )
    code, _ = audit.scanner(
        run,
        "db-update",
        audit.GRYPE_IMAGE,
        ["db", "update"],
        [(cache, "/cache", True)],
        network=True,
    )
    if code:
        raise Rejected("runc_grype_update_failed")
    db = audit.snapshot(cache)
    base, before, old = node.measure(run, cache, db, "source", node.CONFIG)
    config, after, new = node.measure(run, cache, db, "candidate", LOCAL)
    if old["database"] != new["database"] or not exact_observation_matches(
        before, 878, node.OBSERVATION
    ):
        raise Rejected("runc_baseline_observation_or_db_changed")
    node.check_oci(base, config)
    check_archive(run / "candidate.tar", config)
    scoped = compare_inventory(before, after)
    mandatory = {"Critical", "High", "Unknown"}

    def blocking(result):
        return Counter(
            (r["id"], r["severity"]) for r in result["findings"] if r["severity"] in mandatory
        )

    left, right = blocking(old), blocking(new)
    report = {
        "scope": "same-base-runc-image-comparison",
        "release_ready": False,
        **scoped,
        "before": old["severity_counts"],
        "after": new["severity_counts"],
        "removed_blocking_matches": (left - right).total(),
        "added_blocking_matches": (right - left).total(),
        "database_files": db,
        "database": new["database"],
        "source_config": node.CONFIG,
        "candidate_config": new["image_id"],
        "source_sbom": old["sbom_sha256"],
        "candidate_sbom": new["sbom_sha256"],
        "source_grype": old["grype_sha256"],
        "candidate_grype": new["grype_sha256"],
        "signed_runc_sha256": BINARY[1],
        "signer": SIGNER,
        "candidate_status": new["status"],
    }
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if new["status"] == "pass" and not right - left else 1


if __name__ == "__main__":
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("RUNNER_OS") != "Linux"
    ):
        raise SystemExit("GitHub-hosted disposable Linux runner required")
    with tempfile.TemporaryDirectory(prefix="node-runc-") as directory:
        raise SystemExit(qualify(Path(directory)))
