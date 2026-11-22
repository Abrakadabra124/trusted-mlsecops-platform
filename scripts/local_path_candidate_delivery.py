"""Retain the measured local-path archive and seal it after the same job's PVC and cleanup steps."""

import os
import platform
import re
import stat
import subprocess
from pathlib import Path

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from mlsecops.inventory import command
from scripts import image_audit as audit
from scripts.image_local_path_pair import STOCK
from scripts.qualified_publication import LIMIT, REPO_ID, REPOSITORY, is_digest

WORKFLOW = ".github/workflows/local-path-rebuild.yml"
REF = "refs/heads/qualify/r1-localpath-pvc"
RECIPE = "images/candidates/local-path/Dockerfile"
BINARY_SHA256 = "e424baa965649565de70a5e4549fa88a1fa4242c39dfda32aaadd557c2e41612"
STOCK_BINARY_SHA256 = "2390c3c8cc37ac3cf05bce7148c54fd51d9618001511684c0eb923ddc80b4fa7"
LIVE_CHECKS = (
    "pvc_bound",
    "remount_verified",
    "pvc_deleted",
    "pv_deleted",
    "backing_directory_absent",
    "cleanup_verified",
)


def require(condition, reason):
    if not condition:
        raise Rejected("local_path_delivery_" + reason)


def runner_temp():
    env = os.environ
    root = Path(env["RUNNER_TEMP"])
    require(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and platform.system() == "Linux"
        and platform.machine() == "x86_64"
        and root.is_absolute()
        and root.resolve(strict=True) == root
        and root.is_dir(),
        "runner",
    )
    return root


def checked_recipe(revision):
    workspace = Path(os.environ["GITHUB_WORKSPACE"])
    require(
        workspace.resolve(strict=True) == Path.cwd()
        and Path(command(["git", "rev-parse", "--show-toplevel"])).resolve() == Path.cwd()
        and command(["git", "rev-parse", "HEAD"]) == revision
        and not command(["git", "status", "--porcelain=v1", "--untracked-files=all"]),
        "source",
    )
    recipe = bounded_read(workspace / RECIPE, 64 * 1024)
    require(
        recipe
        == subprocess.check_output(
            ["git", "cat-file", "blob", revision + ":" + RECIPE], timeout=15
        ),
        "recipe",
    )
    return digest(recipe)


def producer():
    env = os.environ
    revision = env["GITHUB_SHA"]
    run_id = env["GITHUB_RUN_ID"]
    require(
        env.get("GITHUB_REPOSITORY") == REPOSITORY
        and env.get("GITHUB_REPOSITORY_ID") == str(REPO_ID)
        and env.get("GITHUB_REF") == REF
        and env.get("GITHUB_JOB") == "qualify"
        and env.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{WORKFLOW}@{REF}"
        and env.get("GITHUB_RUN_ATTEMPT") == "1"
        and re.fullmatch("[1-9][0-9]{0,18}", run_id)
        and re.fullmatch("[a-f0-9]{40}", revision),
        "producer",
    )
    return dict(
        repository=REPOSITORY,
        source_revision=revision,
        run_id=int(run_id),
        run_attempt=1,
        recipe_sha256=checked_recipe(revision),
    )


def archive_hash(archive):
    info = archive.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= LIMIT,
        "archive_file",
    )
    return audit.file_hash(archive)


def verify_archive(archive, expected_sha, config):
    require(
        is_digest(config) and config != STOCK[1] and archive_hash(archive) == expected_sha,
        "archive_digest",
    )
    inspect = audit.inspect_image(config)
    require(inspect["Id"] == config == audit.identity(archive, inspect), "config")


def write_record(path, record):
    data = canonical(record) + b"\n"
    require(len(data) <= 8192, "record_size")
    with path.open("xb") as stream:
        stream.write(data)
    return digest(data)


def retain(run, report, measured_sha):
    root = runner_temp()
    require(run.parent == root and run.resolve(strict=True) == run, "measurement_path")
    authority = producer()
    config = report["proposal"]["config"]
    require(
        report["status"] == "diagnostic-clear"
        and report["stock"]["config"] == STOCK[1]
        and report["binary_sha256"] == BINARY_SHA256
        and report["stock_binary_sha256"] == STOCK_BINARY_SHA256,
        "static",
    )
    archive = run / "candidate.tar"
    verify_archive(archive, measured_sha, config)
    record = dict(
        **authority,
        stock_config_id=STOCK[1],
        stock_binary_sha256=STOCK_BINARY_SHA256,
        config_id=config,
        binary_sha256=BINARY_SHA256,
        archive_sha256=measured_sha,
        archive_size=archive.stat().st_size,
        static_report_sha256=digest(canonical(report)),
    )
    stage = root / "local-path-measured"
    stage.mkdir(mode=0o700)
    archive.rename(stage / "candidate.tar")  # Same filesystem. Retain the file Syft actually read.
    sha = write_record(stage / "measurement.json", record)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="ascii", newline="\n") as output:
        output.write(f"measurement_sha256={sha}\n")


def live_approval(root, config):
    env = os.environ
    require(env.get("LIVE_OUTCOME") == env.get("CLEANUP_OUTCOME") == "success", "step_outcome")
    raw = bounded_read(root / "local-path-pvc.json", 8192)
    sha = digest(raw)
    require(sha == env.get("LIVE_REPORT_SHA256"), "live_report_digest")
    live = decode(raw, 8192)
    require(
        type(live) is dict
        and type(live.get("schema_version")) is int
        and live["schema_version"] == 1
        and live.get("scope") == "disposable-local-path-pvc"
        and live.get("status") == "pass"
        and live.get("release_ready") is False
        and "reason" in live
        and live["reason"] is None
        and live.get("candidate_config_id") == config
        and live.get("baseline_config_id") == live.get("restored_stock_config_id") == STOCK[1]
        and is_digest(live.get("candidate_runtime_digest"))
        and all(live.get(key) is True for key in LIVE_CHECKS),
        "live_approval",
    )
    return dict(
        live_report_sha256=sha,
        candidate_runtime_digest=live["candidate_runtime_digest"],
        pvc_status=live["status"],
        restored_stock_config_id=live["restored_stock_config_id"],
        cleanup_verified=live["cleanup_verified"],
        cluster_cleanup_outcome=env["CLEANUP_OUTCOME"],
    )


def prepare():
    root = runner_temp()
    authority = producer()
    stage = root / "local-path-measured"
    require(
        stage.resolve(strict=True) == stage
        and {p.name for p in stage.iterdir()} == {"measurement.json", "candidate.tar"},
        "measured_members",
    )
    data = bounded_read(stage / "measurement.json", 8192)
    sha = digest(data)
    require(sha == os.environ.get("MEASUREMENT_SHA256"), "measurement_digest")
    record = decode(data, 8192)
    expected = {
        **authority,
        "stock_config_id": STOCK[1],
        "stock_binary_sha256": STOCK_BINARY_SHA256,
        "binary_sha256": BINARY_SHA256,
    }
    require(
        type(record) is dict
        and record.keys()
        == expected.keys() | {"config_id", "archive_size", "archive_sha256", "static_report_sha256"}
        and all(type(record[k]) is type(v) and record[k] == v for k, v in expected.items())
        and is_digest(record["config_id"])
        and record["config_id"] != STOCK[1]
        and type(record["archive_size"]) is int
        and 0 < record["archive_size"] <= LIMIT
        and all(
            type(record[k]) is str and re.fullmatch("[a-f0-9]{64}", record[k])
            for k in ("archive_sha256", "static_report_sha256")
        ),
        "measurement_run",
    )
    approval = live_approval(root, record["config_id"])
    archive = stage / "candidate.tar"
    require(archive.lstat().st_size == record["archive_size"], "archive_size")
    verify_archive(archive, record["archive_sha256"], record["config_id"])
    target = root / "local-path-qualified"
    target.mkdir(mode=0o700)
    archive.rename(target / "candidate.tar")
    receipt_sha = write_record(
        target / "receipt.json",
        dict(schema_version=2, **record, measurement_sha256=sha, **approval),
    )
    print(
        f"local-path-qualified-{authority['run_id']}-1 receipt_sha256={receipt_sha} "
        f"archive_sha256={record['archive_sha256']} config_id={record['config_id']}",
        flush=True,
    )


if __name__ == "__main__":
    prepare()
