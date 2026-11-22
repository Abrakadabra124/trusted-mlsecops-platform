"""Apply the two qualified changes in order and measure one final node image."""

import json
import os
import tempfile
from collections import Counter
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.inventory import command
from scripts import image_audit as audit
from scripts import image_node_openssl as node
from scripts import image_node_runc as runc


def recipe():
    source = node.RECIPE.read_text("utf-8")
    base, remaining = source.split("\n", 1)
    addition = node.RECIPE.parents[1] / "node-runc" / "Dockerfile"
    same_base, copy_step = addition.read_text("utf-8").split("\n", 1)
    if base != same_base or base != "FROM " + node.AMD64:
        raise Rejected("node_patch_recipe_base_changed")
    return f"{base} AS openssl\n{remaining.rstrip()}\nFROM openssl AS combined\n{copy_step}"


def unchanged(observation):
    return sorted(
        canonical(row)
        for row in observation["packages"]
        if "/" + runc.PATH not in row["paths"]
        and not (row["type"] == "deb" and row["name"] in node.DEB)
    )


def qualify(run):
    context, cache = run / "inputs", run / "cache"
    for path in (context, cache, run / "debian", run / "runc"):
        path.mkdir(mode=0o700)
    node.prepare(run / "debian", context)
    runc.prepare(run / "runc", context)
    for image in (node.AMD64, audit.SYFT_IMAGE, audit.GRYPE_IMAGE):
        command(["docker", "pull", "--platform", "linux/amd64", image], timeout=360)
    if audit.inspect_image(node.AMD64)["Id"] != node.CONFIG:
        raise Rejected("node_patch_base_changed")
    dockerfile = run / "Dockerfile"
    dockerfile.write_text(recipe(), encoding="utf-8")
    for stage, tag in (("openssl", node.LOCAL), ("combined", runc.LOCAL)):
        command(
            [
                "docker",
                "buildx",
                "build",
                "--load",
                "--provenance=false",
                "--network=none",
                "--platform=linux/amd64",
                "--target",
                stage,
                "-f",
                str(dockerfile),
                "-t",
                tag,
                str(context),
            ],
            timeout=600,
        )
    code, _ = audit.scanner(
        run, "update", audit.GRYPE_IMAGE, ["db", "update"], [(cache, "/cache", True)], network=True
    )
    if code:
        raise Rejected("node_patch_db_update_failed")
    db = audit.snapshot(cache)
    base, before, stock = node.measure(run, cache, db, "source", node.CONFIG)
    step, middle, ssl = node.measure(run, cache, db, "openssl", node.LOCAL)
    final, after, both = node.measure(run, cache, db, "candidate", runc.LOCAL)
    print(
        json.dumps(
            {
                "scope": "scanner-measurements-before-composition-checks",
                "release_ready": False,
                "severities": {s["image_id"]: s["severity_counts"] for s in (stock, ssl, both)},
            },
            sort_keys=True,
        ),
        flush=True,
    )
    node.check_oci(base, step)
    node.verify_archive_overlay(run / "openssl.tar", step, context)
    node.check_inventory(before, middle, ssl["image_id"])
    node.check_findings(stock["findings"], ssl["findings"])
    (run / "openssl.tar").unlink()
    intermediate_layers = step["rootfs"]["diff_ids"]
    node.check_oci(step, final, base_layers=intermediate_layers)
    runc.check_archive(run / "candidate.tar", final, base_layers=intermediate_layers)
    runc_scope = runc.compare_inventory(middle, after)
    node.check_findings(stock["findings"], both["findings"])
    other = unchanged(before)
    if unchanged(after) != other or not stock["database"] == ssl["database"] == both["database"]:
        raise Rejected("node_patch_unrelated_rows_or_database_changed")
    results = {}
    for name, result in (("stock", stock), ("openssl", ssl), ("combined", both)):
        results[name] = {
            key: result[key]
            for key in (
                "image_id",
                "status",
                "packages",
                "severity_counts",
                "sbom_sha256",
                "grype_sha256",
            )
        }

    def blockers(result):
        return Counter(
            (f["id"], f["severity"])
            for f in result["findings"]
            if f["severity"] in {"Critical", "High", "Unknown"}
        )

    added = blockers(both) - blockers(stock)
    print(
        json.dumps(
            {
                "scope": "one-node-openssl-and-runc",
                "release_ready": False,
                "results": results,
                "database_files": db,
                "runc": runc_scope,
                "unchanged_other_rows": len(other),
                "unchanged_other_sha256": digest(b"[" + b",".join(other) + b"]"),
                "added_blocking_matches": added.total(),
                "removed_blocking_matches": (blockers(stock) - blockers(both)).total(),
                "final_diff_ids": final["rootfs"]["diff_ids"],
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0 if both["status"] == "pass" and not added else 1


if __name__ == "__main__":
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("RUNNER_OS") != "Linux"
    ):
        raise SystemExit("GitHub-hosted disposable Linux runner required")
    with tempfile.TemporaryDirectory(prefix="node-patches-") as directory:
        raise SystemExit(qualify(Path(directory)))
