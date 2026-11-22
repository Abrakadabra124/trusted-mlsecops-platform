"""Hosted static diagnostic for one locally built local-path provisioner config."""

import argparse
import json
import os
import platform
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from mlsecops.contracts import Rejected, bounded_read, canonical, digest
from mlsecops.inventory import command
from scripts import image_local_path_pair as pair
from scripts import local_path_candidate_delivery as delivery
from scripts.image_kubernetes_scans import confirm_absent
from scripts.image_node_openssl import measure

SCOPE = "local-path-provisioner-rebuild"
BINARY = "/usr/local/bin/local-path-provisioner"
REVISION = "49b2be8e26d6d34c9afaa21fa33108d2e82f8955"
COMPILER = "go1.27.4"
BINARY_SIZE = 52_174_972
BINARY_SHA256 = delivery.BINARY_SHA256
TRIPLES_SHA256 = "bfe00eb88bef4c5fdefc3527b4620060a78d1ea81b9b0ca52e90d4e7d8a09bec"
PATCHED_MODULES = {
    "github.com/klauspost/compress": "v1.20.2",
    "golang.org/x/net": "v0.62.0",
    "golang.org/x/text": "v0.43.0",
}
# Same sorted "name version sum\n" dep projection as the build's offline ELF check.
DEPENDENCIES_SHA256 = "0c46948e3d47ceda67b8df46140e6b088e00e55eb6e06f38fa1e4bbd51d9624b"
BLOCKING = {"Critical", "High", "Unknown"}
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
# Reviewed Go OSV documents have separate stdlib ranges [0,1.26.9) and [1.27.0-0,1.27.2).
STDLIB_127_FIXES = {
    "GO-2026-6603": "76a1945737d8c2ea4a34d18fd44230946b1185894ea155f9812d1149b2838d3c",
    "GO-2026-6610": "2c7881c7945c7c5eadefd3d0caceb1a23b14467373fb28c601141545ff21f190",
    "GO-2026-6611": "5e89ac4314a24eac41111b71ef4544f22836c7b1baf48747e31c5c1d8282c3de",
    "GO-2026-6612": "76c44a4cbdbc463286fb968abd288a26025b8576fe2aed3dcda542fde9518452",
    "GO-2026-6617": "197efc1b2f05e891ab3dad2127b7ea3997dc80dc39b21294ab93e11333c4c08b",
}


def _cid(path):
    cid = bounded_read(path, 128).decode("ascii").strip()
    if not re.fullmatch("[0-9a-f]{64}", cid):
        raise Rejected("local_path_readback_cid_invalid")
    return cid


def binary_readback(run, image_id):
    """Read the merged filesystem by exact ID. The container is never started."""
    cidfile, binary = run / "readback.cid", run / "binary"
    try:
        command(
            [
                "docker",
                "create",
                "--pull=never",
                "--cidfile",
                str(cidfile),
                "--network=none",
                image_id,
            ]
        )
        cid = _cid(cidfile)
        identity = command(["docker", "inspect", "--format", "{{.Image}} {{.State.Status}}", cid])
        if identity != image_id + " created":
            raise Rejected("local_path_readback_identity_mismatch")
        command(["docker", "cp", cid + ":" + BINARY, str(binary)], timeout=120)
    finally:
        # A private cidfile also covers create timeouts after the daemon allocated the ID.
        if not cidfile.is_file():
            raise Rejected("local_path_readback_cleanup_unconfirmed")
        command(["docker", "rm", "-v", _cid(cidfile)])
        confirm_absent(cidfile)
    content = bounded_read(binary, 128 * 1024**2)
    return len(content), digest(content)


def check_inventory(before, after, info):
    def deb(obs):
        return sorted(canonical(p) for p in obs["packages"] if p["type"] == "deb")

    if before["distro"] != after["distro"] or deb(before) != deb(after):
        raise Rejected("local_path_debian_inventory_changed")
    lines = info.splitlines()
    if not lines or not lines[0].endswith(": " + COMPILER):
        raise Rejected("local_path_compiler_mismatch")
    modules = {"stdlib": COMPILER}
    settings, paths, main, dependencies = {}, [], [], []
    for line in lines[1:]:
        fields = line.strip().split("\t")
        match fields:
            case ["path", name]:
                paths.append(name)
            case ["mod" | "dep" as kind, name, version, *sums]:
                if name in modules or not version.startswith("v") or len(sums) > 1:
                    raise Rejected("local_path_module_invalid")
                modules[name] = version
                if kind == "mod":
                    main.append(name)
                else:
                    dependencies.append(f"{name} {version} {''.join(sums)}\n")
            case ["build", setting]:
                key, sep, value = setting.partition("=")
                if not sep or key in settings:
                    raise Rejected("local_path_build_setting_invalid")
                settings[key] = value
            case _:
                # Includes Go module replacements, which need their own reviewed binding.
                raise Rejected("local_path_build_info_unexpected")
    version = modules.get(pair.APP)
    expected = {
        "GOOS": "linux",
        "GOARCH": "amd64",
        "vcs": "git",
        "vcs.revision": REVISION,
        "vcs.modified": "true" if version == "v0.0.37+dirty" else "false",
    }
    dep_hash = digest("".join(sorted(dependencies)).encode())
    if (
        paths != [pair.APP]
        or main != [pair.APP]
        or version not in ("v0.0.37", "v0.0.37+dirty")
        or any(settings.get(k) != v for k, v in expected.items())
        or dep_hash != DEPENDENCIES_SHA256
        or any(modules.get(k) != v for k, v in PATCHED_MODULES.items())
    ):
        raise Rejected("local_path_upstream_build_mismatch")
    observed = {}
    for row in after["packages"]:
        if row["type"] == "deb":
            continue
        name = row["name"]
        if (
            row["type"] != "go-module"
            or row["foundBy"] != "go-module-binary-cataloger"
            or row["paths"] != [BINARY]
            or name in observed
        ):
            raise Rejected("local_path_go_inventory_invalid")
        observed[name] = row["version"]
    if observed != modules:
        raise Rejected("local_path_go_inventory_mismatch")
    triples = sorted([p["type"], p["name"], p["version"]] for p in after["packages"])
    triples_sha256 = digest(canonical(triples))
    if len(triples) != 59 or triples_sha256 != TRIPLES_SHA256:
        raise Rejected("local_path_package_triples_mismatch")
    return {
        "binary_path": BINARY,
        "compiler": COMPILER,
        "modules": modules,
        "dependencies_sha256": dep_hash,
        "linked_dependencies": len(dependencies),
        "package_triples_sha256": triples_sha256,
        **expected,
    }


def fixed_thresholds(modules, findings):
    """Check named blocking Go fixes against the actual same-DB stock finding."""
    checks = []
    for row in findings:
        name = row["package"]
        if name not in pair.GO_COMPONENTS or row["severity"] not in {"Critical", "High"}:
            continue
        installed = modules[name].removeprefix("go").removeprefix("v").removesuffix("+dirty")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", installed):
            raise Rejected("local_path_fix_version_invalid")
        current = tuple(map(int, installed.split(".")))
        fixes = []
        versions = row["fix"]["versions"]
        for value in versions if isinstance(versions, list) else ():
            if not isinstance(value, str):
                continue
            value = value.removeprefix("go").removeprefix("v")
            if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
                fixes.append(tuple(map(int, value.split("."))))
        # Alternative maintenance-branch fixes do not authorize a lower patch on this branch.
        width = 2 if name == "stdlib" or len({fix[:2] for fix in fixes}) > 1 else 1
        branch = [fix for fix in fixes if current[:width] == fix[:width]]
        upstream = {}
        if (
            name == "stdlib"
            and row["id"] in STDLIB_127_FIXES
            and current[:2] == (1, 27)
            and row["fix"] == {"state": "fixed", "versions": ["1.26.9"]}
        ):
            branch = [(1, 27, 2)]
            upstream["upstream"] = {
                "url": f"https://vuln.go.dev/ID/{row['id']}.json",
                "sha256": STDLIB_127_FIXES[row["id"]],
                "introduced": "1.27.0-0",
                "fixed": "1.27.2",
            }
        if row["fix"]["state"] != "fixed" or not fixes or len(fixes) != len(versions):
            classification = "unverified_fix"
        elif not branch:
            classification = "no_comparable_threshold"
        elif current < max(branch):
            classification = "below_threshold"
        else:
            classification = "threshold_met"
        checks.append(
            {
                "id": row["id"],
                "package": name,
                "candidate_version": modules[name],
                "stock_fix": row["fix"],
                "classification": classification,
                "verified": classification == "threshold_met",
                **upstream,
            }
        )
    return checks


def blocking_delta(source, candidate):
    def counts(result):
        return Counter(canonical(f) for f in result["findings"] if f["severity"] in BLOCKING)

    left, right = counts(source), counts(candidate)
    return {
        name: [dict(json.loads(row), count=n) for row, n in sorted(delta.items())]
        for name, delta in (("added_blocking", right - left), ("removed_blocking", left - right))
    }


def qualify(run, image_id, *, retain_archive=False):
    if not IMAGE_ID.fullmatch(image_id) or image_id == pair.STOCK[1]:
        raise Rejected("local_path_candidate_id_invalid")
    if command(["docker", "image", "inspect", "--format", "{{.Id}}", image_id]) != image_id:
        raise Rejected("local_path_candidate_identity_mismatch")
    pair.pull_verified(pair.STOCK)
    cache, db = pair.scanner_database(run)
    base, before, source = measure(run, cache, db, "source", pair.STOCK[1])
    config, after, candidate = measure(run, cache, db, "candidate", image_id)
    # measure mounted this private export read-only into Syft and verified its SBOM.
    measured_sha = delivery.archive_hash(run / "candidate.tar") if retain_archive else None
    evidence = {}
    try:
        base_layers, layers = base["rootfs"]["diff_ids"], config["rootfs"]["diff_ids"]
        if (
            base["config"] != config["config"]
            or base["rootfs"]["type"] != "layers"
            or config["rootfs"]["type"] != "layers"
            or not base_layers
            or layers[:-2] != base_layers
            or not all(IMAGE_ID.fullmatch(layer) for layer in layers)
        ):
            raise Rejected("local_path_runtime_config_or_layers_changed")
        evidence["base_diff_ids"], evidence["candidate_diff_ids"] = base_layers, layers
        size, checksum = binary_readback(run, image_id)
        evidence.update(
            binary_size=size,
            binary_sha256=checksum,
            expected_binary_size=BINARY_SIZE,
            expected_binary_sha256=BINARY_SHA256,
        )
        if (size, checksum) != (BINARY_SIZE, BINARY_SHA256):
            raise Rejected("local_path_binary_mismatch")
        info = command(["go", "version", "-m", str(run / "binary")])
        evidence["build_info"] = check_inventory(before, after, info)
        checks = fixed_thresholds(evidence["build_info"]["modules"], source["findings"])
        evidence["fixed_thresholds"] = checks
        if not all(c["verified"] for c in checks):
            raise Rejected("local_path_fixed_threshold_unverified")
    except Rejected as error:
        evidence["reason"] = str(error)
    report = pair.compare_measured(
        before, source, after, candidate, db, (image_id, image_id), "build_info" in evidence
    )
    report["stock"]["findings"] = source["findings"]
    report["proposal"]["findings"] = candidate["findings"]
    if "reason" in evidence:
        report["status"] = "inconclusive"
    if candidate["severity_counts"]["Critical"] or candidate["severity_counts"]["High"]:
        report["status"] = "fail"
    report = {
        **report,
        "scope": SCOPE,
        "diagnostic_only": True,
        **evidence,
        **blocking_delta(source, candidate),
    }
    if retain_archive and report["status"] == "diagnostic-clear":
        stock_dir = run / "stock-readback"
        stock_dir.mkdir(mode=0o700)
        _, report["stock_binary_sha256"] = binary_readback(stock_dir, pair.STOCK[1])
        delivery.retain(run, report, measured_sha)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--image-id", required=True)
    parser.add_argument(
        "--retain-archive",
        action="store_true",
        help="Retain the measured archive for this hosted job's live qualification",
    )
    args = parser.parse_args(argv)
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or platform.system() != "Linux"
        or platform.machine() != "x86_64"
    ):
        raise SystemExit("GitHub-hosted Linux x86_64 runner required")
    try:
        root = delivery.runner_temp() if args.retain_archive else None
        with tempfile.TemporaryDirectory(prefix="local-path-rebuild-", dir=root) as tmp:
            report = qualify(Path(tmp), args.image_id, retain_archive=args.retain_archive)
    except (Rejected, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        report = {
            "scope": SCOPE,
            "status": "inconclusive",
            "diagnostic_only": True,
            "release_ready": False,
            "reason": str(error)
            if isinstance(error, Rejected)
            else "local_path_evidence_unavailable",
        }
    print(json.dumps(report, sort_keys=True), flush=True)
    return int(report["status"] != "diagnostic-clear")


if __name__ == "__main__":
    raise SystemExit(main())
