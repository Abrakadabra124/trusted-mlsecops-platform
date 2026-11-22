"""Bind the stock node's kubectl to the official release without starting the node."""

import os
import platform
import re
import tempfile
from pathlib import Path

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from mlsecops.inventory import command
from scripts import image_audit as audit
from scripts import image_kubernetes_aliases as aliases
from scripts.image_audit_contract import SYFT_VERSION
from scripts.image_audit_publication import render
from scripts.image_kubernetes_scans import confirm_absent
from scripts.image_node_openssl import AMD64, CONFIG, IMAGES, LAYERS
from scripts.install_ci_tools import TOOLS

BINARY = "/usr/bin/kubectl"
URL, ELF_SHA, _ = TOOLS["kubectl"]
REVISION = "bb826b1d48562f110659e64e8ec444327433db95"
SETTINGS = {
    "vcs": "git",
    "vcs.revision": REVISION,
    "vcs.modified": "false",
    "GOOS": "linux",
    "GOARCH": "amd64",
    "CGO_ENABLED": "0",
}
CATALOGER = "go-module-binary-cataloger"
MODULES = tuple(
    "k8s.io/" + name
    for name in (
        "api",
        "apimachinery",
        "cli-runtime",
        "client-go",
        "component-base",
        "component-helpers",
        "kubectl",
        "metrics",
        "streaming",
    )
)
# 45050360085 runtime-010: full rows for this path, sorted by canonical JSON.
COUNT = 82
ROWS_SHA = "4a7be190380a4efe3b00c17ab5b7af9953600e717d6f7fea6980534e2f20cbda"


def need(condition, reason):
    if not condition:
        raise Rejected("kubectl_" + reason)


def download(url, destination, limit):
    command(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "300",
            "--max-filesize",
            str(limit),
            "--output",
            str(destination),
            url,
        ],
        timeout=315,
    )


def check_elf(path):
    need(audit.file_hash(path) == ELF_SHA, "elf_digest_mismatch")


def row(name, version):
    return dict(name=name, version=version, type="go-module", foundBy=CATALOGER, paths=[BINARY])


def build_info(text):
    lines = text.splitlines()
    need(lines and lines[0].endswith(": go1.26.5"), "toolchain")
    versions = {"stdlib": "go1.26.5"}
    settings = {}
    paths = []
    mains = []
    for line in lines[1:]:
        fields = line.strip().split("\t")
        match fields:
            case ["path", path]:
                paths.append(path)
            case [("dep" | "mod") as kind, name, version, *checksum]:
                need(name not in versions and len(checksum) <= 1, "duplicate_module")
                versions[name] = "UNKNOWN" if version == "(devel)" else version
                if kind == "mod":
                    mains.append((name, version))
            case ["build", setting]:
                k, sep, v = setting.partition("=")
                need(sep and k not in settings, "build_setting")
                settings[k] = v
            case _:
                raise Rejected("kubectl_unreviewed_buildinfo")
    need(
        paths == ["k8s.io/kubernetes/cmd/kubectl"]
        and mains == [("k8s.io/kubernetes", "v1.36.4")]
        and all(settings.get(k) == v for k, v in SETTINGS.items()),
        "source_identity",
    )
    rows = sorted((row(k, v) for k, v in versions.items()), key=canonical)
    need(
        len(rows) == COUNT
        and digest(canonical(rows)) == ROWS_SHA
        and {k for k, v in versions.items() if v == "UNKNOWN"} == set(MODULES),
        "inventory",
    )
    return versions


def coordinates():
    # Local authority is only for this release ELF, after complete build-info readback.
    # cli-runtime has a source proof in the pinned registry but is auxiliary there.
    proof = aliases.proof_digest()
    path = Path(aliases.__file__).with_name("image_kubernetes_aliases_registry.json")
    raw = bounded_read(path, 128 * 1024)
    need(digest(raw) == proof, "registry_changed")
    reg = decode(raw)
    need(
        reg["source_revision"] == REVISION and reg["known_root"]["version"] == "v1.36.4",
        "registry_source",
    )
    proven = {m["module"]: m for m in reg["modules"]}
    for m in MODULES:
        entry = proven[m]
        need(
            entry["version"] == "v0.36.4"
            and entry["source_path"] == "staging/src/" + m
            and entry["auxiliary"] is (m == "k8s.io/cli-runtime"),
            "staging_source",
        )
        if not entry["auxiliary"]:
            aliases.validate_coordinate(m, "v0.36.4")
    return MODULES


def check_sbom(sbom, versions):
    need(
        sbom["descriptor"]["name"] == "syft"
        and sbom["descriptor"]["version"] == SYFT_VERSION
        and sbom["source"]["type"] == "directory"
        and sbom["source"]["metadata"]["path"] == "/input",
        "syft_subject",
    )
    by_id = {}
    rows = []
    accepted = {BINARY, BINARY.lstrip("/"), "./" + BINARY.lstrip("/"), "/input" + BINARY}
    for p in sbom["artifacts"]:
        locations = p["locations"]
        need(
            len(locations) == 1
            and locations[0].get("path") in accepted
            and locations[0].get("accessPath", BINARY) in accepted
            and p["foundBy"] == CATALOGER
            and p["type"] == "go-module"
            and p["id"]
            and p["id"] not in by_id,
            "syft_location",
        )
        by_id[p["id"]] = (p["name"], p["version"])
        rows.append(row(p["name"], p["version"]))
    need(
        len(rows) == len(versions) == COUNT
        and digest(canonical(sorted(rows, key=canonical))) == ROWS_SHA
        and sorted(by_id.values()) == sorted(versions.items()),
        "syft_inventory",
    )
    return by_id


def copy_binary(run, dest):
    cidfile = run / "node.cid"

    def cid():
        value = bounded_read(cidfile, 128).decode("ascii").strip()
        need(re.fullmatch("[a-f0-9]{64}", value), "container_id")
        return value

    try:
        command(
            [
                "docker",
                "create",
                "--network=none",
                "--pull=never",
                "--cidfile",
                str(cidfile),
                CONFIG,
            ]
        )
        container = cid()
        need(
            command(["docker", "inspect", "--format", "{{.Image}} {{.State.Status}}", container])
            == CONFIG + " created",
            "container_identity",
        )
        command(["docker", "cp", container + ":" + BINARY, str(dest)], timeout=90)
    finally:
        command(["docker", "rm", "-v", cid()])
        confirm_absent(cidfile)


def qualify(run, report):
    from scripts import image_node_kubectl_scan as scan

    root = run / "input"
    binary = root / BINARY.lstrip("/")
    binary.parent.mkdir(mode=0o700, parents=True)
    for ref in (IMAGES["baseline"], AMD64):
        report["stage"] = "node-identity"
        command(["docker", "pull", "--platform", "linux/amd64", ref], timeout=360)
        details = audit.inspect_image(ref)
        need(
            details["Id"] == CONFIG and details["RootFS"]["Layers"] == list(LAYERS), "node_identity"
        )
    report["stage"] = "node-elf"
    copy_binary(run, binary)
    report["observed_elf_sha256"] = audit.file_hash(binary)
    check_elf(binary)
    report["stage"] = "upstream-elf-and-buildinfo"
    reference = run / "release-kubectl"
    download(URL, reference, 128 * 1024**2)
    check_elf(reference)
    versions = build_info(command(["go", "version", "-m", str(binary)]))
    report.update(
        upstream_sha256=ELF_SHA,
        revision=REVISION,
        inventory_sha256=ROWS_SHA,
        packages=sorted((row(k, v) for k, v in versions.items()), key=canonical),
        coordinates=[[m, "v0.36.4"] for m in coordinates()],
        source_proof_sha256=aliases.proof_digest(),
    )
    scan.qualify(run, root, versions, report)
    check_elf(binary)
    report["attribution"] = "verified"


def emit(report):
    content = render(report)
    sha = digest(canonical(report))
    # Verify the exact printable representation round-trips before writing anything.
    reread = decode(content.encode("ascii"), 16 * 1024**2)
    need(digest(canonical(reread)) == sha, "public_report_digest")
    print(content, flush=True)
    print("kubectl_report_sha256=" + sha, flush=True)


def main():
    if not (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and platform.system() == "Linux"
        and platform.machine() == "x86_64"
    ):
        raise SystemExit("GitHub-hosted Linux x86_64 required")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    report = dict(
        scope="stock-node-kubectl-only",
        node_profile="unapproved-system",
        release_ready=False,
        node_config=CONFIG,
        node_manifest=AMD64,
        node_index=IMAGES["baseline"],
        path=BINARY,
        baseline_run=45050360085,
        status="inconclusive",
    )
    try:
        with tempfile.TemporaryDirectory(prefix="kind-kubectl-", dir=temp) as tmp:
            qualify(Path(tmp), report)
    except (Rejected, OSError, KeyError, ValueError, TypeError, IndexError) as exc:
        report.update(
            status="inconclusive",
            reason=str(exc) if isinstance(exc, Rejected) else "kubectl_evidence_unavailable",
        )
    try:
        emit(report)
    except Rejected as exc:
        emit(
            dict(
                scope=report["scope"],
                node_profile="unapproved-system",
                status="inconclusive",
                release_ready=False,
                reason=str(exc),
            )
        )
        return 1
    return int(report["status"] != "diagnostic-clear")


if __name__ == "__main__":
    raise SystemExit(main())
