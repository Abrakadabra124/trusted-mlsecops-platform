import json
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from importlib import metadata
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest, now


def source_fingerprint(root):
    root = Path(root).resolve()
    paths = list((root / "mlsecops").glob("*.py")) + [
        root / name
        for name in (
            "uv.lock",
            "pyproject.toml",
            ".python-version",
            "Dockerfile",
            "policies/local-cpu.json",
        )
    ]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise Rejected("invalid_source_material")
    materials = {path.relative_to(root).as_posix(): digest(path.read_bytes()) for path in paths}
    return digest(canonical(materials))


def build_image(root, image):
    root = Path(root).resolve()
    fingerprint = source_fingerprint(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    command(
        [
            "docker",
            "build",
            "--platform",
            "linux/amd64",
            "-t",
            image,
            "--label",
            f"org.opencontainers.image.revision={revision}",
            "--label",
            f"org.trusted-mlsecops.source-fingerprint={fingerprint}",
            str(root),
        ],
        timeout=900,
    )
    return fingerprint


def command(arguments, timeout=30):
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Rejected("required_tool_unavailable") from error
    if completed.returncode:
        raise Rejected("required_tool_failed")
    return completed.stdout.strip()


def environment_versions(root):
    root = Path(root)
    expected_python = (root / ".python-version").read_text(encoding="utf-8").strip()
    if platform.python_version() != expected_python:
        raise Rejected("python_version_mismatch")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    packages = {}
    for dependency in project["project"]["dependencies"]:
        matched = re.fullmatch(
            r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([0-9A-Za-z.+-]+)", dependency
        )
        if matched is None:
            raise Rejected("dependency_not_exactly_pinned")
        name, expected = matched.groups()
        try:
            observed = metadata.version(name)
        except metadata.PackageNotFoundError as error:
            raise Rejected(f"dependency_missing:{name}") from error
        if observed != expected:
            raise Rejected(f"dependency_version_mismatch:{name}")
        packages[name] = observed
    return {"python": expected_python, "packages": packages}


def collect(root):
    root = Path(root).resolve()
    for tool in ("git", "docker"):
        if not shutil.which(tool):
            raise Rejected(f"required_tool_missing:{tool}")
    if sys.version_info[:2] != (3, 12):
        raise Rejected("python_3_12_required")
    environment = environment_versions(root)
    engine = json.loads(command(["docker", "info", "--format", "{{json .}}"]))
    if engine["OSType"] != "linux" or engine["NCPU"] < 2 or engine["MemTotal"] < 6 * 1024**3:
        raise Rejected("incompatible_docker_profile")
    free = shutil.disk_usage(root).free
    if free < 8 * 1024**3:
        raise Rejected("insufficient_disk_headroom")
    materials = {}
    for name in (
        "uv.lock",
        "pyproject.toml",
        ".python-version",
        "Dockerfile",
        "policies/local-cpu.json",
    ):
        path = root / name
        if not path.is_file():
            raise Rejected(f"missing_material:{name}")
        materials[name] = digest(path.read_bytes())
    return {
        "schema_version": 1,
        "profile": "local-cpu",
        "observed_at": now(),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "source_fingerprint": source_fingerprint(root),
        "python": platform.python_version(),
        "environment": environment,
        "host_system": platform.system(),
        "host_architecture": platform.machine(),
        "docker_version": engine["ServerVersion"],
        "docker_cpus": engine["NCPU"],
        "docker_memory_bytes": engine["MemTotal"],
        "disk_free_bytes": free,
        "materials": materials,
        "limitations": [
            "Docker memory total is capacity, not available headroom",
            "Host administrator controls local identities",
            "Baseline registry is not used or migrated by this runtime",
        ],
    }
