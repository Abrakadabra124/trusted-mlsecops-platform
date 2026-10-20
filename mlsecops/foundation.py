import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from mlsecops.cluster import CHART_SHA256, NODE, kubectl, validate_cluster
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import collect, command
from mlsecops.sandbox import resolve_image
from mlsecops.signing import ROLES
from mlsecops.storage_bootstrap import IMAGE as STORAGE_IMAGE
from mlsecops.storage_bootstrap import WORKSPACE_LABEL

BASELINE_REFERENCE = "fe73d86ef8cf4564478058e50a21ac6a1d3e2dc2"
SHA256 = re.compile(r"sha256:[a-f0-9]{64}")


def snapshot(directory):
    result = {}
    for path in sorted(Path(directory).rglob("*")):
        if path.is_symlink():
            raise Rejected("foundation_snapshot_symlink")
        if path.is_file() and path != Path(directory) / "inventory.json":
            result[path.relative_to(directory).as_posix()] = digest(bounded_read(path))
    return result


def invoke_bootstrap(root, state, empty_path=False):
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from mlsecops.bootstrap import initialize; "
            "from mlsecops.contracts import canonical, Rejected; "
            "\ntry: print(canonical(initialize(sys.argv[1], sys.argv[2])).decode())"
            "\nexcept (Rejected, OSError) as error: "
            "print(str(error), file=sys.stderr); raise SystemExit(1)",
            str(root),
            str(state),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, **({"PATH": ""} if empty_path else {})},
        capture_output=True,
        timeout=90,
        check=False,
    )


def bootstrap_probe(root, parent):
    cases = []
    with tempfile.TemporaryDirectory(prefix="m01-", dir=parent) as directory:
        workspace = Path(directory) / "workspace"
        first = invoke_bootstrap(root, workspace)
        if first.returncode or first.stderr:
            raise Rejected("foundation_first_bootstrap_failed")
        initial = decode(first.stdout)
        expected = {
            "schema_version": 1,
            "workspace_digest": digest(canonical(read_json(workspace / "workspace.json"))),
            "public_keys_digest": digest(canonical(read_json(workspace / "trusted-keys.json"))),
            "policy_digest": digest(canonical(read_json(root / "policies/local-cpu.json"))),
        }
        if initial != expected:
            raise Rejected("foundation_bootstrap_receipt_mismatch")
        atomic_write(workspace / "approved/bootstrap-canary.bin", b"existing-approved-data")
        before = snapshot(workspace)
        if not {f"keys/{role}.pem" for role in ROLES}.issubset(before):
            raise Rejected("foundation_bootstrap_keys_missing")
        inventory_before = read_json(workspace / "inventory.json")
        second = invoke_bootstrap(root, workspace)
        if second.returncode or second.stderr or decode(second.stdout) != initial:
            raise Rejected("foundation_repeat_identity_changed")
        after = snapshot(workspace)
        if before != after:
            raise Rejected("foundation_repeat_data_changed")
        inventory_after = read_json(workspace / "inventory.json")

        def stable(value):
            return {
                name: content
                for name, content in value.items()
                if name not in {"observed_at", "disk_free_bytes"}
            }

        if stable(inventory_before) != stable(inventory_after):
            raise Rejected("foundation_repeat_environment_changed")
        cases.extend(("fresh-bootstrap", "repeat-preserves-identity", "repeat-preserves-data"))
        missing = invoke_bootstrap(root, workspace, empty_path=True)
        if (
            missing.returncode != 1
            or b"required_tool_missing" not in missing.stderr
            or missing.stdout
            or snapshot(workspace) != after
        ):
            raise Rejected("foundation_missing_tool_not_rejected")
        cases.append("missing-tool-rejected-without-mutation")
    return {
        "before": before,
        "after": after,
        "inventory_before": inventory_before,
        "inventory_after": inventory_after,
        "cases": cases,
    }


def incompatible_probe(root, parent):
    with tempfile.TemporaryDirectory(prefix="m01-version-", dir=parent) as directory:
        changed_root = Path(directory) / "source"
        changed_root.mkdir()
        shutil.copyfile(root / "pyproject.toml", changed_root / "pyproject.toml")
        (changed_root / ".python-version").write_text("0.0.0", encoding="utf-8")
        workspace = Path(directory) / "workspace"
        observed = invoke_bootstrap(changed_root, workspace)
        if (
            observed.returncode != 1
            or b"python_version_mismatch" not in observed.stderr
            or observed.stdout
            or workspace.exists()
        ):
            raise Rejected("foundation_incompatible_version_not_rejected")


def image_inventory(reference):
    inspected = decode(command(["docker", "image", "inspect", reference]).encode())[0]
    identifier = inspected["Id"]
    if (
        SHA256.fullmatch(identifier) is None
        or inspected["Os"] != "linux"
        or inspected["Architecture"] != "amd64"
    ):
        raise Rejected("foundation_image_identity_invalid")
    return {
        "reference": reference,
        "image_id": identifier,
        "repo_digests": inspected.get("RepoDigests") or [],
        "os": inspected["Os"],
        "architecture": inspected["Architecture"],
    }


def pod_inventory(document):
    result = []
    for pod in document["items"]:
        for spec_key, status_key in (
            ("containers", "containerStatuses"),
            ("initContainers", "initContainerStatuses"),
            ("ephemeralContainers", "ephemeralContainerStatuses"),
        ):
            statuses = {item["name"]: item for item in pod["status"].get(status_key, [])}
            for container in pod["spec"].get(spec_key, []):
                image = statuses.get(container["name"], {}).get("imageID", "")
                matched = re.search(r"(sha256:[a-f0-9]{64})$", image)
                if matched is None:
                    raise Rejected("foundation_pod_image_unresolved")
                result.append(
                    {
                        "namespace": pod["metadata"]["namespace"],
                        "pod": pod["metadata"]["name"],
                        "container": container["name"],
                        "reference": container["image"],
                        "image_id": matched.group(1),
                    }
                )
    if not result:
        raise Rejected("foundation_cluster_inventory_empty")
    return result


def material_inventory(root):
    policy = read_json(root / "policies/local-cpu.json")
    if policy["baseline_reference"] != BASELINE_REFERENCE:
        raise Rejected("foundation_baseline_changed")
    paths = command(["git", "-C", str(root), "ls-files", "--", "*.lock", "*lock.json"]).splitlines()
    if "uv.lock" not in paths:
        raise Rejected("foundation_lock_inventory_empty")
    return {
        "baseline_reference": BASELINE_REFERENCE,
        "locks": {name: digest(bounded_read(safe_child(root, name))) for name in paths},
    }


def qualify(root, state, image="trusted-mlsecops:dev"):
    root, state = Path(root).resolve(), Path(state)
    workspace = read_json(safe_child(state, "workspace.json"))
    inventory = collect(root)
    if inventory["source_dirty"]:
        raise Rejected("foundation_clean_checkout_required")
    cluster = validate_cluster(state)
    if cluster["workspace_id"] != workspace["workspace_id"]:
        raise Rejected("foundation_workspace_mismatch")
    material = material_inventory(root)
    tools = {
        "git": command(["git", "--version"]),
        "uv": command(["uv", "--version"]),
        "kind": command(["kind", "version"]),
        "helm": command(["helm", "version", "--short"]),
        "kubectl": decode(command(["kubectl", "version", "--client", "-o", "json"]).encode())[
            "clientVersion"
        ]["gitVersion"],
    }
    for name, version in (("uv", "0.12.23"), ("kind", "v0.33.0"), ("helm", "v4.2.4")):
        if version not in tools[name].split():
            if name != "helm" or tools[name].split("+")[0] != version:
                raise Rejected(f"foundation_tool_version_mismatch:{name}")
    if tools["kubectl"] != "v1.36.4" or cluster["chart_sha256"] != CHART_SHA256:
        raise Rejected("foundation_cluster_version_mismatch")
    worker_id = resolve_image(image)
    node_id = command(["docker", "inspect", "--format", "{{.Image}}", NODE])
    images = {
        name: image_inventory(reference)
        for name, reference in (
            ("worker", worker_id),
            ("storage", STORAGE_IMAGE),
            ("kind-node", node_id),
        )
    }
    containers = command(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label={WORKSPACE_LABEL}={workspace['workspace_id']}",
            "--format",
            "{{.ID}}",
        ]
    ).splitlines()
    for identifier in containers:
        container_image = command(["docker", "inspect", "--format", "{{.Image}}", identifier])
        images[f"owned-container:{identifier}"] = image_inventory(container_image)
    pods = pod_inventory(decode(kubectl(state, ["get", "pods", "-A", "-o", "json"]).stdout))
    repeated = bootstrap_probe(root, state)
    incompatible_probe(root, state)
    cases = [
        {"id": identifier, "expected": True, "actual": True, "status": "pass"}
        for identifier in (
            *repeated["cases"],
            "incompatible-version-rejected-before-state",
            "clean-checkout",
            "baseline-pin-unchanged",
            "locked-runtime-versions",
            "runtime-and-controller-image-inventory",
            "p0-boundaries-reported",
        )
    ]
    result = {
        "schema_version": 1,
        "status": "pass",
        "finished_at": now(),
        "source_revision": inventory["source_revision"],
        "source_fingerprint": inventory["source_fingerprint"],
        "image_id": worker_id,
        "cases": cases,
        "checks": len(cases),
        "inventory": inventory,
        "tools": tools,
        "materials": material,
        "images": images,
        "pods": pods,
        "bootstrap": repeated,
        "p0": {
            "baseline_registry": "not-used; separate lab; no migration performed",
            "identity_network": "lab identities; no production TLS/OIDC/KMS claim",
            "image_scope": "worker/storage/node plus all observed cluster containers; severity M18 pending",
            "failure_domains": "single host; production HA/offsite excluded; lab M17 remains mandatory",
            "approval": "ledger metadata is not release approval; M10-M11 remain mandatory",
        },
        "limitations": [
            "M01 validates foundation, not vulnerability remediation or release admission",
            "Inventory covers this owned lab at observation time, not other CI environments",
            "Fresh workspace is separate, while processes use the same pinned host environment",
            "Bootstrap canary is preservation evidence, not an evaluated ML candidate",
        ],
    }
    write_json(safe_child(state, "evidence/foundation-qualification.json"), result)
    return result
