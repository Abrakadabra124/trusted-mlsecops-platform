"""Reviewed Kubernetes module aliases, separate from raw observations and findings.

The fixed registry is a projection of the independently replayed source proof.
Its byte digest is code-pinned, not supplied by an audit caller. Updating source,
recipe, materials, any of the seven publishing deltas or a binding needs review.
No mapping grants coverage, suppresses a finding or proves compiler equivalence.
"""

import json
import re
from collections import Counter
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_kubernetes_inventory as inventory

_REGISTRY_PATH = Path(__file__).with_name("image_kubernetes_aliases_registry.json")
_REGISTRY_SHA256 = "a1e16b7cb7ec48b1429d7af449785ac5109eca61c37a9ef122faf014bf415bae"
_PACKAGE_KEYS = {"name", "version", "type", "foundBy", "paths"}
_REPOSITORY_PART = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_REGISTRY_REFERENCE = re.compile(
    r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?/"
    + _REPOSITORY_PART
    + r"(?:/"
    + _REPOSITORY_PART
    + r")*"
    + r"(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}"
)


def _registry():
    # Re-read for every public API: mutation between batch checks cannot use a cache.
    try:
        with _REGISTRY_PATH.open("rb") as stream:
            raw = stream.read(128 * 1024 + 1)
    except OSError:
        raise Rejected("image_audit_kubernetes_alias_registry_unavailable") from None
    if digest(raw) != _REGISTRY_SHA256:
        raise Rejected("image_audit_kubernetes_alias_registry_mismatch")
    return json.loads(raw)


def proof_digest() -> str:
    """Bind the complete registry, including workspace and known-root proof pins."""
    _registry()
    return _REGISTRY_SHA256


def coordinates() -> tuple[tuple[str, str], ...]:
    """The entire reviewed scan set; two auxiliary proof modules are not scan inputs."""
    return tuple(tuple(row) for row in _registry()["coordinates"])


def validate_coordinate(module, version) -> str:
    """Authorize one exact coordinate and return its canonical scanner PURL."""
    allowed = coordinates()
    if type(module) is not str or type(version) is not str or (module, version) not in allowed:
        raise Rejected("image_audit_kubernetes_alias_coordinate_invalid")
    return f"pkg:golang/{module}@{version}"


def _reference_binding(reference, config, manifest):
    if type(reference) is str and reference == config:
        return "config"
    if (
        type(reference) is not str
        or len(reference) > 600
        or not _REGISTRY_REFERENCE.fullmatch(reference)
        or not reference.endswith("@" + manifest)
    ):
        raise Rejected("image_audit_kubernetes_alias_reference_mismatch")
    return "manifest"


def _full_rows(observation):
    """Preserve original values, path lists and multiplicity; sort rows only."""
    try:
        packages = observation["packages"]
        if (
            type(packages) is not list
            or len(packages) > 4096
            or type(observation["package_count"]) is not int
            or observation["package_count"] != len(packages)
        ):
            raise Rejected("image_audit_kubernetes_alias_inventory_mismatch")
        rows = []
        for package in packages:
            if (
                type(package) is not dict
                or set(package) != _PACKAGE_KEYS
                or any(type(package[k]) is not str for k in ("name", "version", "type", "foundBy"))
                or type(package["paths"]) is not list
                or any(type(path) is not str for path in package["paths"])
            ):
                raise Rejected("image_audit_kubernetes_alias_inventory_mismatch")
            rows.append(
                [
                    package["type"],
                    package["name"],
                    package["version"],
                    package["foundBy"],
                    package["paths"],
                ]
            )
        types = observation["package_types"]
        if (
            type(types) is not dict
            or any(type(n) is not int for n in types.values())
            or types != dict(Counter(package["type"] for package in packages))
        ):
            raise Rejected("image_audit_kubernetes_alias_inventory_mismatch")
        return sorted(rows)
    except (KeyError, TypeError):
        raise Rejected("image_audit_kubernetes_alias_inventory_mismatch") from None


def resolve(observation, reference):
    """Bind a known exact full inventory; unknown configs have no alias fallback."""
    if not isinstance(observation, dict) or type(observation.get("image_id")) is not str:
        return None
    config = observation["image_id"]
    if config not in inventory.INVENTORIES:
        return None
    registry = _registry()
    image = registry["images"].get(config)
    if image is None:
        return None
    binding = _reference_binding(reference, config, image["manifest_digest"])
    rows = _full_rows(observation)
    diagnosis = inventory.diagnose(observation)
    if (
        diagnosis["independent_inventory_verified"] is not True
        or diagnosis["independent_registry_manifest"] != image["manifest_digest"]
        or inventory.INVENTORIES[config]["scanner_rows_sha256"] != image["scanner_rows_sha256"]
        or digest(canonical(rows)) != image["full_rows_sha256"]
    ):
        raise Rejected("image_audit_kubernetes_alias_inventory_mismatch")
    modules = {module for module, _ in registry["coordinates"]}
    observed = sorted([row[1], row[2], row[4][0]] for row in rows if row[1] in modules)
    expected = sorted(
        [i["module"], i["observed_version"], i["binary_path"]] for i in image["instances"]
    )
    if observed != expected:
        raise Rejected("image_audit_kubernetes_alias_instances_mismatch")
    return {
        "schema_version": 1,
        "scope": "kubernetes-supplemental-mapping",
        "image_config_id": config,
        "manifest_digest": image["manifest_digest"],
        "source_revision": registry["source_revision"],
        "proof_digest": _REGISTRY_SHA256,
        "scanner_rows_sha256": image["scanner_rows_sha256"],
        "reference_binding": binding,
        "instances": [dict(instance) for instance in image["instances"]],
        "coordinates": [
            list(pair) for pair in sorted({(i["module"], i["version"]) for i in image["instances"]})
        ],
    }
