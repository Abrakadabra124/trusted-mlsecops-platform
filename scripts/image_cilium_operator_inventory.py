"""Reviewed linux/amd64 mapping for the Cilium operator 1.20.5 supplemental scan.

OCI index -> platform manifest -> config and five layers (compressed SHA-256 and
uncompressed diff_ids) -> two ELF .go.buildinfo sections. Each mod/dep contributes
the linked module name/version (a following => replaces it; neither ELF has one).
Add stdlib from each Go version header. Project (devel) to Syft's UNKNOWN only.
Hash canonical(sorted([type, name, version, foundBy, [binary_path]] rows)) with
SHA-256, preserving duplicates. The fixture is only a qualification input.

The separate gops release binding uses the pinned rebuild receipt. The operator's
own gops dependency remains v0.3.28. A mapping authorizes a scanner input only.
"""

import re

from mlsecops.contracts import Rejected, canonical, digest

PROFILE = "cilium-operator-supplemental"
_INDEX = "sha256:c6e7de6665aa9701db86c4fe46828a75a0d167afe084a9ffb5bce34b2c4fa8c4"
REFERENCE = "quay.io/cilium/operator-generic@" + _INDEX
_MANIFEST = "sha256:3362404f43b6a01cf6e370fb637dac427b7b0259ff2629faa9e5b665121a3a76"
CONFIG = "sha256:56a7372da23608057bd206438f0655e1e6e7d8df9934cffe78be4ff9954afea5"
_MODULE = "github.com/google/gops"
_VERSION = "v0.3.29"
_BINARY = "/usr/bin/gops"
_OPERATOR = "/usr/bin/cilium-operator-generic"
_BINARY_SHA256 = "80cf2af7f90f1b5f6b515021fea1188a109200febae33b8ebe4b006347a95e3a"
_SOURCE_REVISION = "a2d8f7790eac63a6668583a060cb45903410a91b"
_RUN = "44953814982"
_COUNT = 175
_FULL_ROWS_SHA256 = "3b10dcf9cf77fe216e497fb54aa1917a37acf8af48564d2dba7e277a21b6be94"
_MISMATCH = "image_audit_cilium_operator_inventory_mismatch"


def coordinates() -> tuple[tuple[str, str], ...]:
    """Complete set of supplemental scanner inputs for this registry."""
    return ((_MODULE, _VERSION),)


def validate_coordinate(module, version) -> str:
    if (
        type(module) is not str
        or type(version) is not str
        or (module, version) not in coordinates()
    ):
        raise Rejected("image_audit_cilium_operator_coordinate_invalid")
    return f"pkg:golang/{module}@{version}"


def proof_digest() -> str:
    """SHA-256 of the canonical registry pins, including the workflow and observed output."""
    materials = {
        "schema_version": 1,
        "profile": PROFILE,
        "platform": "linux/amd64",
        "reference": REFERENCE,
        "platform_manifest": _MANIFEST,
        "config": CONFIG,
        "package_count": _COUNT,
        "full_rows_sha256": _FULL_ROWS_SHA256,
        "go_version": "go1.26.11",
        "binaries": {
            _OPERATOR: {
                "sha256": "f5e955345c523f95f97764dbee39dcb2b775f689b31b153264858f488b8c574f",
                "buildinfo_sha256": "508ea3baadc6ae828f4159df942b6ee31220be36912eed274b219bb1141f888f",
                "gops_dependency": "v0.3.28",
            },
            _BINARY: {
                "sha256": _BINARY_SHA256,
                "buildinfo_sha256": "a592a04b833d75bd2fadce84e4e47d31e2bbf47ca041927c57bb7867499bbf46",
                "main_module": _MODULE,
                "embedded_version": "(devel)",
                "observed_version": "UNKNOWN",
                "release": _VERSION,
            },
        },
        "source": {
            "repository": "https://github.com/google/gops",
            "revision": _SOURCE_REVISION,
            "commit_archive_sha256": "c7079b73186eff12c8aca2ca8d408817e650bc17b6bdbdd2c46c102f6e85d23a",
        },
        "operator_recipe": {
            "cilium_revision": "150121410c147fad575ac5dcbce6de923be69042",
            "dockerfile_sha256": "936adf8b25c71cec0459b4b628a3099955bfd4017f33d642d7d3b1af111a06bf",
            "build_gops_sh_sha256": "aeb25f7392cff36fe49884a8d9c79e46acb18e6e8c492267862e089b8e9d9c60",
        },
        "rebuild_receipt": {
            "repository": "Abrakadabra124/trusted-mlsecops-platform",
            "workflow": ".github/workflows/cilium-gops-rebuild.yml",
            "workflow_sha256": "887401ace2998b02199df3e9caac210d63871c59c7ca317f8727782811c709d8",
            "revision": "145d24cff0687f9aef99d4bf815bc7bc7434af22",
            "run_id": _RUN,
            "go_image": "docker.io/library/golang@sha256:f6946db66567acc1497655237e58f06ec3a57478a5e0d67fca29d2ffcf2ea136",
            "go_mod_verify": "pass",
            "output_sha256": _BINARY_SHA256,
        },
    }
    return digest(canonical(materials))


def _unknown_distro(distro):
    return distro is None or (
        type(distro) is dict
        and distro.keys() == {"id", "versionID"}
        and all(value in (None, "") for value in distro.values())
    )


def _inventory_digest(observation):
    packages = observation.get("packages")
    types = observation.get("package_types")
    if (
        observation.keys()
        != {"image_id", "status", "scope", "distro", "packages", "package_count", "package_types"}
        or observation["status"] != "inconclusive"
        or observation["scope"] != "package-observation-not-application-coverage"
        or not _unknown_distro(observation["distro"])
        or type(observation["package_count"]) is not int
        or observation["package_count"] != _COUNT
        or type(types) is not dict
        or types != {"go-module": _COUNT}
        or type(types["go-module"]) is not int
        or type(packages) is not list
        or len(packages) != _COUNT
    ):
        raise Rejected(_MISMATCH)
    rows = []
    for p in packages:
        if (
            type(p) is not dict
            or p.keys() != {"type", "name", "version", "foundBy", "paths"}
            or p["type"] != "go-module"
            or p["foundBy"] != "go-module-binary-cataloger"
            or p["paths"] not in ([_BINARY], [_OPERATOR])
            or any(type(p[k]) is not str or not 1 <= len(p[k]) <= 1024 for k in ("name", "version"))
        ):
            raise Rejected(_MISMATCH)
        rows.append([p["type"], p["name"], p["version"], p["foundBy"], p["paths"]])
    return digest(canonical(sorted(rows)))


def resolve(observation, reference):
    """Return one path-bound supplemental mapping, or None for another valid config ID."""
    config = observation.get("image_id") if type(observation) is dict else None
    if type(config) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", config) is None:
        raise Rejected("image_audit_cilium_operator_config_invalid")
    if config != CONFIG:
        return None
    if type(reference) is not str or reference != REFERENCE:
        raise Rejected("image_audit_cilium_operator_reference_mismatch")
    if _inventory_digest(observation) != _FULL_ROWS_SHA256:
        raise Rejected(_MISMATCH)
    return {
        "schema_version": 1,
        "scope": "cilium-operator-supplemental-mapping",
        "image_config_id": CONFIG,
        "observed_reference": REFERENCE,
        "index_digest": _INDEX,
        "manifest_digest": _MANIFEST,
        "full_rows_sha256": _FULL_ROWS_SHA256,
        "proof_digest": proof_digest(),
        "source_revision": _SOURCE_REVISION,
        "rebuild_run_id": _RUN,
        "instances": [
            {
                "binary_path": _BINARY,
                "binary_sha256": _BINARY_SHA256,
                "module": _MODULE,
                "observed_version": "UNKNOWN",
                "version": _VERSION,
            }
        ],
        "coordinates": [list(pair) for pair in coordinates()],
    }
