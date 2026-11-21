"""Reviewed provenance for the etcd 3.6.17-0 linux/amd64 supplemental scanner inputs.

The pinned index selects the manifest used by native run 44954907094. Hash both
the compressed and uncompressed layers before reading the final filesystem.
Read mod, dep, => and toolchain records in each ELF and status.d in dpkg.
Project a local (devel) replacement to Syft's UNKNOWN under its dependency name.
Hash sorted [type, name, version, foundBy, paths] rows, preserving multiplicity.

All three ELFs match the upstream release archive. Their clean VCS revision
selects the Git tree. For each local replace, resolve the literal RHS from the
main module directory in that tree, check require, replace and the target's
module directive. At the Go proxy check .info origin, revision and tag, .mod
bytes and the complete .zip file set and bytes against that module's Git files
(excluding nested modules and accounting for the repository LICENSE).
The registry returns scan inputs only. The original observation retains UNKNOWN.
"""

import re
from typing import NamedTuple

from mlsecops.contracts import Rejected, canonical, digest

PROFILE = "etcd-supplemental"
_INDEX = "sha256:f84fa13db51b1458a5a51d7eb3fa303c179dd28f5d337935418a5bae4a305e5f"
_MANIFEST = "sha256:3ced7fbdc4cadcec31ab34a7513bc97be2b70db923e7154e2d88a980016b5e8b"
REFERENCE = "registry.k8s.io/etcd@" + _MANIFEST
CONFIG = "sha256:be2dd319600bac16f542b8e46e1b78511c35a31e46829ee9acc82a83c94aa377"
_REVISION = "0689586e360e2c6b46f95ad5634c25d5fa1683db"
_VERSION = "v3.6.17"
_FULL_ROWS_SHA256 = "96cf1a57ab93e0093a29998a24f67918edf6043226896bc00baba1bad60f7a00"
_PROOF_SHA256 = "464fc8a3327a90fbe8a2985f5f461bdf5c4621d4a80839ed6a211a2b58088bf3"
_MISMATCH = "image_audit_etcd_inventory_mismatch"
_TYPES = {"deb": 6, "go-module": 148}
_DISTRO = {"id": "debian", "versionID": "13.7"}
_TEXT_FIELDS = ("type", "name", "version", "foundBy")

_API = "go.etcd.io/etcd/api/v3"
_CLIENT_PKG = "go.etcd.io/etcd/client/pkg/v3"
_CLIENT = "go.etcd.io/etcd/client/v3"
_CTL = "go.etcd.io/etcd/etcdctl/v3"
_UTL = "go.etcd.io/etcd/etcdutl/v3"
_PKG = "go.etcd.io/etcd/pkg/v3"
_SERVER = "go.etcd.io/etcd/server/v3"


class _Release(NamedTuple):
    source_dir: str
    proxy_tag_dir: str
    info_sha256: str
    mod_sha256: str
    zip_sha256: str
    files: int


# source_dir is the directory containing go.mod. The proxy Origin.Subdir can
# differ under Go's major-version directory layout (client/v3).
_RELEASES = {
    _API: _Release(
        "api",
        "api",
        "87283a65fa554fcc5f2353458aac045582929713ee85b65ce2ea8457878f1332",
        "36392a2a47fc435230dea94b98f8c28c6ac62ca58a11c2d26f79e9ed2b7aa7c5",
        "8d2a44f5425a7e09e134694e0f9183cf4996053503feae6c716b31892f1683d5",
        27,
    ),
    _CLIENT_PKG: _Release(
        "client/pkg",
        "client/pkg",
        "858d7cec3fa20e300221f2b9d920b57d542c7ba3ec7d24c6c6320fab06bd1846",
        "02d26b3da0d9bb03dee55a2c7fcae0471015c972b3938200bba9d91fca2ac369",
        "eb95a2c65a270f75fd0cbaa434967ba33a58b7ed18896f945f84f1110e0aadfc",
        99,
    ),
    _CLIENT: _Release(
        "client/v3",
        "client",
        "e656a668c88ac5a50ca03116ec379e4f1e30028fb954f5e979277b7c1819c304",
        "db5a60b124778be37b6262c0a9530c7a788facdf920854e80512b5b623ca30fe",
        "2e3a260a22aa9d0b2bd6c4964726e24a7d474cbb0a6cddad4f843e40453cad90",
        88,
    ),
    _CTL: _Release(
        "etcdctl",
        "etcdctl",
        "9e7ccf8319b497383912d1425dd9b7593df9fea50eea75b1bf31e697f1e87fb7",
        "e6feeb32590000b828cd210a6d9babd974c050b7508e25f7d3a1fd56a2122692",
        "72f9c6c8ce5355b2f267b64ccdc4b6769d88f654899f8cbdfbb85e24cc55ba02",
        45,
    ),
    _UTL: _Release(
        "etcdutl",
        "etcdutl",
        "ccfe3ac988063739917e5ffbfa0c49022301fef2b63f85d640c6f92376c22418",
        "3cc3833032d3e30f71f88178c5a23e904194735d967a8907deb6a6b857af6919",
        "c40f162413ca1be8d4db9bcd2f8c4d9ab25f93c861d4e11e7cb5a5a0b984575d",
        24,
    ),
    _PKG: _Release(
        "pkg",
        "pkg",
        "84f422735102f40e597d8b4b1d308f37e27b43fd34192169c67d4c93b787be28",
        "8a6f6031b25c065f47812d9e7f1eaca970025005b45e2c2176a0214589bf650d",
        "cceb97869a0c0e6ca331562204ad708b843d22b1d00d7a8502c033efdf4ee7a6",
        105,
    ),
    _SERVER: _Release(
        "server",
        "server",
        "027695ec46d27ad99759f94e6de68fd2b7ce2a1604d225819ebaf905d2f79b8d",
        "9bb520ead1a25e0eaff722173bac6b171b2de4abc345a1f6053ac63c264af1bb",
        "19805fbbd5aaae68d5f8ccd885ad39c8302238249f149448f5f314ee54e93b4d",
        403,
    ),
}


class _Binary(NamedTuple):
    sha256: str
    buildinfo_sha256: str
    main: str
    replaces: tuple[tuple[str, str], ...]


_COMMON = (
    (_API, "../api"),
    (_CLIENT_PKG, "../client/pkg"),
    (_CLIENT, "../client/v3"),
    (_PKG, "../pkg"),
)
_BINARIES = {
    "/usr/local/bin/etcd": _Binary(
        "b185e71ff67f3f35661fea57967bca11225b3e6268288fccae0cf5d23aecf8c8",
        "d22982a53e033ed7d67806ff13140d945cb1baeb4ff534aca23feaee807f5d56",
        _SERVER,
        _COMMON,
    ),
    "/usr/local/bin/etcdctl": _Binary(
        "fc2721bb95ba175a550b6da208b58822c104d58b9e1659a8b0b4897f080b533c",
        "816848a77fc736d07f8f229f9282d6c519b823879012ae851142605552b72c3d",
        _CTL,
        _COMMON,
    ),
    "/usr/local/bin/etcdutl": _Binary(
        "6ed0d9dbc0cc24274461feffca5badbeed23e10144b50fe983ef86ea0b25e6cc",
        "048b12bae0330405a02dd2403edb7a1f1ad4787c5488281b600658b0ba11befb",
        _UTL,
        (*_COMMON, (_SERVER, "../server")),
    ),
}


def coordinates() -> tuple[tuple[str, str], ...]:
    """Deduplicate only the scan inputs, after binding replacements to each ELF."""
    proof_digest()
    return tuple(
        sorted({(module, _VERSION) for b in _BINARIES.values() for module, _ in b.replaces})
    )


def validate_coordinate(module, version) -> str:
    if (
        type(module) is not str
        or type(version) is not str
        or (module, version) not in coordinates()
    ):
        raise Rejected("image_audit_etcd_coordinate_invalid")
    return f"pkg:golang/{module}@{version}"


def proof_digest() -> str:
    materials = {
        "schema_version": 1,
        "profile": PROFILE,
        "platform": "linux/amd64",
        "reference": REFERENCE,
        "index_digest": _INDEX,
        "manifest_digest": _MANIFEST,
        "config": CONFIG,
        "package_types": _TYPES,
        "distro": _DISTRO,
        "full_rows_sha256": _FULL_ROWS_SHA256,
        # SHA-256 of canonical(sorted([package, version, SHA-256(status.d bytes)])).
        "dpkg_records_sha256": "b2e20b1b33cf0423b3ccc8c788f94020e12f30610977c93e1ad5d373fad5cc88",
        "go_version": "go1.26.11",
        "binaries": {path: b._asdict() for path, b in _BINARIES.items()},
        "source": {
            "repository": "https://github.com/etcd-io/etcd",
            "revision": _REVISION,
            "vcs_modified": False,
            "commit_archive_sha256": "a06073d4041092c4892bcf56a810d69d59a29232d1050dfb3fe97ad69bc3bb71",
            "linux_amd64_release_asset_id": 765311545,
            "release_tar_gz_sha256": "5c6365e03d0c81f605458f3f9a115f6daaebca08d1fb42d3ab0f1a38fd30909c",
        },
        "go_proxy": "https://proxy.golang.org",
        "version": _VERSION,
        "modules": {module: release._asdict() for module, release in _RELEASES.items()},
        "native_observation": {
            "run_id": "44954907094",
            "component": "runtime-008",
            "sbom_digest": "239cdf5da2a7f80ca269c5fa2fe3be740d8cf1ab48d9356e7b57d241dec2d5b4",
            "observation_sha256": "a1239553042f660e59a23ad426aeacfa8eb5c3c7cd1da2284940a43e0fedc355",
        },
    }
    fingerprint = digest(canonical(materials))
    if fingerprint != _PROOF_SHA256:
        raise Rejected("image_audit_etcd_proof_mismatch")
    return fingerprint


def _verify_inventory(observation):
    packages = observation.get("packages")
    counts = observation.get("package_types")
    if (
        observation.keys()
        != {"image_id", "status", "scope", "distro", "package_count", "package_types", "packages"}
        or observation["status"] != "inconclusive"
        or observation["scope"] != "package-observation-not-application-coverage"
        or observation["distro"] != _DISTRO
        or type(counts) is not dict
        or counts != _TYPES
        or any(type(n) is not int for n in counts.values())
        or type(observation["package_count"]) is not int
        or observation["package_count"] != sum(_TYPES.values())
        or type(packages) is not list
        or len(packages) != observation["package_count"]
    ):
        raise Rejected(_MISMATCH)
    rows = []
    for p in packages:
        if (
            type(p) is not dict
            or p.keys() != {*_TEXT_FIELDS, "paths"}
            or any(type(p[k]) is not str or not 1 <= len(p[k]) <= 1024 for k in _TEXT_FIELDS)
            or type(p["paths"]) is not list
            or not 1 <= len(p["paths"]) <= 3
            or any(type(path) is not str or not 1 <= len(path) <= 1024 for path in p["paths"])
        ):
            raise Rejected(_MISMATCH)
        rows.append([p["type"], p["name"], p["version"], p["foundBy"], p["paths"]])
    if digest(canonical(sorted(rows))) != _FULL_ROWS_SHA256:
        raise Rejected(_MISMATCH)


def resolve(observation, reference):
    """Bind the complete native observation before returning path-specific scanner inputs."""
    config = observation.get("image_id") if type(observation) is dict else None
    if type(config) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", config) is None:
        raise Rejected("image_audit_etcd_config_invalid")
    if config != CONFIG:
        return None
    if type(reference) is not str or reference != REFERENCE:
        raise Rejected("image_audit_etcd_reference_mismatch")
    _verify_inventory(observation)
    scan_coordinates = coordinates()
    main_modules = []
    instances = []
    for path, binary in _BINARIES.items():
        binding = {"binary_path": path, "binary_sha256": binary.sha256, "version": _VERSION}
        main_modules.append({**binding, "module": binary.main, "observed_version": _VERSION})
        for module, target in binary.replaces:
            instances.append(
                {
                    **binding,
                    "module": module,
                    "observed_version": "UNKNOWN",
                    "replace_path": target,
                    "replace_version": "(devel)",
                }
            )
    return {
        "schema_version": 1,
        "scope": "etcd-supplemental-mapping",
        "image_config_id": CONFIG,
        "observed_reference": REFERENCE,
        "index_digest": _INDEX,
        "manifest_digest": _MANIFEST,
        "full_rows_sha256": _FULL_ROWS_SHA256,
        "source_revision": _REVISION,
        "proof_digest": _PROOF_SHA256,
        "instances": instances,
        "main_modules": main_modules,
        "coordinates": [list(pair) for pair in scan_coordinates],
    }
