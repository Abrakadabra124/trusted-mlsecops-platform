"""Source-derived scan coordinates for the patched linux/amd64 etcd candidate.

Run 44960577583 printed identical complete go version -m transcripts and ELF
hashes from two builds. Hash each transcript from /elf/<name>: through the last
build line, including blank lines, original tabs, trailing whitespace and LF.
Hash dep/=> graphs as in the workflow (awk fields 1..4, spaces, LF).
For Syft use each main verbatim (+dirty), local => (devel) as UNKNOWN under the
dependency name, and one stdlib row per binary from its toolchain header.

The pinned base manifest selects 13 compressed layers. Config diff_ids bind the
uncompressed tar streams. Its six dpkg records each have a status, md5sums and
copyright location. /etc/debian_version is 13.7. Hash the multiset of complete
[type, name, version, foundBy, paths] rows with SHA256(canonical(sorted(rows))).

Upstream Go files, including tests, were compared by module-relative path and
bytes from the commit archive and each versioned proxy ZIP, excluding nested
Go modules. The recipe changes go.mod/go.sum in eight directories. The seven
release coordinates cover unchanged Go source; actual linked versions of
external dependencies are independently bound in the complete inventory.
"""

import re
from typing import NamedTuple

from mlsecops.contracts import Rejected, canonical, digest

PROFILE = "etcd-patched-supplemental"
# Publication run 44962900166 verified this single-platform manifest and config.
_MANIFEST = "sha256:1d1803f6520e4a8f35a3ee71972cd3d38b205eeb041d9340f500877ce3a06ebe"
REFERENCE = "ghcr.io/abrakadabra124/trusted-mlsecops-platform/etcd@" + _MANIFEST
CONFIG = "sha256:b58a5d62eedb953d96c32200fcfafd40928b7514b40a32667c1f2fc4d8265976"

_RECIPE_SHA256 = "2c2ef58b4f8eeb484d24c0bb1d55b91d9d26fd2e49a1185153bbe8511a2f5f2d"
_REVISION = "0689586e360e2c6b46f95ad5634c25d5fa1683db"
_VERSION = "v3.6.17"
_DIRTY = _VERSION + "+dirty"
_TYPES = {"deb": 6, "go-module": 148}
_DISTRO = {"id": "debian", "versionID": "13.7"}
_FULL_ROWS_SHA256 = "3009716cb46e683a5826568ade37aa6760ffe4ded64c7066b7d6a5e1154c1c62"
_STATIC_PROOF_SHA256 = "5b34874ca8ce634eedf121f9b9ecd356292caad949d2d51e77916c2a94ea6248"
_MISMATCH = "image_audit_patched_etcd_inventory_mismatch"


class _Source(NamedTuple):
    directory: str
    pristine_zip_sha256: str
    pristine_go_mod_sha256: str
    patched_go_mod_sha256: str
    go_files: int
    go_files_sha256: str


# go_files_sha256 hashes canonical(sorted([relative_path, SHA256(file_bytes)])).
_SOURCES = {
    "go.etcd.io/etcd/api/v3": _Source(
        "api",
        "8d2a44f5425a7e09e134694e0f9183cf4996053503feae6c716b31892f1683d5",
        "36392a2a47fc435230dea94b98f8c28c6ac62ca58a11c2d26f79e9ed2b7aa7c5",
        "b35df1e8bf6e190ce4a001aed416677eaa07b782f2765ea14d2ea68e83a0d932",
        17,
        "70f4c0f7cfa9f841d8edd2812dee95863e8dd40a302041629d315e0136972c04",
    ),
    "go.etcd.io/etcd/client/pkg/v3": _Source(
        "client/pkg",
        "eb95a2c65a270f75fd0cbaa434967ba33a58b7ed18896f945f84f1110e0aadfc",
        "02d26b3da0d9bb03dee55a2c7fcae0471015c972b3938200bba9d91fca2ac369",
        "cbd10d8d4656951ad4b5f76e6c7e069cbdfa8d9c202f5e5236a05ad1f3f0d507",
        96,
        "c630c6d24dc9d505bdc227df157bc0090f28ba9f6f3b2cb77989bd8d544b88b7",
    ),
    "go.etcd.io/etcd/client/v3": _Source(
        "client/v3",
        "2e3a260a22aa9d0b2bd6c4964726e24a7d474cbb0a6cddad4f843e40453cad90",
        "db5a60b124778be37b6262c0a9530c7a788facdf920854e80512b5b623ca30fe",
        "75f60d3f285be9569cf13078076f20be0d8e42d9dbe49ff2eb6b6febf1f80c0e",
        82,
        "f8b5029061764e73fb610c6cd4f2c22b005ce5cfc568109b79486831c89ec80d",
    ),
    "go.etcd.io/etcd/etcdctl/v3": _Source(
        "etcdctl",
        "72f9c6c8ce5355b2f267b64ccdc4b6769d88f654899f8cbdfbb85e24cc55ba02",
        "e6feeb32590000b828cd210a6d9babd974c050b7508e25f7d3a1fd56a2122692",
        "d9c2c137121db6ab826bb6ac01b4512cf45922809f84c3f33100e2da0ba079d8",
        38,
        "8622dfdd210674b2deb3d0aac56e71e22b0fb4a0d4bc66d207b2f1c8ace4aef9",
    ),
    "go.etcd.io/etcd/etcdutl/v3": _Source(
        "etcdutl",
        "c40f162413ca1be8d4db9bcd2f8c4d9ab25f93c861d4e11e7cb5a5a0b984575d",
        "3cc3833032d3e30f71f88178c5a23e904194735d967a8907deb6a6b857af6919",
        "6c77ba6144d9931abe2e876570fca45946e1c88aebe3ebb838a1b913a495f045",
        19,
        "5f56a9e25ce6ddf649b7b1afbbb9e94f607e4f0f925b5df94db395b2950f48e5",
    ),
    "go.etcd.io/etcd/pkg/v3": _Source(
        "pkg",
        "cceb97869a0c0e6ca331562204ad708b843d22b1d00d7a8502c033efdf4ee7a6",
        "8a6f6031b25c065f47812d9e7f1eaca970025005b45e2c2176a0214589bf650d",
        "4f3ae9ac7431eff982f0fd9d7136c8d29fba0d9ffbbafec32f079a2798bede36",
        84,
        "f0496c12dde956cb5bd08a153bbbbee8756591322939837a3347f950ca5e23a5",
    ),
    "go.etcd.io/etcd/server/v3": _Source(
        "server",
        "19805fbbd5aaae68d5f8ccd885ad39c8302238249f149448f5f314ee54e93b4d",
        "9bb520ead1a25e0eaff722173bac6b171b2de4abc345a1f6053ac63c264af1bb",
        "5a244f2e291abffee05f653760ef4aea7602f5c3aa4267ac3599c979a74cede6",
        394,
        "4771ecc19a5709f6ea6cb09d610c31aa1900b566a0985071cbd8a494d391ccff",
    ),
}


class _Binary(NamedTuple):
    sha256: str
    transcript_sha256: str
    graph_sha256: str
    rows: int
    main: str
    replacements: tuple[str, ...]


_COMMON = (
    "go.etcd.io/etcd/api/v3",
    "go.etcd.io/etcd/client/pkg/v3",
    "go.etcd.io/etcd/client/v3",
    "go.etcd.io/etcd/pkg/v3",
)
_BINARIES = {
    "/usr/local/bin/etcd": _Binary(
        "2dce8a9457a6a88711b6382fca5cfebe79868c2d502aba40f20c1d0b1e62aad1",
        "d371b7b5731e630aa85e9b6f698f5643d804c40e27e7fb13f45a0c63fc3f7396",
        "bc8b2f9d68efa35a9c5c48cb46e1f454988f2b94cf85fe5ec96ea9a7abb59327",
        64,
        "go.etcd.io/etcd/server/v3",
        _COMMON,
    ),
    "/usr/local/bin/etcdctl": _Binary(
        "65a9ffbe081ea59a88d61e8daa4e1bc6a9e00b1e2da8efa8d628dc40fa5cf20c",
        "fbaff6b13fe7758c48f8f80435e221dd7c1a432e7ca6963d21d2ce8bdbdb192c",
        "21ba09501b771b6843f65c8a146b7a74f919318e482584a48a30e84f0c4aff91",
        33,
        "go.etcd.io/etcd/etcdctl/v3",
        _COMMON,
    ),
    "/usr/local/bin/etcdutl": _Binary(
        "769a514b3e305dfacd1c0781d74fb41d065ab307cf60467a8c8232e2bb5d8fc4",
        "d46e8a0f591c0a60165a4159116b41c492bbcfaf5a025c678cebe5c8557d9bf8",
        "50541f960943d7f5f00c9a5f2fb69b28920eeae9a5ac9608b9aface9775494f7",
        51,
        "go.etcd.io/etcd/etcdutl/v3",
        (*_COMMON, "go.etcd.io/etcd/server/v3"),
    ),
}


def _static_materials():
    return {
        "profile": PROFILE,
        "platform": "linux/amd64",
        "recipe_sha256": _RECIPE_SHA256,
        "upstream_revision": _REVISION,
        "upstream_archive_sha256": "a06073d4041092c4892bcf56a810d69d59a29232d1050dfb3fe97ad69bc3bb71",
        # SHA256(canonical(sorted([path, pristine_sha256, patched_sha256] for all 16 files))).
        "module_manifest_changes_sha256": "58ac78645314cbae9f9d2de8126fb988210f052fdc28b684e15e32173a0df3f7",
        "source_modules": {name: src._asdict() for name, src in _SOURCES.items()},
        "scan_version": _VERSION,
        "observed_main_version": _DIRTY,
        "go_version": "go1.26.11",
        "binary_receipt_run": "44960577583",
        "binary_receipt_commit": "b89194081bd66fae003e8ff4dc892696b1876285",
        "binaries": {path: binary._asdict() for path, binary in _BINARIES.items()},
        "base_manifest": "gcr.io/distroless/static-debian13@sha256:d03c145fad326bff275ec4106475ed8310426caf709decd9f8cbc494af59bc18",
        "base_config": "sha256:df4fa55a70978584dff116efa35fdc03d13ba60770b4fc60b4a0982e814f898d",
        "dpkg_records_sha256": "b2e20b1b33cf0423b3ccc8c788f94020e12f30610977c93e1ad5d373fad5cc88",
        "distro": _DISTRO,
        "package_types": _TYPES,
        "full_rows_sha256": _FULL_ROWS_SHA256,
    }


def proof_digest() -> str:
    if (
        type(REFERENCE) is not str
        or not re.fullmatch(
            r"ghcr\.io/(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)+[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}",
            REFERENCE,
        )
        or any(
            type(pin) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin)
            for pin in (CONFIG, _MANIFEST)
        )
    ):
        raise Rejected("image_audit_patched_etcd_publication_unbound")
    if digest(canonical(_static_materials())) != _STATIC_PROOF_SHA256:
        raise Rejected("image_audit_patched_etcd_proof_mismatch")
    return digest(
        canonical(
            {
                "static_proof": _STATIC_PROOF_SHA256,
                "reference": REFERENCE,
                "manifest": _MANIFEST,
                "config": CONFIG,
            }
        )
    )


def coordinates() -> tuple[tuple[str, str], ...]:
    proof_digest()
    return tuple((module, _VERSION) for module in sorted(_SOURCES))


def validate_coordinate(module, version) -> str:
    allowed = coordinates()
    if type(module) is not str or type(version) is not str or (module, version) not in allowed:
        raise Rejected("image_audit_patched_etcd_coordinate_invalid")
    return f"pkg:golang/{module}@{version}"


def _verify_inventory(observation):
    fields = ("type", "name", "version", "foundBy")
    if (
        observation.keys()
        != {"image_id", "status", "scope", "distro", "package_count", "package_types", "packages"}
        or observation["status"] != "inconclusive"
        or observation["scope"] != "package-observation-not-application-coverage"
        or observation["distro"] != _DISTRO
        or type(observation["package_types"]) is not dict
        or observation["package_types"] != _TYPES
        or any(type(n) is not int for n in observation["package_types"].values())
        or type(observation["package_count"]) is not int
        or observation["package_count"] != sum(_TYPES.values())
        or type(observation["packages"]) is not list
        or len(observation["packages"]) != observation["package_count"]
    ):
        raise Rejected(_MISMATCH)
    rows = []
    for p in observation["packages"]:
        if (
            type(p) is not dict
            or p.keys() != {*fields, "paths"}
            or any(type(p[k]) is not str or not 1 <= len(p[k]) <= 1024 for k in fields)
            or type(p["paths"]) is not list
            or not 1 <= len(p["paths"]) <= 3
            or any(type(x) is not str or not 1 <= len(x) <= 1024 for x in p["paths"])
        ):
            raise Rejected(_MISMATCH)
        rows.append([*(p[k] for k in fields), p["paths"]])
    if digest(canonical(sorted(rows))) != _FULL_ROWS_SHA256:
        raise Rejected(_MISMATCH)


def resolve(observation, reference):
    """Require the published reference/config and the independently expected full inventory."""
    proof = proof_digest()
    config = observation.get("image_id") if type(observation) is dict else None
    if type(config) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", config):
        raise Rejected("image_audit_patched_etcd_config_invalid")
    if config != CONFIG:
        return None
    if type(reference) is not str or reference != REFERENCE:
        raise Rejected("image_audit_patched_etcd_reference_mismatch")
    _verify_inventory(observation)
    instances, mains = [], []
    for path, binary in _BINARIES.items():
        binding = {"binary_path": path, "binary_sha256": binary.sha256, "version": _VERSION}
        mains.append({**binding, "module": binary.main, "observed_version": _DIRTY})
        for module in binary.replacements:
            instances.append(
                {
                    **binding,
                    "module": module,
                    "observed_version": "UNKNOWN",
                    "replace_path": "../" + _SOURCES[module].directory,
                    "replace_version": "(devel)",
                }
            )
    return {
        "schema_version": 1,
        "scope": "etcd-patched-supplemental-mapping",
        "image_config_id": CONFIG,
        "observed_reference": REFERENCE,
        "index_digest": None if REFERENCE.endswith("@" + _MANIFEST) else REFERENCE.split("@")[1],
        "manifest_digest": _MANIFEST,
        "full_rows_sha256": _FULL_ROWS_SHA256,
        "source_revision": _REVISION,
        "proof_digest": proof,
        "instances": instances,
        "main_modules": mains,
        "coordinates": [list(pair) for pair in coordinates()],
    }
