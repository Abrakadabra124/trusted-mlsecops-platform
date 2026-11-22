"""Partial Go provenance for Cilium Agent 1.20.5 linux/amd64.

Run 44959047516, runtime-005: five verified layers, 124 installed dpkg records
and 823 mod/dep/stdlib rows in 13 ELF files, including both dirty main modules.
Compare every cataloger, location and duplicate, and the normalized envelope.
The four path-specific rebuilds authorize three supplemental Go inputs only.
Five other native executables have neither Go buildinfo nor dpkg ownership.
"""

import re
from typing import NamedTuple

from mlsecops.contracts import Rejected, canonical, digest
from scripts.image_audit_contract import exact_observation_matches

PROFILE = "cilium-agent-go-supplemental"
_INDEX = "sha256:aa72499f075ad729947ea91b026218aceba24f1a8e4534bf36b8368c7c561526"
REFERENCE = "quay.io/cilium/cilium@" + _INDEX
CONFIG = "sha256:33f1b95a921dd4ed3acfb9a7fbaa003f51bd221295e6715c7904682d11525264"
_MANIFEST = "sha256:a54ced05354670afb7fecd075e91130dff5cca16518da7ff3d1ef093c5c2d0ae"
_COUNT = 947
_ROWS = "8a4384e7221fd5a9f50e63509d94fd47f8e416d09f530a7b8a7c02f2337bc46c"
_ENVELOPE = "809ba6ea32e7d0185c5353f729fe02fda28d39ee9ebc6d2e42fa105972a7787c"
_PROOF_SHA256 = "03dd13d403f2fda6c8b6626e99055327576114a157012793b36b483ccf3003df"
_MISMATCH = "image_audit_cilium_agent_inventory_mismatch"
_CILIUM = "github.com/cilium/cilium"
_CILIUM_REV = "150121410c147fad575ac5dcbce6de923be69042"


class _Main(NamedTuple):
    binary_path: str
    binary_sha256: str
    buildinfo_sha256: str
    module: str
    observed_version: str
    version: str
    source_revision: str
    rebuild_run_id: str
    rebuild_job_id: str


_GOPS = _Main(
    "/usr/bin/gops",
    "80cf2af7f90f1b5f6b515021fea1188a109200febae33b8ebe4b006347a95e3a",
    "a592a04b833d75bd2fadce84e4e47d31e2bbf47ca041927c57bb7867499bbf46",
    "github.com/google/gops",
    "UNKNOWN",
    "v0.3.29",
    "a2d8f7790eac63a6668583a060cb45903410a91b",
    "44953814982",
    "136997375909",
)
_WRAPPER = _Main(
    "/usr/sbin/iptables-wrapper",
    "3eb32c1812e6c31cfd92e323b7840c8f4ae3ee33f3844324b01577ddd743be72",
    "ebb5302433c20b4e717251c63a6efa2854c2b6057eebd2569434fe6021e52e7f",
    "github.com/kubernetes-sigs/iptables-wrappers",
    "UNKNOWN",
    "v0.0.0-20260420133543-bfef9e5087a1",
    "bfef9e5087a198b50a4124bb9ce9d2c7c99025dd",
    "45020196030",
    "137201153917",
)
_DIRTY_MAINS = (
    _Main(
        "/opt/cni/bin/cilium-cni",
        "5dcc388265be382d8a2f7fea3db693088ef79be3b8c9a81f518f2cd91b00e117",
        "4a1658211840c4039c264d51c788d3ceb24adedc7f978043f281e62f3beeabdf",
        _CILIUM,
        "v1.20.5+dirty",
        "v1.20.5",
        _CILIUM_REV,
        "45020758284",
        "137202903438",
    ),
    _Main(
        "/usr/bin/hubble",
        "e51fc3222cf3966eb8478b9e96ff40291947664b4c806b4d5416d3ee7caeca43",
        "e3d1735659ddb2d3493c04968bec5aa3d9ccf5450143a4b3e6a432b3c0c7227e",
        _CILIUM,
        "v1.20.5+dirty",
        "v1.20.5",
        _CILIUM_REV,
        "45020758284",
        "137202903680",
    ),
)
_MAINS = (_GOPS, _WRAPPER, *_DIRTY_MAINS)


class _Receipt(NamedTuple):
    workflow: str
    workflow_sha256: str
    head_sha: str


_RECEIPTS = {
    "44953814982": _Receipt(
        ".github/workflows/cilium-gops-rebuild.yml",
        "887401ace2998b02199df3e9caac210d63871c59c7ca317f8727782811c709d8",
        "145d24cff0687f9aef99d4bf815bc7bc7434af22",
    ),
    "45020196030": _Receipt(
        ".github/workflows/cilium-iptables-wrapper-rebuild.yml",
        "17ee8eb0efd67668457ae9a6e3fde91ddd729554dc6206d3d57d66ed49c81cd8",
        "a62364f09bbdd1cbe3ae731ce835412e3f56cd35",
    ),
    "45020758284": _Receipt(
        ".github/workflows/cilium-agent-main-rebuild.yml",
        "6fc888daa423ed091950956f7faf162d600b975bf2d05c50d5224f63fb0da295",
        "2a8931eebee34c6bc03353942df012fab83c02a9",
    ),
}

# Exact donor linux/amd64 manifests. Each regular file was also hashed in the donor layer.
_ENVOY = "quay.io/cilium/cilium-envoy@sha256:32d2f9dd9981d92b11c8a37abac32f1c9397b3601af17b45b9403ad2bccc7dab"
_LLVM = "quay.io/cilium/cilium-llvm@sha256:db0f2fb57ec816d65a3fa34d69507c6df69595217361377ff854714ecab851d5"
_BPFTOOL = "quay.io/cilium/cilium-bpftool@sha256:427a210be922aecbb5162810ef04296b399bb981cca954bbece60b5057e60641"
_NATIVE_FILES = (
    (
        "/usr/bin/cilium-envoy",
        "2d738902309dc2dd28753ee28a2c80d9dbdb99e2448ad0407bbdcff77cf885f2",
        _ENVOY,
    ),
    (
        "/usr/bin/cilium-envoy-starter",
        "ebf97e60a561d2355c2b6c60e58711d9d879941ad934bdcd11c3a1a59c1f2244",
        _ENVOY,
    ),
    (
        "/usr/local/bin/bpftool",
        "023276e781975b6e4ca5ab3ac39855f831f6132eb57e6e0b141018e92c2aabed",
        _BPFTOOL,
    ),
    (
        "/usr/local/bin/clang",
        "020ef1d00ee2acdc2921b6437f48af6893dd955348d84a20b71a1416f565e3da",
        _LLVM,
    ),
    (
        "/usr/local/bin/llc",
        "c632411ccb7c1b561da2c8238f6a9c7e6bbcead1aa31c1b745385bbf249a40c3",
        _LLVM,
    ),
)


def _native_gaps():
    return [
        {"binary_path": path, "binary_sha256": checksum, "source_manifest": source}
        for path, checksum, source in _NATIVE_FILES
    ]


def coordinates() -> tuple[tuple[str, str], ...]:
    return tuple(sorted({(b.module, b.version) for b in _MAINS}))


def validate_coordinate(module, version) -> str:
    if (
        type(module) is not str
        or type(version) is not str
        or (module, version) not in coordinates()
    ):
        raise Rejected("image_audit_cilium_agent_coordinate_invalid")
    return f"pkg:golang/{module}@{version}"


def proof_digest() -> str:
    materials = {
        "schema_version": 1,
        "profile": PROFILE,
        "platform": "linux/amd64",
        "reference": REFERENCE,
        "manifest": _MANIFEST,
        "config": CONFIG,
        "package_count": _COUNT,
        "full_rows_sha256": _ROWS,
        "observation_envelope_sha256": _ENVELOPE,
        "native_sbom": {
            "run": "44959047516",
            "component": "runtime-005",
            "sha256": "e6760755f0c3a1173caebb4cb6a7c608e8919a8118a9a2164e2c8fd93f496b81",
        },
        "dpkg_status_sha256": "421e5321549ecb7a12a1a3a0a51721eb39e5622d345d6e32b27028da1051ffb8",
        "cilium_dockerfile_sha256": "8364f29b8381273ade0e2f7123bb381bbf0b83b0f329a2a345b1d16efad9b217",
        "runtime_dockerfile_sha256": "0c21f931b801fbe7c48fd9a7f9102896e8da0e20e1ba9ed5884bd951dc81f46f",
        "go_version": "go1.26.11",
        "repository": "Abrakadabra124/trusted-mlsecops-platform",
        "run_attempt": 1,
        "receipts": {run: r._asdict() for run, r in _RECEIPTS.items()},
        "instances": [b._asdict() for b in _MAINS],
        "coordinates": coordinates(),
        "uncovered_native_applications": _native_gaps(),
        "application_coverage_complete": False,
    }
    fingerprint = digest(canonical(materials))
    if fingerprint != _PROOF_SHA256:
        raise Rejected("image_audit_cilium_agent_proof_mismatch")
    return fingerprint


def _matches(observation):
    if not exact_observation_matches(observation, _COUNT, _ENVELOPE):
        return False
    rows = [
        [p["type"], p["name"], p["version"], p["foundBy"], p["paths"]]
        for p in observation["packages"]
    ]
    return digest(canonical(sorted(rows))) == _ROWS


def resolve(observation, reference):
    """Authorize only three supplemental Go coordinates on the exact package observation."""
    config = observation.get("image_id") if type(observation) is dict else None
    if type(config) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", config):
        raise Rejected("image_audit_cilium_agent_config_invalid")
    if config != CONFIG:
        return None
    if type(reference) is not str or reference != REFERENCE:
        raise Rejected("image_audit_cilium_agent_reference_mismatch")
    if not _matches(observation):
        raise Rejected(_MISMATCH)
    return {
        "schema_version": 1,
        "scope": PROFILE + "-mapping",
        "image_config_id": CONFIG,
        "observed_reference": REFERENCE,
        "index_digest": _INDEX,
        "manifest_digest": _MANIFEST,
        "full_rows_sha256": _ROWS,
        "proof_digest": proof_digest(),
        "instances": [b._asdict() for b in _MAINS],
        "coordinates": [list(pair) for pair in coordinates()],
        "application_coverage_complete": False,
        "uncovered_native_applications": _native_gaps(),
    }


def diagnose(observation, reference):
    """Keep the native findings and the diagnostic reason while native applications lack coverage."""
    if type(observation) is not dict or observation.get("image_id") != CONFIG:
        return None
    verified = type(reference) is str and reference == REFERENCE and _matches(observation)
    result = {
        "component": "cilium-agent",
        "scope": "independent-inventory-not-application-coverage",
        "status": "inconclusive",
        "image_config_id": CONFIG,
        "independent_registry_manifest": _MANIFEST,
        "independent_inventory_verified": verified,
        "reason": _MISMATCH,
    }
    if verified:
        result.update(
            reason="image_audit_cilium_agent_application_provenance_incomplete",
            package_count=_COUNT,
            gops_rebuild={
                "binary_path": _GOPS.binary_path,
                "sha256": _GOPS.binary_sha256,
                "run_id": _GOPS.rebuild_run_id,
                "observed_version": _GOPS.observed_version,
                "release": _GOPS.version,
            },
            wrapper_rebuild={
                "binary_path": _WRAPPER.binary_path,
                "sha256": _WRAPPER.binary_sha256,
                "module": _WRAPPER.module,
                "observed_version": _WRAPPER.observed_version,
                "recipe_tag": "v3",
                "revision": _WRAPPER.source_revision,
                "module_version": _WRAPPER.version,
                "run_id": _WRAPPER.rebuild_run_id,
                "run_attempt": 1,
            },
            main_module_rebuilds=[{**b._asdict(), "vcs_modified": True} for b in _DIRTY_MAINS],
            go_proof_digest=proof_digest(),
            uncovered_native_applications=_native_gaps(),
            application_coverage_complete=False,
        )
    return result
