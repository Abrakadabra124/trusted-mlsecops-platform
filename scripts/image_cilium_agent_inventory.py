"""Cilium 1.20.5 linux/amd64 inventory diagnostic for native run 44959047516.

The index selects the platform manifest and config below. All five compressed
layers and uncompressed diff IDs were verified. The final dpkg status file
(SHA-256 421e5321549ecb7a12a1a3a0a51721eb39e5622d345d6e32b27028da1051ffb8)
has 124 installed packages. Include their status, info and copyright locations
(including multiarch md5sums/conffiles and resolved doc symlinks).
13 ELF .go.buildinfo sections supply 823 main/dep/stdlib rows, no replacements.
For /cni/loopback the linker setting buildversion.BuildVersion is v1.10.0.
Preserve the two (devel) -> UNKNOWN projections and both v1.20.5+dirty versions.
The sorted [type,name,version,foundBy,paths] rows hash to
8a4384e7221fd5a9f50e63509d94fd47f8e416d09f530a7b8a7c02f2337bc46c.
The observation pin additionally binds the native envelope. These rows cover
Syft's package catalog; the copied native Envoy binaries have no Go inventory.
"""

from scripts.image_audit_contract import exact_observation_matches

REFERENCE = (
    "quay.io/cilium/cilium@sha256:aa72499f075ad729947ea91b026218aceba24f1a8e4534bf36b8368c7c561526"
)
CONFIG = "sha256:33f1b95a921dd4ed3acfb9a7fbaa003f51bd221295e6715c7904682d11525264"
_MANIFEST = "sha256:a54ced05354670afb7fecd075e91130dff5cca16518da7ff3d1ef093c5c2d0ae"
_OBSERVATION_PIN = (947, "809ba6ea32e7d0185c5353f729fe02fda28d39ee9ebc6d2e42fa105972a7787c")


def diagnose(observation, reference):
    """Explain the remaining source proof only for the exact catalogued agent."""
    if type(observation) is not dict or observation.get("image_id") != CONFIG:
        return None
    verified = reference == REFERENCE and exact_observation_matches(observation, *_OBSERVATION_PIN)
    result = {
        "component": "cilium-agent",
        "scope": "independent-inventory-not-application-coverage",
        "status": "inconclusive",
        "image_config_id": CONFIG,
        "independent_registry_manifest": _MANIFEST,
        "independent_inventory_verified": verified,
        "reason": "image_audit_cilium_agent_inventory_mismatch",
    }
    if verified:
        result.update(
            reason="image_audit_cilium_agent_application_provenance_incomplete",
            package_count=observation["package_count"],
            gops_rebuild={
                "binary_path": "/usr/bin/gops",
                "sha256": "80cf2af7f90f1b5f6b515021fea1188a109200febae33b8ebe4b006347a95e3a",
                "run_id": "44953814982",
                "observed_version": "UNKNOWN",
                "release": "v0.3.29",
            },
            wrapper_rebuild={
                "binary_path": "/usr/sbin/iptables-wrapper",
                "sha256": "3eb32c1812e6c31cfd92e323b7840c8f4ae3ee33f3844324b01577ddd743be72",
                "module": "github.com/kubernetes-sigs/iptables-wrappers",
                "observed_version": "UNKNOWN",
                "recipe_tag": "v3",
                "revision": "bfef9e5087a198b50a4124bb9ce9d2c7c99025dd",
                "module_version": "v0.0.0-20260420133543-bfef9e5087a1",
                "run_id": "45020196030",
                "run_attempt": 1,
            },
            unverified_main_modules=[
                {
                    "module": "github.com/cilium/cilium",
                    "binary_path": path,
                    "sha256": checksum,
                    "observed_version": "v1.20.5+dirty",
                    "vcs_revision": "150121410c147fad575ac5dcbce6de923be69042",
                    "vcs_modified": True,
                }
                for path, checksum in (
                    (
                        "/opt/cni/bin/cilium-cni",
                        "5dcc388265be382d8a2f7fea3db693088ef79be3b8c9a81f518f2cd91b00e117",
                    ),
                    (
                        "/usr/bin/hubble",
                        "e51fc3222cf3966eb8478b9e96ff40291947664b4c806b4d5416d3ee7caeca43",
                    ),
                )
            ],
        )
    return result
