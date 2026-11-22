import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from mlsecops import local_path_pin
from mlsecops.contracts import Rejected, canonical, digest

SYFT_VERSION = "1.54.1"
GRYPE_VERSION = "0.120.1"
SEVERITIES = ("Negligible", "Low", "Medium", "High", "Critical", "Unknown")
DISTRO_VERSIONS = {"debian": {"12", "13"}, "wolfi": {"20230201"}}
WOLFI_OS_PACKAGES = {"glibc-2.44", "python-3.12", "postgresql-18"}
GO_CONTROLS = {
    "module": ("golang.org/x/net", "v0.16.0"),
    "stdlib": ("stdlib", "go1.20.9"),
}
GO_CONTROL_ADVISORIES = {"GO-2023-2102", "CVE-2023-39325", "GHSA-4374-p667-p6c8"}
# Keep these upstream identities fixed for paired scans and rollback.
COREDNS_MANIFEST = "sha256:3429e3bbffb1e839470c4a3541d4d78aca84a1394c75a539d0200c58c63196ac"
COREDNS_CONFIG = "sha256:881cbdacb8c168aaba50f10b1458f36d1b976c5a856e72d3589bc9cd262f3442"
COREDNS_REPOSITORY = "registry.k8s.io/coredns/coredns"
PROJECT_COREDNS_PREFIX = "ghcr.io/abrakadabra124/trusted-mlsecops-platform"
PUBLISHED_COREDNS_PROFILE = "coredns-published"


@dataclass(frozen=True)
class CoreDNSPin:
    image_repository: str  # kubeadm DNS prefix, before it appends /coredns
    tag: str
    manifest: str
    config: str

    def __post_init__(self):
        tag_pattern = (
            r"1\.15\.0-deps-r1-(?!0{40}$)[0-9a-f]{40}"
            if self.image_repository == PROJECT_COREDNS_PREFIX
            else r"v1\.15\.0"
        )
        if (
            self.image_repository not in (PROJECT_COREDNS_PREFIX, "registry.k8s.io/coredns")
            or not isinstance(self.tag, str)
            or not re.fullmatch(tag_pattern, self.tag)
            or (
                self.image_repository == PROJECT_COREDNS_PREFIX
                and (self.config == COREDNS_CONFIG or self.manifest == COREDNS_MANIFEST)
            )
            or self.config == self.manifest
            or any(
                not isinstance(value, str)
                or not re.fullmatch(r"sha256:(?!0{64}$)[0-9a-f]{64}", value)
                for value in (self.manifest, self.config)
            )
        ):
            raise Rejected("invalid_coredns_pin")

    @property
    def reference(self):
        return f"{self.image_repository}/coredns@{self.manifest}"

    @property
    def spec_image(self):
        return f"{self.image_repository}/coredns:{self.tag}@{self.manifest}"


UPSTREAM_COREDNS = CoreDNSPin(
    COREDNS_REPOSITORY.rsplit("/", 1)[0], "v1.15.0", COREDNS_MANIFEST, COREDNS_CONFIG
)
COREDNS_REFERENCE = UPSTREAM_COREDNS.reference
COREDNS_SPEC_IMAGE = UPSTREAM_COREDNS.spec_image
# Producer 45027909018, public linux/amd64 readback in publisher 45029534828.
PUBLISHED_COREDNS = CoreDNSPin(
    PROJECT_COREDNS_PREFIX,
    "1.15.0-deps-r1-75ed1469660bb69bf0fc2157b9b3e4ed38993910",
    "sha256:907db90829056dc7adc96851cedd0ffef7d82c916d92a935aa140c58333a7424",
    "sha256:d2c1556be74ac5be00316f062c317b9a964cc5da83d7d1141b2ce5b9083ca7f6",
)


def runtime_coredns():
    return PUBLISHED_COREDNS or UPSTREAM_COREDNS


# Run 45024790177, 197 Go and 5 dpkg rows. Full canonical observation except
# image_id, which is checked separately against the published registry pin.
_COREDNS_REBUILD_INVENTORY = "59f58183e23f2f9d0dd1bf820cd7546f8191c82912faa93e23200950882fb325"

# config -> (platform reference, row count, SHA-256 of canonical full observation
# with packages sorted by canonical JSON). v1.14.7 is from native run 44954907094.
# v1.15.0 is independently projected from verified ELF and dpkg bytes (fixture).
_COREDNS_INVENTORIES = {
    COREDNS_CONFIG: (
        COREDNS_REFERENCE,
        202,
        "0eec5fe63064753a5e3d8bcd63f79fff02dfc18e4bb2a542bc449b694ee3f5b5",
    ),
    "sha256:97efff2babf85310d6f87bd969ac64d7006bbbadb147c90579d68d57634750f4": (
        COREDNS_REPOSITORY
        + "@sha256:2329f5f0e7e79fbe56dcdf11ecc4337ee2476bb251095bc275fe9461cb88a55b",
        198,
        "1c8a9c4801aa11930f1ac71a7cee398956f5a4ebc4d1e47f0e78a53789dbd013",
    ),
}
LOCAL_PATH_CONFIG = "sha256:c82008e2cd0186ef96bfd05d6b49d3286768fae5bd7a961f70bd485a3785c006"
# Independent binary build info + dpkg rows, with registry layers/config verified.
# Provenance and all 61 rows: image_system_inventory_fixture.py.
LOCAL_PATH_PACKAGES_SHA256 = "552dfdc00d5981e6bc68ddae319e8d9c4df0aef7d0cf969cc40701f1d369ee91"
PUBLISHED_LOCAL_PATH_PROFILE = "local-path-provisioner-published"
# Run 45048228181, proposal.packages_sha256 = 89714093ff769e817e6c6d7a4c2f47a2bd335b2f8802c573adbe37f63298287b.
# Full observe_packages envelope, including config, distro, counts and all 59 sorted rows.
_PUBLISHED_LOCAL_PATH_INVENTORY = "99240cc10cd88abc28453670623c40c60f0abdc51433b3c2e4ecb391f49bde4d"


def published_local_path_target(reference, config):
    """Reserve this repository and config even when the observed binding is incorrect."""
    return config == local_path_pin.PUBLISHED_CONFIG or (
        isinstance(reference, str)
        and reference.partition("@")[0].partition(":")[0] == local_path_pin.REPOSITORY
    )


def published_local_path_identity(reference, config):
    return (
        config == local_path_pin.PUBLISHED_CONFIG
        and isinstance(reference, str)
        and reference == local_path_pin.PUBLISHED_REFERENCE
        and reference.startswith(local_path_pin.REPOSITORY + "@")
        and re.fullmatch(r"sha256:(?!0{64}$)[a-f0-9]{64}", reference.partition("@")[2]) is not None
        and reference.partition("@")[2] != config
    )


def published_local_path_matches(observation, reference):
    return (
        isinstance(observation, dict)
        and published_local_path_identity(reference, observation.get("image_id"))
        and exact_observation_matches(observation, 59, _PUBLISHED_LOCAL_PATH_INVENTORY)
    )


def local_path_inventory_matches(observation):
    """Recognize exact application coverage, never override vulnerability findings."""
    try:
        if observation.get("image_id") != LOCAL_PATH_CONFIG or observation.get("distro") != {
            "id": "debian",
            "versionID": "13.6",
        }:
            return False
        rows = []
        for package in observation["packages"]:
            if package["type"] == "go-module":
                if package["foundBy"] != "go-module-binary-cataloger" or package["paths"] != [
                    "/usr/local/bin/local-path-provisioner"
                ]:
                    return False
            elif (
                package["type"] != "deb"
                or package["foundBy"] != "dpkg-db-cataloger"
                or f"/var/lib/dpkg/status.d/{package['name']}" not in package["paths"]
            ):
                return False
            rows.append([package["type"], package["name"], package["version"]])
        return digest(canonical(sorted(rows))) == LOCAL_PATH_PACKAGES_SHA256
    except (KeyError, TypeError, AttributeError):
        return False


def coredns_inventory_matches(observation, reference):
    """Bind the manifest and config to every normalized field, path and duplicate."""
    if type(observation) is not dict or type(observation.get("image_id")) is not str:
        return False
    published = PUBLISHED_COREDNS
    if (
        published is not None
        and published.image_repository == PROJECT_COREDNS_PREFIX
        and reference == published.reference
        and observation["image_id"] == published.config
    ):
        inventory = observation.copy()
        del inventory["image_id"]
        return exact_observation_matches(inventory, 202, _COREDNS_REBUILD_INVENTORY)
    spec = _COREDNS_INVENTORIES.get(observation["image_id"])
    if spec is None or reference != spec[0]:
        return False
    return exact_observation_matches(observation, spec[1], spec[2])


def coredns_coverage_profile(observation, reference):
    if not coredns_inventory_matches(observation, reference):
        return None
    if reference.startswith(PROJECT_COREDNS_PREFIX + "/coredns@"):
        return PUBLISHED_COREDNS_PROFILE
    return "coredns"


def exact_observation_matches(observation, count, checksum):
    """Match the entire normalized observation, disregarding only package order."""
    packages = observation.get("packages")
    if type(packages) is not list or len(packages) != count:
        return False
    if any(type(p) is not dict or type(p.get("paths")) is not list for p in packages):
        return False
    try:
        ordered = {**observation, "packages": sorted(packages, key=canonical)}
        return digest(canonical(ordered)) == checksum
    except (Rejected, RecursionError):
        return False


def observe_packages(sbom, image_id):
    """Project bound package facts without claiming application coverage or scan success."""

    def text(value, empty=False):
        if (
            not isinstance(value, str)
            or (not value and not empty)
            or len(value) > 1024
            or any(ord(char) < 32 or ord(char) > 126 for char in value)
        ):
            raise Rejected("image_audit_package_observation_invalid")
        return value

    try:
        if (
            not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            or sbom["descriptor"]["name"] != "syft"
            or sbom["descriptor"]["version"] != SYFT_VERSION
            or sbom["source"]["type"] != "image"
            or sbom["source"]["metadata"]["imageID"] != image_id
            or not isinstance(sbom["artifacts"], list)
            or len(sbom["artifacts"]) > 4096
        ):
            raise Rejected("image_audit_package_observation_invalid")
        declared = sbom.get("distro")
        if declared is not None and not isinstance(declared, dict):
            raise Rejected("image_audit_package_observation_invalid")
        distro = (
            None
            if declared is None
            else {
                name: text(declared[name], empty=True) if name in declared else None
                for name in ("id", "versionID")
            }
        )
        packages, identifiers = [], set()
        for package in sbom["artifacts"]:
            identifier = text(package["id"])
            if identifier in identifiers:
                raise Rejected("image_audit_package_observation_invalid")
            identifiers.add(identifier)
            locations = package.get("locations", [])
            if not isinstance(locations, list) or len(locations) > 64:
                raise Rejected("image_audit_package_observation_invalid")
            paths = sorted(
                {
                    text(location[key])
                    for location in locations
                    for key in ("path", "accessPath")
                    if key in location
                }
            )
            packages.append(
                {
                    **{
                        name: text(package[name], empty=name == "version")
                        for name in ("name", "version", "type", "foundBy")
                    },
                    "paths": paths,
                }
            )
        return {
            "status": "inconclusive",
            "scope": "package-observation-not-application-coverage",
            "image_id": image_id,
            "distro": distro,
            "package_count": len(packages),
            "package_types": dict(Counter(package["type"] for package in packages)),
            "packages": sorted(
                packages,
                key=lambda package: (
                    package["name"],
                    package["version"],
                    package["type"],
                    package["foundBy"],
                    package["paths"],
                ),
            ),
        }
    except (KeyError, TypeError, AttributeError) as error:
        raise Rejected("image_audit_package_observation_invalid") from error


def database(report, timestamp):
    try:
        descriptor = report["descriptor"]
        status = descriptor["db"]["status"]
        built = datetime.fromisoformat(status["built"].replace("Z", "+00:00"))
        if (
            descriptor["name"] != "grype"
            or descriptor["version"] != GRYPE_VERSION
            or status["valid"] is not True
            or status.get("error")
            or not re.fullmatch(r"v6\.\d+\.\d+", status["schemaVersion"])
            or built.tzinfo is None
            or not timedelta(0) <= timestamp - built <= timedelta(hours=120)
        ):
            raise Rejected("image_audit_database_invalid")
        return {"schema_version": status["schemaVersion"], "built": status["built"]}
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise Rejected("image_audit_database_invalid") from error


def detection_control(report, returncode, timestamp=None):
    database(report, timestamp or datetime.now(UTC))
    try:
        detected = any(
            match["artifact"]["name"] == "urllib3"
            and match["artifact"]["version"] == "1.26.7"
            and match["vulnerability"]["id"] == "GHSA-v845-jxx5-vc9f"
            and match["vulnerability"]["severity"] in {"High", "Critical"}
            for match in report["matches"]
        )
        if type(returncode) is not int or returncode != 2 or not detected:
            raise Rejected("image_audit_detection_control_failed")
    except (KeyError, TypeError) as error:
        raise Rejected("image_audit_detection_control_failed") from error


def wolfi_detection_control(report, returncode, timestamp=None):
    database(report, timestamp or datetime.now(UTC))
    try:
        detected = any(
            match["artifact"]["name"] == "openssl"
            and match["artifact"]["version"] == "3.0.7-r0"
            and match["artifact"]["type"] == "apk"
            and match["vulnerability"]["id"] in {"CVE-2023-0286", "CGA-6vj8-747q-h83f"}
            and match["vulnerability"]["severity"] in {"High", "Critical"}
            for match in report["matches"]
        )
        if (
            type(returncode) is not int
            or returncode != 2
            or report["distro"]["name"] != "wolfi"
            or report["distro"]["version"] != "20230201"
            or not detected
        ):
            raise Rejected("image_audit_wolfi_detection_control_failed")
    except (KeyError, TypeError) as error:
        raise Rejected("image_audit_wolfi_detection_control_failed") from error


def go_detection_control(report, returncode, kind, timestamp=None):
    database(report, timestamp or datetime.now(UTC))
    try:
        name, version = GO_CONTROLS[kind]
        detected = any(
            match["artifact"]["name"] == name
            and match["artifact"]["version"] == version
            and match["artifact"]["type"] == "go-module"
            and match["vulnerability"]["id"] in GO_CONTROL_ADVISORIES
            and match["vulnerability"]["severity"] in {"High", "Critical"}
            for match in report["matches"]
        )
        if (
            type(returncode) is not int
            or returncode != 2
            or not detected
            or report.get("ignoredMatches")
            or report.get("alertsByPackage")
        ):
            raise Rejected("image_audit_go_detection_control_failed")
    except (KeyError, TypeError) as error:
        raise Rejected("image_audit_go_detection_control_failed") from error


def inventory(sbom, image_id, required_packages, *, distro="debian"):
    try:
        if (
            not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            or sbom["descriptor"]["name"] != "syft"
            or sbom["descriptor"]["version"] != SYFT_VERSION
            or sbom["source"]["type"] != "image"
            or sbom["source"]["metadata"]["imageID"] != image_id
            or distro not in DISTRO_VERSIONS
            or sbom["distro"]["id"] != distro
            or sbom["distro"]["versionID"].split(".")[0] not in DISTRO_VERSIONS[distro]
            or (distro == "wolfi" and sbom["distro"]["versionID"] != "20230201")
            or not isinstance(sbom["artifacts"], list)
            or not sbom["artifacts"]
            or not required_packages
        ):
            raise Rejected("image_audit_binding_or_coverage_invalid")
        packages = {}
        for package in sbom["artifacts"]:
            if (
                any(
                    not isinstance(package[field], str) or not package[field]
                    for field in ("id", "name", "version", "type", "foundBy")
                )
                or package["id"] in packages
            ):
                raise Rejected("image_audit_package_inventory_invalid")
            packages[package["id"]] = package
        if not required_packages <= {package["name"] for package in packages.values()}:
            raise Rejected("image_audit_required_packages_missing")
        if distro == "wolfi" and any(
            package["name"] in WOLFI_OS_PACKAGES
            and (package["type"] != "apk" or package["foundBy"] != "apk-db-cataloger")
            for package in packages.values()
        ):
            raise Rejected("image_audit_wolfi_package_coverage_invalid")
        return packages
    except (KeyError, TypeError, AttributeError) as error:
        raise Rejected("image_audit_inventory_invalid") from error


def assess(
    sbom,
    report,
    image_id,
    required_packages,
    returncode,
    timestamp=None,
    *,
    distro="debian",
    diagnostic_only=False,
):
    status = database(report, timestamp or datetime.now(UTC))
    if diagnostic_only:
        observation = observe_packages(sbom, image_id)
        if not observation["package_count"]:
            raise Rejected("image_audit_empty_observation")
        packages = {package["id"]: package for package in sbom["artifacts"]}
        declared = observation["distro"] or {}
        distro = declared.get("id") or None
        version = declared.get("versionID") or None
        versions = {version}
        if distro == "debian" and version:
            versions.add(version.split(".")[0])
    else:
        packages = inventory(sbom, image_id, required_packages, distro=distro)
        versions = {sbom["distro"]["versionID"], sbom["distro"]["versionID"].split(".")[0]}
    try:
        observed_distro = report.get("distro")
        if observed_distro is None and diagnostic_only:
            observed_distro = {}
        if not isinstance(observed_distro, dict):
            raise Rejected("image_audit_binding_or_coverage_invalid")
        name, version = observed_distro.get("name"), observed_distro.get("version")
        if diagnostic_only:
            name = None if name == "" else name
            version = None if version == "" else version
        if (
            type(returncode) is not int
            or returncode not in (0, 2)
            or report["source"]["type"] != "image"
            or report["source"]["target"]["imageID"] != image_id
            or name != distro
            or version not in versions
            or report.get("ignoredMatches")
            or report.get("alertsByPackage")
            or not isinstance(report["matches"], list)
        ):
            raise Rejected("image_audit_binding_or_coverage_invalid")
        counts = Counter({name: 0 for name in SEVERITIES})
        findings = []
        for match in report["matches"]:
            artifact, vulnerability = match["artifact"], match["vulnerability"]
            package = packages[artifact["id"]]
            if (
                any(artifact[field] != package[field] for field in ("name", "version", "type"))
                or vulnerability["severity"] not in SEVERITIES
                or not isinstance(vulnerability["id"], str)
                or not vulnerability["id"]
            ):
                raise Rejected("image_audit_match_invalid")
            counts[vulnerability["severity"]] += 1
            findings.append(
                {
                    "id": vulnerability["id"],
                    "severity": vulnerability["severity"],
                    "package": artifact["name"],
                    "installed": artifact["version"],
                    "type": artifact["type"],
                    "fix": {
                        "state": vulnerability.get("fix", {}).get("state"),
                        "versions": vulnerability.get("fix", {}).get("versions", []),
                    },
                }
            )
        blocked = counts["High"] + counts["Critical"] > 0
        if returncode != (2 if blocked else 0):
            raise Rejected("image_audit_exit_report_disagreement")
        return {
            "status": "fail"
            if blocked
            else "inconclusive"
            if counts["Unknown"] or diagnostic_only
            else "pass",
            "diagnostic_only": diagnostic_only,
            "image_id": image_id,
            "distro": distro,
            "packages": len(packages),
            "package_types": dict(Counter(package["type"] for package in packages.values())),
            "apk_packages": sorted(
                [
                    {"name": package["name"], "version": package["version"]}
                    for package in packages.values()
                    if package["type"] == "apk"
                ],
                key=lambda package: (package["name"], package["version"]),
            ),
            "matches": len(findings),
            "unique_vulnerabilities": len({finding["id"] for finding in findings}),
            "severity_counts": dict(counts),
            "findings": findings,
            "database": status,
            "scanner_exit_code": returncode,
        }
    except (KeyError, TypeError, AttributeError) as error:
        raise Rejected("image_audit_report_invalid") from error
