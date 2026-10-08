import re
from collections import Counter
from datetime import UTC, datetime, timedelta

from mlsecops.contracts import Rejected

SYFT_VERSION = "1.54.1"
GRYPE_VERSION = "0.120.1"
SEVERITIES = ("Negligible", "Low", "Medium", "High", "Critical", "Unknown")


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
            or not re.fullmatch(r"6\.\d+\.\d+", status["schemaVersion"])
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


def inventory(sbom, image_id, required_packages):
    try:
        if (
            not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            or sbom["descriptor"]["name"] != "syft"
            or sbom["descriptor"]["version"] != SYFT_VERSION
            or sbom["source"]["type"] != "image"
            or sbom["source"]["metadata"]["imageID"] != image_id
            or sbom["distro"]["id"] != "debian"
            or sbom["distro"]["versionID"].split(".")[0] not in {"12", "13"}
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
        return packages
    except (KeyError, TypeError, AttributeError) as error:
        raise Rejected("image_audit_inventory_invalid") from error


def assess(sbom, report, image_id, required_packages, returncode, timestamp=None):
    status = database(report, timestamp or datetime.now(UTC))
    packages = inventory(sbom, image_id, required_packages)
    try:
        if (
            type(returncode) is not int
            or returncode not in (0, 2)
            or report["source"]["type"] != "image"
            or report["source"]["target"]["imageID"] != image_id
            or report["distro"]["name"] != "debian"
            or report["distro"]["version"]
            not in {sbom["distro"]["versionID"], sbom["distro"]["versionID"].split(".")[0]}
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
            "status": "fail" if blocked else "inconclusive" if counts["Unknown"] else "pass",
            "image_id": image_id,
            "packages": len(packages),
            "package_types": dict(Counter(package["type"] for package in packages.values())),
            "matches": len(findings),
            "unique_vulnerabilities": len({finding["id"] for finding in findings}),
            "severity_counts": dict(counts),
            "findings": findings,
            "database": status,
            "scanner_exit_code": returncode,
        }
    except (KeyError, TypeError, AttributeError) as error:
        raise Rejected("image_audit_report_invalid") from error
