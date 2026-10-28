import copy
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, read_json, write_json
from scripts import image_audit, image_candidates, image_scope, tracking_spike
from scripts.image_audit_qualification import fixtures


def qualify():
    cases = []
    scenarios = {
        "comparison": "pass",
        "comparison-foreign": "inconclusive",
        "comparison-no-wolfi-detection": "rejected",
        "comparison-wolfi-medium": "rejected",
        "comparison-wolfi-database-changed": "rejected",
        "comparison-wolfi-high": "fail",
        "comparison-tracking-high": "fail",
        "comparison-missing-tracking": "inconclusive",
        "clean": "pass",
        "runtime-clean": "inconclusive",
        "runtime-local-export": "inconclusive",
        "runtime-known-worker": "pass",
        "runtime-distro-changed": "inconclusive",
        "runtime-source-mismatch": "rejected",
        "runtime-local-image-changed": "inconclusive",
        "runtime-missing-image": "inconclusive",
        "runtime-foreign-config": "inconclusive",
        "runtime-changed": "rejected",
        "runtime-unsupported-distro": "inconclusive",
        "runtime-high": "fail",
        "missing-tracking-image": "inconclusive",
        "bad-tracking-materials": "inconclusive",
        "root-tracking-image": "inconclusive",
        "missing-tracking-package": "inconclusive",
        "missing-tracking-tracing": "inconclusive",
        "tracking-os-only": "inconclusive",
        "tracking-foreign-distro": "inconclusive",
        "tracking-high": "fail",
        "tracking-unknown": "inconclusive",
        "tracking-scanner-crash": "inconclusive",
        "changed-tracking-materials": "rejected",
        "no-wolfi-detection": "rejected",
        "debian-baseline": "inconclusive",
        "high": "fail",
        "unknown": "inconclusive",
        "foreign-report": "inconclusive",
        "broken-report": "inconclusive",
        "bad-worker-source": "inconclusive",
        "worker-save-error": "inconclusive",
        "empty-sbom": "rejected",
        "syft-crash": "rejected",
        "db-unavailable": "rejected",
        "no-detection": "rejected",
        "changed-db": "rejected",
        "changed-source": "rejected",
        "changed-sbom": "inconclusive",
        "missing-image-pull": "pass",
        "low-disk": "rejected",
    }
    for name, expected in scenarios.items():
        with tempfile.TemporaryDirectory(prefix="audit-flow-contract-") as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts/tracking_spike.py").write_bytes(b"# controlled helper material\n")
            calls = []
            sbom, report, match, image_id, unused = fixtures()
            report["descriptor"]["db"]["status"]["built"] = datetime.now(UTC).isoformat()
            fingerprint = "f" * 64
            tracking_materials = "e" * 64
            runtime_reference = "registry.example/system@" + image_id
            runtime_snapshot = {
                "targets": [
                    {"name": "runtime-000", "reference": runtime_reference, "config_id": image_id}
                ],
                "source_revision": "revision",
                "source_fingerprint": fingerprint,
                "containers": [],
                "pods": [],
            }
            if name == "runtime-source-mismatch":
                runtime_snapshot["source_revision"] = "different-revision"
            if name == "runtime-local-export":
                runtime_snapshot["targets"][0].update(
                    reference=image_id, containerd_reference="registry.example/system:local"
                )
            if name == "runtime-local-image-changed":
                runtime_snapshot["targets"][0].update(
                    reference="sha256:" + "9" * 64, config_id=None
                )
            inspected = {
                "Id": image_id,
                "Config": {"Labels": {"org.trusted-mlsecops.source-fingerprint": fingerprint}},
            }

            def inspect(reference):
                calls.append(("inspect", reference))
                if name == "runtime-missing-image" and reference == runtime_reference:
                    raise Rejected("missing")
                if name == "missing-image-pull" and len(calls) == 1:
                    raise Rejected("missing")
                details = copy.deepcopy(inspected)
                if name in {"runtime-known-worker", "runtime-distro-changed"}:
                    if reference == image_audit.STORAGE_IMAGE:
                        details["Id"] = "sha256:" + "8" * 64
                    elif reference == tracking_spike.TAG:
                        details["Id"] = "sha256:" + "7" * 64
                if name == "bad-worker-source" and reference == "trusted-mlsecops:dev":
                    details["Config"]["Labels"] = {}
                if reference == tracking_spike.TAG:
                    if name in {"missing-tracking-image", "comparison-missing-tracking"}:
                        raise Rejected("missing")
                    details["Config"].update(
                        User="0:0" if name == "root-tracking-image" else "65532:65532",
                        Labels={
                            tracking_spike.LABEL: "old"
                            if name == "bad-tracking-materials"
                            else tracking_materials
                        },
                    )
                return details

            def command(arguments, **kwargs):
                if "--output" in arguments:
                    output = Path(arguments[arguments.index("--output") + 1])
                    if name == "runtime-local-export" and output.stem == "runtime-000":
                        raise AssertionError("local export must not be overwritten by Docker save")
                    if name == "worker-save-error" and output.stem == "worker":
                        raise Rejected("save_failed")
                    output.write_bytes(b"controlled archive placeholder")
                return "" if "--porcelain" in arguments else "revision"

            def local_export(target, archive):
                if target != runtime_snapshot["targets"][0]:
                    raise AssertionError("export must retain the observed config")
                archive.write_bytes(b"controlled local archive")
                return copy.deepcopy(inspected)

            def scanner(run, stage, image, arguments, mounts=(), network=False):
                path = run / f"{stage}.json"
                document = copy.deepcopy(report)
                observed_id = image_id
                if name in {"runtime-known-worker", "runtime-distro-changed"}:
                    if stage.startswith("storage-"):
                        observed_id = "sha256:" + "8" * 64
                    elif stage.startswith("tracking-"):
                        observed_id = "sha256:" + "7" * 64
                document["source"]["target"]["imageID"] = observed_id
                returncode = 0
                if stage.endswith("-sbom"):
                    document = copy.deepcopy(sbom)
                    document["source"]["metadata"]["imageID"] = observed_id
                    document["artifacts"].extend(
                        [
                            {
                                "id": package,
                                "name": package,
                                "version": "1",
                                "type": "python",
                                "foundBy": "python-package-cataloger",
                            }
                            for package in ("scikit-learn", "onnxruntime", "cryptography")
                        ]
                    )
                    if stage == "tracking-sbom":
                        document["artifacts"].extend(
                            {
                                "id": package,
                                "name": package,
                                "version": "1",
                                "type": "python",
                                "foundBy": "python-package-cataloger",
                            }
                            for package in (
                                "mlflow",
                                "mlflow-skinny",
                                "mlflow-tracing",
                                "psycopg",
                                "uvicorn",
                            )
                            if name != "tracking-os-only"
                            and (name != "missing-tracking-package" or package != "mlflow")
                            and (name != "missing-tracking-tracing" or package != "mlflow-tracing")
                        )
                    if stage == "runtime-000-sbom" and name != "runtime-known-worker":
                        if name == "runtime-unsupported-distro":
                            document["distro"] = {"id": "unsupported", "versionID": "1"}
                    elif name != "debian-baseline" or stage == "tracking-sbom":
                        document["distro"] = {"id": "wolfi", "versionID": "20230201"}
                        for package in document["artifacts"]:
                            if package["name"] == "libc6":
                                package["name"] = "glibc-2.44"
                            if package["type"] == "deb":
                                package.update(type="apk", foundBy="apk-db-cataloger")
                        document["artifacts"].append(
                            {
                                "id": "python-3.12",
                                "name": "python-3.12",
                                "version": "3.12.15-r4",
                                "type": "apk",
                                "foundBy": "apk-db-cataloger",
                            }
                        )
                    if stage == "tracking-sbom" and name == "tracking-foreign-distro":
                        document["distro"] = {"id": "debian", "versionID": "13"}
                    if name == "empty-sbom":
                        document["artifacts"] = []
                    if name == "syft-crash":
                        returncode = 1
                elif stage == "db-update":
                    (run / "cache/vulnerability.db").write_bytes(b"controlled database placeholder")
                    returncode = 1 if name == "db-unavailable" else 0
                elif stage == "detection-control":
                    control_match = copy.deepcopy(match)
                    control_match["artifact"].update(name="urllib3", version="1.26.7")
                    control_match["vulnerability"].update(id="GHSA-v845-jxx5-vc9f")
                    document["matches"] = [] if name == "no-detection" else [control_match]
                    returncode = 2
                elif stage == "wolfi-detection-control":
                    if arguments[:3] != [
                        "pkg:apk/wolfi/openssl@3.0.7-r0?arch=x86_64&distro=wolfi-20230201",
                        "--fail-on",
                        "high",
                    ]:
                        raise AssertionError("Wolfi control input or severity changed")
                    control_match = copy.deepcopy(match)
                    control_match["artifact"].update(name="openssl", version="3.0.7-r0", type="apk")
                    control_match["vulnerability"].update(id="CVE-2023-0286")
                    document["distro"] = {"name": "wolfi", "version": "20230201"}
                    document["matches"] = (
                        []
                        if name in {"comparison-no-wolfi-detection", "no-wolfi-detection"}
                        else [control_match]
                    )
                    document["matches"].append(copy.deepcopy(match))
                    if name == "comparison-wolfi-database-changed":
                        document["descriptor"]["db"]["status"]["built"] = (
                            datetime.now(UTC) - timedelta(minutes=1)
                        ).isoformat()
                    returncode = 2
                    if name == "comparison-wolfi-medium":
                        control_match["vulnerability"]["severity"] = "Medium"
                        returncode = 0
                else:
                    document["distro"] = (
                        {"name": "debian", "version": "12"}
                        if stage == "runtime-000-scan" and name != "runtime-known-worker"
                        else {"name": "wolfi", "version": "20230201"}
                    )
                    if "-candidate-" in stage and name == "comparison-wolfi-high":
                        finding = copy.deepcopy(match)
                        finding["artifact"].update(name="glibc-2.44", type="apk")
                        document["matches"] = [finding]
                        returncode = 2
                    if name in {"high", "unknown"}:
                        finding = copy.deepcopy(match)
                        finding["artifact"].update(name="glibc-2.44", type="apk")
                        finding["vulnerability"]["severity"] = (
                            "High" if name == "high" else "Unknown"
                        )
                        document["matches"] = [finding]
                        returncode = 2 if name == "high" else 0
                    elif name == "foreign-report":
                        document["source"]["target"]["imageID"] = "foreign"
                    elif name == "broken-report":
                        document = {}
                    elif name == "changed-db":
                        (run / "cache/vulnerability.db").write_bytes(b"changed")
                    elif name == "changed-sbom":
                        with (run / f"{stage.split('-')[0]}-sbom.json").open("ab") as output:
                            output.write(b" ")
                    if stage == "tracking-scan" and name in {
                        "tracking-high",
                        "tracking-unknown",
                        "comparison-tracking-high",
                    }:
                        finding = copy.deepcopy(match)
                        finding["artifact"].update(name="glibc-2.44", type="apk")
                        finding["vulnerability"]["severity"] = (
                            "Unknown" if name == "tracking-unknown" else "High"
                        )
                        document["matches"] = [finding]
                        returncode = 0 if name == "tracking-unknown" else 2
                    if stage == "tracking-scan" and name == "tracking-scanner-crash":
                        returncode = 1
                    if stage == "runtime-000-scan" and name == "runtime-high":
                        document["matches"] = [copy.deepcopy(match)]
                        returncode = 2
                write_json(path, document)
                return returncode, path

            with (
                patch.object(
                    image_scope,
                    "collect",
                    side_effect=[
                        runtime_snapshot,
                        {**runtime_snapshot, "pods": ["changed"]}
                        if name == "runtime-changed"
                        else runtime_snapshot,
                    ],
                ),
                patch.object(
                    tracking_spike,
                    "materials",
                    side_effect=[
                        tracking_materials,
                        "changed" if name == "changed-tracking-materials" else tracking_materials,
                    ],
                ),
                patch.object(
                    image_candidates,
                    "validate",
                    side_effect=Rejected("foreign-recipe")
                    if name == "comparison-foreign"
                    else None,
                    return_value={"recipe_digest": "c" * 64},
                ),
                patch.object(image_audit, "inspect_image", side_effect=inspect),
                patch.object(
                    image_audit, "export_local_image", side_effect=local_export
                ) as exported,
                patch.object(image_audit, "command", side_effect=command),
                patch.object(
                    image_audit,
                    "identity",
                    side_effect=lambda archive, details: (
                        "sha256:" + "9" * 64
                        if name == "runtime-foreign-config" and archive.stem == "runtime-000"
                        else details["Id"]
                    ),
                ),
                patch.object(image_audit, "scanner", side_effect=scanner),
                patch.object(
                    image_audit.shutil,
                    "disk_usage",
                    return_value=SimpleNamespace(free=1 if name == "low-disk" else 9 * 1024**3),
                ),
                patch.object(
                    image_audit,
                    "source_fingerprint",
                    side_effect=[
                        fingerprint,
                        "changed" if name == "changed-source" else fingerprint,
                    ],
                ),
            ):
                try:
                    result = image_audit.audit(
                        root,
                        include_candidates=name.startswith("comparison"),
                        **({"runtime_state": root} if name.startswith("runtime-") else {}),
                    )
                    outcome = result["status"]
                    if name == "runtime-local-export" and exported.call_count != 1:
                        raise AssertionError("local-only runtime target was not exported")
                    if name == "runtime-known-worker":
                        if (
                            result["runtime_scope"]["status"] != "pass"
                            or result["runtime_scope"]["covered_images"] != 1
                        ):
                            raise AssertionError("every observed image must be scanned")
                    if name in {"runtime-clean", "runtime-high"}:
                        if result["runtime_scope"]["status"] != "inconclusive":
                            raise AssertionError("OS-only scan cannot prove application coverage")
                    if name in {
                        "runtime-clean",
                        "runtime-unsupported-distro",
                        "runtime-local-export",
                    }:
                        component = next(
                            item for item in result["components"] if item["name"] == "runtime-000"
                        )
                        observation = component.get("package_observation", {})
                        if (
                            observation.get("image_id") != image_id
                            or observation.get("status") != "inconclusive"
                            or observation.get("package_count") != 5
                            or component.get("observed_reference")
                            != runtime_snapshot["targets"][0]["reference"]
                            or result["runtime_scope"]["status"] != "inconclusive"
                        ):
                            raise AssertionError(
                                "bound observation must survive unsupported coverage without passing"
                            )
                    if name in {"comparison-tracking-high", "comparison-missing-tracking"}:
                        if result["comparison"]["status"] != "pass" or outcome == "pass":
                            raise AssertionError(
                                "comparison cannot override incomplete or failed tracking"
                            )
                    if name in {"comparison", "clean"}:
                        indexed = {
                            component["name"]: component for component in result["components"]
                        }
                        if (
                            set(indexed)
                            != {"worker", "storage", "tracking"}
                            | (
                                {"worker-candidate", "storage-candidate"}
                                if name == "comparison"
                                else set()
                            )
                            or not indexed["tracking"]["scan_executed"]
                            or indexed["tracking"].get("recipe_digest") != tracking_materials
                            or result["policy"]["scope"] != ["worker", "storage", "tracking"]
                            or result["release_ready"] is not False
                        ):
                            raise AssertionError(
                                "tracking must be audited with exact recipe binding"
                            )
                        if name == "comparison" and result["comparison"]["status"] != "pass":
                            raise AssertionError("candidate comparison must remain complete")
                except Rejected:
                    outcome = "rejected"
            if outcome != expected or list(root.rglob("*.tar")):
                raise Rejected(f"audit_flow_contract_failed:{name}:{outcome}")
            if name.startswith("comparison") or name in {"clean", "no-wolfi-detection"}:
                saved = read_json(root / image_audit.REPORT)
                observation = saved["wolfi_control_observation"]
                severity = "Medium" if name == "comparison-wolfi-medium" else "High"
                expected_matches = (
                    []
                    if name in {"comparison-no-wolfi-detection", "no-wolfi-detection"}
                    else [{"id": "CVE-2023-0286", "severity": severity}]
                )
                if (
                    observation["exit_code"] != (0 if severity == "Medium" else 2)
                    or observation["distro"] != {"name": "wolfi", "version": "20230201"}
                    or observation["expected_matches"] != expected_matches
                    or len(saved["wolfi_detection_control_digest"]) != 64
                ):
                    raise Rejected("wolfi_control_diagnostics_not_preserved")
            cases.append({"id": name, "status": "pass", "actual": outcome, "expected": expected})
    return {
        "status": "pass",
        "scope": "controlled-audit-orchestration-only",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
