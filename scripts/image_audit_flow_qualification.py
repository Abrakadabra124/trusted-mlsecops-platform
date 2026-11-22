import copy
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, read_json, write_json
from scripts import (
    image_audit,
    image_audit_contract,
    image_candidates,
    image_node_candidate,
    image_scope,
    tracking_spike,
)
from scripts.image_audit_qualification import fixtures
from scripts.image_package_observation_qualification import coredns_rebuild_sbom


def qualify():
    cases = []
    scenarios = {
        "runtime-coredns-published-unknown": "inconclusive",
        "runtime-etcd-candidate-clean": "fail",
        "runtime-etcd-candidate-high": "fail",
        "runtime-etcd-candidate-unknown": "fail",
        "runtime-etcd-candidate-foreign": "fail",
        "runtime-etcd-candidate-missing": "fail",
        "runtime-etcd-candidate-empty": "fail",
        "node-proposal": "inconclusive",
        "node-known-worker": "inconclusive",
        "node-forged": "rejected",
        "node-changed": "rejected",
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
        "runtime-no-go-module": "rejected",
        "runtime-no-go-stdlib": "rejected",
        "runtime-go-database-changed": "rejected",
        "runtime-go-database-file-changed": "rejected",
        "runtime-minimal-debian": "inconclusive",
        "runtime-minimal-high": "fail",
        "runtime-ubuntu": "inconclusive",
        "runtime-go-only": "inconclusive",
        "runtime-empty-observation": "inconclusive",
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
            node_binding = {
                "images": {
                    role: {"reference": reference, "config_id": "sha256:" + str(index) * 64}
                    for index, (role, reference) in enumerate(
                        image_node_candidate.IMAGES.items(), 8
                    )
                }
            }
            if name == "node-known-worker":
                for item in node_binding["images"].values():
                    item["config_id"] = image_id
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
            dns_pin = (
                image_audit_contract.PUBLISHED_COREDNS
                if name == "runtime-coredns-published-unknown"
                else None
            )
            if dns_pin:
                runtime_snapshot["targets"][0].update(
                    reference=dns_pin.reference, config_id=dns_pin.config
                )
            etcd_case = name.startswith("runtime-etcd-candidate-")
            etcd_reference = "registry.k8s.io/etcd@sha256:3ced7fbdc4cadcec31ab34a7513bc97be2b70db923e7154e2d88a980016b5e8b"
            etcd_config = "sha256:be2dd319600bac16f542b8e46e1b78511c35a31e46829ee9acc82a83c94aa377"
            if etcd_case:
                runtime_snapshot["targets"] = [
                    {
                        "name": f"runtime-{index:03}",
                        "reference": f"registry.example/system-{index}@sha256:{index:064x}",
                        "config_id": f"sha256:{index:064x}",
                    }
                    for index in range(14)
                ]
                runtime_snapshot["targets"][0].update(
                    reference="registry.k8s.io/etcd@sha256:00edecc7baeaf69c61708ed713d55a8c928d539f200298d8d67cbfed59db9c7e",
                    config_id="sha256:a17708350060c02414f0ecd9a0afd44404df2e4ed8cc9726a3a9c5776b40645e",
                )
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
                if dns_pin and reference == dns_pin.reference:
                    details["Id"] = dns_pin.config
                if etcd_case:
                    for target in runtime_snapshot["targets"]:
                        if reference == target["reference"]:
                            details["Id"] = target["config_id"]
                    if reference == etcd_reference:
                        if name == "runtime-etcd-candidate-missing":
                            raise Rejected("controlled_candidate_unavailable")
                        details["Id"] = (
                            "sha256:" + "b" * 64
                            if name == "runtime-etcd-candidate-foreign"
                            else etcd_config
                        )
                for item in node_binding["images"].values():
                    if reference == item["reference"]:
                        details["Id"] = item["config_id"]
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
                if etcd_case:
                    for target in runtime_snapshot["targets"]:
                        if stage.startswith(target["name"] + "-"):
                            observed_id = target["config_id"]
                    if stage.startswith("etcd-xnet-candidate-"):
                        observed_id = etcd_config
                for role, item in node_binding["images"].items():
                    if stage.startswith(f"node-{role}-"):
                        observed_id = item["config_id"]
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
                    if stage == "runtime-000-sbom" and name == "runtime-empty-observation":
                        document["artifacts"] = []
                    if stage == "runtime-000-sbom" and name in {
                        "runtime-minimal-debian",
                        "runtime-minimal-high",
                        "runtime-ubuntu",
                        "runtime-go-only",
                    }:
                        document["distro"] = (
                            {}
                            if name == "runtime-go-only"
                            else {"id": "ubuntu", "versionID": "26.04"}
                            if name == "runtime-ubuntu"
                            else {"id": "debian", "versionID": "12.14"}
                        )
                        document["artifacts"] = [
                            {
                                "id": "app",
                                "name": "example.org/app",
                                "version": "v1.0.0",
                                "type": "go-module",
                                "foundBy": "go-module-binary-cataloger",
                                "locations": [{"path": "/app"}],
                            }
                        ]
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
                elif stage in {"go-module-detection-control", "go-stdlib-detection-control"}:
                    kind = "module" if stage == "go-module-detection-control" else "stdlib"
                    package, version = (
                        ("golang.org/x/net", "v0.16.0")
                        if kind == "module"
                        else ("stdlib", "go1.20.9")
                    )
                    if (
                        arguments
                        != [f"pkg:golang/{package}@{version}", "--fail-on", "high", "-o", "json"]
                        or network
                        or mounts != [(run / "cache", "/cache", False)]
                        or image != image_audit.GRYPE_IMAGE
                    ):
                        raise AssertionError(
                            "Go controls require pinned offline scanner and database"
                        )
                    control_match = copy.deepcopy(match)
                    control_match["artifact"].update(
                        name=package, version=version, type="go-module"
                    )
                    control_match["vulnerability"].update(id="GO-2023-2102")
                    document["matches"] = [] if name == f"runtime-no-go-{kind}" else [control_match]
                    returncode = 2
                    if name == "runtime-go-database-changed":
                        document["descriptor"]["db"]["status"]["built"] = (
                            datetime.now(UTC) - timedelta(minutes=1)
                        ).isoformat()
                    if name == "runtime-go-database-file-changed":
                        (run / "cache/vulnerability.db").write_bytes(b"changed")
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
                    if stage == "runtime-000-scan" and name in {
                        "runtime-minimal-debian",
                        "runtime-minimal-high",
                        "runtime-ubuntu",
                        "runtime-go-only",
                    }:
                        document["distro"] = (
                            None
                            if name == "runtime-go-only"
                            else {"name": "ubuntu", "version": "26.04"}
                            if name == "runtime-ubuntu"
                            else {"name": "debian", "version": "12"}
                        )
                        if name == "runtime-minimal-high":
                            finding = copy.deepcopy(match)
                            finding["artifact"] = {
                                "id": "app",
                                "name": "example.org/app",
                                "version": "v1.0.0",
                                "type": "go-module",
                            }
                            document["matches"], returncode = [finding], 2
                if etcd_case and stage.startswith(("runtime-", "etcd-xnet-candidate-")):
                    candidate = stage.startswith("etcd-xnet-candidate-")
                    packages = [
                        {
                            "id": binary,
                            "name": "golang.org/x/net",
                            "version": "v0.62.0" if candidate else "v0.61.0",
                            "type": "go-module",
                            "foundBy": "go-module-binary-cataloger",
                            "locations": [{"path": "/usr/local/bin/" + binary}],
                        }
                        for binary in ("etcd", "etcdctl", "etcdutl")
                    ]
                    document["distro"] = None
                    if stage.endswith("-sbom"):
                        document["artifacts"] = (
                            [] if candidate and name == "runtime-etcd-candidate-empty" else packages
                        )
                    else:
                        document["matches"] = []
                        severity = "Unknown" if name == "runtime-etcd-candidate-unknown" else "High"
                        if stage == "runtime-000-scan" or (
                            candidate
                            and name
                            in {"runtime-etcd-candidate-high", "runtime-etcd-candidate-unknown"}
                        ):
                            for package in packages:
                                finding = copy.deepcopy(match)
                                finding["artifact"] = {
                                    key: package[key] for key in ("id", "name", "version", "type")
                                }
                                finding["vulnerability"].update(
                                    id="CVE-2099-0001" if candidate else "GO-2026-6860",
                                    severity=severity if candidate else "High",
                                )
                                document["matches"].append(finding)
                        returncode = (
                            2
                            if document["matches"] and (not candidate or severity == "High")
                            else 0
                        )
                if dns_pin and stage == "runtime-000-sbom":
                    document = coredns_rebuild_sbom(dns_pin.config)
                if dns_pin and stage == "runtime-000-scan":
                    document["source"]["target"]["imageID"] = dns_pin.config
                    package = read_json(run / "runtime-000-sbom.json")["artifacts"][0]
                    finding = copy.deepcopy(match)
                    finding["artifact"] = {k: package[k] for k in ("id", "name", "version", "type")}
                    finding["vulnerability"]["severity"] = "Unknown"
                    document["matches"] = [finding]
                write_json(path, document)
                return returncode, path

            with (
                patch.object(
                    image_node_candidate,
                    "validate",
                    side_effect=[
                        Rejected("foreign-build") if name == "node-forged" else node_binding,
                        {**node_binding, "changed": True}
                        if name == "node-changed"
                        else node_binding,
                    ],
                ),
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
                        **({"include_node_candidate": True} if name.startswith("node-") else {}),
                    )
                    outcome = result["status"]
                    if dns_pin:
                        component = next(
                            c for c in result["components"] if c["name"] == "runtime-000"
                        )
                        if (
                            component["coverage_profile"]
                            != image_audit_contract.PUBLISHED_COREDNS_PROFILE
                            or component["catalogued_packages"] != 202
                            or component["sbom_validated"] is not True
                            or result["runtime_scope"]["covered_images"] != 0
                            or result["release_ready"] is not False
                            or component["status"] != "inconclusive"
                            or component["severity_counts"]["Unknown"] != 1
                            or component["findings"][0]["id"] != match["vulnerability"]["id"]
                            or component["scanner_exit_code"] != 0
                        ):
                            raise AssertionError(
                                "an Unknown finding must remain visible and block CoreDNS adoption"
                            )
                    if etcd_case:
                        components = {item["name"]: item for item in result["components"]}
                        if (
                            len(components) != 18
                            or result["runtime_scope"]["expected_images"] != 14
                            or result["runtime_scope"]["covered_images"] != 0
                            or result["release_ready"] is not False
                            or result["policy"]["allow_exceptions"] is not False
                            or result["policy"]["threshold"] != "High"
                            or result["policy"]["unknown_severity"] != "inconclusive"
                        ):
                            raise AssertionError(
                                "candidate must add a scan without replacing 14 required targets"
                            )
                        for target in runtime_snapshot["targets"]:
                            item = components[target["name"]]
                            if (
                                not item["scan_executed"]
                                or item["image_config_id"] != target["config_id"]
                            ):
                                raise AssertionError("original runtime target lost or substituted")
                        baseline = components["runtime-000"]
                        if len(baseline["findings"]) != 3 or any(
                            item["id"] != "GO-2026-6860"
                            or item["installed"] != "v0.61.0"
                            or item["severity"] != "High"
                            for item in baseline["findings"]
                        ):
                            raise AssertionError("original High findings must remain visible")
                        candidate = components["etcd-xnet-candidate"]
                        invalid = name in {
                            "runtime-etcd-candidate-foreign",
                            "runtime-etcd-candidate-missing",
                            "runtime-etcd-candidate-empty",
                        }
                        if (
                            candidate["scan_executed"] != (not invalid)
                            or candidate["coverage_profile"] != "unapproved-system"
                        ):
                            raise AssertionError(
                                "unavailable or substituted candidate cannot claim a valid scan"
                            )
                        if not invalid and (
                            candidate["sbom_validated"] is not False
                            or candidate["status"]
                            != ("fail" if name == "runtime-etcd-candidate-high" else "inconclusive")
                            or len(candidate["findings"])
                            != (0 if name == "runtime-etcd-candidate-clean" else 3)
                        ):
                            raise AssertionError(
                                "candidate findings or missing coverage must not be hidden"
                            )
                    if name in {"node-proposal", "node-known-worker"}:
                        nodes = [c for c in result["components"] if c["name"].startswith("node-")]
                        if (
                            len(nodes) != 2
                            or any(not c["scan_executed"] or c["sbom_validated"] for c in nodes)
                            or result["release_ready"] is not False
                            or "runtime_scope" in result
                            or any(
                                c["status"] != "pass"
                                for c in result["go_detection_controls"].values()
                            )
                        ):
                            raise AssertionError(
                                "candidate scan must retain controls without granting runtime coverage"
                            )
                    if name.startswith("runtime-"):
                        controls = result["go_detection_controls"]
                        if set(controls) != {"module", "stdlib"} or any(
                            item["status"] != "pass" or item["exit_code"] != 2
                            for item in controls.values()
                        ):
                            raise AssertionError(
                                "runtime audit requires both independent Go controls"
                            )
                    if name == "runtime-local-export" and exported.call_count != 1:
                        raise AssertionError("local-only runtime target was not exported")
                    if name == "runtime-empty-observation":
                        component = next(
                            c for c in result["components"] if c["name"] == "runtime-000"
                        )
                        if (
                            component["scan_executed"]
                            or component["reason"] != "image_audit_empty_observation"
                        ):
                            raise AssertionError(
                                "empty inventory must not become a diagnostic scan"
                            )
                    if name in {
                        "runtime-minimal-debian",
                        "runtime-minimal-high",
                        "runtime-ubuntu",
                        "runtime-go-only",
                    }:
                        component = next(
                            c for c in result["components"] if c["name"] == "runtime-000"
                        )
                        if (
                            component.get("scan_executed") is not True
                            or component.get("diagnostic_only") is not True
                            or component["sbom_validated"] is not False
                            or component["package_binding_validated"] is not True
                            or result["runtime_scope"]["covered_images"] != 0
                        ):
                            raise AssertionError(
                                "diagnostic scan must retain findings without approving coverage"
                            )
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
