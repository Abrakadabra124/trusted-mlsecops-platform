import copy
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, write_json
from scripts import image_audit
from scripts.image_audit_qualification import fixtures


def qualify():
    cases = []
    scenarios = {
        "clean": "pass",
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
            calls = []
            sbom, report, match, image_id, unused = fixtures()
            report["descriptor"]["db"]["built"] = datetime.now(UTC).isoformat()
            fingerprint = "f" * 64
            inspected = {
                "Id": image_id,
                "Config": {"Labels": {"org.trusted-mlsecops.source-fingerprint": fingerprint}},
            }

            def inspect(reference):
                calls.append(("inspect", reference))
                if name == "missing-image-pull" and len(calls) == 1:
                    raise Rejected("missing")
                details = copy.deepcopy(inspected)
                if name == "bad-worker-source" and reference == "trusted-mlsecops:dev":
                    details["Config"]["Labels"] = {}
                return details

            def command(arguments, **kwargs):
                if "--output" in arguments:
                    output = Path(arguments[arguments.index("--output") + 1])
                    if name == "worker-save-error" and output.stem == "worker":
                        raise Rejected("save_failed")
                    output.write_bytes(b"controlled archive placeholder")
                return "" if "--porcelain" in arguments else "revision"

            def scanner(run, stage, image, arguments, mounts=(), network=False):
                path = run / f"{stage}.json"
                document = copy.deepcopy(report)
                returncode = 0
                if stage.endswith("-sbom"):
                    document = copy.deepcopy(sbom)
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
                else:
                    if name in {"high", "unknown"}:
                        finding = copy.deepcopy(match)
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
                write_json(path, document)
                return returncode, path

            with (
                patch.object(image_audit, "inspect_image", side_effect=inspect),
                patch.object(image_audit, "command", side_effect=command),
                patch.object(image_audit, "identity", return_value=image_id),
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
                    outcome = image_audit.audit(root)["status"]
                except Rejected:
                    outcome = "rejected"
            if outcome != expected or list(root.rglob("*.tar")):
                raise Rejected(f"audit_flow_contract_failed:{name}:{outcome}")
            cases.append({"id": name, "status": "pass", "actual": outcome, "expected": expected})
    return {
        "status": "pass",
        "scope": "controlled-audit-orchestration-only",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
