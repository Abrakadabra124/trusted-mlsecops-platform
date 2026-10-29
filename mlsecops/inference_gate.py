"""M12 executes both approved-release and genuine candidate HTTP on one image."""

import subprocess
import sys
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from scripts import inference_contracts, kube_serving_native
from scripts.kube_trust_native import hosted

NATIVE_CASES = {
    "initial-worker-absence",
    "verified-ready",
    "ready-model",
    "ready-bundle",
    "golden-status",
    "golden-model",
    "golden-bundle",
    "golden-parity-1e-6",
    "finite-bounded-scores",
    "unauthorized-401",
    "413-over-64KiB",
    "64KiB-accepted",
    "100-rows-status",
    "100-rows-count",
    "outside-support-status",
    "outside-support-abstains",
    "outside-support-no-score",
    "429-busy",
    "ready-after-invalid",
    "one-persistent-worker",
    "actual-candidate-not-release",
    "qualification-audit-context",
    "stopped-worker-503",
    "stopped-worker-not-ready",
    "final-worker-absence",
    *(
        "422-" + n
        for n in (
            "empty",
            "malformed",
            "fields",
            "version",
            "boolean-version",
            "unknown-feature",
            "missing-feature",
            "boolean-feature",
            "empty-batch",
            "101-rows",
            "nan",
            "inf",
            "negative-inf",
        )
    ),
    *(
        fault + "-" + suffix
        for fault in (
            "unsigned-permit",
            "unsigned-proposal",
            "changed-model",
            "mutable-model",
            "malformed-model",
        )
        for suffix in ("ready-503", "predict-503", "worker-constructions", "cleanup")
    ),
    "unsigned-permit-signature-reason",
    "unsigned-proposal-signature-reason",
}


def contracts(root):
    process = subprocess.run(
        [sys.executable, "-m", "scripts.inference_contracts"],
        cwd=root,
        capture_output=True,
        timeout=300,
        check=False,
    )
    if process.returncode:
        raise Rejected("M12_controlled_contracts_failed")
    value = decode(process.stdout, 1024**2)
    expected = [
        {"id": name, "status": "pass", "expected": True, "actual": True}
        for name in sorted(inference_contracts.case_ids(root))
    ]
    if (
        value.get("scope") != inference_contracts.SCOPE
        or value.get("status") != "pass"
        or type(value.get("checks")) is not int
        or value["checks"] != len(expected)
        or not expected
        or canonical(value.get("cases")) != canonical(expected)
    ):
        raise Rejected("M12_controlled_contracts_incomplete")
    return value


def reconcile(result, source):
    try:
        return _reconcile(result, source)
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M12_native_shape") from error


def _reconcile(result, source):
    actual = result["actual_inference"]
    native = actual["native"]
    if (
        result["status"] != "pass"
        or result["release_ready"] is not False
        or result["source_dirty"] is not False
        or {key: result[key] for key in source} != source
        or actual["source"] != source
        or actual["source_dirty"] is not False
        or actual["release_ready"] is not False
        or actual["status"] != "pass"
        or native["status"] != "pass"
        or native["release_ready"] is not False
        or native["model_sha256"] != actual["model_sha256"]
        or native["subject_sha256"] != actual["subject_sha256"]
        or result["actual"]["candidate"] != actual["candidate_reference"]
        or result["actual"]["proposal"] != actual["proposal_reference"]
        or result["actual"]["model"] != actual["model_sha256"]
    ):
        raise Rejected("M12_native_binding")
    cases = native["cases"]
    if (
        not isinstance(cases, list)
        or len(cases) != len(NATIVE_CASES)
        or {case["id"] for case in cases} != NATIVE_CASES
        or any(
            set(case) != {"id", "status", "expected", "actual"}
            or case["status"] != "pass"
            or type(case["expected"]) is not type(case["actual"])
            or case["expected"] != case["actual"]
            for case in cases
        )
    ):
        raise Rejected("M12_native_cases_incomplete")
    for phase, mandatory in (
        (
            "before_approval",
            {
                "unapproved-or-revoked-ready-503",
                "unapproved-or-revoked-predict-503",
                "refused-before-worker-start",
            },
        ),
        (
            "approved",
            {
                "ordinary-CLI-ready-after-verified-load",
                "ONNX-golden-parity",
                "response-model-and-bundle-binding",
                "same-worker-UID-across-requests",
                "stopped-worker-503",
            },
        ),
        ("after_revocation", {"unapproved-or-revoked-ready-503", "refused-before-worker-start"}),
    ):
        current = result[phase]
        if (
            current["status"] != "pass"
            or current["release_ready"] is not False
            or not (mandatory | {"worker-cleanup-confirmed"}).issubset(current["cases"])
        ):
            raise Rejected("M12_normal_CLI_incomplete")
    return cases


def qualify(root, state, image="trusted-mlsecops:dev"):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    started = now()
    output = safe_child(state, "evidence/inference-gate.json")
    write_json(output, {"status": "inconclusive", "release_ready": False})
    paths = [module.replace(".", "/") + ".py" for module in inference_contracts.MODULES]
    paths += [
        "scripts/inference_contracts.py",
        "scripts/evaluation_contracts.py",
        "scripts/kube_candidate_native.py",
        "scripts/kube_serving_native.py",
        "scripts/candidate_serving_reader.py",
        "scripts/kube_promotion_native.py",
        "data.lock",
    ]
    materials = {path: digest(bounded_read(root / path)) for path in paths}
    controlled = contracts(root)
    native = kube_serving_native.qualify(root, state, image, include_candidate=True)
    source = {
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_fingerprint": source_fingerprint(root),
        "image_id": native["image_id"],
    }
    cases = reconcile(native, source)
    if command(["git", "-C", str(root), "status", "--porcelain"]) or any(
        digest(bounded_read(root / path)) != value for path, value in materials.items()
    ):
        raise Rejected("M12_inputs_changed")
    write_json(safe_child(state, "evidence/inference-native.json"), native)
    write_json(safe_child(state, "evidence/inference-contracts.json"), controlled)
    actual = native["actual_inference"]
    result = {
        "schema_version": 1,
        "scope": "M12-fresh-candidate-and-normal-CLI-inference",
        "status": "pass",
        "release_ready": False,
        "source_dirty": False,
        "started_at": started,
        "finished_at": now(),
        "source_revision": source["source_revision"],
        "cases": controlled["cases"] + cases,
        "checks": len(controlled["cases"]) + len(cases),
        "metrics": {
            "native_cases": len(cases),
            "max_golden_error": actual["native"]["max_golden_error"],
        },
        "input_digests": {
            **source,
            "model": actual["model_sha256"],
            "release_subject": actual["subject_sha256"],
            "candidate_reference": actual["candidate_reference"],
            "proposal_reference": actual["proposal_reference"],
        },
        "artifact_hashes": {
            "native": digest(bounded_read(state / "evidence/inference-native.json")),
            "contracts": digest(bounded_read(state / "evidence/inference-contracts.json")),
            "contract_materials": digest(canonical(materials)),
            **actual["artifact_hashes"],
        },
        "limitations": [
            "Synthetic lab only; this M12 report does not authorize release",
            "Ordinary CLI approvals use separately labelled controlled material; actual candidate uses a purpose-separated permit",
            "M11, M13-M18, system image findings and independent M22 review remain separate requirements",
        ],
    }
    write_json(output, result)
    return result
