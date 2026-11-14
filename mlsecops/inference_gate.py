"""M12 executes both approved-release and genuine candidate HTTP on one image."""

import os
import subprocess
import sys
from datetime import datetime
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
    "qualification-permit-payload",
    "qualification-permit-envelope",
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


def joint_cases(actual, permit_envelope):
    """Select original M12 rows from the richer baseline Job, checking their typed values."""
    rows = actual["native"]["cases"]
    model, bundle = actual["model_sha256"], actual["subject_sha256"]
    expected = {
        "verified-ready": 200,
        "ready-model": model,
        "ready-bundle": bundle,
        "golden-status": 200,
        "golden-model": model,
        "golden-bundle": bundle,
        "golden-parity-1e-6": True,
        "finite-bounded-scores": True,
        "unauthorized-401": 401,
        "initial-worker-absence": 0,
        "final-worker-absence": 0,
        "413-over-64KiB": 413,
        "64KiB-accepted": 200,
        "100-rows-status": 200,
        "100-rows-count": 100,
        "outside-support-status": 200,
        "outside-support-abstains": "abstain",
        "outside-support-no-score": None,
        "429-busy": 429,
        "ready-after-invalid": 200,
        "one-persistent-worker": 1,
        "actual-candidate-not-release": False,
        "qualification-audit-context": "candidate-qualification",
        "qualification-permit-payload": actual["qualification_permit_sha256"],
        "qualification-permit-envelope": digest(canonical(permit_envelope)),
        "stopped-worker-503": 503,
        "stopped-worker-not-ready": 503,
        "unsigned-permit-signature-reason": "unexpected_fields",
        "unsigned-proposal-signature-reason": "invalid_signature_count",
        **{name: 422 for name in NATIVE_CASES if name.startswith("422-")},
    }
    for fault in (
        "unsigned-permit",
        "unsigned-proposal",
        "changed-model",
        "mutable-model",
        "malformed-model",
    ):
        expected.update(
            {
                fault + "-ready-503": 503,
                fault + "-predict-503": 503,
                fault + "-cleanup": 0,
                fault + "-worker-constructions": int(fault == "malformed-model"),
            }
        )
    selected = [r for r in rows if r["id"] in expected]
    if (
        len({r["id"] for r in rows}) != len(rows)
        or set(expected) != NATIVE_CASES
        or {r["id"] for r in selected} != NATIVE_CASES
        or any(
            canonical(r)
            != canonical(
                dict(
                    id=r["id"], status="pass", actual=expected[r["id"]], expected=expected[r["id"]]
                )
            )
            for r in selected
        )
        or actual["native"]["authority_target"] != "primary"
        or not 0 <= actual["native"]["max_golden_error"] <= 1e-6
    ):
        raise Rejected("M12_joint_native_cases")
    return selected


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
    preparation_started = now()
    output = safe_child(state, "evidence/inference-gate.json")
    write_json(output, {"status": "inconclusive", "release_ready": False})
    proposal_pin = os.environ.get("M12_PROPOSAL_SHA256")
    early_pin = os.environ.get("M12_EARLY_SHA256")
    if early_pin is not None and proposal_pin is None:
        raise Rejected("M12_early_proposal_required")
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
    joint_pin = os.environ.get("M11_M12_NATIVE_SHA256")
    if joint_pin is None and "M11_M12_ACTUAL_SHA256" in os.environ:
        raise Rejected("M12_joint_native_required")
    view = None
    if joint_pin is not None:
        from scripts import shared_serving_native

        binding, native, config = shared_serving_native.lookup(root, state, image)
        actual = native["actual_inference"]
        selected = joint_cases(actual, config["permit_envelope"])
        view = {
            **native,
            "actual_inference": {**actual, "native": {**actual["native"], "cases": selected}},
        }
        preparation_started, started = native["started_at"], actual["started_at"]
        controlled = contracts(root)
    elif proposal_pin is not None:
        from scripts import m12_pinned_native

        started, native = m12_pinned_native.finish(root, state, image, proposal_pin, early_pin)
        preparation_started = native["started_at"]
        controlled = contracts(root)
    else:
        prepared = kube_serving_native.prepare(root, state, image, proposal_pin=None)
        started = now()
        controlled = contracts(root)
        native = kube_serving_native.qualify(
            root, state, image, include_candidate=True, prepared=prepared
        )
    source = {
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_fingerprint": source_fingerprint(root),
        "image_id": native["image_id"],
    }
    cases = reconcile(native if view is None else view, source)
    if command(["git", "-C", str(root), "status", "--porcelain"]) or any(
        digest(bounded_read(root / path)) != value for path, value in materials.items()
    ):
        raise Rejected("M12_inputs_changed")
    write_json(safe_child(state, "evidence/inference-native.json"), native)
    write_json(safe_child(state, "evidence/inference-contracts.json"), controlled)
    actual = native["actual_inference"]
    issued = actual["proposal_issued_at"]
    if type(issued) is not int or datetime.fromisoformat(started).timestamp() < issued:
        raise Rejected("M12_descriptor_must_precede_checks")
    result = {
        "schema_version": 1,
        "scope": "M12-fresh-candidate-and-normal-CLI-inference",
        "status": "pass",
        "release_ready": False,
        "source_dirty": False,
        "started_at": started,
        "preparation_started_at": preparation_started,
        "finished_at": now(),
        "source_revision": source["source_revision"],
        "cases": controlled["cases"] + cases,
        "checks": len(controlled["cases"]) + len(cases),
        "metrics": {
            **(
                {"qualification_permit_sha256": actual["qualification_permit_sha256"]}
                if joint_pin is not None
                else {}
            ),
            "native_cases": len(cases),
            "max_golden_error": actual["native"]["max_golden_error"],
        },
        "input_digests": {
            **source,
            "model": actual["model_sha256"],
            "release_subject": actual["subject_sha256"],
            "candidate_reference": actual["candidate_reference"],
            "evaluation_reference": actual["evaluation_reference"],
            "proposal_reference": actual["proposal_reference"],
        },
        "artifact_hashes": {
            **(
                {
                    "shared_native": joint_pin,
                    "pinned_actual": os.environ["M11_M12_ACTUAL_SHA256"],
                    "proposal_packet": binding["input_files"]["evidence/release-native.json"],
                }
                if joint_pin is not None
                else {}
            ),
            **({"pinned_actual": early_pin} if early_pin is not None else {}),
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
