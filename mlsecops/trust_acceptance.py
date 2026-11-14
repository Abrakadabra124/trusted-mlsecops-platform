"""Run one fresh M11 campaign on the explicitly authorized disposable hosted lab."""

import os
import subprocess
import sys
import uuid
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

from mlsecops import trust_delivery, trust_gate
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
from scripts import (
    kube_serving_native,
    release_key_native,
    release_key_serving_native,
    serving_output_native,
    trust_contracts,
)
from scripts.kube_trust_native import hosted
from scripts.release_reader_native import disposable


def materials(root):
    paths = sorted(
        {
            *root.glob("mlsecops/*.py"),
            *root.glob("scripts/*.py"),
            *(
                root / name
                for name in (
                    "data.lock",
                    "uv.lock",
                    "pyproject.toml",
                    ".python-version",
                    "Dockerfile",
                    "policies/local-cpu.json",
                )
            ),
        }
    )
    return {path.relative_to(root).as_posix(): digest(bounded_read(path)) for path in paths}


def controlled_contracts(root):
    process = subprocess.run(
        [sys.executable, "-m", "scripts.trust_contracts"],
        cwd=root,
        capture_output=True,
        timeout=300,
        check=False,
    )
    if process.returncode:
        raise Rejected("M11_contracts_failed")
    value = decode(process.stdout, 2 * 1024**2)
    expected = [
        {"id": name, "status": "pass", "expected": True, "actual": True}
        for name in sorted(trust_contracts.case_ids())
    ]
    if (
        not expected
        or value.get("status") != "pass"
        or value.get("scope") != trust_contracts.SCOPE
        or type(value.get("checks")) is not int
        or value["checks"] != len(expected)
        or canonical(value.get("cases")) != canonical(expected)
    ):
        raise Rejected("M11_contracts_incomplete")
    return value


def qualify(root, state, image="trusted-mlsecops:dev", *, proposal_pin=None, demo_pin=None):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    preparation_started = now()
    output = safe_child(state, "evidence/trust-gate.json")
    write_json(output, {"status": "inconclusive", "release_ready": False})
    proposal_pin = (
        proposal_pin if proposal_pin is not None else os.environ.get("M11_PROPOSAL_SHA256") or None
    )
    demo_pin = demo_pin if demo_pin is not None else os.environ.get("M11_DEMO_SHA256") or None
    trust_delivery.check_pins(proposal_pin, demo_pin)
    before = materials(root)
    frozen = None
    joint_pin = os.environ.get("M11_M12_NATIVE_SHA256")
    if joint_pin is None and "M11_M12_ACTUAL_SHA256" in os.environ:
        raise Rejected("M11_joint_native_required")
    if joint_pin is not None:
        from scripts import shared_serving_native

        frozen, native, _ = shared_serving_native.lookup(root, state, image)
        trust_gate.require(
            frozen["input_files"]["evidence/release-native.json"] == proposal_pin
            and frozen["input_files"]["storage-demo.json"] == demo_pin
        )
        source = frozen["source"]
        preparation_started, started = (
            native["started_at"],
            native["actual_inference"]["started_at"],
        )
        controlled = controlled_contracts(root)
    else:
        if proposal_pin is not None:
            trust_delivery.clean_campaign(state)
            frozen = trust_delivery.freeze(
                root, state, serving_output_native.source(root, image), proposal_pin, demo_pin
            )
        prepared = kube_serving_native.prepare(
            root, state, image, **({} if frozen is None else {"proposal_pin": proposal_pin})
        )
        source = {k: prepared[k] for k in ("source_revision", "source_fingerprint")}
        source["image_id"] = prepared["profile"]["image_id"]
        started = now()
        controlled = controlled_contracts(root)
        native = kube_serving_native.qualify(
            root,
            state,
            image,
            prepared=prepared,
            include_candidate=True,
            include_key_revocation=True,
            include_trust_lifecycle=True,
        )
    write_json(safe_child(state, "evidence/kubernetes-serving.json"), native)
    metrics = trust_gate.reconcile(native, source)
    # Rotation history is synthetic. Keep the owner's source SQL available for
    # subsequent gates and backup when qualifying an externally frozen proposal.
    rotation_state = (
        nullcontext(state)
        if frozen is None
        else disposable(root, state, uuid.uuid4().hex, "M11-rotations", 15446)
    )
    with rotation_state as isolated:
        rotation = release_key_native.qualify(root, isolated)
        trust_gate.passed(rotation)
        trust_gate.require(
            {k: rotation[k] for k in ("source_revision", "source_fingerprint")}
            == {k: source[k] for k in ("source_revision", "source_fingerprint")}
            and len(rotation["cases"]) == len(set(rotation["cases"])) == 37
            and rotation["head_sequence"] == rotation["policy_version"] == 4
            and len(set(rotation["rotations"])) == 3
        )
        signers = release_key_serving_native.qualify(root, isolated, image)
    if frozen is not None:
        trust_gate.require(not isolated.exists())
    write_json(safe_child(state, "evidence/release-key-native.json"), rotation)
    write_json(safe_child(state, "evidence/release-key-serving.json"), signers)
    metrics["signer_first_503_seconds"] = trust_gate.release_signers(signers, source)
    actual = native["actual_inference"]
    joins = {} if frozen is None else trust_delivery.retained(state, native, frozen)
    finished = now()
    times = [
        datetime.fromisoformat(t)
        for t in (
            preparation_started,
            started,
            actual["started_at"],
            actual["finished_at"],
            finished,
        )
    ]
    if (
        any(t.utcoffset() is None for t in times)
        or times != sorted(times)
        or type(actual["proposal_issued_at"]) is not int
        or actual["proposal_issued_at"] > times[1].timestamp()
    ):
        raise Rejected("M11_descriptor_or_time_order")
    if (
        command(["git", "-C", str(root), "status", "--porcelain"])
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != source["source_revision"]
        or source_fingerprint(root) != source["source_fingerprint"]
        or materials(root) != before
    ):
        raise Rejected("M11_inputs_changed")
    frozen_hashes = {}
    if frozen is not None:
        binding_path = safe_child(state, "evidence/trust-frozen.json")
        write_json(binding_path, {"binding": frozen, "joins": joins})
        frozen_hashes = {
            "frozen_binding": digest(bounded_read(binding_path)),
            "proposal_packet": proposal_pin,
            "storage_demo": demo_pin,
            "signed_evaluation": frozen["evaluation_reference"],
        }
    write_json(safe_child(state, "evidence/trust-contracts.json"), controlled)
    criteria = {
        "actual-candidate-binding",
        "five-clock-cache-faults",
        "still-valid-trust-version-replay",
        "independent-key-model-authorities",
        "signed-approval-expiry",
        "still-valid-release-sequence-replay",
        "authorized-and-denied-whole-bundle-rollback",
        "signer-sql-policy-history",
        *metrics["first_503_seconds"],
        *("signer-" + role for role in metrics["signer_first_503_seconds"]),
        *(
            (
                "frozen-proposal-signed-evaluation",
                "production-refusal-controlled-subject-separation",
                "isolated-rotation-cleanup",
            )
            if frozen is not None
            else ()
        ),
    }
    cases = controlled["cases"] + [
        {"id": "M11-" + name, "status": "pass", "expected": True, "actual": True}
        for name in sorted(criteria)
    ]
    result = {
        "schema_version": 1,
        "scope": "M11-fresh-trust-lifecycle-and-controlled-release-contracts",
        "status": "pass",
        "release_ready": False,
        "source_dirty": False,
        "started_at": started,
        "preparation_started_at": preparation_started,
        "finished_at": finished,
        "source_revision": source["source_revision"],
        "cases": cases,
        "checks": len(cases),
        "metrics": {**metrics, **joins},
        "input_digests": {
            **source,
            "candidate_reference": actual["candidate_reference"],
            "proposal_reference": actual["proposal_reference"],
            "model": actual["model_sha256"],
            "release_subject": actual["subject_sha256"],
            **(
                {}
                if frozen is None
                else {
                    "evaluation_reference": frozen["evaluation_reference"],
                    "qualified_candidate_subject": frozen["subject_sha256"],
                    "qualified_candidate_model": frozen["model_sha256"],
                }
            ),
        },
        "artifact_hashes": {
            **actual["artifact_hashes"],
            **(
                {"shared_native": joint_pin, "pinned_actual": os.environ["M11_M12_ACTUAL_SHA256"]}
                if joint_pin is not None
                else {}
            ),
            "method_materials": digest(canonical(before)),
            **frozen_hashes,
            **{
                name: digest(bounded_read(safe_child(state, "evidence/" + name + ".json")))
                for name in (
                    "kubernetes-serving",
                    "release-key-native",
                    "release-key-serving",
                    "trust-contracts",
                )
            },
        },
        "limitations": [
            "Synthetic single-node lab; this M11 mechanism result never authorizes release",
            "Actual candidate uses a purpose-separated qualification permit; approval/rollback/signer positives use labelled controlled releases",
            "Injected dependency clocks do not change OS clocks; independent M22, other gates and whole-candidate M18 remain mandatory",
        ],
    }
    write_json(output, result)
    return result
