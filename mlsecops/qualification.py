import argparse
import copy
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np

from mlsecops.acceptance import report
from mlsecops.bootstrap import initialize
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.datasets import generate, prepare, validate_approval, validate_rows, verify_dataset
from mlsecops.inventory import collect, source_fingerprint
from mlsecops.pipeline import evaluate_candidate, train_candidate, validate_scores
from mlsecops.sandbox import run_worker
from mlsecops.signing import encode64, pae, sign, verify


def qualify(root, state, image):
    root, state = Path(root).resolve(), Path(state).resolve()
    policy = read_json(root / "policies/local-cpu.json")
    cases = []

    def rejected(identifier, operation):
        try:
            operation()
        except Rejected as error:
            cases.append(
                {"id": identifier, "expected": "reject", "actual": str(error), "status": "pass"}
            )
        else:
            raise Rejected(f"qualification_bypass:{identifier}")

    def confirmed(identifier, condition):
        if not condition:
            raise Rejected(f"qualification_failed:{identifier}")
        cases.append({"id": identifier, "expected": True, "actual": True, "status": "pass"})

    initial = initialize(root, state)
    confirmed("bootstrap-repeat-stable-keys", initial == initialize(root, state))
    missing_tool = subprocess.run(
        [sys.executable, "-m", "mlsecops.bootstrap", "--state", str(state)],
        cwd=root,
        env={**os.environ, "PATH": ""},
        capture_output=True,
        timeout=30,
    )
    confirmed(
        "missing-tool-exit-1",
        missing_tool.returncode == 1 and b"required_tool_missing" in missing_tool.stderr,
    )
    for index, payload in enumerate(
        (b'{"duplicate":1,"duplicate":2}', b'{"number":NaN}', b'{"number":Infinity}', b"{")
    ):
        rejected(f"json-invalid-{index}", lambda payload=payload: decode(payload))
    rejected("json-size-limit", lambda: decode(b"{}", limit=1))
    for index, name in enumerate(("../escape", "/absolute", "a\\b", "C:escape")):
        rejected(f"path-invalid-{index}", lambda name=name: safe_child(state, name))
    rejected("probability-count", lambda: validate_scores([0.1], 2))
    rejected("probability-boolean", lambda: validate_scores([True], 1))
    rejected("probability-nan", lambda: validate_scores([float("nan")], 1))
    rejected("probability-range", lambda: validate_scores([1.01], 1))
    public = read_json(state / "trusted-keys.json")
    envelope = sign({"subject": "synthetic-fixture"}, "dataset", state / "keys/curator.pem")
    confirmed(
        "signature-roundtrip",
        verify(envelope, "dataset", public["curator"]) == {"subject": "synthetic-fixture"},
    )
    confirmed(
        "dsse-pae-reference-vector",
        pae("http://example.com/HelloWorld", b"hello world")
        == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world",
    )
    rejected("signature-wrong-role", lambda: verify(envelope, "dataset", public["approver"]))
    rejected("signature-wrong-type", lambda: verify(envelope, "approval", public["curator"]))
    damaged = {**envelope, "payload": encode64(b'{"subject":"changed"}')}
    rejected("signature-payload-tamper", lambda: verify(damaged, "dataset", public["curator"]))
    damaged = {**envelope, "signatures": []}
    rejected("signature-empty", lambda: verify(damaged, "dataset", public["curator"]))
    confirmed("generator-repeat", canonical(generate(rows=100)) == canonical(generate(rows=100)))
    fixtures = generate(rows=100)
    for name in ("duplicate", "label-type", "missing-field", "extra-field", "nan", "range"):
        modified = copy.deepcopy(fixtures)
        if name == "duplicate":
            modified[1]["entity_id"] = modified[0]["entity_id"]
        elif name == "label-type":
            modified[0]["label"] = True
        elif name == "missing-field":
            del modified[0]["features"]
        elif name == "extra-field":
            modified[0]["feedback"] = "forged"
        elif name == "nan":
            modified[0]["features"][0] = float("nan")
        else:
            modified[0]["features"][0] = 1.01
        rejected(f"dataset-{name}", lambda modified=modified: validate_rows(modified))
    dataset_id = prepare(state, policy)
    confirmed("dataset-repeat", prepare(state, policy) == dataset_id)
    approval = verify(read_json(state / "source-approval.json"), "source", public["curator"])
    rejected(
        "source-expired",
        lambda: validate_approval({**approval, "expires_at": "2000-01-01T00:00:00+00:00"}, policy),
    )
    rejected("source-unknown", lambda: validate_approval({**approval, "source": "unknown"}, policy))
    rejected(
        "source-purpose", lambda: validate_approval({**approval, "purpose": "real-PII"}, policy)
    )
    scratch_root = state / "scratch"
    scratch_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="qualification-", dir=scratch_root) as temporary:
        scratch = Path(temporary).resolve()
        if not scratch.is_relative_to(scratch_root.resolve()):
            raise Rejected("scratch_path_escape")
        shutil.copytree(state / "approved", scratch / "approved")
        for filename in ("trusted-keys.json", "source-approval.json"):
            shutil.copyfile(state / filename, scratch / filename)
        target = scratch / "approved" / dataset_id / "train.json"
        original = target.read_bytes()
        atomic_write(target, original[:-1] + b" ")
        rejected("dataset-byte-tamper", lambda: verify_dataset(scratch, dataset_id, policy))
        atomic_write(target, original)
        target.rename(target.with_suffix(".missing"))
        rejected("dataset-missing-object", lambda: verify_dataset(scratch, dataset_id, policy))
    for index, payload in enumerate((b"not-onnx", b"\x80\x04pickle", b"")):
        request = {
            "action": "predict",
            "model": encode64(payload),
            "features": [[0.5] * 6],
            "batch_id": "a" * 32,
        }
        rejected(
            f"worker-invalid-model-{index}", lambda request=request: run_worker(image, request)
        )
    rejected(
        "worker-protocol-invalid",
        lambda: run_worker(image, {"action": "shell", "command": "ignored"}),
    )
    for gate in policy["required_gates"]:
        result = report(gate, "local-cpu", root)
        confirmed(
            f"unimplemented-{gate}-closed",
            result["status"] == "inconclusive" and result["exit_code"] != 0,
        )
    runs = [train_candidate(state, dataset_id, policy, image) for _ in range(3)]
    evaluations = [evaluate_candidate(state, run["run_id"], policy, image) for run in runs]
    vectors = [
        np.asarray(read_json(state / "candidates" / run["run_id"] / "validation-scores.json"))
        for run in runs
    ]
    max_difference = max(float(np.max(np.abs(vector - vectors[0]))) for vector in vectors[1:])
    confirmed("fresh-process-inputs-identical", len({run["input_digest"] for run in runs}) == 1)
    confirmed("fresh-process-repeat-tolerance", max_difference <= policy["repeat_tolerance"])
    confirmed(
        "synthetic-quality-component",
        all(value["quality_component"] == "pass" for value in evaluations),
    )
    confirmed(
        "onnx-parity",
        all(
            value["validation_parity_max_error"] <= policy["parity_tolerance"]
            for value in evaluations
        ),
    )
    result = {
        "schema_version": 1,
        "scope": "developer-components-not-full-M-gates",
        "status": "pass",
        "observed_at": now(),
        "source_fingerprint": source_fingerprint(root),
        "inventory": collect(root),
        "policy_digest": digest(canonical(policy)),
        "dataset_id": dataset_id,
        "cases": cases,
        "metrics": {
            "fresh_runs": 3,
            "max_probability_difference": max_difference,
            "auprc": [value["auprc"] for value in evaluations],
            "dummy_auprc": evaluations[0]["dummy_auprc"],
            "positive_holdout": evaluations[0]["positives"],
            "max_parity_error": max(value["validation_parity_max_error"] for value in evaluations),
        },
        "runs": runs,
        "release_status": "unapproved",
        "full_acceptance": "inconclusive",
        "limitations": [
            "No production or full R1 acceptance",
            "Synthetic utility only",
            "No MLflow/DVC/Kubernetes gate evidence yet",
            "No poisoning campaign, release service, monitoring or disaster recovery yet",
            "Human evaluator and author are not independent",
        ],
    }
    write_json(state / "evidence" / "developer-qualification.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description="Executable developer-profile qualification")
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    try:
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        print(
            canonical(
                {
                    "scope": result["scope"],
                    "cases": len(result["cases"]),
                    "metrics": result["metrics"],
                    "full_acceptance": result["full_acceptance"],
                }
            ).decode()
        )
        return 0
    except (Rejected, OSError) as error:
        print(f"Qualification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
