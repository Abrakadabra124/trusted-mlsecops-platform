import copy
import importlib.metadata
import io
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import acceptance
from mlsecops.authority_probe import MUTATIONS, corrupt
from mlsecops.authority_qualification import combine
from mlsecops.contracts import Rejected, canonical, read_json, write_json
from mlsecops.prediction_protocol import PredictionBatch, response


def qualify():
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"authority_contract_failed:{name}")
        cases.append({"id": name, "status": "pass", "expected": True, "actual": condition})

    scan = {
        "format": "onnx",
        "inspected_nodes": 3,
        "unsupported": 0,
        "skipped": 0,
        "errors": 0,
        "policy_version": "linear-onnx-v1",
        "onnx_version": importlib.metadata.version("onnx"),
    }
    for name, expected in MUTATIONS.items():
        batch = PredictionBatch(b"fixture", [[0.1] * 6, [0.2] * 6])
        valid = response(batch.request, [0.1, 0.2], scan)
        earlier = PredictionBatch(b"fixture", [[0.1] * 6, [0.2] * 6])
        replay = response(earlier.request, [0.1, 0.2], scan)
        invalid = corrupt(name, valid, replay)
        try:
            batch.consume(invalid)
        except Rejected as error:
            confirmed(f"fixture:{name}", str(error) == expected)
        else:
            confirmed(f"fixture:{name}", False)
        confirmed(
            f"fixture-preserves-control:{name}", valid == response(batch.request, [0.1, 0.2], scan)
        )
    binding = {
        name: name
        for name in (
            "source_fingerprint",
            "image_id",
            "dataset_reference",
            "candidate_reference",
            "model_digest",
            "policy_digest",
        )
    }
    components = {
        name: {"status": "pass", "cases": [{"id": "fixture", "status": "pass"}], **binding}
        for name in ("isolation", "protocol", "controller", "outputs", "access")
    }
    merged, artifacts = combine(components, binding)
    confirmed("combine-positive", len(merged) == len(artifacts) == 5)
    confirmed(
        "aggregate-case-observations",
        all(case.get("expected") == case.get("actual") == "pass" for case in merged),
    )
    for name, change in (
        ("missing-component", lambda value: value.pop("outputs")),
        ("unknown-component", lambda value: value.update(other=value["protocol"])),
        ("failed-component", lambda value: value["outputs"].update(status="fail")),
        ("skipped-component", lambda value: value["access"].update(status="inconclusive")),
        ("empty-cases", lambda value: value["protocol"].update(cases=[])),
        ("non-list-cases", lambda value: value["protocol"].update(cases="fixture")),
        ("non-object-case", lambda value: value["protocol"].update(cases=["fixture"])),
        (
            "duplicate-case",
            lambda value: value["outputs"]["cases"].append({"id": "fixture", "status": "pass"}),
        ),
        ("failed-case", lambda value: value["outputs"]["cases"][0].update(status="fail")),
        ("blank-case", lambda value: value["outputs"]["cases"][0].update(id="")),
        ("stale-source", lambda value: value["protocol"].update(source_fingerprint="old")),
        ("wrong-image", lambda value: value["isolation"].update(image_id="old")),
        ("wrong-candidate", lambda value: value["outputs"].update(candidate_reference="old")),
        ("wrong-model", lambda value: value["controller"].update(model_digest="old")),
        ("wrong-dataset", lambda value: value["access"].update(dataset_reference="old")),
        ("wrong-policy", lambda value: value["outputs"].update(policy_digest="old")),
    ):
        invalid = copy.deepcopy(components)
        change(invalid)
        try:
            combine(invalid, binding)
        except Rejected:
            confirmed(f"aggregate:{name}", True)
        else:
            confirmed(f"aggregate:{name}", False)
    with tempfile.TemporaryDirectory(prefix="authority-cli-") as temporary:
        state = Path(temporary)
        output = state / "M20.json"
        arguments = ["acceptance", "--gate", "M20", "--state", str(state), "--output", str(output)]
        with patch("sys.argv", arguments), redirect_stdout(io.StringIO()):
            write_json(output, {"status": "pass", "stale": True})
            exit_code = acceptance.main()
        observed = read_json(output)
        confirmed(
            "cli-missing-prerequisites-replaces-stale-pass",
            exit_code == 2 and observed["status"] == "inconclusive" and "stale" not in observed,
        )
        for name, failure, expected_exit in (
            ("rejected", Rejected("fixture-rejected"), 1),
            ("io-failure", OSError("fixture-unavailable"), 1),
            ("unexpected-crash", RuntimeError("fixture-crash"), None),
        ):
            write_json(output, {"status": "pass", "stale": True})
            with (
                patch("sys.argv", arguments),
                patch("mlsecops.acceptance.report", side_effect=failure),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                try:
                    exit_code = acceptance.main()
                except RuntimeError:
                    exit_code = None
            observed = read_json(output)
            confirmed(
                f"cli-{name}-invalidates-stale-pass",
                exit_code == expected_exit
                and observed["status"] == "inconclusive"
                and observed["exit_code"] == 2
                and "stale" not in observed,
            )
    return {
        "status": "pass",
        "scope": "M20-fixture-and-aggregation-contracts-only",
        "cases": cases,
        "checks": len(cases),
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
