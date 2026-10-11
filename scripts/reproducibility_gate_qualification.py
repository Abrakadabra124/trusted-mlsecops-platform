import copy
import io
import subprocess
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import acceptance, reproducibility_gate
from mlsecops.bootstrap import initialize
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.datasets import generate, prepare, publish_records, verify_dataset
from mlsecops.inventory import command, source_fingerprint
from scripts import reproducibility_native
from scripts.reproducibility import compare
from scripts.reproducibility_native import projection, record_from


def fixture(root, state):
    identity = "a" * 32
    campaign = state / "reproducibility" / identity
    with patch("mlsecops.bootstrap.collect", return_value={"scope": "controlled-fixture"}):
        initialize(root, campaign)
    policy = read_json(root / "policies/local-cpu.json")
    seed_policy = {**policy, "training_seed": policy["training_seed"] + 1}
    dataset = prepare(campaign, policy)
    seeded = publish_records(campaign, seed_policy, generate(policy["data_seed"], policy["rows"]))
    rows = generate(policy["data_seed"], policy["rows"])
    rows[0]["features"][0] = 1 - rows[0]["features"][0]
    changed = publish_records(campaign, policy, rows)
    base, mutated = "sha256:" + "b" * 64, "sha256:" + "c" * 64
    fingerprint = source_fingerprint(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    records, vectors, receipts = [], [], []
    for index, dataset_id in enumerate((dataset, dataset, dataset, seeded, changed, dataset)):
        current_policy = seed_policy if index == 3 else policy
        splits, manifest = verify_dataset(campaign, dataset_id, current_policy)
        vector = [0.9 if row["label"] else 0.1 for row in splits["holdout"]]
        request = {
            "action": "train",
            "train": splits["train"],
            "seed": current_policy["training_seed"],
            "features": [row["features"] for row in splits["validation"]],
        }
        metadata = {
            "run_id": f"{index + 1:032x}",
            "dataset_id": dataset_id,
            "policy_digest": digest(canonical(current_policy)),
            "model_digest": digest(b"controlled-fixture-not-a-real-model"),
            "input_digest": digest(canonical(request)),
            "source_fingerprint": fingerprint,
            "source_revision": revision,
            "image_id": mutated if index == 5 else base,
            "versions": {"fixture": "1"},
            "materials": manifest["objects"],
            "status": "unapproved-candidate",
        }
        record = record_from(
            metadata, splits["holdout"], vector, {"OMP_NUM_THREADS": "2" if index == 5 else "1"}
        )
        location = campaign / "candidates" / record["run_id"]
        location.mkdir()
        (location / "model.onnx").write_bytes(b"controlled-fixture-not-a-real-model")
        write_json(location / "run.json", metadata)
        write_json(location / "golden-scores.json", vector)
        exported = projection(record, metadata, reproducibility_gate.NAMES[index])
        receipts.append(
            {
                "run_id": f"{index + 10:032x}",
                "artifact_path": "/api/2.0/mlflow-artifacts/artifacts/fixture/run-materials.json",
                "record_digest": digest(canonical(exported)),
            }
        )
        records.append(record)
        vectors.append(vector)
    return {
        "status": "pass",
        "scope": "native-input-mutations-and-tracking-not-full-M06",
        "release_ready": False,
        "campaign_id": identity,
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "source_dirty": False,
        "image_id": base,
        "environment_image_id": mutated,
        "baseline_environment": {"OMP_NUM_THREADS": "1"},
        "mutated_environment": {"OMP_NUM_THREADS": "2"},
        "training_runs": 6,
        "prediction_runs": 6,
        "golden_rows": 3000,
        "baseline": compare(records[:3], vectors[:3]),
        "records": records,
        "tracking_receipts": receipts,
        "mutations": [
            {
                "kind": name,
                "status": "pass",
                "comparison": "rejected-input-change",
                "changed_inputs": sorted(
                    key
                    for key in records[0]["inputs"]
                    if records[0]["inputs"][key] != record["inputs"][key]
                ),
                "max_probability_difference": 0.0,
            }
            for name, record in zip(("seed", "data", "environment"), records[3:], strict=True)
        ],
    }


def qualify():
    root = Path(__file__).resolve().parents[1]
    cases = []
    with tempfile.TemporaryDirectory(prefix="m06-contract-") as directory:
        state = Path(directory)
        evidence = fixture(root, state)
        with patch("scripts.tracking_client.read_back") as reader:
            result = reproducibility_gate.reconcile(root, state, evidence, object())
            if result["status"] != "pass" or reader.call_count != 6:
                raise Rejected("m06_positive_contract_failed")
        cases.append("reconciled-controlled-materials")
        for name, mutate in (
            (
                "wrong-artifact-path",
                lambda value: value["tracking_receipts"][0].update(
                    artifact_path="https://example.invalid/"
                ),
            ),
            (
                "artifact-path-not-text",
                lambda value: value["tracking_receipts"][0].update(artifact_path=42),
            ),
            ("malformed-record", lambda value: value["records"].__setitem__(0, None)),
            ("invalid-run-path", lambda value: value["records"][0].update(run_id="../escape")),
            ("missing-run", lambda value: value["records"].pop()),
            ("reused-run", lambda value: value["records"].__setitem__(2, value["records"][0])),
            ("stale-source", lambda value: value.update(source_fingerprint="f" * 64)),
            ("stale-revision", lambda value: value.update(source_revision="f" * 40)),
            ("failed-campaign", lambda value: value.update(status="fail")),
            ("wrong-scope", lambda value: value.update(scope="fixture")),
            ("approved-campaign", lambda value: value.update(release_ready=True)),
            ("boolean-count", lambda value: value.update(training_runs=True)),
            ("wrong-golden-count", lambda value: value.update(golden_rows=2)),
            ("escaped-campaign", lambda value: value.update(campaign_id="../escape")),
            (
                "forged-numeric-pass",
                lambda value: value["baseline"].update(max_probability_difference=0.5),
            ),
            ("missing-mutation", lambda value: value["mutations"].pop()),
            ("forged-mutation", lambda value: value["mutations"][0].update(status="fail")),
            ("wrong-image", lambda value: value.update(image_id="sha256:" + "f" * 64)),
            (
                "unchanged-environment",
                lambda value: value.update(environment_image_id=value["image_id"]),
            ),
            (
                "wrong-thread-profile",
                lambda value: value.update(baseline_environment={"OMP_NUM_THREADS": "2"}),
            ),
            ("missing-tracking-run", lambda value: value["tracking_receipts"].pop()),
            (
                "reused-tracking-run",
                lambda value: value["tracking_receipts"][1].update(
                    run_id=value["tracking_receipts"][0]["run_id"]
                ),
            ),
            (
                "wrong-tracking-hash",
                lambda value: value["tracking_receipts"][0].update(record_digest="f" * 64),
            ),
            ("wrong-request", lambda value: value["records"][0]["inputs"].update(request="f" * 64)),
        ):
            invalid = copy.deepcopy(evidence)
            mutate(invalid)
            with patch("scripts.tracking_client.read_back"):
                try:
                    reproducibility_gate.reconcile(root, state, invalid, object())
                except Rejected:
                    cases.append(name)
                else:
                    raise Rejected("m06_bad_evidence_accepted:" + name)
        location = (
            state
            / "reproducibility"
            / evidence["campaign_id"]
            / "candidates"
            / evidence["records"][0]["run_id"]
        )
        for name in ("model.onnx", "golden-scores.json", "run.json"):
            path = location / name
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"tampered")
                with patch("scripts.tracking_client.read_back"):
                    try:
                        reproducibility_gate.reconcile(root, state, evidence, object())
                    except Rejected:
                        cases.append("stored-" + name + "-tampered")
                    else:
                        raise Rejected("m06_stored_tampering_accepted:" + name)
            finally:
                path.write_bytes(original)
        for name, mutation in (
            ("run.json", lambda value: value.update(input_digest="f" * 64)),
            ("golden-scores.json", lambda value: value.__setitem__(0, 0.5)),
        ):
            path = location / name
            original = path.read_bytes()
            value = read_json(path)
            mutation(value)
            try:
                write_json(path, value)
                with patch("scripts.tracking_client.read_back"):
                    try:
                        reproducibility_gate.reconcile(root, state, evidence, object())
                    except Rejected:
                        cases.append("valid-json-tampering-" + name)
                    else:
                        raise Rejected("m06_valid_json_tampering_accepted")
            finally:
                path.write_bytes(original)
        for name, mutated_comparison in (
            ("unexpected-denial", Rejected("unexpected_comparison")),
            ("unexpected-accept", None),
        ):
            with (
                patch(
                    "scripts.reproducibility.compare",
                    side_effect=[evidence["baseline"], mutated_comparison],
                ),
                patch("scripts.tracking_client.read_back"),
            ):
                try:
                    reproducibility_gate.reconcile(root, state, evidence, object())
                except Rejected:
                    cases.append("mutation-" + name)
                else:
                    raise Rejected("m06_mutation_comparator_bypass")
        output = state / "M06.json"
        write_json(output, {"status": "pass", "stale": True})
        with (
            patch(
                "sys.argv",
                ["acceptance", "--gate", "M06", "--state", str(state), "--output", str(output)],
            ),
            redirect_stdout(io.StringIO()),
        ):
            exit_code = acceptance.main()
        if (
            exit_code != 2
            or read_json(output)["status"] != "inconclusive"
            or "stale" in read_json(output)
        ):
            raise Rejected("m06_stale_pass_retained")
        cases.append("cli-custom-state-missing-prerequisites")
        tracker = state / "tracking-service"
        write_json(tracker / "configuration.json", {"port": 15445})
        write_json(tracker / "resources.json", {})
        write_json(tracker / "credentials.json", {"reader": "controlled-fixture"})
        saved = (
            state / "reproducibility" / evidence["campaign_id"] / "evidence/reproducibility.json"
        )
        write_json(saved, evidence)
        with (
            patch("scripts.reproducibility_native.qualify", return_value=evidence) as execute,
            patch("scripts.tracking_client.Client", return_value=object()),
            patch("scripts.tracking_client.read_back"),
            patch("mlsecops.reproducibility_gate.uuid.uuid4") as identity,
        ):
            identity.return_value.hex = evidence["campaign_id"]
            result = reproducibility_gate.qualify(root, state)
            execute.assert_called_once_with(
                root.resolve(),
                "trusted-mlsecops:dev",
                runtime_state=state.resolve(),
                campaign_id=evidence["campaign_id"],
            )
            if result["status"] != "pass":
                raise Rejected("m06_fresh_dispatch_failed")
        cases.append("qualifier-executes-campaign-in-explicit-state")
        with (
            patch("scripts.reproducibility_native.qualify", return_value=evidence),
            patch("mlsecops.reproducibility_gate.uuid.uuid4") as identity,
            patch.object(reproducibility_gate, "host_source", side_effect=["before", "after"]),
        ):
            identity.return_value.hex = evidence["campaign_id"]
            try:
                reproducibility_gate.qualify(root, state)
            except Rejected:
                cases.append("host-script-change-during-campaign")
            else:
                raise Rejected("m06_mutating_host_source_accepted")
        for name, native_result, persisted in (
            ("wrong-campaign", {**evidence, "campaign_id": "f" * 32}, evidence),
            ("persisted-report-changed", evidence, {**evidence, "status": "fail"}),
        ):
            write_json(saved, persisted)
            with (
                patch("scripts.reproducibility_native.qualify", return_value=native_result),
                patch("mlsecops.reproducibility_gate.uuid.uuid4") as identity,
            ):
                identity.return_value.hex = evidence["campaign_id"]
                try:
                    reproducibility_gate.qualify(root, state)
                except Rejected:
                    if (
                        read_json(state / "evidence/reproducibility-qualification.json")["status"]
                        != "inconclusive"
                    ):
                        raise Rejected("m06_qualifier_retained_stale_pass")
                    cases.append(name)
                else:
                    raise Rejected("m06_wrong_native_report_accepted")
        write_json(state / "evidence/reproducibility-qualification.json", result)
        with patch.object(reproducibility_gate, "qualify", return_value=result) as qualified:
            reported = acceptance.report("M06", "local-cpu", root, state)
            qualified.assert_called_once_with(root, state)
            if (
                reported["status"] != "pass"
                or reported["exit_code"] != 0
                or len(reported["cases"]) != 18
            ):
                raise Rejected("m06_acceptance_dispatch_invalid")
        cases.append("acceptance-dispatches-and-binds-qualification")
        for name, error, expected in (
            ("rejected", Rejected("M06_invalid_materials"), "fail"),
            ("io-unavailable", OSError("secret"), "inconclusive"),
            ("timeout", subprocess.TimeoutExpired("secret", 1), "inconclusive"),
            ("tool-unavailable", Rejected("required_tool_unavailable"), "inconclusive"),
            (
                "stale-image",
                Rejected("image_source_fingerprint_mismatch_rebuild_required"),
                "inconclusive",
            ),
            ("tracking-mismatch", Rejected("tracking_read_back_mismatch"), "fail"),
            ("missing-artifact", Rejected("artifact_unavailable"), "inconclusive"),
        ):
            with patch.object(reproducibility_gate, "qualify", side_effect=error):
                reported = acceptance.report("M06", "local-cpu", root, state)
                if (
                    reported["status"] != expected
                    or reported["exit_code"] == 0
                    or "secret" in canonical(reported).decode()
                ):
                    raise Rejected("m06_failure_classification_invalid")
            cases.append("dispatch-" + name)
        for name, identity_value in (
            ("reused-campaign", evidence["campaign_id"]),
            ("invalid-campaign", "../escape"),
        ):
            with (
                patch.object(
                    reproducibility_native, "resolve_image", return_value=evidence["image_id"]
                ),
                patch.object(
                    reproducibility_native, "environment", return_value={"OMP_NUM_THREADS": "1"}
                ),
                patch.object(reproducibility_native, "up") as started,
            ):
                try:
                    reproducibility_native.qualify(
                        root, "fixture", runtime_state=state, campaign_id=identity_value
                    )
                except Rejected:
                    started.assert_not_called()
                    cases.append(name)
                else:
                    raise Rejected("m06_native_reused_state_accepted")
    return {
        "status": "pass",
        "scope": "M06-controlled-reconciliation-contracts-not-native-training",
        "checks": len(cases),
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
