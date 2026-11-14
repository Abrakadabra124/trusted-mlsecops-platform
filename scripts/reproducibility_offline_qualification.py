"""Local contract tests. All model bytes, observations and identities here are test fixtures."""

import copy
import importlib.metadata
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from mlsecops import final_evidence as final
from mlsecops import reproducibility_candidate as signed
from mlsecops import reproducibility_gate as native
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, now, read_json, write_json
from mlsecops.prediction_protocol import PredictionBatch, response
from scripts import m18_delivery_freeze as driver
from scripts import reproducibility_native
from scripts.reproducibility_gate_qualification import fixture
from scripts.reproducibility_native import projection
from scripts.tracking_client import read_back

ROOT = Path(__file__).resolve().parents[1]


class OfflineRepeat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        state = cls.state = Path(tmp.name)
        start = now()
        evidence = fixture(ROOT, state)
        campaign = cls.campaign = state / "reproducibility" / evidence["campaign_id"]
        policy = read_json(ROOT / "policies/local-cpu.json")
        scan = dict(
            format="onnx",
            inspected_nodes=2,
            unsupported=0,
            skipped=0,
            errors=0,
            policy_version="linear-onnx-v2",
            onnx_version=importlib.metadata.version("onnx"),
        )
        readbacks, predictions, manifests = [], [], {}
        for name, record, receipt in zip(
            native.NAMES, evidence["records"], evidence["tracking_receipts"], strict=True
        ):
            location = campaign / "candidates" / record["run_id"]
            meta = read_json(location / "run.json")
            boundary = dict(
                image_id=meta["image_id"],
                elapsed_seconds=1.0,
                network="none",
                deadline_seconds=600,
                cpu_limit=2,
                memory_limit_bytes=4 * 1024**3,
            )
            write_json(location / "run.json", dict(meta, execution=boundary))
            model = bounded_read(location / "model.onnx")
            scores = read_json(location / "golden-scores.json")
            dataset = campaign / "approved" / meta["dataset_id"]
            manifests[dataset.name] = read_json(dataset / "manifest.json")
            holdout = read_json(dataset / "holdout.json")
            batch = PredictionBatch(model, [r["features"] for r in holdout])
            output = response(batch.request, scores, scan)
            _, _, proof = batch.consume(output)
            predictions.append(dict(protocol=proof, execution=boundary, scan=scan))
            exported = projection(record, meta, name)
            client = Mock()
            data = {
                field: [dict(key=k, value=v) for k, v in exported[field].items()]
                for field in ("params", "metrics")
            }
            data["tags"] = [dict(key="source_run_id", value=record["run_id"])]
            client.request.side_effect = [
                canonical(dict(run=dict(info=dict(run_id=receipt["run_id"]), data=data))),
                canonical(exported),
            ]
            readbacks.append(read_back(client, receipt, exported))
        evidence.update(
            completed_at=now(),
            predictions=predictions,
            tracking_readbacks=readbacks,
            local_manifests=manifests,
            curator=read_json(campaign / "trusted-keys.json")["curator"],
            source_approval=read_json(campaign / "source-approval.json"),
        )
        write_json(campaign / "evidence/reproducibility.json", evidence)
        with patch("scripts.tracking_client.read_back"):
            packet = native.reconcile(ROOT, state, evidence, None)
        first = evidence["records"][0]
        meta = read_json(campaign / "candidates" / first["run_id"] / "run.json")
        meta.update(run_id="f" * 32, dataset_id=digest(b"signed dataset fixture"))
        bindings = {
            k: digest(k.encode())
            for k in ("candidate_reference", "dataset_reference", "evaluation_reference")
        }
        demo = digest(b"frozen demo fixture")
        batch = PredictionBatch(model, [r["features"] for r in holdout])
        scores[0] += 1e-8
        output = response(batch.request, scores, scan)
        _, _, proof = batch.consume(output)
        candidate = dict(
            metadata=meta,
            model=model,
            policy=policy,
            bindings=bindings,
            files={"storage-demo.json": demo},
        )
        evaluation = dict(
            prediction_protocol=proof,
            scan=scan,
            holdout_digest=first["inputs"]["golden"],
            auprc=first["auprc"],
        )
        write_json(state / "storage-trust.json", {})
        with (
            patch.object(signed, "subject", return_value=candidate),
            patch.object(
                signed.storage_pipeline, "read_evaluation", return_value=dict(report=evaluation)
            ),
            patch.object(signed, "run_worker", return_value=(output, predictions[0]["execution"])),
        ):
            signed.bind(ROOT, state, evidence, packet, demo)
        host = native.host_source(ROOT)
        packet["input_digests"]["host_scripts"] = host
        packet["finished_at"] = now()
        primary_path = state / "evidence/reproducibility-qualification.json"
        write_json(primary_path, packet)
        cls.report = dict(
            schema_version=1,
            gate="M06",
            profile="local-cpu",
            redaction_version=1,
            status="pass",
            exit_code=0,
            source_dirty=False,
            policy_digest=first["inputs"]["policy"],
            source_revision=evidence["source_revision"],
            started_at=start,
            finished_at=now(),
            residual_risks=packet["limitations"],
            cases=packet["cases"],
            metrics=dict(checks=packet["checks"], **packet["metrics"]),
            artifact_hashes=dict(
                reproducibility_qualification=digest(bounded_read(primary_path)),
                **packet["artifact_hashes"],
            ),
            input_digests=dict(
                source_fingerprint=evidence["source_fingerprint"], **packet["input_digests"]
            ),
        )
        write_json(state / "evidence/M06.json", cls.report)
        cls.pin = digest(bounded_read(state / "evidence/M06.json"))
        cls.values = dict(
            cls.report["input_digests"],
            source_revision=evidence["source_revision"],
            dataset=meta["dataset_id"],
            image_id=meta["image_id"],
            model=final.retain(state, model),
            evaluation_scan=scan,
            evaluation_artifacts=dict(metadata=final.retain(state, canonical(meta))),
            prediction_protocol=proof,
            split_materials=meta["materials"],
            evaluation_auprc=evaluation["auprc"],
            reproducibility_host_scripts=host,
        )
        final.retain(state, canonical(policy))
        cls.metrics = driver.verify_reproducibility(state, cls.values, cls.pin)

    def read(self, ref):
        return final.blob(self.state, ref)

    def test_all_six_and_signed_candidate_recomputed_after_capture(self):
        self.assertEqual(len(self.report["cases"]), 19)
        for key in ("training_runs", "tracking_runs", "prediction_runs"):
            self.assertEqual(self.metrics[key], 6)
        self.assertEqual(self.metrics["golden_rows"], 3000)
        self.assertGreater(self.metrics["candidate_probability_difference"], 0)
        self.assertLess(self.metrics["candidate_probability_difference"], 1e-6)
        # No campaign workspace or live clients in the full M18 primary interface.
        final.primary("M06", self.report, self.read, self.values)

    def test_native_producer_retains_the_worker_response_and_exact_vector(self):
        record = read_json(self.campaign / "evidence/reproducibility.json")["records"][0]
        loc = self.campaign / "candidates" / record["run_id"]
        meta = read_json(loc / "run.json")
        golden = read_json(self.campaign / "approved" / meta["dataset_id"] / "holdout.json")
        model, vector = bounded_read(loc / "model.onnx"), read_json(loc / "golden-scores.json")
        scan, boundary = self.values["evaluation_scan"], meta["execution"]
        captured = []

        def observe(image, request):
            self.assertEqual(image, meta["image_id"])
            output = response(request, vector, scan)
            captured.append(output)
            return output, boundary

        with (
            patch.object(reproducibility_native, "train_candidate", return_value=meta),
            patch.object(reproducibility_native, "load_candidate", return_value=(meta, model)),
            patch.object(reproducibility_native, "run_worker", side_effect=observe),
        ):
            actual, scores, _, observed = reproducibility_native.run_one(
                self.campaign,
                meta["dataset_id"],
                {},
                meta["image_id"],
                golden,
                {"OMP_NUM_THREADS": "1"},
            )
        self.assertEqual((actual, scores, observed["execution"]), (record, vector, boundary))
        self.assertEqual(observed["protocol"]["response_digest"], digest(canonical(captured[0])))

    def test_missing_vector_and_foreign_signed_model_fail_closed(self):
        ref = self.report["artifact_hashes"]["vector:repeat-1"]

        def missing_vector(reference):
            if reference == ref:
                raise final.Missing("material-missing")
            return self.read(reference)

        with self.assertRaises(final.Missing):
            final.primary("M06", self.report, missing_vector, self.values)
        foreign = dict(self.values, model=final.retain(self.state, b"other model bytes"))
        with self.assertRaisesRegex(Rejected, "repeat-prediction"):
            final.primary("M06", self.report, self.read, foreign)

    def test_wrong_pin_and_mutated_model_bytes_refused(self):
        with self.assertRaisesRegex(Rejected, "report-digest"):
            driver.verify_reproducibility(self.state, self.values, "0" * 64)
        model = next((self.campaign / "candidates").glob("*/model.onnx"))
        raw = model.read_bytes()
        self.addCleanup(model.write_bytes, raw)
        model.write_bytes(raw + b" ")
        with self.assertRaisesRegex(Rejected, "repeat-material-digest"):
            driver.verify_reproducibility(self.state, self.values, self.pin)

    def test_rehashed_claims_are_checked_against_observations(self):
        for target, change in (
            ("native_campaign", lambda d: d["mutations"][2].update(max_probability_difference=0.1)),
            ("native_campaign", lambda d: d["tracking_readbacks"][5]["metrics"].update(auprc=0.2)),
            (
                "native_campaign",
                lambda d: d["predictions"][1]["protocol"].update(response_digest="e" * 64),
            ),
            ("candidate_replay", lambda d: d["scores"].reverse()),
            ("candidate_replay", lambda d: d["reference_runs"].reverse()),
            (
                "reproducibility_qualification",
                lambda d: d["metrics"].update(candidate_probability_difference=0.0),
            ),
        ):
            with self.subTest(target=target, change=change):
                report = copy.deepcopy(self.report)
                refs = report["artifact_hashes"]
                primary_key = "reproducibility_qualification"
                packet = read_json(self.state / "evidence/reproducibility-qualification.json")
                if target == primary_key:
                    change(packet)
                    report["metrics"].update(packet["metrics"])
                else:
                    doc = read_json(self.state / "evidence/M18-objects" / refs[target])
                    change(doc)
                    ref = final.retain(
                        self.state, canonical(doc) + (b"" if target == "native_campaign" else b"\n")
                    )
                    refs[target] = packet["artifact_hashes"][target] = ref
                refs[primary_key] = final.retain(self.state, canonical(packet) + b"\n")
                with self.assertRaises(Rejected):
                    final.primary("M06", report, self.read, self.values)

    def test_cleanup_guards_keep_early_replay_independent_of_m06(self):
        workflow = (ROOT / ".github/workflows/storage-recovery.yml").read_text()
        steps = workflow.split("      - name: ")
        early = next(s for s in steps if "scripts.m18_delivery_freeze replay\n" in s)
        late = next(s for s in steps if "scripts.m18_delivery_freeze replay-m06\n" in s)
        for gate in ("M01", "M02", "M03", "M07"):
            self.assertIn(gate + "_REPORT_SHA256:", early)
        self.assertNotIn("repeated.", early)
        self.assertNotIn("stop_tracking.", early)
        for step in ("stop_cluster", "stop_sql", "m18_freeze"):
            self.assertIn(f"steps.{step}.outcome == 'success'", early)
            self.assertIn(f"steps.{step}.outcome == 'success'", late)
        for step in ("repeated", "stop_tracking"):
            self.assertIn(f"steps.{step}.outcome == 'success'", late)
        self.assertIn("always()", early)
        self.assertIn("always()", late)
        self.assertIn("steps.repeated.outputs.sha256", late)
        producer = next(s for s in steps if "id: repeated\n" in s)
        self.assertLess(
            producer.index("--gate M06"), producer.index("sha256sum .runtime/evidence/M06.json")
        )
        self.assertLess(
            workflow.index("scripts.reproducibility_offline_qualification"),
            workflow.index("id: repeated"),
        )
