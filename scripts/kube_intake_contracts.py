import copy
import gzip
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import (
    artifact_intake,
    controller_worker,
    intake_probe,
    kube_intake_qualification,
    worker,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, now
from mlsecops.controller_api import APIError
from mlsecops.datasets import generate
from mlsecops.signing import decode64

PROFILE = {
    "image": "example/worker@sha256:" + "1" * 64,
    "image_id": "sha256:" + "2" * 64,
    "config_id": "sha256:" + "3" * 64,
    "manifest_id": "sha256:" + "1" * 64,
    "source_fingerprint": "4" * 64,
    "source_revision": "5" * 40,
}


class KubeIntakeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = decode64(
            worker.train(
                {
                    "action": "train",
                    "train": generate(rows=1000),
                    "seed": 17,
                    "features": [[0.5] * 6],
                }
            )["model"]
        )

    def test_actual_job_deadline_is_not_reported_as_process_crash(self):
        for reason, code in (
            ("DeadlineExceeded", "controller_worker_deadline"),
            ("BackoffLimitExceeded", "controller_worker_failed"),
        ):

            class Client:
                def __init__(self, role):
                    self.namespace = "ml-eval"

                def request(self, resource, name=None, method="GET", value=None, job=None):
                    if method == "POST":
                        return {"metadata": {"uid": resource}}
                    if method == "GET":
                        return {
                            "metadata": {"uid": "jobs"},
                            "status": {
                                "conditions": [
                                    {"type": "Failed", "status": "True", "reason": reason}
                                ]
                            },
                        }
                    return {}

            with (
                patch.object(controller_worker, "Client", Client),
                self.assertRaisesRegex(Rejected, "^" + code + "$"),
            ):
                controller_worker.run(PROFILE, "scorer", {"action": "inspect"})

    def test_deadline_maps_to_intake_inconclusive_timeout(self):
        def executor(*args):
            raise Rejected("controller_worker_deadline")

        with self.assertRaises(artifact_intake.IntakeFailure) as failure:
            artifact_intake.inspect_candidate(
                b"fixture",
                artifact_intake.digest(b"fixture"),
                PROFILE["image_id"],
                PROFILE["image_id"],
                executor,
            )
        self.assertEqual(failure.exception.report["reason"], "scanner_timeout")

    def test_corruption_is_explicit_and_does_not_mutate_input(self):
        source = {
            "inspected": 1,
            "unsupported": 0,
            "skipped": 0,
            "errors": 0,
            "model_digest": "1" * 64,
            "approved_outputs": ["1" * 64],
            "tool": {"policy": "linear-onnx-v2"},
            "status": "fail",
        }
        original = copy.deepcopy(source)
        for name in intake_probe.MUTATIONS:
            result = intake_probe.corrupt(name, source, {"old": True})
            self.assertNotEqual(result, source)
            self.assertEqual(source, original)
        with self.assertRaises(Rejected):
            intake_probe.corrupt("unknown", source, {})

    def matrix(self):
        objects, outputs, observations, reads = {}, {}, [], {}

        class Client:
            def __init__(self, role):
                self.namespace = "ml-eval"

            def request(self, resource, name=None, method="GET", value=None, job=None):
                if method == "POST":
                    document = copy.deepcopy(value)
                    name = document["metadata"]["name"]
                    document["metadata"]["uid"] = resource + "-" + name
                    if resource == "jobs":
                        request = decode(
                            gzip.decompress(
                                decode64(objects[("configmaps", name)]["binaryData"]["request.gz"])
                            )
                        )
                        try:
                            outputs[name] = worker.execute(request)
                        except Rejected:
                            condition = {
                                "type": "Failed",
                                "reason": "BackoffLimitExceeded",
                                "status": "True",
                            }
                        else:
                            condition = {"type": "Complete", "status": "True"}
                        if "nodeSelector" in document["spec"]["template"]["spec"]:
                            condition = {
                                "type": "Failed",
                                "reason": "DeadlineExceeded",
                                "status": "True",
                            }
                        document["status"] = {"conditions": [condition]}
                        observations.append(document)
                    objects[(resource, name)] = document
                    return document
                if resource == "pods":
                    document = objects.get(("jobs", job))
                    if document is None:
                        return {"items": []}
                    condition = document["status"]["conditions"][0]
                    if condition.get("reason") == "DeadlineExceeded" and reads.get(job, 0) >= 2:
                        return {"items": []}
                    return {
                        "items": [
                            {
                                "metadata": {
                                    "name": job + "-pod",
                                    "uid": job + "-pod-uid",
                                    "ownerReferences": [
                                        {"uid": document["metadata"]["uid"], "controller": True}
                                    ],
                                },
                                "spec": document["spec"]["template"]["spec"],
                                "status": {
                                    "containerStatuses": [
                                        {
                                            "imageID": PROFILE["config_id"],
                                            "state": {
                                                "terminated": {
                                                    "exitCode": 0
                                                    if condition["type"] == "Complete"
                                                    else 1
                                                }
                                            },
                                        }
                                    ]
                                },
                            }
                        ]
                    }
                if resource == "logs":
                    return canonical(
                        {
                            "schema_version": 1,
                            "output": outputs[name.removesuffix("-pod")],
                            "diagnostics": {
                                "bytes": 0,
                                "gpu_discovery_warning": False,
                                "raw_output_retained": False,
                            },
                        }
                    )
                if (resource, name) not in objects:
                    raise APIError(404, "NotFound")
                if method == "DELETE":
                    assert (
                        value["preconditions"]["uid"]
                        == objects[(resource, name)]["metadata"]["uid"]
                    )
                    del objects[(resource, name)]
                    return {}
                observed = copy.deepcopy(objects[(resource, name)])
                if (
                    resource == "jobs"
                    and observed["status"]["conditions"][0].get("reason") == "DeadlineExceeded"
                ):
                    reads[name] = reads.get(name, 0) + 1
                    if reads[name] == 1:
                        observed["status"]["conditions"] = []
                return observed

        cases, previous = [], None
        with (
            patch.object(intake_probe, "Client", Client),
            patch.object(controller_worker, "Client", Client),
            patch.object(controller_worker.time, "sleep"),
        ):
            for name in intake_probe.MATRIX:
                case, response = intake_probe.inspect_case(PROFILE, name, self.content, previous)
                cases.append(case)
                if name == "clean-before":
                    previous = response
        return cases, observations, objects

    def test_entire_matrix_with_controlled_api_and_real_host_parser(self):
        cases, observations, objects = self.matrix()
        self.assertEqual(len(cases), 12)
        self.assertFalse(objects)
        self.assertEqual({case["id"] for case in cases}, set(intake_probe.MATRIX))
        for document in observations:
            spec = document["spec"]["template"]["spec"]
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertEqual(spec["containers"][0]["image"], PROFILE["image"])
            self.assertEqual(
                spec["containers"][0]["command"],
                [
                    "python",
                    "-m",
                    "mlsecops.worker_transport",
                    "--request-file",
                    "/input/request.gz",
                ],
            )
            self.assertTrue(spec["containers"][0]["securityContext"]["readOnlyRootFilesystem"])

    def reconciliation_fixture(self):
        started = now()
        cases, _, _ = self.matrix()
        indexed = {case["id"]: case for case in cases}
        cases.extend(
            {"id": name, "status": "pass"}
            for name in intake_probe.CASE_IDS - set(intake_probe.MATRIX)
        )
        positive = {
            "candidate_reference": "6" * 64,
            "dataset_reference": "7" * 64,
            "holdout_access": {"slot": 1},
            "report": {
                "quality_component": "pass",
                "created_at": now(),
                "model_digest": digest(self.content),
                "image_id": PROFILE["image_id"],
            },
        }
        denials = [
            {
                "reference": str(index + 8) * 64,
                "payload": {
                    "intake": indexed[name]["report"],
                    "candidate_reference": "6" * 64,
                    "decision": "deny-evaluation",
                    "release_ready": False,
                    "holdout_access": {"slot": index + 2},
                },
            }
            for index, name in enumerate(("zero-inspected", "stale-response"))
        ]
        evidence = {
            "schema_version": 1,
            "scope": "scoped-kubernetes-intake-matrix",
            "status": "pass",
            "observed_at": now(),
            "image_id": PROFILE["image_id"],
            "source_fingerprint": PROFILE["source_fingerprint"],
            "model_digest": digest(self.content),
            "materials": {},
            "release_ready": False,
            "candidate_reference": "6" * 64,
            "dataset_reference": "7" * 64,
            "positive": {"evaluation_reference": "a" * 64, "evaluation": positive},
            "denials": denials,
            "cases": cases,
            "checks": len(cases),
            "controller": {"pod_uid": "controlled-scorer"},
            "process": {
                "uid": 65532,
                "model_parser_loaded": False,
                "host_socket_present": False,
                "api_token_present": True,
                "signer_present": True,
                "peak_memory_kib": 1000,
            },
        }
        persisted = {
            "release_ready": False,
            "candidate_reference": "6" * 64,
            "model_digest": digest(self.content),
            "positive": copy.deepcopy(positive),
            "denials": [copy.deepcopy(item["payload"]) for item in denials],
            "controller": {"pod_uid": "controlled-promoter"},
        }
        return evidence, persisted, started

    def reconcile(self, evidence, persisted, started):
        kube_intake_qualification.reconcile(
            evidence,
            persisted,
            self.content,
            PROFILE["image_id"],
            PROFILE["source_fingerprint"],
            {},
            started,
        )

    def test_host_reconciles_every_case_and_independent_readback(self):
        self.reconcile(*self.reconciliation_fixture())

    def test_host_rejects_missing_foreign_stale_or_rewritten_evidence(self):
        original, persisted, started = self.reconciliation_fixture()
        for field, value in (
            ("schema_version", True),
            ("scope", "foreign"),
            ("image_id", "foreign"),
            ("source_fingerprint", "0" * 64),
            ("model_digest", "0" * 64),
            ("materials", {"unbound": True}),
            ("release_ready", True),
            ("denials", []),
            ("observed_at", "2000-01-01T00:00:00+00:00"),
            ("cases", original["cases"][:-1]),
        ):
            evidence = copy.deepcopy(original)
            evidence[field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.reconcile(evidence, persisted, started)
        altered = copy.deepcopy(persisted)
        altered["positive"]["report"]["quality_component"] = "fail"
        with self.assertRaisesRegex(Rejected, "kube_intake_material_binding"):
            self.reconcile(original, altered, started)
        with self.assertRaises(Rejected):
            self.reconcile({}, persisted, started)

    def test_host_rejects_broken_boundary_cleanup_and_reused_execution(self):
        original, persisted, started = self.reconciliation_fixture()
        for mutate in (
            lambda value: value["process"].update(model_parser_loaded=True),
            lambda value: value["cases"][0].update(cleanup_verified=False),
            lambda value: value["cases"][0]["execution"].update(exit_code=1),
            lambda value: value["cases"][11].update(report=value["cases"][0]["report"]),
            lambda value: value["cases"][10]["execution"].update(selector_matches=False),
            lambda value: value["cases"][9]["execution"].update(exit_code=0),
        ):
            evidence = copy.deepcopy(original)
            mutate(evidence)
            with self.assertRaises(Rejected):
                self.reconcile(evidence, persisted, started)
        altered = copy.deepcopy(persisted)
        altered["controller"]["pod_uid"] = original["controller"]["pod_uid"]
        with self.assertRaisesRegex(Rejected, "kube_intake_reused_execution"):
            self.reconcile(original, altered, started)

    def test_readback_cannot_change_subject_or_approval_even_if_summaries_match(self):
        original, original_persisted, started = self.reconciliation_fixture()
        for field, value in (
            ("decision", "approve"),
            ("candidate_reference", "0" * 64),
            ("release_ready", True),
        ):
            evidence, persisted = copy.deepcopy(original), copy.deepcopy(original_persisted)
            evidence["denials"][0]["payload"][field] = value
            persisted["denials"][0][field] = value
            with self.assertRaisesRegex(Rejected, "kube_intake_denial_binding"):
                self.reconcile(evidence, persisted, started)
        evidence, persisted = copy.deepcopy(original), copy.deepcopy(original_persisted)
        evidence["denials"][0]["payload"]["holdout_access"]["slot"] = 1
        persisted["denials"][0]["holdout_access"]["slot"] = 1
        with self.assertRaisesRegex(Rejected, "kube_intake_budget_reuse"):
            self.reconcile(evidence, persisted, started)

    def test_reader_requires_promoter_and_does_not_load_parser(self):
        request = {
            "context": {},
            "evaluation_reference": "1" * 64,
            "denial_references": ["2" * 64, "3" * 64],
        }
        with (
            patch.object(intake_probe, "context", return_value=(None, {}, {}, {}, self.content)),
            self.assertRaisesRegex(Rejected, "kube_intake_reader_authority"),
        ):
            intake_probe.readback(request, Path("controlled"))
        for references in ([], ["2" * 64, "2" * 64]):
            with (
                patch.object(
                    intake_probe, "context", return_value=(None, {}, {}, {}, self.content)
                ),
                self.assertRaisesRegex(Rejected, "kube_intake_readback_set"),
            ):
                intake_probe.readback(
                    {**request, "denial_references": references}, Path("controlled")
                )

    def test_host_launcher_rejects_other_roles_without_resources(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(Rejected, "kube_intake_host_role"),
        ):
            kube_intake_qualification.invoke(Path(temporary), PROFILE, "publisher", {})

    def test_cleanup_refuses_foreign_uid_and_unknown_api_error(self):
        class Client:
            def request(self, *args, **kwargs):
                return {"metadata": {"uid": "foreign"}}

        with self.assertRaisesRegex(Rejected, "kube_intake_cleanup_identity"):
            intake_probe.cleanup(Client(), [("jobs", "owned", "expected")])
        with (
            patch.object(Client, "request", side_effect=APIError(403, "Forbidden")),
            self.assertRaises(APIError),
        ):
            intake_probe.cleanup(Client(), [("jobs", "owned", "expected")])

    def test_cleanup_timeout_is_not_success(self):
        class Client:
            def request(self, resource, *args, **kwargs):
                return {"items": []} if resource == "pods" else {"metadata": {"uid": "expected"}}

        with (
            patch.object(intake_probe.time, "monotonic", side_effect=[0, 31]),
            self.assertRaisesRegex(Rejected, "kube_intake_cleanup_deadline"),
        ):
            intake_probe.cleanup(Client(), [("jobs", "owned", "expected")])


if __name__ == "__main__":
    unittest.main()
