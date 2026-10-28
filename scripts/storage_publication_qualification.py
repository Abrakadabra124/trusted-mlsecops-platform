import copy
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import image_audit, storage_publication


def fixtures():
    moment = datetime.now(UTC)
    revision = "a" * 40
    fingerprint = "b" * 64
    identities = {
        role: {
            "role": role,
            "image_id": "sha256:" + marker * 64,
            "recipe_digest": marker * 64,
            "source_fingerprint": fingerprint,
            "release_ready": False,
        }
        for role, marker in (("worker", "c"), ("storage", "d"))
    }
    worker = {
        **identities["worker"],
        "scope": "candidate-developer-profile-only",
        "status": "pass",
        "completed_at": moment.isoformat(),
    }
    storage = {
        "scope": "candidate-storage-compatibility-not-adoption",
        "status": "pass",
        "release_ready": False,
        "completed_at": moment.isoformat(),
        "source_revision": revision,
        "source_dirty": False,
        "identities": identities,
        "source_resources_removed": True,
        "golden_rows": 1000,
        "golden_max_error": 0.0,
    }
    audit = {
        "scope": "worker-storage-tracking-image-audit-only",
        "status": "fail",
        "release_ready": False,
        "completed_at": moment.isoformat(),
        "source_revision": revision,
        "source_dirty": False,
        "source_fingerprint": fingerprint,
        "includes_candidates": True,
        "detection_control": "pass",
        "wolfi_detection_control": "pass",
        "policy": copy.deepcopy(image_audit.POLICY),
        "policy_digest": digest(canonical(image_audit.POLICY)),
        "components": [
            {
                "name": "tracking",
                "status": "fail",
                "scan_executed": True,
                "sbom_validated": True,
            }
        ]
        + [
            {
                "name": role + suffix,
                "status": "pass" if suffix else "fail",
                "scan_executed": True,
                "sbom_validated": True,
                "image_config_id": identities[role]["image_id"],
                "recipe_digest": identities[role]["recipe_digest"],
                "distro": "wolfi",
                "severity_counts": {"Critical": 0, "High": 0, "Unknown": 0},
            }
            for suffix in ("", "-candidate")
            for role in identities
        ],
    }
    return audit, worker, storage, identities, revision, fingerprint, moment, 0.000001


class PublicationContracts(unittest.TestCase):
    def test_tracking_cannot_be_omitted_or_left_unchecked(self):
        for mutation in (
            lambda audit: audit["components"].pop(0),
            lambda audit: audit["components"][0].update(scan_executed=False),
            lambda audit: audit["components"][0].update(sbom_validated=False),
            lambda audit: audit["components"][0].update(status="inconclusive"),
            lambda audit: audit.update(scope="worker-storage-image-audit-only"),
        ):
            arguments = fixtures()
            mutation(arguments[0])
            with self.assertRaises(Rejected):
                storage_publication.permit(*arguments)

    def test_qualified_artifact_does_not_override_baseline_failure(self):
        arguments = fixtures()
        result = storage_publication.permit(*arguments)
        self.assertIs(result["release_ready"], False)
        self.assertEqual(result["baseline_audit_status"], "fail")
        self.assertEqual(result["identity"], arguments[3]["storage"])
        self.assertEqual(len(result["evidence_digests"]), 3)

    def test_refuses_incomplete_foreign_stale_or_weakened_evidence(self):
        mutations = [
            lambda audit, worker, storage: audit.update(status="inconclusive"),
            lambda audit, worker, storage: audit.update(scope="other"),
            lambda audit, worker, storage: audit.update(source_dirty=True),
            lambda audit, worker, storage: storage.update(source_dirty=True),
            lambda audit, worker, storage: audit.update(source_revision="foreign"),
            lambda audit, worker, storage: storage.update(source_revision="foreign"),
            lambda audit, worker, storage: audit.update(source_fingerprint="foreign"),
            lambda audit, worker, storage: audit.update(detection_control="inconclusive"),
            lambda audit, worker, storage: audit.update(wolfi_detection_control="inconclusive"),
            lambda audit, worker, storage: audit.update(includes_candidates=False),
            lambda audit, worker, storage: audit["policy"].update(allow_exceptions=True),
            lambda audit, worker, storage: audit.update(policy_digest="foreign"),
            lambda audit, worker, storage: audit["components"].pop(),
            lambda audit, worker, storage: audit["components"].append(audit["components"][0]),
            lambda audit, worker, storage: audit["components"][0].update(scan_executed=False),
            lambda audit, worker, storage: audit["components"][0].update(status="inconclusive"),
            lambda audit, worker, storage: audit["components"][-1].update(status="fail"),
            lambda audit, worker, storage: audit["components"][-1].update(sbom_validated=False),
            lambda audit, worker, storage: audit["components"][-1].update(image_config_id="other"),
            lambda audit, worker, storage: audit["components"][-1].update(recipe_digest="other"),
            lambda audit, worker, storage: audit["components"][-1].update(distro="debian"),
            lambda audit, worker, storage: audit["components"][-1]["severity_counts"].update(
                High=1
            ),
            lambda audit, worker, storage: audit["components"][-1]["severity_counts"].update(
                Unknown=1
            ),
            lambda audit, worker, storage: audit["components"][-1]["severity_counts"].update(
                Critical=False
            ),
            lambda audit, worker, storage: worker.update(image_id="other"),
            lambda audit, worker, storage: worker.update(status="inconclusive"),
            lambda audit, worker, storage: worker.update(scope="fixture"),
            lambda audit, worker, storage: storage.update(identities={}),
            lambda audit, worker, storage: storage.update(status="fail"),
            lambda audit, worker, storage: storage.update(scope="fixture"),
            lambda audit, worker, storage: storage.update(source_resources_removed=False),
            lambda audit, worker, storage: storage.update(golden_rows=999),
            lambda audit, worker, storage: storage.update(golden_max_error=1),
            lambda audit, worker, storage: storage.update(golden_max_error=float("nan")),
            lambda audit, worker, storage: storage.update(golden_max_error=-1),
            lambda audit, worker, storage: storage.update(release_ready=True),
            lambda audit, worker, storage: worker.update(release_ready=True),
            lambda audit, worker, storage: audit.update(release_ready=True),
            lambda audit, worker, storage: audit.clear(),
            lambda audit, worker, storage: audit.update(completed_at=None),
            lambda audit, worker, storage: audit.update(completed_at="bad"),
            lambda audit, worker, storage: audit.update(completed_at="2026-10-20T00:00:00"),
            lambda audit, worker, storage: worker.update(
                completed_at=(datetime.now(UTC) - timedelta(hours=3)).isoformat()
            ),
            lambda audit, worker, storage: storage.update(
                completed_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat()
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                arguments = fixtures()
                mutate(*arguments[:3])
                with self.assertRaises(Rejected):
                    storage_publication.permit(*arguments)

    def test_only_expected_dispatch_can_publish(self):
        revision = "a" * 40
        environment = {
            "GITHUB_REPOSITORY": storage_publication.REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": revision,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        self.assertEqual(
            storage_publication.destination(environment, revision),
            f"{storage_publication.REGISTRY}:candidate-{revision}-123-1",
        )
        for key in environment:
            for invalid in ("", "../foreign", "0"):
                with self.subTest(key=key, value=invalid):
                    changed = {**environment, key: invalid}
                    with self.assertRaises(Rejected):
                        storage_publication.destination(changed, revision)
        with self.assertRaises(Rejected):
            storage_publication.destination(environment, "../bad")

    def test_registry_readback_binds_manifest_config_and_actual_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = fixtures()[3]["storage"]
            target = storage_publication.REGISTRY + ":candidate-test"
            descriptor = {"digest": "sha256:" + "e" * 64}
            manifest = {"schemaVersion": 2, "config": {"digest": identity["image_id"]}}
            actual = {"Id": identity["image_id"]}
            for fault in (
                "none",
                "digest",
                "schema",
                "config",
                "actual",
                "malformed",
                "empty",
                "local",
            ):
                with self.subTest(fault=fault):
                    selected = copy.deepcopy([descriptor, manifest, [actual]])
                    if fault == "digest":
                        selected[0]["digest"] = "mutable-tag"
                    if fault == "schema":
                        selected[1]["schemaVersion"] = 1
                    if fault == "config":
                        selected[1]["config"]["digest"] = "other"
                    if fault == "actual":
                        selected[2][0]["Id"] = "other"
                    if fault == "malformed":
                        selected[0] = {}
                    if fault == "empty":
                        selected[2] = []
                    outputs = [
                        canonical(selected[0]).decode(),
                        canonical(selected[1]).decode(),
                        "",
                        canonical(selected[2]).decode(),
                    ]
                    with (
                        patch.object(storage_publication, "command", side_effect=outputs),
                        patch.object(
                            storage_publication.image_candidates,
                            "inspect",
                            return_value={} if fault == "local" else identity,
                        ),
                    ):
                        if fault == "none":
                            self.assertEqual(
                                storage_publication.registry_readback(root, target, identity),
                                storage_publication.REGISTRY + "@" + descriptor["digest"],
                            )
                        else:
                            with self.assertRaises(Rejected):
                                storage_publication.registry_readback(root, target, identity)

    def test_checkout_and_actual_images_are_bound_before_publication(self):
        audit, worker, storage, identities, revision, fingerprint, moment, tolerance = fixtures()
        with (
            patch.object(storage_publication, "command", side_effect=[revision, ""]),
            patch.object(storage_publication, "destination", return_value="target") as destination,
            patch.object(
                storage_publication.image_candidates,
                "inspect",
                side_effect=lambda root, role: identities[role],
            ),
            patch.object(storage_publication, "source_fingerprint", return_value=fingerprint),
            patch.object(
                storage_publication,
                "read_json",
                side_effect=[audit, worker, storage, {"repeat_tolerance": tolerance}],
            ),
        ):
            result = storage_publication.qualification(Path("fixture"))
            self.assertEqual(result["target"], "target")
            self.assertEqual(destination.call_args.args[1], revision)
        with (
            patch.object(storage_publication, "command", side_effect=[revision, "dirty"]),
            patch.object(storage_publication.image_candidates, "inspect") as inspect,
        ):
            with self.assertRaises(Rejected):
                storage_publication.qualification(Path("fixture"))
            inspect.assert_not_called()

    def test_prepare_preserves_full_audit_with_baseline_failure(self):
        audit = fixtures()[0]
        proof = {"status": "pass", "release_ready": False}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(storage_publication, "publication_context"),
                patch.object(storage_publication.image_audit, "audit", return_value=audit) as scan,
                patch.object(storage_publication, "qualification", return_value=proof),
            ):
                self.assertEqual(storage_publication.prepare(root), proof)
                scan.assert_called_once_with(root, include_candidates=True)
            self.assertEqual(read_json(root / image_audit.REPORT), audit)
            with (
                patch.object(
                    storage_publication, "publication_context", side_effect=Rejected("context")
                ),
                patch.object(storage_publication.image_audit, "audit") as scan,
            ):
                with self.assertRaises(Rejected):
                    storage_publication.prepare(root)
                scan.assert_not_called()

    def test_publish_pushes_exact_checked_image_then_reads_digest(self):
        root = Path("fixture")
        proof = storage_publication.permit(*fixtures())
        proof["target"] = storage_publication.REGISTRY + ":candidate-test"
        reference = storage_publication.REGISTRY + "@sha256:" + "e" * 64
        with (
            patch.object(storage_publication, "qualification", return_value=proof),
            patch.object(storage_publication, "command") as command,
            patch.object(
                storage_publication, "registry_readback", return_value=reference
            ) as readback,
        ):
            report = storage_publication.publish(root)
            self.assertEqual(
                command.call_args_list[0].args[0],
                ["docker", "tag", proof["identity"]["image_id"], proof["target"]],
            )
            self.assertEqual(command.call_args_list[1].args[0], ["docker", "push", proof["target"]])
            readback.assert_called_once_with(root, proof["target"], proof["identity"])
            self.assertEqual(report["registry_reference"], reference)
            self.assertIs(report["public_access_verified"], False)
            self.assertIs(report["release_ready"], False)
        with (
            patch.object(storage_publication, "qualification", side_effect=Rejected("invalid")),
            patch.object(storage_publication, "command") as command,
        ):
            with self.assertRaises(Rejected):
                storage_publication.publish(root)
            command.assert_not_called()

    def test_entrypoint_invalidates_previous_success_and_sanitizes_io_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for action in ("prepare", "publish", None, "typo"):
                for failure in (None, Rejected("known_refusal"), OSError("private-canary")):
                    with self.subTest(action=action, failure=type(failure).__name__):
                        write_json(
                            root / storage_publication.REPORT, {"status": "pass", "old": True}
                        )
                        output = io.StringIO()
                        with (
                            patch("sys.argv", ["storage_publication", "prepare"]),
                            patch.object(
                                storage_publication,
                                "prepare",
                                return_value={"status": "pass", "release_ready": False},
                                side_effect=failure,
                            ),
                            patch.object(
                                storage_publication,
                                "publish",
                                return_value={"status": "pass", "release_ready": False},
                                side_effect=failure,
                            ),
                            redirect_stdout(output),
                        ):
                            exit_code = storage_publication.main(action, root)
                        expected = 2 if failure or action == "typo" else 0
                        self.assertEqual(exit_code, expected)
                        report = read_json(root / storage_publication.REPORT)
                        self.assertEqual(report["status"], "inconclusive" if expected else "pass")
                        self.assertNotIn("old", report)
                        self.assertNotIn("private-canary", output.getvalue())


if __name__ == "__main__":
    unittest.main()
