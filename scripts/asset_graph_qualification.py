import copy
import unittest
from unittest.mock import patch

from mlsecops.asset_graph import assess
from mlsecops.contracts import Rejected, canonical, digest
from scripts.asset_graph_fixture import ENVIRONMENT, OWNERS, fixture


class AssetGraphContracts(unittest.TestCase):
    def setUp(self):
        self.graph, self.snapshot, self.revoked = fixture()
        self.assets = {asset["asset_id"]: asset for asset in self.graph["assets"]}

    def run_case(self, owners=None, environment=ENVIRONMENT, revoked=None):
        return assess(
            self.graph,
            OWNERS if owners is None else owners,
            environment,
            self.snapshot,
            self.revoked if revoked is None else revoked,
        )

    def rebind_snapshot(self):
        self.snapshot["graph_sha256"] = digest(canonical(self.graph))

    def test_exact_m19_fixture_and_no_release_authority(self):
        result = self.run_case()
        self.assertEqual(
            result["impacted_assets"],
            sorted(
                [
                    "dataset-a",
                    "run-a-current",
                    "run-a-previous",
                    "model-a-current",
                    "model-a-previous",
                    "release-a-current",
                    "release-a-previous",
                    "deployment-a-primary",
                    "deployment-a-canary",
                    "deployment-a-rollback",
                ]
            ),
        )
        self.assertEqual(
            result["blocked_deployments"],
            [
                "deployment-a-canary",
                "deployment-a-primary",
                "deployment-a-rollback",
            ],
        )
        self.assertEqual(result["unaffected_deployments"], ["deployment-b"])
        self.assertEqual(result["component_status"], "pass")
        self.assertEqual(result["full_M19"], "inconclusive")
        self.assertIs(result["release_ready"], False)
        self.assertEqual(result["asset_count"], 17)

    def test_unknown_owner_cannot_self_register(self):
        self.assets["dataset-a"]["owner"] = "attacker"
        with self.assertRaisesRegex(Rejected, "owner"):
            self.run_case()

    def test_unknown_dangling_and_digest_swapped_dependencies(self):
        original = copy.deepcopy(self.graph)
        for field, value in (("asset_id", "missing"), ("sha256", "f" * 64)):
            with self.subTest(field=field):
                self.graph = copy.deepcopy(original)
                self.graph["assets"][4]["dependencies"][0][field] = value
                with self.assertRaises(Rejected):
                    self.run_case()

    def test_cycles_including_self_reference_are_rejected(self):
        for target in ("dataset-a", "model-a-current"):
            with self.subTest(target=target):
                self.assets["dataset-a"]["dependencies"] = [
                    {"asset_id": target, "sha256": self.assets[target]["sha256"]}
                ]
                with self.assertRaisesRegex(Rejected, "cycle"):
                    self.run_case()

    def test_missing_required_dependencies_cannot_make_models_roots(self):
        for asset in self.graph["assets"]:
            if not asset["dependencies"]:
                continue
            original = asset["dependencies"]
            asset["dependencies"] = []
            with (
                self.subTest(kind=asset["kind"]),
                self.assertRaisesRegex(Rejected, "dependency_kinds"),
            ):
                self.run_case()
            asset["dependencies"] = original

    def test_actual_digest_mismatches_and_alias_fields_rejected(self):
        original = copy.deepcopy(self.snapshot)
        for key in ("sha256", "release_sha256", "model_sha256", "runtime_sha256", "policy_sha256"):
            self.snapshot = copy.deepcopy(original)
            self.snapshot["deployments"][0][key] = "f" * 64
            with self.subTest(key=key), self.assertRaisesRegex(Rejected, "observed_digest"):
                self.run_case()
        self.snapshot = original
        self.snapshot["deployments"][0]["alias"] = "champion"
        with self.assertRaises(Rejected):
            self.run_case()

    def test_incomplete_unknown_duplicate_snapshot_is_rejected(self):
        original = copy.deepcopy(self.snapshot)
        variants = [
            original["deployments"][:-1],
            original["deployments"] * 2,
            [{**original["deployments"][0], "asset_id": "unknown"}],
        ]
        for variant in variants:
            self.snapshot = {**original, "deployments": variant}
            with self.subTest(variant=variant), self.assertRaises(Rejected):
                self.run_case()

    def test_revocation_requires_known_immutable_reference(self):
        for revoked in (
            [{"asset_id": "unknown", "sha256": "a" * 64}],
            [{"asset_id": "dataset-a", "sha256": "a" * 64}],
            self.revoked * 2,
            ["dataset-a"],
            None,
        ):
            with self.subTest(revoked=revoked), self.assertRaises(Rejected):
                assess(self.graph, OWNERS, ENVIRONMENT, self.snapshot, revoked)

    def test_shared_runtime_revokes_all_deployments(self):
        result = self.run_case(
            revoked=[
                {
                    "asset_id": "runtime-shared",
                    "sha256": self.assets["runtime-shared"]["sha256"],
                }
            ]
        )
        self.assertEqual(len(result["blocked_deployments"]), 4)
        self.assertEqual(result["unaffected_deployments"], [])
        self.assertNotIn("dataset-a", result["impacted_assets"])
        self.assertNotIn("dataset-b", result["impacted_assets"])

    def test_empty_revocation_is_not_promotion(self):
        result = self.run_case(revoked=[])
        self.assertEqual(result["impacted_assets"], [])
        self.assertEqual(len(result["unaffected_deployments"]), 4)
        self.assertIs(result["release_ready"], False)

    def test_alias_of_impacted_content_cannot_escape_revocation(self):
        self.assets["model-b"]["sha256"] = self.assets["model-a-current"]["sha256"]
        self.assets["release-b"]["dependencies"][0]["sha256"] = self.assets["model-b"]["sha256"]
        self.snapshot["deployments"][3]["model_sha256"] = self.assets["model-b"]["sha256"]
        self.rebind_snapshot()
        result = self.run_case()
        self.assertEqual(len(result["blocked_deployments"]), 4)
        self.assertNotIn("dataset-b", result["impacted_assets"])
        self.assertNotIn("run-b", result["impacted_assets"])

    def test_inputs_not_mutated_and_results_deterministic(self):
        before = copy.deepcopy((self.graph, self.snapshot, self.revoked))
        result = self.run_case()
        self.assertEqual(result, self.run_case())
        self.assertEqual(before, (self.graph, self.snapshot, self.revoked))

    def test_schema_versions_and_unknown_fields_rejected(self):
        for target in (self.graph, self.snapshot):
            for version in (0, 2, True, 1.0, "1", None):
                target["schema_version"] = version
                with self.subTest(version=version), self.assertRaises(Rejected):
                    self.run_case()
            target["schema_version"] = 1
            target["unknown"] = "not-accepted"
            with self.assertRaises(Rejected):
                self.run_case()
            del target["unknown"]

    def test_document_and_collection_bounds(self):
        with patch("mlsecops.asset_graph.MAX_DOCUMENT_BYTES", 10):
            with self.assertRaisesRegex(Rejected, "document_too_large"):
                self.run_case()
        original = self.graph["assets"]
        for value in ([], None, {}, original * 60):
            self.graph["assets"] = value
            with self.subTest(value_type=type(value)), self.assertRaises(Rejected):
                self.run_case()
        self.graph["assets"] = original
        original_dependencies = self.assets["run-b"]["dependencies"]
        self.assets["run-b"]["dependencies"] = original_dependencies * 11
        with self.assertRaises(Rejected):
            self.run_case()
        self.assets["run-b"]["dependencies"] = original_dependencies
        self.snapshot["deployments"] *= 251
        with self.assertRaises(Rejected):
            self.run_case()
        self.graph, self.snapshot, self.revoked = fixture()
        with self.assertRaises(Rejected):
            self.run_case(revoked=self.revoked * 1001)

    def test_excessively_nested_input_is_a_controlled_rejection(self):
        nested = []
        for index in range(12000):
            nested = [nested]
        self.graph["assets"] = nested
        with self.assertRaisesRegex(Rejected, "document_nesting"):
            self.run_case()

    def test_owner_registry_bounds_and_environment(self):
        for owners in ([], ["owner"] * 129, ["data-owner"] * 2, [None], [" bad"], {}):
            with self.subTest(owners=owners), self.assertRaises(Rejected):
                self.run_case(owners=owners)
        for environment in (None, "production"):
            with self.subTest(environment=environment), self.assertRaises(Rejected):
                self.run_case(environment=environment)

    def test_asset_id_kind_digest_and_shape_validation(self):
        asset = self.assets["dataset-a"]
        for key, values in {
            "asset_id": [None, "dataset-b", "../escape", "a" * 97, "A"],
            "kind": [[], "unknown"],
            "sha256": [None, "a" * 63, "A" * 64, "sha256:" + "a" * 64],
            "owner": [None],
            "environment": [None, "production"],
            "dependencies": [None],
        }.items():
            original = asset[key]
            for value in values:
                asset[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(Rejected):
                    self.run_case()
            asset[key] = original
        asset["unknown"] = 1
        with self.assertRaises(Rejected):
            self.run_case()
        del asset["unknown"]
        self.graph["assets"][0] = "not-a-record"
        with self.assertRaises(Rejected):
            self.run_case()

    def test_duplicate_dependency_and_wrong_root_edge_rejected(self):
        run = self.assets["run-b"]
        run["dependencies"].append(copy.deepcopy(run["dependencies"][0]))
        with self.assertRaisesRegex(Rejected, "duplicate_dependency"):
            self.run_case()
        run["dependencies"].pop()
        self.assets["dataset-a"]["dependencies"] = [
            {"asset_id": "dataset-b", "sha256": self.assets["dataset-b"]["sha256"]}
        ]
        with self.assertRaisesRegex(Rejected, "dependency_kinds"):
            self.run_case()

    def test_multiple_datasets_and_multiple_revocations(self):
        self.assets["run-b"]["dependencies"].append(copy.deepcopy(self.revoked[0]))
        self.rebind_snapshot()
        result = self.run_case()
        self.assertEqual(len(result["blocked_deployments"]), 4)
        self.assertNotIn("dataset-b", result["impacted_assets"])
        extra = {"asset_id": "dataset-b", "sha256": self.assets["dataset-b"]["sha256"]}
        result = self.run_case(revoked=[extra, *self.revoked])
        self.assertEqual(result["revoked_assets"], ["dataset-a", "dataset-b"])

    def test_release_cannot_swap_training_runtime_or_policy(self):
        for kind in ("runtime", "policy"):
            self.graph, self.snapshot, self.revoked = fixture()
            assets = {asset["asset_id"]: asset for asset in self.graph["assets"]}
            alternate = copy.deepcopy(assets[f"{kind}-shared"])
            alternate["asset_id"] = f"{kind}-alternate"
            self.graph["assets"].append(alternate)
            release = assets["release-a-current"]
            for reference in release["dependencies"]:
                if reference["asset_id"] == f"{kind}-shared":
                    reference["asset_id"] = alternate["asset_id"]
            with self.subTest(kind=kind), self.assertRaisesRegex(Rejected, "material_mismatch"):
                self.run_case()

    def test_snapshot_requires_current_graph_and_environment(self):
        for field, value in (("environment", "production"), ("graph_sha256", "a" * 64)):
            original = self.snapshot[field]
            self.snapshot[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(Rejected, "binding_mismatch"):
                self.run_case()
            self.snapshot[field] = original
        self.snapshot["deployments"][0]["asset_id"] = "dataset-a"
        with self.assertRaisesRegex(Rejected, "deployment"):
            self.run_case()

    def test_deployment_revocation_does_not_revoke_ancestors_or_peers(self):
        name = "deployment-a-primary"
        result = self.run_case(revoked=[{"asset_id": name, "sha256": self.assets[name]["sha256"]}])
        self.assertEqual(result["impacted_assets"], [name])
        self.assertEqual(result["blocked_deployments"], [name])
        self.assertEqual(len(result["unaffected_deployments"]), 3)

    def test_shared_policy_and_duplicate_content_are_transitive(self):
        self.assets["policy-shared"]["sha256"] = self.assets["dataset-b"]["sha256"]
        for asset in self.graph["assets"]:
            for reference in asset["dependencies"]:
                if reference["asset_id"] == "policy-shared":
                    reference["sha256"] = self.assets["policy-shared"]["sha256"]
        for record in self.snapshot["deployments"]:
            record["policy_sha256"] = self.assets["policy-shared"]["sha256"]
        self.rebind_snapshot()
        result = self.run_case(
            revoked=[
                {
                    "asset_id": "policy-shared",
                    "sha256": self.assets["policy-shared"]["sha256"],
                }
            ]
        )
        self.assertEqual(len(result["blocked_deployments"]), 4)
        self.assertNotIn("dataset-b", result["impacted_assets"])

    def test_acyclic_wrong_dependency_type_is_rejected(self):
        self.assets["model-a-current"]["dependencies"] = copy.deepcopy(self.revoked)
        with self.assertRaisesRegex(Rejected, "dependency_kinds"):
            self.run_case()

    def test_graph_order_does_not_change_impact(self):
        expected = self.run_case()["impacted_assets"]
        self.graph["assets"].reverse()
        for asset in self.graph["assets"]:
            asset["dependencies"].reverse()
        self.rebind_snapshot()
        self.assertEqual(self.run_case()["impacted_assets"], expected)


if __name__ == "__main__":
    unittest.main()
