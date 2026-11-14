"""Apply the exact runbook patch in a private copy and check native phase ordering."""

import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/storage-recovery.yml"
PATCH_BASE = "ec3f4e31df7c42a9aa4e10183f147bf22f4da2c8"


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        document = (ROOT / "docs/operations/load-profile.md").read_text(encoding="utf-8")
        blocks = re.findall(r"```diff\n(.*?)```", document, re.S)
        if len(blocks) != 1:
            raise AssertionError("Expected one exact integration patch")
        cls.patch = blocks[0]
        cls.text = (ROOT / WORKFLOW).read_text(encoding="utf-8")
        if "      serving_trio:" not in cls.text:
            if "id: m23_sources" not in cls.text:
                # Independent branch before integration. Hosted checks use the
                # integrated workflow and do not require historical Git objects.
                cls.text = subprocess.run(
                    ["git", "show", PATCH_BASE + ":" + WORKFLOW],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                ).stdout.decode()
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                target = directory / WORKFLOW
                target.parent.mkdir(parents=True)
                target.write_text(cls.text, encoding="utf-8", newline="\n")
                subprocess.run(
                    ["git", "apply", "--check", "-"],
                    input=cls.patch.encode(),
                    cwd=directory,
                    capture_output=True,
                    check=True,
                )
                subprocess.run(
                    ["git", "apply", "-"],
                    input=cls.patch.encode(),
                    cwd=directory,
                    capture_output=True,
                    check=True,
                )
                cls.text = target.read_text(encoding="utf-8")
        cls.steps = re.split(r"^      - ", cls.text, flags=re.M)[1:]

    def test_patch_only_targets_workflow_and_preserves_one_proposal_producer(self):
        self.assertEqual(re.findall(r"^\+\+\+ (.*)$", self.patch, re.M), ["b/" + WORKFLOW])
        self.assertEqual(self.text.count("-m scripts.release_native --state .runtime"), 1)
        self.assertIn('test "$DELIVERY_SERVING_GATE" = M11-M12', self.text)
        self.assertIn("default: false", self.text)

    def test_trio_precedes_joint_actual_and_cluster_survives_until_controlled(self):
        ids = re.findall(r"^        id: (\S+)$", self.text, re.M)
        self.assertEqual(len(ids), len(set(ids)))
        ordered = (
            "source",
            "m18_freeze",
            "serving_retention",
            "full_intake",
            "m23_sources",
            "m23_inventory",
            "m23_outage",
            "m23_transition",
            "inventory_capture",
            "trio_m13",
            "privacy_to_load",
            "trio_m14",
            "load_to_monitoring",
            "trio_m15",
            "monitoring_to_joint",
            "joint_actual",
            "recovery",
            "stop_sql",
            "joint_controlled",
            "joint_gates",
            "stop_cluster",
            "joint_receipt",
            "m23_gate",
            "delivery",
            "trio_delivery",
        )
        positions = [ids.index(i) for i in ordered]
        self.assertEqual(positions, sorted(positions))
        actual = self.text.index("        id: joint_actual")
        controlled = self.text.index("        id: joint_controlled")
        self.assertNotIn("serving-campaign-transition", self.text[actual:controlled])
        self.assertNotIn("kind delete", self.text[actual:controlled])
        for phase in ("M23", "M13", "M14", "M15", "M11-M12"):
            self.assertIn("-m scripts.serving_retention check " + phase, self.text)

    def test_raw_file_pins_offline_witness_and_m18_strict_gap_are_preserved(self):
        for gate in ("M14", "M15"):
            self.assertIn(gate + "_KEYS_SHA256: ${{ steps.source.outputs.keys_file }}", self.text)
        replay = next(s for s in self.steps if "id: trio_delivery\n" in s)
        self.assertIn("SOURCE_OFFLINE_SHA256: ${{ steps.stop_sql.outputs.source_state }}", replay)
        self.assertIn("PARENT_RECEIPT: ${{ steps.delivery.outputs.receipt }}", replay)
        self.assertNotIn("always()", replay)
        self.assertIn('test "$result" -eq 2', self.text)
        self.assertIn("set(CHILDREN) - set(gates)", self.text)
        self.assertIn('set(gates) | {"M13", "M14", "M15"}', self.text)
        self.assertIn("from scripts.m23_delivery import gates as intake_gates", self.text)
        self.assertIn("-m scripts.m23_delivery receipt | tee", self.text)

    def test_inline_python_and_action_script_compile_without_running_native_commands(self):
        action = (ROOT / ".github/actions/serving-campaign-transition/action.yml").read_text(
            encoding="utf-8"
        )
        for source in (self.text, action):
            scripts = re.findall(r"<<'PY'\n(.*?)^\s*PY$", source, re.M | re.S)
            self.assertTrue(scripts)
            for script in scripts:
                compile(textwrap.dedent(script), "workflow-inline", "exec")
        self.assertIn('"M15": "M11-M12"', action)
        self.assertIn('phase == "M15" and not retention', action)
        self.assertEqual(action.count("preflight(root, state, retention"), 2)


if __name__ == "__main__":
    unittest.main()
