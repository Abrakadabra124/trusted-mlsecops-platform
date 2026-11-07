"""Hosted composition preconditions and safe failure publication."""

import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, read_json, write_json
from scripts import kube_candidate_native as candidate
from scripts import kube_monitoring_native as native
from scripts import kube_serving_native as serving
from scripts.kube_serving_runtime_qualification import PROFILE


class NativeMonitoringContracts(unittest.TestCase):
    def test_module_entrypoint_rejects_unowned_host_before_infrastructure(self):
        with (
            patch("scripts.kube_trust_native.hosted", side_effect=Rejected("PRIVATE")),
            patch.object(sys, "stdout", io.StringIO()) as output,
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_module("scripts.kube_monitoring_native", run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertNotIn("PRIVATE", output.getvalue())

    def test_mode_conflicts_reject_before_any_resource_change(self):
        for options in (
            {},
            {"candidate_probe": True, "load_operator": Mock()},
            {"candidate_probe": True, "privacy_operator": Mock()},
            {"candidate_probe": True, "cli_privacy": True},
            {"candidate_probe": True, "coordinator": Mock()},
            {"candidate_probe": True, "trust_target": serving.Target.MODEL_REVOCATION},
        ):
            with patch.object(serving, "kubectl") as api, self.assertRaises(Rejected):
                serving.invoke(
                    Path("unused"), PROFILE, {}, {}, monitoring_operator=Mock(), **options
                )
            api.assert_not_called()
        for options in (
            {"load": True},
            {"privacy": True},
            {"include_trust_lifecycle": True},
            {"include_key_revocation": True},
            {},
        ):
            with (
                patch.object(candidate, "hosted"),
                patch.object(candidate, "command") as command,
                self.assertRaises(Rejected),
            ):
                candidate.qualify(
                    "unused", "unused", "unused", monitoring=True if options else 1, **options
                )
            command.assert_not_called()

    def test_run_keeps_inconclusive_until_candidate_and_primary_reverification_succeed(self):
        for failure in (None, "prepare", "qualify", "reverify"):
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                campaign = "a" * 32
                write_json(state / ("evidence/monitoring/" + campaign + "/binding.json"), {})
                result = {
                    name: "fixture"
                    for name in (
                        "source",
                        "started_at",
                        "finished_at",
                        "candidate_reference",
                        "proposal_reference",
                        "model_sha256",
                        "subject_sha256",
                        "qualification_permit_sha256",
                    )
                }
                result.update(
                    source_dirty=False,
                    full_M15="inconclusive",
                    release_ready=False,
                    native={},
                    monitoring_campaign_id=campaign,
                )
                with (
                    patch.object(native, "hosted"),
                    patch.object(native.promotion_state, "install") as install,
                    patch.object(
                        native,
                        "prepare",
                        return_value={"profile": PROFILE, "actual": {}},
                        side_effect=Rejected("PRIVATE") if failure == "prepare" else None,
                    ),
                    patch.object(
                        native,
                        "qualify",
                        return_value=result,
                        side_effect=Rejected("PRIVATE") if failure == "qualify" else None,
                    ) as qualify,
                    patch.object(
                        native,
                        "reverify",
                        return_value={"status": "pass"},
                        side_effect=Rejected("PRIVATE") if failure == "reverify" else None,
                    ),
                ):
                    if failure:
                        with self.assertRaises(Rejected):
                            native.run(state, state)
                    else:
                        public = native.run(state, state)
                        self.assertEqual(public["full_M15"], "inconclusive")
                        self.assertFalse(public["release_ready"])
                        self.assertTrue(qualify.call_args.kwargs["monitoring"])
                    install.assert_called_once_with(state, backend=native.kube_storage.binding)
                    if failure in ("prepare", "qualify"):
                        self.assertEqual(
                            read_json(state / "evidence/kubernetes-monitoring-public.json")[
                                "status"
                            ],
                            "inconclusive",
                        )
                    if failure == "reverify":
                        self.assertEqual(
                            read_json(state / "evidence/kubernetes-monitoring-public.json")[
                                "status"
                            ],
                            "fail",
                        )

    def test_cli_success_reverification_invalid_arguments_and_private_failure(self):
        for arguments in ([], ["--reverify"], ["--wrong"]):
            with (
                patch.object(native, "hosted"),
                patch.object(native, "run", return_value={"status": "pass"}) as run,
                patch.object(native, "reverify", return_value={"status": "pass"}) as verify,
                patch.object(sys, "argv", ["native", *arguments]),
                patch.object(sys, "stdout", io.StringIO()) as output,
            ):
                self.assertEqual(native.main(), int(arguments == ["--wrong"]))
                self.assertEqual(run.call_count, int(not arguments))
                self.assertEqual(verify.call_count, int(arguments == ["--reverify"]))
                self.assertNotIn("PRIVATE", output.getvalue())
        with (
            patch.object(native, "hosted", side_effect=RuntimeError("PRIVATE")),
            patch.object(sys, "stdout", io.StringIO()) as output,
        ):
            self.assertEqual(native.main(), 1)
            self.assertNotIn("PRIVATE", output.getvalue())


if __name__ == "__main__":
    unittest.main()
