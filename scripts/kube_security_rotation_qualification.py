"""Rotation operator refuses unproven state before mutating owned resources."""

import copy
import importlib.util
import io
import unittest
from contextlib import ExitStack, redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_observer_profile_qualification as profiles


class RotationOperator(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.kube_security_rotation"))
        from mlsecops import kube_security_rotation as subject

        self.subject = subject
        self.fx = profiles.ObserverProfile()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.marker = dict(
            workspace_id="a" * 32,
            profile={"image": "test@sha256:" + "b" * 64},
            context=self.fx.context,
            resources={},
            pins={"trust": "c" * 64},
            ready=True,
        )

    def test_interrupted_update_never_restores_ready_or_resets_outbox(self):
        for failure in ("create", "replace", "wait_empty", "wait_observed", "final_validate", None):
            with self.subTest(failure=failure), ExitStack() as stack:
                saved, calls = [], []

                def step(name, result=None):
                    def run(*args, **kwargs):
                        calls.append(name)
                        if name == failure:
                            raise Rejected("controlled_interruption")
                        return result

                    return run

                validates = iter([self.marker, self.marker])

                def validate(*args, **kwargs):
                    value = next(validates)
                    if kwargs:
                        step("final_validate")()
                    return value

                stack.enter_context(
                    patch.object(self.subject.audit, "validate", side_effect=validate)
                )
                stack.enter_context(
                    patch.object(self.subject.io, "history", return_value=self.fx.history)
                )
                stack.enter_context(
                    patch.object(self.subject.io, "outbox", return_value={"pin": "c" * 64})
                )
                stack.enter_context(
                    patch.object(self.subject.io, "pod", return_value={"metadata": {"uid": "old"}})
                )
                stack.enter_context(
                    patch.object(self.subject.audit, "directory", return_value="private-state")
                )
                stack.enter_context(
                    patch.object(
                        self.subject.audit,
                        "save",
                        side_effect=lambda path, marker: saved.append(copy.deepcopy(marker)),
                    )
                )
                stack.enter_context(
                    patch.object(self.subject.audit, "create", side_effect=step("create"))
                )
                stack.enter_context(
                    patch.object(self.subject, "replace", side_effect=step("replace"))
                )
                stack.enter_context(
                    patch.object(self.subject, "wait_empty", side_effect=step("wait_empty"))
                )
                stack.enter_context(
                    patch.object(
                        self.subject,
                        "wait_observed",
                        side_effect=step("wait_observed", {"verified": True}),
                    )
                )
                if failure is None:
                    self.assertEqual(
                        self.subject.update(
                            "unused", self.fx.package, next_root=self.fx.fx.new_public
                        ),
                        dict(verified=True, reused=False, release_ready=False),
                    )
                    self.assertEqual(
                        calls,
                        [
                            "create",
                            "replace",
                            "wait_empty",
                            "replace",
                            "wait_observed",
                            "final_validate",
                        ],
                    )
                    self.assertTrue(saved[-1]["ready"])
                else:
                    with self.assertRaisesRegex(Rejected, "controlled_interruption"):
                        self.subject.update(
                            "unused", self.fx.package, next_root=self.fx.fx.new_public
                        )
                    self.assertFalse(saved[-1]["ready"])
                self.assertFalse(saved[0]["ready"])
                self.assertEqual(saved[-1]["pins"], self.marker["pins"])
                self.assertTrue(self.marker["ready"])

    def test_state_continuity_requires_prefix_identity_pin_and_advancing_heartbeat(self):
        before = dict(pin="p", producer_id="id", count=2, prefix_sha256="hash", heartbeat=5)
        after = {**before, "heartbeat": 6}
        self.subject.retained(before, after, "p")
        for key, value in (
            ("pin", "other"),
            ("producer_id", "other"),
            ("count", 1),
            ("prefix_sha256", "changed"),
            ("heartbeat", 5),
            ("heartbeat", 0),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.subject.retained(before, {**after, key: value}, "p")

    def test_delivery_needs_new_instance_and_independent_current_counter(self):
        self.marker["pins"]["collector"] = "d" * 64
        before = dict(pin="c" * 64, producer_id="id", count=2, prefix_sha256="hash", heartbeat=5)
        after = {**before, "heartbeat": 6}
        identity = ("new", "container", 0)
        receipt = dict(pin="d" * 64, heartbeat=6)
        for fault in (
            "same-pod",
            "old-counter",
            "wrong-collector",
            "restarted",
            "no-first-success",
            "late",
            None,
        ):
            with self.subTest(fault=fault), ExitStack() as stack:
                stack.enter_context(
                    patch.object(
                        self.subject.io,
                        "success",
                        side_effect=Rejected("missing") if fault == "no-first-success" else None,
                        return_value=("old", *identity[1:]) if fault == "same-pod" else identity,
                    )
                )
                stack.enter_context(patch.object(self.subject.io, "outbox", return_value=after))
                stack.enter_context(
                    patch.object(
                        self.subject.io,
                        "collector",
                        return_value={
                            **receipt,
                            **(
                                {"heartbeat": 5}
                                if fault == "old-counter"
                                else {"pin": "foreign"}
                                if fault == "wrong-collector"
                                else {}
                            ),
                        },
                    )
                )
                stack.enter_context(patch.object(self.subject.io, "pod"))
                stack.enter_context(
                    patch.object(
                        self.subject.io,
                        "instance",
                        return_value=("new", "restarted", 1) if fault == "restarted" else identity,
                    )
                )
                stack.enter_context(
                    patch.object(
                        self.subject.time, "monotonic", return_value=10 if fault is None else 121
                    )
                )
                if fault is None:
                    self.assertTrue(
                        self.subject.wait_observed(
                            "state", self.marker, before, "old", pin="pin", started=0
                        )["first_source_check_confirmed"]
                    )
                else:
                    with self.assertRaisesRegex(Rejected, "transition_deadline"):
                        self.subject.wait_observed(
                            "state", self.marker, before, "old", pin="pin", started=0
                        )

    def test_stop_wait_is_bounded_and_never_deletes_unidentified_pods(self):
        document = self.subject.audit.runtime(self.marker, "trust")
        with patch.object(
            self.subject, "kubectl", return_value=SimpleNamespace(stdout=canonical({"items": []}))
        ) as call:
            self.subject.wait_empty("state", document)
        self.assertEqual(call.call_args.args[1][0], "get")
        with (
            patch.object(
                self.subject,
                "kubectl",
                return_value=SimpleNamespace(stdout=canonical({"items": [{}]})),
            ),
            patch.object(self.subject.time, "monotonic", side_effect=[0, 46]),
            self.assertRaisesRegex(Rejected, "stop_deadline"),
        ):
            self.subject.wait_empty("state", document)

    def test_native_probe_rejects_local_host_before_authority_access(self):
        from scripts import kube_observer_rotation_native as native

        with (
            patch.object(native, "hosted", side_effect=Rejected("hosted_only")),
            patch.object(native.audit, "validate") as read,
            self.assertRaisesRegex(Rejected, "hosted_only"),
        ):
            native.qualify("state", "key")
        read.assert_not_called()

    def test_owned_obsolete_config_deletion_requires_uid_and_absence_readback(self):
        document = self.subject.profiles.mapping(
            self.marker["workspace_id"], self.fx.created(), self.marker["context"]
        )
        key = self.subject.storage.reference(document)
        self.marker["resources"][key] = "owned"
        observed = copy.deepcopy(document)
        observed["metadata"]["uid"] = "owned"
        with (
            patch.object(self.subject.storage, "get", side_effect=[observed, None]),
            patch.object(self.subject, "kubectl") as api,
            patch.object(self.subject.audit, "save"),
        ):
            self.subject.remove("state", "private", self.marker, document)
        self.assertEqual(api.call_args.args[2]["preconditions"], {"uid": "owned"})
        self.assertNotIn(key, self.marker["resources"])
        self.marker["resources"][key] = "owned"
        for wrong in (False, True):
            foreign = copy.deepcopy(observed)
            if wrong:
                foreign["metadata"]["uid"] = "foreign"
            with (
                patch.object(self.subject.storage, "get", return_value=foreign),
                patch.object(self.subject, "kubectl") as api,
                patch.object(self.subject.audit, "save") as save,
                self.assertRaises(Rejected),
            ):
                self.subject.remove("state", "private", self.marker, document)
            save.assert_not_called()
            self.assertIn(key, self.marker["resources"])
            if wrong:
                api.assert_not_called()

    def test_outbox_pin_and_changed_deployment_identity_refuse_before_write(self):
        with (
            patch.object(self.subject.audit, "validate", return_value=self.marker),
            patch.object(self.subject.io, "history", return_value=self.fx.history),
            patch.object(self.subject.io, "outbox", return_value={"pin": "foreign"}),
            patch.object(self.subject.audit, "save") as save,
            self.assertRaisesRegex(Rejected, "outbox_pin"),
        ):
            self.subject.update("state", self.fx.package, next_root=self.fx.fx.new_public)
        save.assert_not_called()
        before = self.subject.audit.runtime(self.marker, "trust")
        after = copy.deepcopy(before)
        after["metadata"]["name"] = "foreign"
        with (
            patch.object(self.subject.storage, "get") as read,
            self.assertRaisesRegex(Rejected, "deployment_changed"),
        ):
            self.subject.replace("state", self.marker, before, after)
        read.assert_not_called()

    def test_successful_second_transition_removes_only_previous_mapping_after_proof(self):
        self.marker["observer"] = self.fx.created()
        candidate = copy.deepcopy(self.marker["observer"])
        candidate["history"]["clock"] += 1
        calls = []
        with (
            patch.object(self.subject.audit, "validate", return_value=self.marker),
            patch.object(self.subject.profiles, "advance", return_value=candidate),
            patch.object(self.subject.io, "history"),
            patch.object(self.subject.io, "outbox", return_value={"pin": "c" * 64}),
            patch.object(self.subject.io, "pod", return_value={"metadata": {"uid": "old"}}),
            patch.object(self.subject.audit, "directory", return_value="private-state"),
            patch.object(self.subject.audit, "save"),
            patch.object(self.subject.audit, "create"),
            patch.object(self.subject, "replace"),
            patch.object(self.subject, "wait_empty"),
            patch.object(
                self.subject,
                "wait_observed",
                side_effect=lambda *a, **k: calls.append("proof") or {},
            ),
            patch.object(self.subject, "remove", side_effect=lambda *a: calls.append("remove")),
        ):
            self.subject.update("state", self.fx.package, next_root=self.fx.fx.new_public)
        self.assertEqual(calls, ["proof", "remove"])

    def test_readiness_poll_recovers_without_rewriting_state_or_using_old_container(self):
        self.marker["pins"]["collector"] = "d" * 64
        before = dict(pin="c" * 64, producer_id="id", count=0, prefix_sha256="hash", heartbeat=1)
        identity = ("new", "container", 0)
        with (
            patch.object(self.subject.io, "success", side_effect=[Rejected("not_ready"), identity]),
            patch.object(self.subject.io, "outbox", return_value={**before, "heartbeat": 2}),
            patch.object(
                self.subject.io, "collector", return_value=dict(pin="d" * 64, heartbeat=2)
            ),
            patch.object(self.subject.io, "pod"),
            patch.object(self.subject.io, "instance", return_value=identity),
            patch.object(self.subject.time, "monotonic", return_value=10),
            patch.object(self.subject.time, "sleep") as sleep,
        ):
            self.subject.wait_observed("state", self.marker, before, "old", pin="pin", started=0)
        sleep.assert_called_once_with(0.5)
        document = self.subject.audit.runtime(self.marker, "trust")
        with (
            patch.object(
                self.subject,
                "kubectl",
                side_effect=[
                    SimpleNamespace(stdout=canonical({"items": [{}]})),
                    SimpleNamespace(stdout=canonical({"items": []})),
                ],
            ),
            patch.object(self.subject.time, "monotonic", return_value=10),
            patch.object(self.subject.time, "sleep") as sleep,
        ):
            self.subject.wait_empty("state", document)
        sleep.assert_called_once_with(0.5)

    def test_cli_sanitizes_private_failure_and_interrupt(self):
        for error, expected in ((Rejected("PRIVATE-CANARY"), 1), (KeyboardInterrupt(), 130)):
            with (
                patch.object(self.subject, "bounded_read", side_effect=error),
                redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(
                    self.subject.main(
                        ["--state", "state", "--package", "file", "--next-root", "key"]
                    ),
                    expected,
                )
            self.assertEqual(stderr.getvalue(), "kube_observer_transition_rejected\n")
        from contextlib import redirect_stdout

        with (
            patch.object(self.subject, "bounded_read", return_value=b"{}"),
            patch.object(self.subject, "update", return_value={"release_ready": False}),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                self.subject.main(["--state", "state", "--package", "file", "--next-root", "key"]),
                0,
            )
        self.assertEqual(output.getvalue(), '{"release_ready":false}\n')

    def test_unproven_transition_never_changes_marker_or_cluster(self):
        changed = copy.deepcopy(self.fx.package)
        changed["acceptance"]["signatures"] = []
        with (
            patch.object(self.subject.audit, "validate", return_value=self.marker),
            patch.object(self.subject.io, "history", return_value=self.fx.history),
            patch.object(self.subject.audit, "save") as save,
            patch.object(self.subject, "replace") as replace,
            self.assertRaises(Rejected),
        ):
            self.subject.update("unused", changed, next_root=self.fx.fx.new_public)
        save.assert_not_called()
        replace.assert_not_called()
        self.assertTrue(self.marker["ready"])

    def test_retry_is_read_only_and_rejects_changed_package(self):
        self.marker["observer"] = self.fx.created()
        with (
            patch.object(self.subject.audit, "validate", return_value=self.marker),
            patch.object(self.subject.io, "history", return_value=self.fx.history),
            patch.object(self.subject.audit, "save") as save,
            patch.object(self.subject, "replace") as replace,
        ):
            result = self.subject.update("unused", self.fx.package, next_root=self.fx.fx.new_public)
        self.assertTrue(result["reused"])
        self.assertFalse(result["release_ready"])
        save.assert_not_called()
        replace.assert_not_called()

    def test_replace_binds_uid_and_resource_version_and_accepts_new_version(self):
        before = self.subject.audit.runtime(self.marker, "trust")
        after = copy.deepcopy(before)
        after["spec"]["replicas"] = 0
        key = self.subject.storage.reference(before)
        self.marker["resources"][key] = "owned"
        observed = copy.deepcopy(before)
        observed["metadata"].update(uid="owned", resourceVersion="123")
        result = copy.deepcopy(after)
        result["metadata"].update(uid="owned", resourceVersion="124")
        with (
            patch.object(self.subject.storage, "get", return_value=observed),
            patch.object(
                self.subject, "kubectl", return_value=SimpleNamespace(stdout=canonical(result))
            ) as call,
        ):
            self.subject.replace("state", self.marker, before, after)
        self.assertEqual(call.call_args.args[2]["metadata"]["resourceVersion"], "123")
        self.assertNotIn("uid", before["metadata"])
        for mutation in ({"uid": "foreign"}, {"resourceVersion": ""}):
            wrong = copy.deepcopy(observed)
            wrong["metadata"].update(mutation)
            with (
                patch.object(self.subject.storage, "get", return_value=wrong),
                patch.object(self.subject, "kubectl") as call,
                self.assertRaises(Rejected),
            ):
                self.subject.replace("state", self.marker, before, after)
            call.assert_not_called()


class ObserverReadback(unittest.TestCase):
    def setUp(self):
        from mlsecops import kube_observer_readback as subject

        self.subject = subject
        self.pod = dict(
            metadata={"uid": "pod", "name": "observer"},
            status={
                "containerStatuses": [
                    dict(
                        name="worker",
                        state={"running": {"startedAt": "timestamp"}},
                        restartCount=0,
                        containerID="containerd://owned",
                    )
                ]
            },
        )

    def test_missing_running_identity_and_boolean_restart_are_rejected(self):
        self.assertEqual(self.subject.instance(self.pod), ("pod", "containerd://owned", 0))
        for key, value in (
            ("name", "sidecar"),
            ("state", {"terminated": {}}),
            ("restartCount", True),
            ("restartCount", -1),
            ("containerID", ""),
            ("containerID", None),
        ):
            changed = copy.deepcopy(self.pod)
            changed["status"]["containerStatuses"][0][key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.subject.instance(changed)

    def test_pod_readback_binds_deployment_and_exact_live_uid(self):
        document = dict(
            kind="Deployment",
            metadata={"name": "security-trust", "namespace": "ml-serving"},
            spec={},
        )
        observed = copy.deepcopy(document)
        observed["metadata"]["uid"] = "deployment"
        marker = {"resources": {self.subject.storage.reference(document): "deployment"}}
        with (
            patch.object(self.subject.audit, "runtime", return_value=document),
            patch.object(self.subject.storage, "get", return_value=observed),
            patch.object(self.subject.audit, "live", return_value="pod"),
            patch.object(
                self.subject,
                "kubectl",
                return_value=SimpleNamespace(stdout=canonical({"items": [self.pod]})),
            ),
        ):
            self.assertEqual(self.subject.pod("state", marker, "trust"), self.pod)
            with patch.object(self.subject.audit, "live", return_value="replaced"):
                with self.assertRaisesRegex(Rejected, "pod_changed"):
                    self.subject.pod("state", marker, "trust")
            with patch.object(self.subject.storage, "get", return_value=None):
                with self.assertRaises(Rejected):
                    self.subject.pod("state", marker, "trust")

    def test_exec_decodes_only_after_instance_checked_readback(self):
        identity = ("pod", "container", 0)
        with patch.object(self.subject, "read", return_value=(b'{"value":1}', identity)) as read:
            self.assertEqual(
                self.subject.execute("state", {}, "trust", "code", limit=16),
                ({"value": 1}, identity),
            )
            self.assertEqual(read.call_args.args[3], ["exec", "--", "python", "-c", "code"])
            read.return_value = (b"invalid", identity)
            with self.assertRaises(Rejected):
                self.subject.execute("state", {}, "trust", "code")

    def test_logs_cannot_be_credited_to_a_restarted_container_or_other_config(self):
        pin = "a" * 64
        signal = canonical(
            dict(state="trust_observer_first_success", config_sha256=pin, release_ready=False)
        )
        with (
            patch.object(self.subject, "pod", return_value=self.pod),
            patch.object(
                self.subject, "kubectl", return_value=SimpleNamespace(stdout=signal + b"\n")
            ) as call,
        ):
            self.assertEqual(
                self.subject.success("state", {}, pin), self.subject.instance(self.pod)
            )
            self.assertNotIn("--previous", call.call_args.args[1])
            with self.assertRaisesRegex(Rejected, "first_success_missing"):
                self.subject.success("state", {}, "b" * 64)
        restarted = copy.deepcopy(self.pod)
        restarted["status"]["containerStatuses"][0].update(
            containerID="containerd://other", restartCount=1
        )
        with (
            patch.object(self.subject, "pod", side_effect=[self.pod, restarted]),
            patch.object(self.subject, "kubectl", return_value=SimpleNamespace(stdout=signal)),
            self.assertRaisesRegex(Rejected, "container_changed"),
        ):
            self.subject.success("state", {}, pin)

    def test_response_bounds_and_negative_prefix_do_not_read_private_payload(self):
        with (
            patch.object(self.subject, "pod", return_value=self.pod),
            patch.object(
                self.subject, "kubectl", return_value=SimpleNamespace(stdout=b"x" * 65537)
            ),
            self.assertRaisesRegex(Rejected, "readback_limit"),
        ):
            self.subject.success("state", {}, "a" * 64)
        for count in (True, -1, 1025, 1.5, "1"):
            with patch.object(self.subject, "execute") as execute, self.assertRaises(Rejected):
                self.subject.outbox("state", {}, count=count)
            execute.assert_not_called()

    def test_readback_programs_are_read_only_and_bound_history_transport(self):
        marker = {"context": {"environment": "local-cpu"}}
        with patch.object(self.subject, "execute", return_value=({"value": 1}, None)) as execute:
            for operation in (
                lambda: self.subject.history("state", marker),
                lambda: self.subject.outbox("state", marker, count=0),
                lambda: self.subject.collector("state", marker),
            ):
                self.assertEqual(operation(), {"value": 1})
                code = execute.call_args.args[3]
                compile(code, "readback", "exec")
                self.assertNotIn("store.heartbeat(", code)
                self.assertNotIn("emit(", code)
            self.subject.history("state", marker)
            self.assertEqual(execute.call_args.kwargs["limit"], 8 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
