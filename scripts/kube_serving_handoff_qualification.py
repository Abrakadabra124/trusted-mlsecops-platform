"""Single-owner transfer contracts; no local infrastructure."""

import copy
import importlib.util
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest


class ServingHandoff(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.kube_serving_handoff"))
        from mlsecops import kube_serving_handoff

        self.subject = kube_serving_handoff
        self.marker = dict(ready=True, config_sha256="a" * 64, audit_pin="b" * 64)
        self.order = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.observer = {
            "metadata": {"uid": "owned-trust"},
            "spec": {"serviceAccountName": "serving"},
            "status": {
                "containerStatuses": [
                    {
                        "name": "worker",
                        "containerID": "trust-container",
                        "restartCount": 0,
                        "state": {"running": {"startedAt": "now"}},
                    }
                ]
            },
        }
        self.real_verified_observer = self.subject.verified_observer
        self.observer_reader = self.stack.enter_context(
            patch.object(self.subject, "verified_observer", return_value=self.observer)
        )

        def validate(state, *, suspended=None):
            self.order.append("validate-live" if suspended is None else "validate-suspended")
            if suspended is not None:
                self.assertFalse(self.marker["ready"])
                self.assertEqual(self.marker["handoff"], suspended)
            return self.marker

        service = self.subject.service
        self.audit = self.stack.enter_context(
            patch.object(
                service.kube_security_events, "validate", return_value={"verified": "audit"}
            )
        )
        self.stack.enter_context(patch.object(service, "validate", side_effect=validate))
        self.stack.enter_context(patch.object(service, "directory", return_value="private-state"))
        self.stack.enter_context(
            patch.object(service, "pod", return_value={"metadata": {"uid": "old"}})
        )
        self.stack.enter_context(
            patch.object(
                service.kube_security_events,
                "save",
                side_effect=lambda *a: self.order.append("save"),
            )
        )
        self.scale = self.stack.enter_context(
            patch.object(
                service,
                "set_replicas",
                side_effect=lambda s, m, a, b: self.order.append(f"{a}->{b}"),
            )
        )
        self.empty = self.stack.enter_context(
            patch.object(service, "wait_empty", side_effect=lambda *a: self.order.append("empty"))
        )
        self.live = self.stack.enter_context(patch.object(service, "wait_live", return_value="new"))
        self.jobs = self.stack.enter_context(
            patch.object(
                self.subject, "kubectl", return_value=SimpleNamespace(stdout=b'{"items":[]}')
            )
        )

    def test_transfer_serializes_real_owner_and_keeps_context_and_identity(self):
        before = copy.deepcopy(self.marker)
        with self.subject.transfer("state") as report:
            self.assertFalse(self.marker["ready"])
            self.assertEqual(self.order[-1], "validate-suspended")
            self.order.append("actual-HTTP-owner")
            self.assertEqual(report, {"before": "old"})
        self.assertEqual(self.marker, before)
        self.assertEqual(report, {"before": "old", "after": "new", "release_ready": False})
        self.assertLess(self.order.index("1->0"), self.order.index("actual-HTTP-owner"))
        self.assertLess(self.order.index("actual-HTTP-owner"), self.order.index("0->1"))
        self.assertEqual(self.order[-2:], ["save", "validate-live"])
        self.live.assert_called_once_with("state", self.marker, previous="old")

    def test_foreign_job_blocks_transfer_before_suspending_deployment(self):
        self.jobs.return_value.stdout = b'{"items":[{"metadata":{"name":"foreign"}}]}'
        with self.assertRaisesRegex(Rejected, "jobs_present"):
            self.subject.suspend("state")
        self.scale.assert_not_called()
        self.assertTrue(self.marker["ready"])
        self.assertNotIn("save", self.order)

    def test_failed_suspension_or_old_worker_never_starts_qualification_owner(self):
        for failure in (self.scale, self.empty):
            with self.subTest(failure=failure):
                self.marker = dict(ready=True, config_sha256="a" * 64, audit_pin="b" * 64)
                failure.side_effect = Rejected("cleanup_failed")
                with self.assertRaisesRegex(Rejected, "cleanup_failed"):
                    with self.subject.transfer("state"):
                        self.fail("second owner started")
                self.assertFalse(self.marker["ready"])
                self.live.assert_not_called()
                failure.side_effect = None

    def test_altered_ticket_or_marker_cannot_resume_or_adopt_state(self):
        ticket = self.subject.suspend("state")
        calls = self.scale.call_count
        for bad in (
            {},
            {**ticket, "extra": True},
            {**ticket, "marker_sha256": "f" * 64},
            *({**ticket, "nonce": value} for value in (None, True, "", "g" * 32, "a" * 64)),
            {**ticket, "previous": ""},
        ):
            with self.subTest(ticket=bad), self.assertRaises(Rejected):
                self.subject.resume("state", bad)
            self.assertEqual(self.scale.call_count, calls)
        self.marker["config_sha256"] = "c" * 64
        with self.assertRaises(Rejected):
            self.subject.resume("state", ticket)
        self.assertEqual(self.scale.call_count, calls)

    def test_remaining_probe_job_or_worker_prevents_return_to_deployment(self):
        for kind in ("job", "worker"):
            self.marker = dict(ready=True, config_sha256="a" * 64, audit_pin="b" * 64)
            ticket = self.subject.suspend("state")
            calls = self.scale.call_count
            if kind == "job":
                self.jobs.return_value.stdout = b'{"items":[{}]}'
            else:
                self.empty.side_effect = Rejected("cleanup_failed")
            with self.assertRaises(Rejected):
                self.subject.resume("state", ticket)
            self.assertEqual(self.scale.call_count, calls)
            self.assertFalse(self.marker["ready"])
            self.jobs.return_value.stdout = b'{"items":[]}'
            self.empty.side_effect = None

    def test_failed_probe_still_fails_after_confirmed_owner_return(self):
        with self.assertRaisesRegex(Rejected, "probe_failed"):
            with self.subject.transfer("state"):
                raise Rejected("probe_failed")
        self.assertTrue(self.marker["ready"])
        self.assertEqual(self.scale.call_count, 2)

    def test_orphaned_pod_without_any_job_blocks_new_owner(self):
        ticket = self.subject.suspend("state")
        calls = self.scale.call_count
        for namespace in ("ml-serving", "ml-serve"):

            def inventory(state, arguments):
                orphan = arguments[1] == "pods" and namespace in arguments
                return SimpleNamespace(stdout=canonical({"items": [{}] if orphan else []}))

            with (
                self.subTest(namespace=namespace),
                patch.object(self.subject, "kubectl", side_effect=inventory),
                patch("time.monotonic", side_effect=[0, 46]),
                self.assertRaisesRegex(Rejected, "pods_present"),
            ):
                self.subject.resume("state", ticket)
            self.assertEqual(self.scale.call_count, calls)
            self.assertFalse(self.marker["ready"])

    def test_failed_return_keeps_suspended_marker(self):
        ticket = self.subject.suspend("state")
        self.live.side_effect = Rejected("startup_failed")
        with self.assertRaisesRegex(Rejected, "startup_failed"):
            self.subject.resume("state", ticket)
        self.assertFalse(self.marker["ready"])
        self.assertEqual(digest(canonical(self.marker)), ticket["marker_sha256"])

    def test_pod_inventory_must_be_complete_and_background_cleanup_is_awaited(self):
        for content in (b"{}", b'{"items":null}', b'{"items":{}}'):
            self.jobs.return_value.stdout = content
            with self.subTest(content=content), self.assertRaisesRegex(Rejected, "pod_inventory"):
                self.subject.wait_pods_absent("state")
        self.jobs.side_effect = [
            SimpleNamespace(stdout=content)
            for content in (b'{"items":[{}]}', b'{"items":[]}', b'{"items":[]}', b'{"items":[]}')
        ]
        with (
            patch.object(self.subject.time, "monotonic", side_effect=[0, 1]),
            patch.object(self.subject.time, "sleep") as sleep,
        ):
            self.subject.wait_pods_absent("state")
        sleep.assert_called_once_with(0.5)
        self.scale.assert_not_called()

    def test_missing_jobs_inventory_is_not_an_empty_namespace(self):
        for content in (b"{}", b'{"items":null}', b'{"items":{}}'):
            self.jobs.return_value.stdout = content
            with self.assertRaisesRegex(Rejected, "jobs_present"):
                self.subject.suspend("state")
        self.scale.assert_not_called()

    def test_probe_preflight_rejects_any_existing_owner_or_incomplete_inventory(self):
        self.subject.require_probe_slot("state")
        self.assertEqual(self.jobs.call_count, 4)
        for namespace in ("ml-serving", "ml-serve"):
            for kind in ("jobs", "pods"):
                for items in (None, {}, [{}]):

                    def inventory(state, arguments):
                        bad = kind == arguments[1] and namespace in arguments
                        return SimpleNamespace(stdout=canonical({"items": items if bad else []}))

                    with (
                        self.subTest(namespace=namespace, kind=kind, items=items),
                        patch.object(self.subject, "kubectl", side_effect=inventory),
                        self.assertRaisesRegex(Rejected, "probe_owner_present|pod_inventory"),
                    ):
                        self.subject.require_probe_slot("state")
        self.scale.assert_not_called()

    def test_only_verified_trust_observer_is_exempt_from_http_ownership_inventory(self):
        self.assertEqual(
            self.subject.remaining_pods([self.observer], "ml-serving", self.observer), []
        )
        self.assertEqual(
            self.subject.remaining_pods([self.observer], "ml-serve", self.observer), [self.observer]
        )
        foreign = copy.deepcopy(self.observer)
        foreign["metadata"]["uid"] = "lookalike"
        self.assertEqual(
            self.subject.remaining_pods([self.observer, foreign], "ml-serving", self.observer),
            [foreign],
        )
        for changed in ("spec", "container", "duplicate"):
            document = copy.deepcopy(self.observer)
            if changed == "spec":
                document["spec"] = {"foreign": True}
            if changed == "container":
                document["status"]["containerStatuses"][0]["containerID"] = "restarted"
            items = [document] * (2 if changed == "duplicate" else 1)
            with (
                self.subTest(changed=changed),
                self.assertRaisesRegex(Rejected, "observer_changed"),
            ):
                self.subject.remaining_pods(items, "ml-serving", self.observer)
        self.observer_reader.return_value = foreign
        with self.assertRaisesRegex(Rejected, "observer_changed"):
            self.subject.confirm_observer("state", self.observer)

    def test_observer_exemption_uses_verified_role_owner_chain(self):
        with (
            patch.object(
                self.subject.service.kube_security_events,
                "validate",
                return_value={"verified": "audit"},
            ) as marker,
            patch.object(
                self.subject.kube_observer_readback, "pod", return_value=self.observer
            ) as pod,
        ):
            self.assertEqual(self.real_verified_observer("state"), self.observer)
            marker.assert_called_once_with("state")
            pod.assert_called_once_with("state", {"verified": "audit"}, "trust")

    def test_inventory_is_reused_only_inside_one_preflight_and_refreshed_after_job(self):
        marker = {"verified": "caller-preflight"}
        self.subject.require_probe_slot("state", marker=marker)
        self.audit.assert_not_called()
        self.assertEqual(self.observer_reader.call_count, 2)
        for call in self.observer_reader.call_args_list:
            self.assertIs(call.kwargs["marker"], marker)
        self.observer_reader.reset_mock()
        self.subject.wait_pods_absent("state")
        self.audit.assert_called_once_with("state")
        for call in self.observer_reader.call_args_list:
            self.assertIs(call.kwargs["marker"], self.audit.return_value)

    def test_verified_observer_can_reuse_inventory_but_still_verifies_live_owner(self):
        marker = {"verified": "same-operation"}
        with patch.object(
            self.subject.kube_observer_readback, "pod", return_value=self.observer
        ) as pod:
            self.assertEqual(self.real_verified_observer("state", marker=marker), self.observer)
            self.audit.assert_not_called()
            pod.assert_called_once_with("state", marker, "trust")


if __name__ == "__main__":
    unittest.main()
