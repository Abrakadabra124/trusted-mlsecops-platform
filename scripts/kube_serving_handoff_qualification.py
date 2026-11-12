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

        def validate(state, *, suspended=None):
            self.order.append("validate-live" if suspended is None else "validate-suspended")
            if suspended is not None:
                self.assertFalse(self.marker["ready"])
                self.assertEqual(self.marker["handoff"], suspended)
            return self.marker

        service = self.subject.service
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

    def test_failed_return_keeps_suspended_marker(self):
        ticket = self.subject.suspend("state")
        self.live.side_effect = Rejected("startup_failed")
        with self.assertRaisesRegex(Rejected, "startup_failed"):
            self.subject.resume("state", ticket)
        self.assertFalse(self.marker["ready"])
        self.assertEqual(digest(canonical(self.marker)), ticket["marker_sha256"])

    def test_missing_jobs_inventory_is_not_an_empty_namespace(self):
        for content in (b"{}", b'{"items":null}', b'{"items":{}}'):
            self.jobs.return_value.stdout = content
            with self.assertRaisesRegex(Rejected, "jobs_present"):
                self.subject.suspend("state")
        self.scale.assert_not_called()


if __name__ == "__main__":
    unittest.main()
