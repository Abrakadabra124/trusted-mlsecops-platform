"""Host guard, proof ownership and finite results; no cluster is executed here."""

import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_security_native as subject


class NativeAuditContracts(unittest.TestCase):
    def setUp(self):
        self.profile = {"image": "image@sha256:" + "a" * 64, "image_id": "sha256:" + "a" * 64}

    def test_http_receipt_requires_a_new_identity_event_same_outbox_and_independent_match(self):
        record = {
            "id": "b" * 64,
            "kind": "identity.denied",
            "envelope": "c" * 64,
            "receipt": "d" * 64,
        }
        before = {"pin": "a" * 64, "records": []}
        after = {"pin": "a" * 64, "records": [record]}
        inbox = {"records": [record]}
        self.assertEqual(subject.identity_receipts(before, after, inbox), 1)
        for old, current, observed in (
            (after, after, inbox),
            (after, {**after, "records": [record, record]}, inbox),
            (before, {**after, "records": [record, record]}, inbox),
            (before, after, {"records": [record, record]}),
            (before, before, inbox),
            (before, {**after, "pin": "e" * 64}, inbox),
            (before, {**after, "records": [{**record, "receipt": None}]}, inbox),
            (before, after, {"records": []}),
            (before, after, {"records": [{**record, "receipt": "e" * 64}]}),
            (before, {**after, "records": [{**record, "kind": "promotion.denied"}]}, inbox),
            ({**before, "records": [{**record, "id": "e" * 64}]}, after, inbox),
        ):
            with (
                self.subTest(old=old["records"], current=current["records"]),
                self.assertRaises(Rejected),
            ):
                subject.identity_receipts(old, current, observed)

    def test_all_remote_programs_compile_and_use_fixed_private_paths(self):
        for code in (
            subject.HEALTH.replace("EXPECTED", "True"),
            subject.HEALTH.replace("EXPECTED", "False"),
            subject.COLLECTOR,
            subject.PROMOTER,
            subject.SERVING,
        ):
            compile(code, "<owned-audit-proof>", "exec")
            self.assertNotIn("initialize(", code)
            self.assertNotIn("print(document", code)
        self.assertIn("store.snapshot()", subject.COLLECTOR)
        self.assertIn("'/security/audit.json'", subject.PROMOTER)

    def test_host_guard_precedes_any_job_or_network_action(self):
        with (
            patch.object(subject, "hosted", side_effect=Rejected("hosted_only")),
            patch.object(subject, "kubectl") as api,
        ):
            for action in (
                lambda: subject.job("state", self.profile, "pass"),
                lambda: subject.qualify("root", "state", {}, {}, "image"),
            ):
                with self.assertRaisesRegex(Rejected, "hosted_only"):
                    action()
            api.assert_not_called()

    def job(
        self,
        *,
        worker=False,
        serving=False,
        code=0,
        owner="owned",
        content=b'{"verified":true}',
        terminal="Complete",
        multiple=False,
    ):
        record = {}

        def api(state, args, document=None):
            if args[0] == "create":
                record["document"] = copy.deepcopy(document)
                observed = copy.deepcopy(document)
                observed["metadata"]["uid"] = "owned"
                return SimpleNamespace(stdout=canonical(observed))
            self.assertEqual(args[0], "logs")
            return SimpleNamespace(stdout=content)

        def wait(*args):
            statuses = [{"state": {"terminated": {"exitCode": code}}}]
            return (
                {"type": terminal},
                {
                    "spec": record["document"]["spec"]["template"]["spec"],
                    "metadata": {"name": "proof-pod", "ownerReferences": [{"uid": owner}]},
                    "status": {"containerStatuses": statuses * (2 if multiple else 1)},
                },
                0.1,
            )

        with (
            patch.object(subject, "hosted"),
            patch.object(subject, "workspace_id", return_value="a" * 32),
            patch.object(subject, "kubectl", side_effect=api),
            patch.object(subject, "wait_job", side_effect=wait),
            patch.object(subject, "verify_running_image"),
            patch.object(subject.kube_promotion, "cleanup") as cleanup,
        ):
            try:
                result = subject.job("state", self.profile, "pass", worker=worker, serving=serving)
            finally:
                cleanup.assert_called_once()
                self.assertEqual(cleanup.call_args.args[1][0][1], "owned")
                self.assertEqual(
                    cleanup.call_args.kwargs["namespace"],
                    "ml-train" if worker else "ml-serving" if serving else "ml-promoter",
                )
        return result, record["document"]

    def test_owned_probe_is_removed_and_worker_does_not_receive_audit_secret(self):
        for worker in (False, True):
            result, document = self.job(worker=worker)
            self.assertEqual(result, {"verified": True})
            spec = document["spec"]["template"]["spec"]
            secrets = [v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v]
            self.assertEqual(secrets, [] if worker else ["security-promoter"])
            self.assertFalse(spec["automountServiceAccountToken"])

    def test_serving_probe_uses_only_serving_credentials_and_conflicting_roles_refuse(self):
        _, document = self.job(serving=True)
        spec = document["spec"]["template"]["spec"]
        self.assertEqual(spec["serviceAccountName"], "serving")
        self.assertEqual(
            [v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v],
            ["security-serving"],
        )
        self.assertEqual(
            [
                v["persistentVolumeClaim"]["claimName"]
                for v in spec["volumes"]
                if "persistentVolumeClaim" in v
            ],
            ["security-serving"],
        )
        with patch.object(subject, "hosted"), patch.object(subject, "kubectl") as api:
            for flags in ({"serving": True, "worker": True}, {"serving": 1}, {"worker": "yes"}):
                with self.assertRaises(Rejected):
                    subject.job("state", self.profile, "pass", **flags)
            api.assert_not_called()

    def test_failed_replaced_ambiguous_or_malformed_probe_is_never_a_pass(self):
        for change in (
            {"code": 1},
            {"code": True},
            {"owner": "foreign"},
            {"terminal": "Failed"},
            {"multiple": True},
            {"content": b"private malformed output"},
        ):
            with self.assertRaises(Rejected):
                self.job(**change)

    def test_fresh_probe_must_report_exact_expected_health_without_release_grant(self):
        for result in (
            {"healthy": True, "release_ready": True},
            {"healthy": False, "release_ready": False},
            {"healthy": True},
            {},
        ):
            with patch.object(subject, "job", return_value=result), self.assertRaises(Rejected):
                subject.health("state", self.profile)
        with patch.object(subject, "job", return_value={"healthy": False, "release_ready": False}):
            subject.health("state", self.profile, False)

    def test_outage_policy_cleanup_is_bound_to_created_uid(self):
        def create(state, args, document):
            self.assertEqual(document["spec"]["ingressDeny"], [{"fromEntities": ["all"]}])
            observed = copy.deepcopy(document)
            observed["metadata"]["uid"] = "outage-owned"
            return SimpleNamespace(stdout=canonical(observed))

        with (
            patch.object(subject, "kubectl", side_effect=create),
            patch.object(subject.kube_promotion, "cleanup") as cleanup,
        ):
            with self.assertRaisesRegex(Rejected, "probe_failed"):
                with subject.outage("state", "a" * 32):
                    raise Rejected("probe_failed")
            cleanup.assert_called_once()
            self.assertEqual(cleanup.call_args.args[1][0][1], "outage-owned")
            self.assertEqual(cleanup.call_args.kwargs["namespace"], "ml-audit")


if __name__ == "__main__":
    unittest.main()
