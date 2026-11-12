"""Batch GET must preserve exact resource inventory and every existing drift check."""

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import kube_storage
from mlsecops.contracts import Rejected, canonical, digest


class ResourceReadback(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.kube_resource_readback"))
        from mlsecops import kube_resource_readback

        self.subject = kube_resource_readback
        self.documents = [
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "same", "namespace": "control"},
                "data": {"key": "private-canary"},
            },
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "same", "namespace": "serving"},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
            },
        ]
        self.observed = copy.deepcopy(self.documents)
        for number, item in enumerate(self.observed):
            item["metadata"]["uid"] = f"owned-{number}"

    def response(self, value):
        return patch.object(
            self.subject, "kubectl", return_value=SimpleNamespace(stdout=canonical(value))
        )

    def test_one_read_requests_only_named_resources_without_secret_payload(self):
        with self.response(
            {"apiVersion": "v1", "kind": "List", "items": self.observed[::-1]}
        ) as call:
            actual = self.subject.read("state", self.documents)
        self.assertEqual(actual, self.observed)
        call.assert_called_once()
        self.assertEqual(call.call_args.args[:2], ("state", ["get", "-f", "-", "-o", "json"]))
        request = call.call_args.args[2]
        self.assertEqual(request["kind"], "List")
        self.assertEqual(len(request["items"]), 2)
        for item in request["items"]:
            self.assertEqual(set(item), {"apiVersion", "kind", "metadata"})
            self.assertEqual(set(item["metadata"]), {"name", "namespace"})
        self.assertNotIn("private-canary", canonical(request).decode())

    def test_single_object_and_cluster_scoped_address(self):
        doc = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "owned"}}
        actual = copy.deepcopy(doc)
        actual["metadata"]["uid"] = "namespace-uid"
        with self.response(actual) as call:
            self.assertEqual(self.subject.read("state", [doc]), [actual])
        self.assertEqual(call.call_args.args[2]["items"][0]["metadata"], {"name": "owned"})

    def test_missing_duplicate_extra_wrong_namespace_or_version_is_refused(self):
        foreign = copy.deepcopy(self.observed[0])
        foreign["metadata"]["namespace"] = "foreign"
        version = copy.deepcopy(self.observed[0])
        version["apiVersion"] = "foreign/v1"
        for items in (
            [],
            self.observed[:1],
            self.observed * 2,
            [self.observed[0], self.observed[0]],
            [foreign, self.observed[1]],
            [version, self.observed[1]],
            [None, self.observed[1]],
        ):
            with (
                self.subTest(items=items),
                self.response({"apiVersion": "v1", "kind": "List", "items": items}),
                self.assertRaises(Rejected),
            ):
                self.subject.read("state", self.documents)

    def test_malformed_transport_or_resource_metadata_is_refused(self):
        for value in (
            None,
            [],
            {},
            {"apiVersion": "v1", "kind": "List", "items": {}},
            {"apiVersion": "wrong", "kind": "List", "items": self.observed},
            {"apiVersion": "v1", "kind": "Secret", "metadata": None},
            {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": 1}},
        ):
            with self.subTest(value=value), self.response(value), self.assertRaises(Rejected):
                self.subject.read("state", self.documents)

    def test_every_fresh_read_keeps_existing_uid_secret_and_network_checks(self):
        for edit in (
            lambda items: items[0]["metadata"].update(uid="foreign"),
            lambda items: items[0]["data"].update(extra="unauthorized"),
            lambda items: items[1]["spec"].update(ingress=[{}]),
        ):
            items = copy.deepcopy(self.observed)
            edit(items)
            with (
                self.response({"apiVersion": "v1", "kind": "List", "items": items}),
                self.assertRaises(Rejected),
            ):
                actual = self.subject.read("state", self.documents)
                for number, (document, observed) in enumerate(
                    zip(self.documents, actual, strict=True)
                ):
                    kube_storage.verify_resource(document, observed, f"owned-{number}")

    def test_read_does_not_cache_inventory_across_calls(self):
        with self.response({"apiVersion": "v1", "kind": "List", "items": self.observed}) as call:
            self.subject.read("state", self.documents)
            call.side_effect = Rejected("read-unavailable")
            with self.assertRaisesRegex(Rejected, "read-unavailable"):
                self.subject.read("state", self.documents)
        self.assertEqual(call.call_count, 2)

    def test_duplicate_or_malformed_request_never_reaches_kubectl(self):
        for documents in (
            [self.documents[0]] * 2,
            [None],
            [{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "x", "namespace": 2}}],
        ):
            with patch.object(self.subject, "kubectl") as call, self.assertRaises(Rejected):
                self.subject.read("state", documents)
            call.assert_not_called()

    def test_empty_inventory_needs_no_process(self):
        with patch.object(self.subject, "kubectl") as call:
            self.assertEqual(self.subject.read("state", []), [])
        call.assert_not_called()

    def test_storage_live_binding_is_read_only_after_every_resource_passes(self):
        marker = {
            "spec_digest": digest(canonical(self.documents)),
            "resources": {
                kube_storage.reference(document): f"owned-{number}"
                for number, document in enumerate(self.documents)
            },
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(kube_storage, "validate_cluster"),
            patch.object(kube_storage, "local_state", return_value=Path(directory)),
            patch.object(kube_storage, "desired", return_value=self.documents),
            patch.object(kube_storage, "read_json", return_value=marker),
            patch.object(kube_storage, "live_state", return_value={"pod_uid": "live"}) as live,
        ):
            with self.response({"apiVersion": "v1", "kind": "List", "items": self.observed[::-1]}):
                self.assertEqual(kube_storage.validate("state")["pod_uid"], "live")
            live.assert_called_once_with("state", marker)
            for number in range(len(self.observed)):
                items = copy.deepcopy(self.observed)
                items[number]["metadata"]["uid"] = "foreign"
                live.reset_mock()
                with (
                    self.response({"apiVersion": "v1", "kind": "List", "items": items}),
                    self.assertRaises(Rejected),
                ):
                    kube_storage.validate("state")
                live.assert_not_called()


if __name__ == "__main__":
    unittest.main()
