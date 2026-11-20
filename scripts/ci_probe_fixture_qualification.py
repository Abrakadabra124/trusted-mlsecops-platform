"""Offline checks for operator provisioning and retirement of the disposable access fixture."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import signing
from mlsecops.contracts import Rejected, read_json
from scripts import ci_probe_fixture as fixture


class API:
    def __init__(self):
        self.repo = dict(
            id=fixture.store.REPOSITORY_ID,
            full_name=fixture.store.REPOSITORY,
            owner={"login": "Abrakadabra124"},
            private=True,
            visibility="private",
            fork=False,
            default_branch="main",
        )
        self.head = "a" * 40
        self.tag = self.release = None
        self.calls = []
        self.reserved = ""
        self.foreign = []

    def json(self, method, path, *, body=None, absent=False):
        path = path.removeprefix(fixture.store.ROOT)
        self.calls.append((method, path))
        if method == "GET":
            if not path:
                return self.repo
            if path == "/git/ref/heads/main":
                return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": self.head}}
            if path.startswith("/git/ref/tags/"):
                return self.tag
            if "?" in path and "/assets?" in path:
                return self.release["assets"] if self.release else None
            if path in ("/releases?per_page=100", "/releases?per_page=20"):
                return self.foreign + ([self.release] if self.release else [])
            if path.startswith("/releases/"):
                return self.release
        if method == "POST" and path == "/git/refs":
            self.reserved = body["ref"].removeprefix("refs/tags/")
            self.tag = dict(ref=body["ref"], object=dict(type="commit", sha=body["sha"]))
            return self.tag
        if method == "POST" and path == "/releases":
            self.release = body | dict(id=12, assets=[], immutable=False)
            return self.release.copy()
        if method == "PATCH" and path == "/releases/12":
            self.release.update(body)
            return self.release
        if method == "DELETE" and path == "/releases/12":
            self.release = None
            return {}
        if method == "DELETE" and path == "/git/refs/tags/" + self.reserved:
            self.tag = None
            return {}
        raise AssertionError("unexpected API request")


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.api = API()
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve() / "fixture"

    def create(self):
        return fixture.create(self.api, self.folder)

    def test_create_and_retire_confirm_absence_and_leave_private_receipt(self):
        self.create()
        state = read_json(self.folder / "fixture.json")
        self.assertEqual(
            signing.verify(
                fixture.decode(self.api.release["body"].encode()),
                "store-access-probe",
                state["public"],
            ),
            state["descriptor"],
        )
        from scripts.ci_access_probe import Probe

        probe = Probe(self.api, state["descriptor"]["nonce"], state["public"], 123, 1)
        self.assertEqual(probe.release_id, state["descriptor"]["release_id"])
        self.assertEqual(probe.initial, {})
        self.assertEqual([f.name for f in self.folder.iterdir()], ["fixture.json"])
        fixture.retire(self.api, self.folder)
        self.assertIsNone(self.api.tag)
        self.assertIsNone(self.api.release)
        self.assertEqual(read_json(self.folder / "fixture.json")["stage"], "retired")
        deletes = self.api.calls.count(("DELETE", "/releases/12"))
        fixture.retire(self.api, self.folder)
        self.assertEqual(self.api.calls.count(("DELETE", "/releases/12")), deletes)

    def test_wrong_repo_foreign_assets_and_modified_markers_refuse_deletion(self):
        self.create()
        for field, value in (
            ("assets", [{"id": 123}]),
            ("body", "foreign"),
            ("id", 13),
            ("target_commitish", "b" * 40),
        ):
            with self.subTest(field=field):
                old = self.api.release[field]
                self.api.release[field] = value
                with self.assertRaises(Rejected):
                    fixture.retire(self.api, self.folder)
                self.api.release[field] = old
        self.api.repo["private"] = False
        with self.assertRaises(Rejected):
            fixture.retire(self.api, self.folder)
        self.assertFalse(any(method == "DELETE" for method, _ in self.api.calls))

    def test_foreign_tag_never_deleted_or_adopted(self):
        self.api.tag = dict(ref="foreign", object=dict(type="commit", sha=self.api.head))
        with self.assertRaises(Rejected):
            self.create()
        self.assertFalse(any(m in ("POST", "DELETE") for m, _ in self.api.calls))


class LocalCliTests(unittest.TestCase):
    def call(self, header, *, operation="GET", status=0, absent=False):
        response = SimpleNamespace(returncode=status, stdout=header)
        with patch.object(fixture.subprocess, "run", return_value=response) as invoked:
            value = fixture.Gh().json(operation, fixture.store.ROOT + "/releases/12", absent=absent)
        self.assertIn("github.com", invoked.call_args.args[0])
        return value

    def test_read_deleted_and_explicit_absence(self):
        self.assertEqual(self.call(b'HTTP/2.0 200 OK\r\nDate: x\r\n\r\n{"id":12}'), {"id": 12})
        self.assertEqual(self.call(b"HTTP/2.0 204 No Content\nDate: x\n\n", operation="DELETE"), {})
        self.assertIsNone(self.call(b"HTTP/2.0 404 Not Found\n\n{}", status=1, absent=True))

    def test_transport_errors_are_not_absence(self):
        for raw in (b"failure", b"HTTP/2.0 403 Forbidden\n\n{}", b"HTTP/2.0 503 Unavailable\n\n{}"):
            with self.subTest(raw=raw), self.assertRaises(Rejected):
                self.call(raw, status=1, absent=True)
