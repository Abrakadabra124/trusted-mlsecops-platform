"""Exercise the actual role CLI and HTTP dispatcher against a socket-free private store."""

import io
import os
import runpy
import sys
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import ci_access_probe as probe
from scripts import ci_asset_http as http
from scripts import ci_private_assets as store

NONCE = "ab" * 16
HEAD = "ed" * 20
NAME = "ci-access-" + NONCE
ROOT = "/" + store.ROOT
RELEASE = ROOT + "/releases/71"
LIST = RELEASE + "/assets?per_page=6"
ASSET = ROOT + "/releases/assets/"
DENIAL = {"message": "Resource not accessible by personal access token", "status": "403"}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = signing.encode64(self.key.public_key().public_bytes_raw())
        self.env = dict(
            CANDIDATE_ACCESS_TOKEN="github_pat_test-role-token",
            CANDIDATE_PROBE_NONCE=NONCE,
            CANDIDATE_PROBE_PUBLIC=self.public,
            GITHUB_RUN_ID="221",
            GITHUB_RUN_ATTEMPT="3",
        )
        self.record = dict(
            nonce=NONCE, repository_id=store.REPOSITORY_ID, release_id=71, target_commitish=HEAD
        )
        self.repo = dict(
            id=store.REPOSITORY_ID,
            full_name=store.REPOSITORY,
            fork=False,
            private=True,
            visibility="private",
            owner={"login": "Abrakadabra124"},
            default_branch="main",
        )
        self.release = dict(
            id=71,
            name=NAME,
            tag_name=NAME,
            target_commitish=HEAD,
            draft=False,
            prerelease=True,
            immutable=False,
            body=self.signed(self.record),
        )
        self.extra = []
        self.rows = []
        self.raw = {}
        self.next_id = 50
        self.denial = (403, DENIAL, [])
        self.writes = []
        self.deletes = []
        self.calls = []
        self.change = lambda method, path, status, value, headers: (status, value, headers)
        self.enterContext(patch.dict(os.environ, self.env, clear=True))
        self.enterContext(patch.object(http, "_response", self.response))

    def signed(self, record, kind="store-access-probe"):
        with patch.object(signing, "load_key", return_value=self.key):
            return canonical(signing.sign(record, kind, "unused")).decode()

    def install(self, name, data):
        self.next_id += 1
        row = dict(
            id=self.next_id,
            name=name,
            state="uploaded",
            size=len(data),
            digest="sha256:" + digest(data),
        )
        self.rows.append(row)
        self.raw[self.next_id] = data
        return row

    @contextmanager
    def response(self, host, method, path, headers, body=None):
        self.assertEqual(headers["Authorization"], "Bearer github_pat_test-role-token")
        self.calls.append((method, path))
        release = self.release | {"assets": self.rows}
        status, extra = 200, []
        if method == "POST":
            self.assertEqual(host, "uploads.github.com")
            self.assertEqual(headers["Content-Type"], "application/octet-stream")
            self.assertIn(
                path, [RELEASE + "/assets?name=" + n for n in ("publisher.bin", "reader.bin")]
            )
            name = path.split("=")[1]
            self.writes.append((name, body))
            if name == "reader.bin" and self.denial[0] != 201:
                status, value, extra = self.denial
            else:
                self.assertFalse(any(r["name"] == name for r in self.rows))
                status, value = 201, self.install(name, body)
        else:
            self.assertEqual(host, "api.github.com")
            self.assertIsNone(body)
            if path.startswith(ASSET):
                ident = int(path.removeprefix(ASSET))
                row = next((r for r in self.rows if r["id"] == ident), None)
                if method == "DELETE":
                    self.deletes.append(ident)
                    self.rows.remove(row)
                    self.raw.pop(ident)
                    status, value = 204, b""
                elif row is None:
                    status, value = 404, {}
                elif headers["Accept"] == "application/octet-stream":
                    value = self.raw[ident]
                else:
                    value = row
            else:
                self.assertEqual(method, "GET")
                value = {
                    ROOT: self.repo,
                    ROOT + "/releases?per_page=100": [release, *self.extra],
                    ROOT + "/git/ref/heads/main": {
                        "ref": "refs/heads/main",
                        "object": {"type": "commit", "sha": HEAD},
                    },
                    RELEASE: release,
                    LIST: self.rows,
                }[path]
        status, value, extra = self.change(method, path, status, deepcopy(value), extra)
        raw = value if type(value) is bytes else canonical(value)
        message = Message()
        message["Content-Length"] = str(len(raw))
        for key, val in extra:
            message[key] = val
        yield SimpleNamespace(status=status, headers=message, read=io.BytesIO(raw).read)

    def stage(self, action, passed):
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            code = probe.main([action])
        self.assertEqual(code, 0 if passed else 1)
        self.assertEqual(
            out.getvalue(), f"access_probe_{action}={'pass' if passed else 'refused'}\n"
        )
        self.assertEqual(err.getvalue(), "")

    def fixture(self, role):
        return probe.payload(NONCE, 221, 3, role)

    def test_invalid_inputs_do_not_dispatch_or_echo_secrets(self):
        for field, invalid in (
            ("CANDIDATE_PROBE_NONCE", NONCE.upper()),
            ("CANDIDATE_PROBE_PUBLIC", "a" * 44),
            ("CANDIDATE_PROBE_PUBLIC", self.public[:-1] + "A"),
            ("CANDIDATE_ACCESS_TOKEN", ""),
            ("CANDIDATE_ACCESS_TOKEN", "classic-test-token"),
            ("GITHUB_RUN_ID", "01"),
            ("GITHUB_RUN_ATTEMPT", "0"),
        ):
            with self.subTest(field=field), patch.dict(os.environ, {field: invalid}):
                self.stage("cleanup", False)
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(probe.main(["private-detail"]), 1)
        self.assertEqual(out.getvalue(), "access_probe_invalid=refused\n")
        self.assertFalse(self.calls)

    def test_record_is_canonical_signed_by_external_key_and_bound_to_exact_release(self):
        for body in (
            "",
            self.release["body"] + " ",
            self.signed(self.record, "different-kind"),
            self.signed(self.record | {"nonce": "1" * 32}),
            self.signed(self.record | {"release_id": 72}),
            self.signed(self.record | {"repository_id": 1}),
            self.signed(self.record | {"target_commitish": "f" * 40}),
            self.signed(self.record | {"extra": 1}),
            self.signed(self.record | {"release_id": True}),
        ):
            with self.subTest(body_length=len(body)), patch.dict(self.release, {"body": body}):
                self.stage("upload", False)
        other_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        with patch.dict(os.environ, {"CANDIDATE_PROBE_PUBLIC": signing.encode64(other_key)}):
            self.stage("upload", False)
        self.assertFalse(self.writes)

    def test_refuse_ambiguous_lookup_inexact_release_flags_and_inconsistent_id(self):
        for field, invalid in (
            ("name", "different"),
            ("draft", 0),
            ("prerelease", False),
            ("immutable", True),
            ("tag_name", "different"),
        ):
            with self.subTest(field=field), patch.dict(self.release, {field: invalid}):
                self.stage("upload", False)
        for extras in (
            [self.release],
            [self.release | {"tag_name": "different", "id": 72}],
            [self.release | {"name": "other", "tag_name": "other"}] * 99,
        ):
            self.extra = extras
            self.stage("upload", False)
        self.extra = []
        self.change = lambda m, p, s, v, h: (s, v | {"id": 72} if p == RELEASE else v, h)
        self.stage("upload", False)
        with patch.dict(self.repo, {"private": False}):
            self.stage("cleanup", False)
        self.assertFalse(self.writes)
        self.assertFalse(self.deletes)

    def test_short_page_can_include_other_releases_but_cannot_alias_the_signed_id(self):
        self.extra = [self.release | {"id": 71, "name": "other", "tag_name": "other"}]
        self.stage("upload", False)
        self.assertFalse(self.writes)
        self.extra[0]["id"] = 72
        self.stage("upload", True)

    def test_wrongly_writable_reader_leaves_both_fixtures_for_verified_cleanup(self):
        self.stage("upload", True)
        self.stage("upload", False)
        self.denial = (201, {}, [])
        self.stage("reader", False)
        self.assertEqual(
            self.writes, [(name + ".bin", self.fixture(name)) for name in ("publisher", "reader")]
        )
        self.assertEqual(len(self.rows), 2)
        self.assertFalse(self.deletes)
        self.stage("cleanup", True)
        self.assertCountEqual(self.deletes, [51, 52])
        for ident in self.deletes:
            self.assertIn(
                ("GET", ASSET + str(ident)),
                self.calls[self.calls.index(("DELETE", ASSET + str(ident))) + 1 :],
            )
        self.stage("cleanup", True)
        self.assertEqual(len(self.deletes), 2)

    def test_ordinary_remote_permission_refusal_requires_unchanged_inventory(self):
        self.stage("reader", False)
        self.assertFalse(self.writes)
        self.stage("upload", True)
        for message in (
            "Resource not accessible by personal access token",
            "Resource not accessible by integration",
        ):
            self.denial = (403, {"message": message}, [("X-RateLimit-Remaining", "4299")])
            self.stage("reader", True)
        self.stage("cleanup", True)
        self.assertEqual([n for n, _ in self.writes], ["publisher.bin", "reader.bin", "reader.bin"])

    def test_status_rate_limits_and_inconclusive_transport_never_prove_denial(self):
        self.stage("upload", True)
        for status, body, headers in (
            *((s, DENIAL, []) for s in (200, 301, 401, 404, 409, 422, 429, 500, 503)),
            (403, {"message": "Forbidden"}, []),
            (403, {"message": "API rate limit exceeded"}, []),
            (403, DENIAL, [("Retry-After", "20")]),
            (403, DENIAL, [("X-RateLimit-Remaining", "0")]),
            (403, DENIAL, [("X-RateLimit-Remaining", "7"), ("X-RateLimit-Remaining", "0")]),
            (403, DENIAL, [("X-RateLimit-Limit", "0")]),
            (403, DENIAL, [("X-RateLimit-Limit", "100"), ("X-RateLimit-Used", "100")]),
            (403, DENIAL | {"documentation_url": "https://docs.github.com/rest/rate-limits"}, []),
            (403, DENIAL | {"errors": [{"message": "abuse"}]}, []),
            (403, DENIAL | {"status": "429"}, []),
            (403, b"private-detail", []),
            (403, b"a" * 8193, []),
        ):
            with self.subTest(status=status):
                self.denial = status, body, headers
                count = len(self.writes)
                self.stage("reader", False)
                self.assertEqual(len(self.writes), count + 1)

        def dropped(m, p, s, v, h):
            if m == "POST":
                raise OSError("private-detail")
            return s, v, h

        self.change = dropped
        count = len(self.writes)
        self.stage("reader", False)
        self.assertEqual(len(self.writes), count + 1)
        self.assertFalse(self.deletes)

    def test_false_denial_with_actual_write_or_replaced_publisher_fails_postcheck(self):
        self.stage("upload", True)

        def replace(m, p, s, v, h):
            if m == "POST":
                self.rows[0]["id"] += 1
            return s, v, h

        self.change = replace
        self.stage("reader", False)
        self.rows[0]["id"] -= 1

        def write_anyway(m, p, s, v, h):
            if m == "POST":
                self.install("reader.bin", self.fixture("reader"))
            return s, v, h

        self.change = write_anyway
        self.stage("reader", False)
        self.stage("reader", False)
        self.assertEqual(len(self.writes), 3)
        self.assertFalse(self.deletes)

    def test_cleanup_checks_all_bytes_before_deleting_any_and_rejects_another_attempt(self):
        self.stage("upload", True)
        reader = self.install("reader.bin", self.fixture("reader"))
        self.raw[reader["id"]] = b"x" * reader["size"]
        self.stage("cleanup", False)
        self.raw[reader["id"]] = self.fixture("reader")
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            self.stage("cleanup", False)
        for change in (
            {"name": "control.bin"},
            {"name": "publisher.bin"},
            {"size": True},
            {"id": 51},
            {"state": "starter"},
            {"digest": "sha256:" + "0" * 64},
        ):
            with self.subTest(field=list(change)), patch.dict(reader, change):
                self.stage("cleanup", False)
        self.assertFalse(self.deletes)

    def test_direct_asset_and_both_inventories_must_match_original_write(self):
        for path, change in (
            (RELEASE + "/assets?name=publisher.bin", lambda row: row | {"id": 88}),
            (LIST, lambda rows: []),
            (ASSET + "51", lambda row: row | {"id": 88}),
        ):
            self.rows.clear()
            self.raw.clear()
            self.next_id = 50
            self.change = lambda m, p, s, v, h: (s, change(v) if p == path else v, h)
            self.stage("upload", False)
        self.assertFalse(self.deletes)

    def test_cleanup_never_retries_unknown_delete_or_accepts_unconfirmed_absence(self):
        for uncertain in (
            "lost",
            "still_visible",
            "release_unreadable",
            "embedded_not_empty",
            "listed_not_empty",
        ):
            self.rows.clear()
            self.raw.clear()
            self.change = lambda m, p, s, v, h: (s, v, h)
            row = self.install("publisher.bin", self.fixture("publisher"))
            path = ASSET + str(row["id"])
            self.deletes.clear()

            def changed(m, p, s, v, h):
                if m == "DELETE" and uncertain == "lost":
                    raise OSError("private-detail")
                if self.deletes:
                    if p == path and uncertain == "still_visible":
                        return 200, row, h
                    if p == RELEASE and uncertain == "release_unreadable":
                        return 404, {}, h
                    if p == RELEASE and uncertain == "embedded_not_empty":
                        return 200, v | {"assets": [row]}, h
                    if p == LIST and uncertain == "listed_not_empty":
                        return 200, [row], h
                return s, v, h

            self.change = changed
            with self.subTest(uncertain=uncertain):
                self.stage("cleanup", False)
            self.assertEqual(self.deletes, [row["id"]])

    def test_cleanup_stops_before_deleting_a_replacement_by_name(self):
        self.stage("upload", True)
        reader = self.install("reader.bin", self.fixture("reader"))
        original = reader["id"]

        def moved(method, path, status, value, headers):
            if method == "DELETE":
                self.rows.remove(reader)
                self.install("reader.bin", self.raw.pop(original))
            return status, value, headers

        self.change = moved
        self.stage("cleanup", False)
        self.assertEqual(self.deletes, [51])
        self.assertEqual([r["id"] for r in self.rows], [53])

    def test_reader_never_probes_after_unconfirmed_publisher_bytes(self):
        self.stage("upload", True)
        self.raw[51] = b"X" * len(self.raw[51])
        self.stage("reader", False)
        self.assertEqual(len(self.writes), 1)
        self.assertFalse(self.deletes)

    def test_payload_is_fixed_and_domain_separated(self):
        raw = self.fixture("publisher")
        self.assertIsInstance(raw, bytes)
        self.assertEqual(raw, probe.payload(NONCE, "221", "3", "publisher"))
        for args in (
            ("a" * 32, 221, 3, "publisher"),
            (NONCE, 220, 3, "publisher"),
            (NONCE, 221, 2, "publisher"),
            (NONCE, 221, 3, "reader"),
        ):
            self.assertNotEqual(raw, probe.payload(*args))
        with self.assertRaises(Rejected):
            probe.payload(NONCE, True, 3, "reader")
        with self.assertRaises(Rejected):
            probe.payload(NONCE, 221, 3, "cleanup")

    def test_module_entry_emits_only_fixed_refusal(self):
        with (
            patch.object(sys, "argv", ["cli", "private-diagnostic"]),
            patch.dict(sys.modules),
            redirect_stdout(io.StringIO()) as out,
        ):
            sys.modules.pop("scripts.ci_access_probe", None)
            with self.assertRaises(SystemExit) as caught:
                runpy.run_module("scripts.ci_access_probe", run_name="__main__")
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(out.getvalue(), "access_probe_invalid=refused\n")


if __name__ == "__main__":
    unittest.main()
