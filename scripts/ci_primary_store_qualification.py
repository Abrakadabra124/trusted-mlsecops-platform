"""Private retained evidence against a stateful, socket-free release store."""

import io
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import ci_asset_http as http
from scripts import ci_primary_store as primary
from scripts import ci_private_assets_qualification as fixtures

ROOT = "repos/Abrakadabra124/trusted-mlsecops-ci-private"
PATH = ROOT + "/releases/700"
OWNER = {k: v for k, v in fixtures.EXPECTED.items() if k != "source_revision"}
SOURCE = dict(source_revision="e" * 40, source_fingerprint="c" * 64, image_id="sha256:" + "d" * 64)
RELEASE = dict(
    repository_id=1465012664, release_id=700, name="ci-primary-123-1", target_commitish="b" * 40
)
MAGIC = b"MLSPRIMARY\x01"
DATA = MAGIC + bytes(range(64))
SIBLING = MAGIC + b"other encrypted fixture"


class ReleaseAPI:
    def __init__(self):
        self.repo = fixtures.StoreAPI().repo
        self.release = dict(
            id=700,
            name="ci-primary-123-1",
            tag_name="ci-primary-123-1",
            target_commitish="b" * 40,
            draft=False,
            prerelease=True,
            immutable=False,
        )
        self.rows = []
        self.contents = {}
        self.calls = []
        self.uploads = []
        self.next_id = 100
        self.hook = lambda op, path, value: value

    def install(self, name, data):
        identifier = self.next_id
        self.next_id += 1
        row = dict(
            id=identifier,
            name=name,
            size=len(data),
            state="uploaded",
            digest="sha256:" + digest(data),
        )
        self.rows.append(row)
        self.contents[identifier] = data
        return row

    def json(self, method, path):
        self.calls.append((method, path))
        assert method == "GET"
        if path == ROOT:
            result = self.repo
        elif path == PATH:
            result = self.release | {"assets": self.rows}
        elif path == PATH + "/assets?per_page=6":
            result = self.rows
        else:
            prefix = ROOT + "/releases/assets/"
            assert path.startswith(prefix)
            result = next(row for row in self.rows if path == prefix + str(row["id"]))
        return self.hook(method, path, deepcopy(result))

    def upload(self, path, name, data):
        self.calls.append(("UPLOAD", path))
        self.uploads.append(name)
        assert path == PATH + "/assets" and name in ("shared.bin", "serving.bin")
        assert name not in {row["name"] for row in self.rows}
        return self.hook("UPLOAD", path, self.install(name, data).copy())

    def download(self, path, limit):
        self.calls.append(("DOWNLOAD", path))
        prefix = ROOT + "/releases/assets/"
        identifier = int(path.removeprefix(prefix))
        assert path == prefix + str(identifier)
        raw = self.contents[identifier]
        assert limit == next(row["size"] for row in self.rows if row["id"] == identifier)
        return self.hook("DOWNLOAD", path, raw)


class PrimaryStoreTests(unittest.TestCase):
    def setUp(self):
        self.api = ReleaseAPI()
        self.args = dict(
            role="shared", run_owner=OWNER.copy(), source=SOURCE.copy(), release=RELEASE.copy()
        )

    def put(self, data=DATA, **changes):
        return primary.put(self.api, data, **(self.args | changes))

    def get(self, receipt, **changes):
        return primary.get(self.api, receipt, **(self.args | changes))

    def unverified(self, **changes):
        return primary.get_unverified(self.api, **(self.args | changes))

    def test_invalid_local_binding_never_contacts_the_store(self):
        for change in (
            dict(role="producer"),
            dict(role="shared.bin"),
            dict(run_owner=OWNER | {"run_id": True}),
            dict(run_owner=OWNER | {"producer_job": "shared"}),
            dict(run_owner=OWNER | {"run_attempt": 2}),
            dict(source=SOURCE | {"source_revision": "HEAD"}),
            dict(source=SOURCE | {"image_id": "latest"}),
            dict(release=RELEASE | {"repository_id": 1}),
            dict(release=RELEASE | {"release_id": True}),
            dict(release=RELEASE | {"target_commitish": "main"}),
            dict(release=RELEASE | {"unexpected": 1}),
            dict(release=RELEASE | {"name": "ci-candidate-123-1"}),
            dict(release=RELEASE | {"name": "ci-journal-123-1"}),
        ):
            with self.subTest(change=list(change)):
                with self.assertRaises(Rejected):
                    self.put(**change)
                with self.assertRaises(Rejected):
                    self.unverified(**change)
        self.assertEqual(self.api.calls, [])

    def test_wire_magic_and_size_before_any_upload(self):
        for raw in (
            b"",
            b"private plaintext",
            b"MLSPRIMARY\\x01data",
            b"MLSPRIMARY\x02data",
            MAGIC,
            bytearray(DATA),
            "not bytes",
        ):
            with self.subTest(kind=type(raw)), self.assertRaises(Rejected):
                self.put(raw)
        with patch.object(primary.ci_transfer, "MAX_ENVELOPE_BYTES", len(DATA) - 1):
            with self.assertRaises(Rejected):
                self.put()
        self.assertEqual(self.api.calls, [])

    def test_private_repository_and_fixed_release_identity_guard_all_operations(self):
        for row, field, value in (
            (self.api.repo, "private", False),
            (self.api.repo, "fork", True),
            (self.api.repo, "visibility", "public"),
            (self.api.repo, "id", 1465012665),
            (self.api.repo, "owner", {"login": "other"}),
            (self.api.release, "id", "700"),
            (self.api.release, "name", "ci-journal-x"),
            (self.api.release, "tag_name", "ci-candidate-123-1"),
            (self.api.release, "target_commitish", "f" * 40),
        ):
            with self.subTest(field=field), patch.dict(row, {field: value}):
                with self.assertRaises(Rejected):
                    self.put()
                with self.assertRaises(Rejected):
                    self.unverified()
        self.assertEqual(self.api.uploads, [])

    def test_roundtrip_and_exact_retry_use_full_bytes_and_an_owned_private_receipt(self):
        with patch.object(primary.ci_transfer, "MAX_ENVELOPE_BYTES", len(DATA)):
            receipt = self.put()
            self.assertEqual(
                receipt,
                dict(
                    schema_version=1,
                    role="shared",
                    run_owner=OWNER,
                    source=SOURCE,
                    release=RELEASE,
                    asset=dict(id=100, name="shared.bin", size=len(DATA), sha256=digest(DATA)),
                ),
            )
            self.assertEqual(self.get(receipt), DATA)
            self.assertEqual(self.unverified(), DATA)
            self.assertEqual(self.put(), receipt)
        self.assertEqual(self.api.uploads, ["shared.bin"])
        self.assertEqual(sum(op == "DOWNLOAD" for op, _ in self.api.calls), 4)
        self.args["release"]["release_id"] = 999
        self.args["source"]["source_fingerprint"] = "0" * 64
        self.assertEqual(receipt["release"], RELEASE)
        self.assertEqual(receipt["source"], SOURCE)

    def test_conflicting_ciphertext_never_replaces_a_role(self):
        self.put()
        with self.assertRaises(Rejected):
            self.put(DATA[:-1] + b"X")
        self.assertEqual(self.api.uploads, ["shared.bin"])
        self.assertEqual(self.api.contents[100], DATA)

    def test_replaced_asset_with_identical_bytes_is_untrusted_to_anchored_reader(self):
        original = self.put()
        self.api.rows.clear()
        self.api.contents.clear()
        self.api.install("shared.bin", DATA)
        self.api.calls.clear()
        with self.assertRaises(Rejected):
            self.get(original)
        self.assertFalse(any(op == "DOWNLOAD" for op, _ in self.api.calls))
        self.assertEqual(self.unverified(), DATA)

    def test_receipt_is_bound_to_role_owner_source_release_and_exact_pin(self):
        receipt = self.put()
        self.api.calls.clear()
        for field, value in (
            ("schema_version", True),
            ("role", "serving"),
            ("run_owner", OWNER | {"run_attempt": True}),
            ("source", SOURCE | {"source_fingerprint": "0" * 64}),
            ("release", RELEASE | {"release_id": 701}),
            ("asset", receipt["asset"] | {"name": "serving.bin"}),
            ("asset", receipt["asset"] | {"id": True}),
            ("asset", receipt["asset"] | {"size": True}),
            ("asset", receipt["asset"] | {"sha256": "Z" * 64}),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.get(receipt | {field: value})
        self.assertEqual(self.api.calls, [])
        for field, value in (("id", 101), ("size", len(DATA) + 1), ("sha256", "0" * 64)):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.get(receipt | {"asset": receipt["asset"] | {field: value}})
        self.assertFalse(any(op == "DOWNLOAD" for op, _ in self.api.calls))

    def test_mutable_remote_digest_cannot_authenticate_recovered_bytes(self):
        receipt = self.put()
        replacement = DATA[:-1] + b"X"
        self.api.contents[100] = replacement
        self.api.rows[0]["digest"] = "sha256:" + digest(replacement)
        with self.assertRaises(Rejected):
            self.get(receipt)
        self.assertEqual(self.unverified(), replacement)
        self.assertEqual(self.api.uploads, ["shared.bin"])

    def test_real_scoped_clients_accept_store_routes_with_synthetic_responses(self):
        @contextmanager
        def respond(host, method, target, headers, body=None):
            path = target.removeprefix("/")
            if method == "POST":
                self.assertEqual(host, "uploads.github.com")
                route, name = path.split("?name=")
                raw = canonical(self.api.upload(route, name, body))
                status = 201
            else:
                self.assertEqual((host, method, body), ("api.github.com", "GET", None))
                if headers["Accept"] == "application/octet-stream":
                    self.assertEqual(path, ROOT + "/releases/assets/100")
                    raw = self.api.download(path, len(DATA))
                else:
                    raw = canonical(self.api.json(method, path))
                status = 200
            reply = Message()
            reply["Content-Length"] = str(len(raw))
            yield SimpleNamespace(status=status, headers=reply, read=io.BytesIO(raw).read)

        with patch.object(http, "_response", respond):
            writer = http.Client("fixture-writer", write=True)
            reader = http.Client("fixture-reader")
            receipt = primary.put(writer, DATA, **self.args)
            self.assertEqual(primary.get(reader, receipt, **self.args), DATA)
            self.assertEqual(primary.get_unverified(reader, **self.args), DATA)
            with self.assertRaises(Rejected):
                primary.put(reader, SIBLING, **(self.args | {"role": "serving"}))
        self.assertEqual(self.api.uploads, ["shared.bin"])

    def test_direct_and_listed_metadata_must_identify_the_same_uploaded_file(self):
        receipt = self.put()
        asset_path = ROOT + "/releases/assets/100"
        for path, change in (
            (PATH + "/assets?per_page=6", lambda rows: []),
            (PATH + "/assets?per_page=6", lambda rows: rows + [rows[0]]),
            (PATH + "/assets?per_page=6", lambda rows: rows + [rows[0] | {"name": "serving.bin"}]),
            (
                PATH + "/assets?per_page=6",
                lambda rows: rows + [rows[0] | {"name": "foreign.bin", "id": 333}],
            ),
            (asset_path, lambda r: r | {"id": 101}),
            (asset_path, lambda r: r | {"state": "starter"}),
            (asset_path, lambda r: r | {"name": "serving.bin"}),
            (asset_path, lambda r: r | {"digest": None}),
            (asset_path, lambda r: r | {"digest": "sha256:" + "z" * 64}),
            (asset_path, lambda r: r | {"size": 0}),
        ):
            self.api.hook = lambda op, p, r: change(r) if p == path else r
            with self.subTest(path=path):
                with self.assertRaises(Rejected):
                    self.get(receipt)
                with self.assertRaises(Rejected):
                    self.unverified()
        self.assertEqual(self.api.uploads, ["shared.bin"])

    def test_readback_truncation_wrong_bytes_or_bad_prefix_never_returns_evidence(self):
        receipt = self.put()
        for raw in (None, DATA[:-1], b"X" + DATA[1:], DATA[:-1] + b"X"):
            self.api.hook = lambda op, p, r: raw if op == "DOWNLOAD" else r
            with self.subTest(raw=type(raw)):
                for action in (lambda: self.get(receipt), self.unverified, self.put):
                    with self.assertRaises(Rejected):
                        action()
        self.assertEqual(self.api.uploads, ["shared.bin"])

    def test_unverified_retrieval_uses_fixed_role_only_and_never_writes(self):
        self.api.install("serving.bin", SIBLING)
        with self.assertRaises(Rejected):
            self.unverified()
        self.assertEqual(self.unverified(role="serving"), SIBLING)
        self.assertEqual(self.api.uploads, [])

    def test_sibling_can_arrive_between_release_and_asset_listing(self):
        def concurrent(op, path, value):
            if path == PATH and not self.api.rows:
                self.api.install("serving.bin", SIBLING)
            return value

        self.api.hook = concurrent
        receipt = self.put()
        self.assertEqual(self.get(receipt), DATA)
        self.assertEqual(self.unverified(role="serving"), SIBLING)
        self.assertEqual(self.api.uploads, ["shared.bin"])

    def test_in_flight_sibling_does_not_block_our_role(self):
        self.api.install("serving.bin", SIBLING).update(state="starter", size=0, digest=None)
        receipt = self.put()
        self.assertEqual(self.get(receipt), DATA)
        with self.assertRaises(Rejected):
            self.unverified(role="serving")

    def test_visibility_drift_at_end_of_listing_blocks_first_upload(self):
        def reveal(op, path, value):
            if path == PATH + "/assets?per_page=6":
                self.api.repo.update(private=False, visibility="public")
            return value

        self.api.hook = reveal
        with self.assertRaises(Rejected):
            self.put()
        self.assertFalse(self.api.uploads)

    def test_only_published_prereleases_with_boolean_flags_are_accepted(self):
        receipt = self.put()
        for field, invalid in (
            ("draft", True),
            ("draft", 0),
            ("prerelease", False),
            ("prerelease", 1),
            ("immutable", 0),
        ):
            with (
                self.subTest(field=field, invalid=invalid),
                patch.dict(self.api.release, {field: invalid}),
            ):
                for action in (
                    lambda: self.get(receipt),
                    self.unverified,
                    self.put,
                    lambda: self.put(SIBLING, role="serving"),
                ):
                    with self.assertRaises(Rejected):
                        action()
        self.assertEqual(self.api.uploads, ["shared.bin"])

    def test_sealed_prerelease_supports_readback_and_prevents_new_upload(self):
        receipt = self.put()
        self.api.release["immutable"] = True
        self.assertEqual(self.get(receipt), DATA)
        self.assertEqual(self.unverified(), DATA)
        self.assertEqual(self.put(), receipt)
        with self.assertRaises(Rejected):
            self.put(SIBLING, role="serving")
        self.assertEqual(self.api.uploads, ["shared.bin"])

    def test_prerelease_contract_is_checked_again_after_downloading(self):
        receipt = self.put()
        for action in (lambda: self.get(receipt), self.unverified, self.put):
            for field, value in (("draft", True), ("prerelease", False)):

                def changed(op, path, result):
                    if op == "DOWNLOAD":
                        self.api.release[field] = value
                    return result

                with self.subTest(field=field), patch.dict(self.api.release):
                    self.api.hook = changed
                    with self.assertRaises(Rejected):
                        action()
        self.assertEqual(self.api.uploads, ["shared.bin"])

    def test_returned_upload_metadata_and_postdownload_ownership_must_still_match(self):
        for delta in (
            {"name": "serving.bin"},
            {"id": 123},
            {"digest": "sha256:" + "c" * 64},
            {"size": len(DATA) + 1},
        ):
            self.api = ReleaseAPI()
            self.api.hook = lambda op, p, r: r | delta if op == "UPLOAD" else r
            with self.subTest(delta=delta), self.assertRaises(Rejected):
                self.put()
            self.assertEqual(self.api.uploads, ["shared.bin"])
        self.api = ReleaseAPI()

        def moved(op, path, value):
            if op == "DOWNLOAD":
                self.api.release["tag_name"] = "ci-candidate-123-1"
            return value

        self.api.hook = moved
        with self.assertRaises(Rejected):
            self.put()

    def test_lost_upload_response_has_no_automatic_retry_and_no_private_diagnostics(self):
        def lost(op, path, value):
            if op == "UPLOAD":
                raise OSError("private-fixture-detail")
            return value

        self.api.hook = lost
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(Rejected) as caught:
                self.put()
        self.assertNotIn("private-fixture-detail", str(caught.exception))
        self.assertEqual(out.getvalue() + err.getvalue(), "")
        self.assertEqual(self.api.uploads, ["shared.bin"])
        self.api.hook = lambda op, p, r: r
        receipt = self.put()
        self.assertEqual(self.get(receipt), DATA)
        self.assertEqual(self.api.uploads, ["shared.bin"])


if __name__ == "__main__":
    unittest.main()
