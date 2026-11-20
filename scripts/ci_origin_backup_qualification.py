"""Real publication, producer authentication and journal recovery on isolated in-memory releases."""

import unittest
from copy import deepcopy
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import signing
from mlsecops.contracts import Rejected, digest
from scripts import ci_campaign_control_qualification as crypto
from scripts import ci_campaign_handoff as handoff
from scripts import ci_campaign_journal as journal
from scripts import ci_campaign_journal_qualification as journal_fixture
from scripts import ci_origin_backup as backup
from scripts import ci_private_assets as store
from scripts import ci_private_assets_qualification as working

RELEASE = dict(
    repository_id=store.REPOSITORY_ID,
    release_id=907,
    name="ci-origin-31-2",
    target_commitish="b" * 40,
)
PATH = store._endpoint(RELEASE)
ASSETS = store.ROOT + "/releases/assets/"


class PrivateStore(working.StoreAPI):
    def __init__(self):
        super().__init__()
        self.origin = dict(
            id=907,
            name=RELEASE["name"],
            tag_name=RELEASE["name"],
            target_commitish=RELEASE["target_commitish"],
            draft=False,
            prerelease=True,
            immutable=False,
        )
        self.rows = []
        self.saved = {}
        self.writes = []
        self.calls = []
        self.next_origin = 9000

    def install(self, name, raw):
        i = self.next_origin
        self.next_origin += 1
        row = dict(id=i, name=name, size=len(raw), digest="sha256:" + digest(raw), state="uploaded")
        self.rows.append(row)
        self.saved[i] = raw
        return row

    def json(self, method, path, **options):
        self.calls.append((method, path))
        if path == PATH:
            value = self.origin | {"assets": self.rows}
        elif path == PATH + "/assets?per_page=6":
            value = self.rows
        elif path.startswith(ASSETS) and int(path.removeprefix(ASSETS)) in self.saved:
            value = next(row for row in self.rows if str(row["id"]) == path.removeprefix(ASSETS))
        else:
            return super().json(method, path, **options)
        assert method == "GET"
        return self.hook(method, path, deepcopy(value))

    def upload(self, path, name, content):
        if path != PATH + "/assets":
            return super().upload(path, name, content)
        assert name not in [r["name"] for r in self.rows]
        assert name in {stem + ".bin" for stem in store.LIMITS}
        self.writes.append(name)
        return self.hook("UPLOAD", path, self.install(name, content).copy())

    def download(self, path, limit):
        self.calls.append(("DOWNLOAD", path))
        i = int(path.removeprefix(ASSETS))
        if i not in self.saved:
            return super().download(path, limit)
        raw = self.saved[i]
        assert limit == next(r["size"] for r in self.rows if r["id"] == i)
        return self.hook("DOWNLOAD", path, raw)


class OriginTests(unittest.TestCase):
    def setUp(self):
        fx = crypto.CampaignControlTests()
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        self.enterContext(patch.object(working, "TAG", "ci-candidate-31-2"))
        self.enterContext(patch.object(working, "REF", "refs/tags/ci-candidate-31-2"))
        self.api = PrivateStore()
        self.steps = []
        self.public, self.working = handoff.publish(
            self.api,
            owner=fx.owner,
            origin=fx.origin,
            reports=fx.reports,
            packets=fx.packets,
            key=crypto.KEY,
            checkpoint=self.steps.append,
        )
        self.expected = {
            stem: self.api.contents[pin["id"]] for stem, pin in self.working["assets"].items()
        }
        self.context = dict(run_owner=fx.run.copy(), source=fx.source.copy())
        self.args = dict(
            **self.context, release=RELEASE.copy(), checkpoint=deepcopy(self.steps[-1])
        )
        self.api.calls.clear()
        self.api.downloads.clear()
        self.api.mutations.clear()

    def copy(self, **changes):
        return backup.copy_originals(self.api, **(self.args | {"key": crypto.KEY} | changes))

    def reader(self, **changes):
        return backup.reader(self.api, **(self.args | changes))

    def test_incomplete_or_inconsistent_checkpoint_before_dispatch(self):
        for state in self.steps[:-1]:
            with self.assertRaises(Rejected):
                self.copy(checkpoint=state)
            with self.assertRaises(Rejected):
                self.reader(checkpoint=state)
        closed = self.steps[-1]
        for key, value in (
            ("public", "invalid"),
            ("storage_sha256", "a" * 64),
            ("control_sha256", "b" * 64),
        ):
            with patch.dict(closed["issuer"], {key: value}), self.assertRaises(Rejected):
                self.reader(checkpoint=closed)
        self.assertFalse(self.api.calls)
        self.assertFalse(self.api.writes)

    def test_target_binding_rejects_working_journal_primary_and_cross_run(self):
        for override in (
            {"release_id": 71},
            {"release_id": True},
            {"repository_id": 1},
            {"name": "ci-journal-fixture"},
            {"name": "ci-primary-31-2"},
            {"name": "ci-origin-31-3"},
            {"target_commitish": "main"},
            {"extra": 1},
        ):
            with self.subTest(override=override), self.assertRaises(Rejected):
                self.copy(release=RELEASE | override)
        self.assertFalse(self.api.calls)
        for key, bad in (
            ("id", 71),
            ("name", "ci-primary-31-2"),
            ("tag_name", "ci-journal-x"),
            ("target_commitish", "0" * 40),
            ("draft", 0),
            ("prerelease", 1),
        ):
            with patch.dict(self.api.origin, {key: bad}), self.assertRaises(Rejected):
                self.copy()
        with patch.dict(self.api.repo, {"private": False}), self.assertRaises(Rejected):
            self.copy()
        self.assertFalse(self.api.writes)

    def test_wrong_key_issuer_source_or_source_control_id_never_copies(self):
        with self.assertRaises(Rejected):
            self.copy(key=b"z" * 32)
        with self.assertRaises(Rejected):
            self.copy(source=self.context["source"] | {"source_fingerprint": "c" * 64})
        with (
            patch.dict(self.args["checkpoint"]["issuer"], {"public": signing.encode64(b"x" * 32)}),
            self.assertRaises(Rejected),
        ):
            self.copy()
        pin = self.args["checkpoint"]["storage"]["assets"][store.CONTROL]
        with patch.dict(pin, {"id": 602}), self.assertRaises(Rejected):
            self.copy()
        i = self.working["assets"][store.CONTROL]["id"]
        raw = self.api.contents[i]
        replacement = raw[:-1] + bytes([raw[-1] ^ 1])
        with (
            patch.dict(self.api.contents, {i: replacement}),
            patch.dict(self.api.assets[i], {"digest": "sha256:" + digest(replacement)}),
            self.assertRaises(Rejected),
        ):
            self.copy()
        self.assertFalse(self.api.writes)

    def test_signed_journal_roundtrip_expiry_and_detached_reader(self):
        path = Path(self.enterContext(TemporaryDirectory())) / "fixture.pem"
        args = dict(
            journal=journal_fixture.PIN,
            key=crypto.KEY,
            trusted_public=signing.create_key(path),
            **self.context,
        )
        remote = journal_fixture.JournalAPI()
        append = journal.publisher(remote, key_path=path, **args)
        tips = [append(s) for s in self.steps]
        closed = journal.recover(remote, expected_tip=tips[-1], **args)["checkpoint"]
        self.assertIsNone(self.copy(checkpoint=closed))
        self.assertCountEqual(
            self.api.downloads, [(v["id"], v["size"]) for v in self.working["assets"].values()]
        )
        writes = self.api.writes.copy()
        self.assertCountEqual(writes, [s + ".bin" for s in self.expected])
        self.assertEqual(
            {r["name"]: self.api.saved[r["id"]] for r in self.api.rows},
            {k + ".bin": v for k, v in self.expected.items()},
        )
        self.assertIsNone(self.copy(checkpoint=closed))
        self.assertEqual(self.api.writes, writes)
        self.assertFalse(self.api.mutations)
        self.api.origin["immutable"] = True
        self.api.release = self.api.tag = None
        self.api.contents.clear()
        self.api.assets.clear()
        with patch("time.time", return_value=self.working["expires_at"] + 300):
            self.api.calls.clear()
            read = self.reader(checkpoint=closed)
            closed["storage"]["assets"].clear()
            self.args["release"]["name"] = "wrong"
            for stem, raw in self.expected.items():
                self.assertEqual(read(stem, len(raw)), raw)
        allowed = {
            store.ROOT,
            PATH,
            PATH + "/assets?per_page=6",
            *(ASSETS + str(i) for i in self.api.saved),
        }
        self.assertTrue(
            all(op in ("GET", "DOWNLOAD") and path in allowed for op, path in self.api.calls)
        )

    def test_partial_ambiguous_upload_recovers_only_identical_bytes(self):
        def lost(op, path, value):
            if op == "UPLOAD" and len(self.api.writes) == 2:
                raise Rejected("controlled lost acknowledgment")
            return value

        self.api.hook = lost
        with self.assertRaises(Rejected):
            self.copy()
        self.assertEqual(len(self.api.writes), 2)
        with self.assertRaises(Rejected):
            self.reader()
        self.api.hook = lambda op, path, value: value
        row = self.api.rows[-1]
        ident = row["id"]
        raw = self.api.saved[ident]
        with (
            patch.dict(self.api.saved, {ident: raw[:-1] + bytes([raw[-1] ^ 1])}),
            self.assertRaises(Rejected),
        ):
            self.copy()
        self.assertEqual(len(self.api.writes), 2)
        self.copy()
        self.assertEqual(len(set(self.api.writes)), 5)
        self.assertEqual(len(self.api.writes), 5)

    def test_inventory_rejects_cross_role_ids_foreign_metadata_and_sealed_partial(self):
        first = store.PACKETS[0]
        row = self.api.install(first + ".bin", self.expected[first])
        other_working_id = self.working["assets"][store.CONTROL]["id"]
        for change in (
            {"id": other_working_id},
            {"digest": "sha256:" + "0" * 64},
            {"name": "shared.bin"},
            {"size": True},
            {"state": "starter"},
        ):
            with patch.dict(row, change), self.assertRaises(Rejected):
                self.copy()
        with patch.dict(self.api.origin, {"immutable": True}), self.assertRaises(Rejected):
            self.copy()
        self.api.hook = lambda op, path, v: [] if path == PATH + "/assets?per_page=6" else v
        with self.assertRaises(Rejected):
            self.copy()
        self.assertFalse(self.api.writes)

    def test_release_repurposed_during_preupload_listing_gets_no_ciphertext(self):
        listings = 0

        def reassigned(op, path, value):
            nonlocal listings
            if path == PATH + "/assets?per_page=6":
                listings += 1
                if listings == 2:
                    self.api.origin.update(name="ci-journal-other", tag_name="ci-journal-other")
            return value

        self.api.hook = reassigned
        with self.assertRaises(Rejected):
            self.copy()
        self.assertFalse(self.api.writes)

    def test_upload_must_confirm_the_same_id_metadata_and_bytes(self):
        for delta in (
            {"id": 444},
            {"size": True},
            {"digest": "sha256:" + "a" * 64},
            {"name": "primary.bin"},
        ):
            self.api.rows.clear()
            self.api.writes.clear()
            self.api.saved.clear()
            self.api.hook = lambda op, path, value: value | delta if op == "UPLOAD" else value
            with self.subTest(delta=delta), self.assertRaises(Rejected):
                self.copy()
            self.assertEqual(len(self.api.writes), 1)

    def test_working_payload_corruption_blocks_its_upload(self):
        stem = store.PACKETS[0]
        i = self.working["assets"][stem]["id"]
        raw = self.expected[stem]
        changed = raw[:-1] + bytes([raw[-1] ^ 1])
        with patch.dict(self.api.contents, {i: changed}), self.assertRaises(Rejected):
            self.copy()
        self.assertFalse(self.api.writes)

    def test_original_window_covers_upload_and_completion(self):
        with (
            patch("time.time", return_value=self.working["expires_at"]),
            self.assertRaises(Rejected),
        ):
            self.copy()
        self.assertFalse(self.api.writes)
        with patch("time.time", return_value=crypto.NOW) as clock:

            def expire(op, path, value):
                if op == "DOWNLOAD" and len(self.api.writes) == 5:
                    clock.return_value = self.working["expires_at"]
                return value

            self.api.hook = expire
            with self.assertRaises(Rejected):
                self.copy()
        self.assertEqual(len(self.api.writes), 5)

    def test_reader_bound_limit_content_and_membership_at_readback(self):
        self.copy()
        read = self.reader()
        stem = store.PACKETS[0]
        size = len(self.expected[stem])
        for args in (("../foreign", size), (stem, size - 1), (stem, True)):
            self.api.calls.clear()
            with self.assertRaises(Rejected):
                read(*args)
            self.assertFalse(self.api.calls)
        row = next(r for r in self.api.rows if r["name"] == stem + ".bin")
        original = self.api.saved[row["id"]]
        with patch.dict(self.api.saved, {row["id"]: original[:-1]}), self.assertRaises(Rejected):
            read(stem, size)
        with patch.dict(row, {"id": 9999}), self.assertRaises(Rejected):
            read(stem, size)

        def moved(op, path, value):
            if op == "DOWNLOAD":
                self.api.origin["tag_name"] = "elsewhere"
            return value

        self.api.hook = moved
        with self.assertRaises(Rejected):
            read(stem, size)


class TerminalIntegrationTests(unittest.TestCase):
    def test_expired_terminal_cleanup_uses_retained_originals_for_both_receiver_replays(self):
        from scripts import ci_terminal_primary_qualification as terminal_fixture

        case = terminal_fixture.TerminalPrimaryTests()
        case.setUpClass()
        self.addCleanup(case.doClassCleanups)
        self.addCleanup(case.doCleanups)
        case.setUp()
        fx = case.fx
        api = PrivateStore()
        for field in ("tag", "release", "assets", "contents"):
            setattr(api, field, deepcopy(getattr(fx.api, field)))
        case.caller.private = api
        release = RELEASE | {"name": "ci-origin-123-1"}
        api.origin.update(name=release["name"], tag_name=release["name"])
        remote = journal_fixture.JournalAPI()
        path = Path(self.enterContext(TemporaryDirectory())) / "synthetic.pem"
        params = dict(
            journal=journal_fixture.PIN, key=crypto.KEY, trusted_public=signing.create_key(path)
        )
        append = journal.publisher(remote, key_path=path, **params, **case.binding)
        tip = [append(state) for state in fx.journal][-1]
        recover = partial(journal.recover, remote, **params)
        closed = recover(expected_tip=tip, **case.binding)["checkpoint"]
        bound = dict(release=release, checkpoint=closed, **case.binding)
        backup.copy_originals(api, key=crypto.KEY, **bound)
        readonly = SimpleNamespace(json=api.json, download=api.download)
        api.downloads.clear()
        with patch("time.time", return_value=fx.receipt["expires_at"] + 60):
            read = backup.reader(readonly, **bound)
            case.clean(case.callback(read_asset=read), read_journal=recover, expected_tip=tip)
            for stem, pin in closed["storage"]["assets"].items():
                self.assertEqual(digest(read(stem, pin["size"])), pin["sha256"])
        self.assertEqual(case.replayed, ["shared", "serving"])
        self.assertIsNone(api.release)
        self.assertIsNone(api.tag)
        self.assertFalse(api.assets)
        self.assertFalse(api.downloads)
        self.assertEqual(len(api.rows), 5)


if __name__ == "__main__":
    unittest.main()
