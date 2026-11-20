"""Real Ed25519 and AES-GCM, a bounded in-memory private GitHub release, no sockets."""

import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import ci_campaign_control as control
from scripts import ci_campaign_control_qualification as control_fixture
from scripts import ci_campaign_handoff as handoff
from scripts import ci_campaign_journal as journal
from scripts import ci_private_assets_qualification as assets

PIN = dict(
    repository_id=1465012664, release_id=700, name="ci-journal-example", target_commitish="b" * 40
)
OWNER = {k: v for k, v in assets.EXPECTED.items() if k != "source_revision"}
SOURCE = dict(
    source_revision=assets.EXPECTED["source_revision"],
    source_fingerprint="c" * 64,
    image_id="sha256:" + "d" * 64,
)
STEMS = (
    "candidate-shared",
    "candidate-serving",
    "upstream-serving",
    "validation-serving",
    "producer-control",
)


def workflow_checkpoints(issuer_public):
    storage = dict(
        schema_version=1,
        expected=assets.EXPECTED,
        repository_id=1465012664,
        tag=assets.TAG,
        private_head=assets.HEAD,
        release_id=None,
        issued_at=10000,
        expires_at=11800,
        assets={},
    )
    result = [dict(storage=deepcopy(storage), issuer=None)]
    storage["release_id"] = 71
    result.append(dict(storage=deepcopy(storage), issuer=None))
    for i, stem in enumerate(STEMS[:-1], start=100):
        raw = assets.PACKETS[stem]
        storage["assets"][stem] = dict(id=i, size=len(raw), sha256=digest(raw))
        result.append(dict(storage=deepcopy(storage), issuer=None))
    issuer = dict(
        public=issuer_public,
        storage_sha256=digest(canonical(storage)),
        control_sha256=digest(assets.CONTROL),
    )
    result.append(dict(storage=deepcopy(storage), issuer=issuer.copy()))
    storage["assets"]["producer-control"] = dict(
        id=104, size=len(assets.CONTROL), sha256=digest(assets.CONTROL)
    )
    result.append(dict(storage=storage, issuer=issuer))
    return result


class JournalAPI:
    def __init__(self):
        self.repo = assets.StoreAPI().repo
        self.release = dict(
            id=700,
            name=PIN["name"],
            tag_name=PIN["name"],
            target_commitish=PIN["target_commitish"],
            draft=False,
            prerelease=True,
            immutable=False,
        )
        self.others = []
        self.rows = []
        self.data = {}
        self.uploads = []
        self.hook = lambda method, path, value: value

    def json(self, method, path):
        assert method == "GET"
        if path == assets.ROOT:
            result = self.repo
        elif path == assets.ROOT + "/releases?per_page=100":
            result = [self.release, *self.others]
        elif path == assets.ROOT + "/releases/700":
            result = self.release | {"assets": self.rows}
        else:
            i = int(path.removeprefix(assets.ROOT + "/releases/assets/"))
            result = next(row for row in self.rows if row["id"] == i)
        return self.hook(method, path, deepcopy(result))

    def upload(self, path, name, content):
        assert path == assets.ROOT + "/releases/700/assets"
        if any(row["name"] == name for row in self.rows):
            raise Rejected("already exists")
        i = 1000 + len(self.uploads)
        self.uploads.append(name)
        row = dict(
            id=i, name=name, state="uploaded", size=len(content), digest="sha256:" + digest(content)
        )
        self.rows.append(row)
        self.data[i] = content
        return self.hook("UPLOAD", path, row.copy())

    def download(self, path, limit):
        i = int(path.removeprefix(assets.ROOT + "/releases/assets/"))
        content = self.data[i]
        assert len(content) <= limit <= 16 * 1024
        return self.hook("DOWNLOAD", path, content)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.api = JournalAPI()
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.path = self.root / "journal.pem"
        self.public = signing.create_key(self.path)
        self.issuer = signing.create_key(self.root / "control.pem")
        self.inputs = dict(
            journal=PIN.copy(),
            run_owner=OWNER.copy(),
            source=SOURCE.copy(),
            key=bytes(range(32)),
            trusted_public=self.public,
        )
        self.checkpoints = workflow_checkpoints(self.issuer)

    def writer(self, **changes):
        return journal.publisher(self.api, key_path=self.path, **(self.inputs | changes))

    def read(self, **changes):
        return journal.recover(self.api, **(self.inputs | changes))

    def append(self, n=8):
        write = self.writer()
        tips = [write(row) for row in self.checkpoints[:n]]
        return write, tips

    def test_completed_real_signature_and_decryption_survive_new_reader_and_expiry(self):
        write, tips = self.append()
        self.assertEqual(len(set(self.api.uploads)), 8)
        self.api.rows.reverse()  # REST enumeration order is not a signed sequence.
        with patch("time.time", return_value=200000):
            got = self.read(expected_tip=tips[-1])
        self.assertEqual(got, dict(checkpoint=self.checkpoints[-1], tip=tips[-1], complete=True))
        for index, tip in enumerate(tips, start=1):
            self.assertEqual(
                tip,
                dict(step=index, asset_id=999 + index, sha256=digest(self.api.data[999 + index])),
            )
            self.assertNotIn(self.issuer.encode(), self.api.data[999 + index])
            self.assertNotIn(SOURCE["source_fingerprint"].encode(), self.api.data[999 + index])
        with self.assertRaises(Rejected):
            write(self.checkpoints[-1])

    def test_wrong_key_never_allows_first_mutation(self):
        with self.assertRaises(Rejected):
            self.writer(trusted_public=self.issuer)
        self.assertFalse(self.api.uploads)

    def test_every_partial_stage_requires_explicit_diagnostic_read(self):
        write = self.writer()
        for i in range(8):
            with self.subTest(step=i):
                with self.assertRaises(Rejected):
                    self.read()
                got = self.read(allow_partial=True)
                self.assertFalse(got["complete"])
                self.assertEqual(got["checkpoint"], self.checkpoints[i - 1] if i else None)
            write(self.checkpoints[i])

    def test_modified_stage_or_non_monotone_receipt_refused_before_write(self):
        cases = (
            (0, {"issuer": {}}),
            (0, {"unknown": 1}),
            (1, {"release_id": 700}),
            (2, {"private_head": "f" * 40}),
            (3, {"issued_at": 10001, "expires_at": 11801}),
            (
                6,
                {
                    "issuer": {
                        "public": self.issuer,
                        "control_sha256": "a" * 64,
                        "storage_sha256": "9" * 64,
                    }
                },
            ),
            (7, {"issuer": None}),
        )
        for stage, bad in cases:
            self.api = JournalAPI()
            write, _ = self.append(stage)
            row = deepcopy(self.checkpoints[stage])
            target = row if "issuer" in bad or "unknown" in bad else row["storage"]
            target.update(bad)
            with self.subTest(stage=stage, bad=list(bad)), self.assertRaises(Rejected):
                write(row)
            self.assertEqual(len(self.api.uploads), stage)

    def test_previous_payload_id_replacement_and_wrong_control_pin_refuse_before_write(self):
        for stage, stem in ((3, "candidate-shared"), (7, "producer-control")):
            self.api = JournalAPI()
            write, _ = self.append(stage)
            row = deepcopy(self.checkpoints[stage])
            row["storage"]["assets"][stem]["sha256"] = "f" * 64
            with self.assertRaises(Rejected):
                write(row)
            self.assertEqual(len(self.api.uploads), stage)

    def test_replay_out_of_order_and_foreign_attempt_never_append(self):
        for stage, index in ((0, 1), (1, 0), (2, 3), (4, 3), (6, 5), (7, 6)):
            self.api = JournalAPI()
            write, _ = self.append(stage)
            with self.subTest(stage=stage, index=index), self.assertRaises(Rejected):
                write(self.checkpoints[index])
            self.assertEqual(len(self.api.uploads), stage)
        self.api = JournalAPI()
        write = self.writer()
        row = deepcopy(self.checkpoints[0])
        row["storage"]["expected"]["run_attempt"] = 3
        with self.assertRaises(Rejected):
            write(row)

    def test_superseded_recovery_anchor_and_changed_keys_or_source(self):
        _, tips = self.append()
        for changed in (
            dict(expected_tip=tips[2]),
            dict(trusted_public=self.issuer),
            dict(key=b"z" * 32),
            dict(run_owner=OWNER | {"run_attempt": 2}),
            dict(source=SOURCE | {"source_fingerprint": "e" * 64}),
        ):
            with self.subTest(change=list(changed)), self.assertRaises(Rejected):
                self.read(**changed)

    def test_truncated_tail_requires_full_chain_or_fresh_independent_witness(self):
        _, tips = self.append()
        self.api.rows.pop()
        for options in ({}, dict(allow_partial=True, expected_tip=tips[-1])):
            with self.assertRaises(Rejected):
                self.read(**options)
        partial = self.read(allow_partial=True, expected_tip=tips[-2])
        self.assertFalse(partial["complete"])
        self.assertEqual(partial["checkpoint"], self.checkpoints[6])
        self.assertEqual(len(self.api.uploads), 8)

    def test_bad_middle_slot_or_foreign_asset_or_duplicate_blocks_recovery(self):
        self.append()
        original = self.api.rows.copy()
        for rows in (
            original[1:],
            original[:-1] + [original[-2]],
            original + [original[0]],
            [original[0] | {"name": "another-run.bin"}],
            [original[0] | {"id": True}],
            [original[0] | {"state": "starter"}],
            [original[0] | {"size": 16385}],
            [original[0] | {"digest": None}],
        ):
            self.api.rows = rows
            with self.subTest(length=len(rows)), self.assertRaises(Rejected):
                self.read(allow_partial=True)

    def test_bytes_reordered_or_tampered_with_fresh_metadata_refuse(self):
        self.append()
        for change in ("swap", "alter"):
            i = 1002
            original = self.api.data[i]
            raw = (
                self.api.data[1001]
                if change == "swap"
                else original[:-1] + bytes([original[-1] ^ 1])
            )
            self.api.rows[2].update(size=len(raw), digest="sha256:" + digest(raw))
            self.api.data[i] = raw
            with self.assertRaises(Rejected):
                self.read()
            self.api.data[i] = original
            self.api.rows[2].update(size=len(original), digest="sha256:" + digest(original))

    def test_operator_release_identity_draft_collision_and_visibility_drift(self):
        for change in (
            {"draft": True},
            {"immutable": True},
            {"name": "other"},
            {"tag_name": "ci-candidate-123-1"},
            {"target_commitish": "a" * 40},
        ):
            self.api = JournalAPI()
            write = self.writer()
            self.api.release.update(change)
            with self.assertRaises(Rejected):
                write(self.checkpoints[0])
            self.assertFalse(self.api.uploads)
        self.api = JournalAPI()
        self.api.others = [self.api.release | {"id": 702, "draft": True}]
        with self.assertRaises(Rejected):
            self.writer()
        self.api = JournalAPI()
        write = self.writer()

        def reveal(method, path, value):
            if path.endswith("/releases/700"):
                self.api.repo["visibility"] = "public"
            return value

        self.api.hook = reveal
        with self.assertRaises(Rejected):
            write(self.checkpoints[0])
        self.assertFalse(self.api.uploads)

    def test_reply_lost_after_valid_append_never_retries_mutation(self):
        write = self.writer()

        def disconnect(method, path, value):
            if method == "UPLOAD":
                raise OSError("synthetic disconnect")
            return value

        self.api.hook = disconnect
        with self.assertRaises((OSError, Rejected)):
            write(self.checkpoints[0])
        self.api.hook = lambda m, p, v: v
        with self.assertRaises(Rejected):
            write(self.checkpoints[0])
        with self.assertRaises(Rejected):
            self.writer()
        self.assertEqual(self.read(allow_partial=True)["checkpoint"], self.checkpoints[0])
        self.assertEqual(len(self.api.uploads), 1)

    def test_actual_handoff_recovery_verifies_original_signed_control_after_expiry(self):
        fixture = control_fixture.CampaignControlTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        campaign_api = assets.StoreAPI()
        campaign_api.sibling = [self.api.release]
        tag = "ci-candidate-31-2"
        self.enterContext(patch.object(assets, "TAG", tag))
        self.enterContext(patch.object(assets, "REF", "refs/tags/" + tag))

        def include_working_release(method, path, result):
            if path.endswith("releases?per_page=100") and campaign_api.release:
                return result + [campaign_api.release.copy()]
            return result

        self.api.hook = include_working_release
        options = dict(run_owner=fixture.run, source=fixture.source)
        callback = self.writer(**options)
        public, storage = handoff.publish(
            campaign_api,
            key=control_fixture.KEY,
            owner=fixture.owner,
            reports=fixture.reports,
            origin=fixture.origin,
            packets=fixture.packets,
            checkpoint=callback,
        )
        self.assertEqual(len(self.api.uploads), 8)
        with patch("time.time", return_value=storage["expires_at"] + 86400):
            recovered = self.read(**options)
            checkpoint = recovered["checkpoint"]
            self.assertEqual(checkpoint["storage"], storage)
            self.assertEqual(checkpoint["issuer"]["public"], public)
            blob = campaign_api.contents[storage["assets"]["producer-control"]["id"]]
            self.assertTrue(
                control.verify_retained_control(
                    blob,
                    checkpoint,
                    key=control_fixture.KEY,
                    run_owner=fixture.run,
                    source=fixture.source,
                )
            )

    def test_known_aes_key_cannot_replace_or_transplant_a_signed_record(self):
        # Re-encrypt with a valid tag; verification must still enforce the independent Ed25519 pin
        # and the signed binding even when the encryption key is available to a reader.
        self.append(1)
        bind = dict(journal=PIN, run_owner=OWNER, source=SOURCE, trusted_public=self.public)
        header = dict(binding=bind, step=1, previous=None)
        original = self.api.data[1000]
        magic = b"MLSJOURNAL\x01"
        offset = len(magic) + 12
        aad = magic + canonical(header)
        cipher = journal._cipher(self.inputs["key"])
        signed = decode(cipher.decrypt(original[len(magic) : offset], original[offset:], aad))
        body = signing.verify(signed, journal.KIND, self.public)
        for i, forged in enumerate(
            (
                signing.sign(body, journal.KIND, self.root / "control.pem"),
                signing.sign(body | {"step": True}, journal.KIND, self.path),
                signing.sign(
                    body | {"binding": bind | {"journal": PIN | {"release_id": 701}}},
                    journal.KIND,
                    self.path,
                ),
            ),
            start=1,
        ):
            nonce = i.to_bytes(12, "big")
            raw = magic + nonce + cipher.encrypt(nonce, canonical(forged), aad)
            self.api.data[1000] = raw
            self.api.rows[0].update(digest="sha256:" + digest(raw), size=len(raw))
            with self.subTest(i=i), self.assertRaises(Rejected):
                self.read(allow_partial=True)

    def test_wrong_upload_metadata_or_failed_readback_never_allows_next_callback(self):
        for failure in ("upload-id", "upload-pin", "direct-metadata", "truncated", "after-read"):
            self.api = JournalAPI()
            write = self.writer()

            def fault(method, path, result):
                if method == "UPLOAD" and failure == "upload-id":
                    return result | {"id": 2000}
                if method == "UPLOAD" and failure == "upload-pin":
                    return result | {"digest": "sha256:" + "a" * 64}
                if (
                    path.endswith("/releases/assets/1000")
                    and method == "GET"
                    and failure == "direct-metadata"
                ):
                    return result | {"id": 2000}
                if method == "DOWNLOAD":
                    if failure == "truncated":
                        return result[:-1]
                    if failure == "after-read":
                        self.api.release.update(target_commitish="c" * 40)
                return result

            self.api.hook = fault
            with self.subTest(failure=failure), self.assertRaises(Rejected):
                write(self.checkpoints[0])
            with self.assertRaises(Rejected):
                write(self.checkpoints[1])
            self.assertEqual(len(self.api.uploads), 1)

    def test_same_ciphertext_recreated_under_new_numeric_id_breaks_successor_link(self):
        self.append()
        self.api.rows[4]["id"] = 2000
        self.api.data[2000] = self.api.data.pop(1004)
        with self.assertRaises(Rejected):
            self.read()

    def test_rotated_signing_key_refuses_before_second_upload(self):
        write, _ = self.append(1)
        self.path.write_bytes((self.root / "control.pem").read_bytes())
        with self.assertRaises(Rejected):
            write(self.checkpoints[1])
        self.assertEqual(len(self.api.uploads), 1)

    def test_operator_pins_key_shape_and_bounds_refuse(self):
        for kw in (
            dict(journal=PIN | {"repository_id": 1}),
            dict(journal=PIN | {"release_id": True}),
            dict(journal=PIN | {"name": "ci-candidate-123-1"}),
            dict(journal=PIN | {"target_commitish": "main"}),
            dict(key=b"short"),
            dict(trusted_public="***"),
            dict(trusted_public="A" * 44),
        ):
            with self.subTest(kw=list(kw)), self.assertRaises(Rejected):
                self.writer(**kw)
        self.api.others = [
            dict(id=i + 900, name=f"release-{i}", tag_name=f"r-{i}") for i in range(99)
        ]
        with self.assertRaises(Rejected):
            self.writer()
        self.assertFalse(self.api.uploads)

    def test_operator_namespace_does_not_adopt_unrelated_or_superseded_entries(self):
        self.api.others = [dict(id=701, tag_name="other", name="Unrelated release")]
        write, tips = self.append(1)
        self.api.rows[0]["name"] = "checkpoint-123-2-01.bin"
        with self.assertRaises(Rejected):
            write(self.checkpoints[1])
        with self.assertRaises(Rejected):
            self.read(expected_tip=tips[0], allow_partial=True)
        self.assertEqual(len(self.api.uploads), 1)


if __name__ == "__main__":
    unittest.main()
