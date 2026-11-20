"""Offline qualification of the signed journal-tip.bin wire format."""

import secrets
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import ci_campaign_journal as journal
from scripts import ci_campaign_journal_qualification as fixture
from scripts import ci_tip_witness as witness

MAGIC = b"MLSTIP\x01"
KIND = "campaign-journal-tip"
TIP = dict(step=8, asset_id=1007, sha256="a" * 64)
ORIGIN = fixture.PIN | {"name": "ci-origin-123-1", "release_id": 701}


class TipWitnessTests(unittest.TestCase):
    def setUp(self):
        folder = Path(self.enterContext(TemporaryDirectory(dir=Path.cwd())))
        self.signer = folder / "journal.pem"
        self.public = signing.create_key(self.signer)
        self.other = folder / "other.pem"
        self.other_public = signing.create_key(self.other)
        self.key = secrets.token_bytes(32)
        self.inputs = dict(
            journal_release=fixture.PIN,
            origin_release=ORIGIN,
            run_owner=fixture.OWNER,
            source=fixture.SOURCE,
            trusted_public=self.public,
            key=self.key,
        )
        self.binding = dict(
            journal=fixture.PIN,
            origin=ORIGIN,
            run_owner=fixture.OWNER,
            source=fixture.SOURCE,
            trusted_public=self.public,
        )
        self.aad = MAGIC + canonical(self.binding)
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=MAGIC).derive(self.key)
        self.cipher = AESGCM(derived)

    def seal(self, tip=TIP, **changes):
        return witness.seal(tip, key_path=self.signer, **(self.inputs | changes))

    def read(self, raw, **changes):
        return witness.open_witness(raw, **(self.inputs | changes))

    def wrap(self, plain):
        nonce = secrets.token_bytes(12)
        return MAGIC + nonce + self.cipher.encrypt(nonce, plain, self.aad)

    def test_actual_publisher_tip_survives_without_the_signer(self):
        remote = fixture.JournalAPI()
        params = dict(
            journal=fixture.PIN,
            run_owner=fixture.OWNER,
            source=fixture.SOURCE,
            trusted_public=self.public,
            key=self.key,
        )
        append = journal.publisher(remote, key_path=self.signer, **params)
        tips = [append(row) for row in fixture.workflow_checkpoints(self.other_public)]
        raw = self.seal(tips[-1])
        self.assertNotEqual(raw, self.seal(tips[-1]))
        self.signer.unlink()
        tip = self.read(raw)
        self.assertEqual(tip, dict(step=8, asset_id=1007, sha256=digest(remote.data[1007])))
        self.assertTrue(journal.recover(remote, expected_tip=tip, **params)["complete"])
        self.assertNotIn(tip["sha256"].encode(), raw)
        with self.assertRaises(Rejected):
            self.seal(tips[-2])

    def test_wire_format_signature_and_key_domains(self):
        raw = self.seal()
        self.assertTrue(raw.startswith(MAGIC))
        self.assertLessEqual(len(raw), 16384)
        offset = len(MAGIC) + 12
        nonce, ciphertext = raw[len(MAGIC) : offset], raw[offset:]
        with self.assertRaises(InvalidTag):
            journal._cipher(self.key).decrypt(nonce, ciphertext, self.aad)
        plain = self.cipher.decrypt(nonce, ciphertext, self.aad)
        signed = decode(plain)
        self.assertEqual(plain, canonical(signed))
        record = dict(binding=self.binding, tip=TIP)
        self.assertEqual(signing.verify(signed, KIND, self.public), record)
        self.assertEqual(signing.decode64(signed["payload"]), canonical(record))
        with self.assertRaises(Rejected):
            signing.verify(signed, journal.KIND, self.public)

    def test_only_exact_full_tip_is_accepted_on_either_side(self):
        for bad in (
            None,
            TIP | {"step": 7},
            TIP | {"step": 8.0},
            TIP | {"asset_id": True},
            TIP | {"asset_id": 0},
            TIP | {"asset_id": 2**53},
            TIP | {"sha256": "A" * 64},
            TIP | {"sha256": "a" * 63},
            TIP | {"extra": 1},
            {"step": 8, "sha256": TIP["sha256"]},
        ):
            with self.subTest(tip=bad):
                with self.assertRaises(Rejected):
                    self.seal(bad)
                signed = signing.sign(dict(binding=self.binding, tip=bad), KIND, self.signer)
                with self.assertRaises(Rejected):
                    self.read(self.wrap(canonical(signed)))

    def test_invalid_descriptors_owner_and_keys_are_refused_even_at_seal(self):
        for changes in (
            dict(origin_release=ORIGIN | {"release_id": fixture.PIN["release_id"]}),
            dict(origin_release=ORIGIN | {"repository_id": 1}),
            dict(origin_release=ORIGIN | {"release_id": True}),
            dict(origin_release=ORIGIN | {"name": "ci-origin-123-2"}),
            dict(origin_release=ORIGIN | {"target_commitish": "main"}),
            dict(origin_release=ORIGIN | {"extra": 1}),
            dict(journal_release=ORIGIN, origin_release=fixture.PIN),
            dict(journal_release=fixture.PIN | {"repository_id": 1}),
            dict(run_owner=fixture.OWNER | {"producer_job": "shared"}),
            dict(source=fixture.SOURCE | {"source_revision": "main"}),
            dict(trusted_public=self.other_public),
            dict(trusted_public="?"),
            dict(key=self.key[:-1]),
            dict(key=bytearray(self.key)),
        ):
            with self.subTest(fields=tuple(changes)), self.assertRaises(Rejected):
                self.seal(**changes)

    def test_reader_requires_independent_pins_for_the_same_attempt(self):
        raw = self.seal()
        for changes in (
            dict(journal_release=fixture.PIN | {"name": "ci-journal-other"}),
            dict(journal_release=fixture.PIN | {"release_id": 777}),
            dict(journal_release=fixture.PIN | {"target_commitish": "7" * 40}),
            dict(origin_release=ORIGIN | {"release_id": 777}),
            dict(origin_release=ORIGIN | {"target_commitish": "7" * 40}),
            dict(
                run_owner=fixture.OWNER | {"run_attempt": 2},
                origin_release=ORIGIN | {"name": "ci-origin-123-2"},
            ),
            dict(
                run_owner=fixture.OWNER | {"run_id": 124},
                origin_release=ORIGIN | {"name": "ci-origin-124-1"},
            ),
            dict(source=fixture.SOURCE | {"source_revision": "7" * 40}),
            dict(source=fixture.SOURCE | {"source_fingerprint": "7" * 64}),
            dict(source=fixture.SOURCE | {"image_id": "sha256:" + "7" * 64}),
            dict(run_owner=fixture.OWNER | {"producer_job": "serving"}),
            dict(trusted_public=self.other_public),
            dict(key=secrets.token_bytes(32)),
        ):
            with self.subTest(fields=tuple(changes)), self.assertRaises(Rejected):
                self.read(raw, **changes)

    def test_tampering_truncation_and_size_limits(self):
        raw = self.seal()
        for bad in (
            None,
            bytearray(raw),
            b"",
            MAGIC + bytes(28),
            journal.MAGIC + raw[len(MAGIC) :],
            MAGIC + bytes([raw[len(MAGIC)] ^ 1]) + raw[len(MAGIC) + 1 :],
            raw[:-1],
            raw[:-1] + bytes([raw[-1] ^ 1]),
            raw + b"\x00",
            MAGIC.ljust(16385, b"x"),
        ):
            with self.assertRaises(Rejected):
                self.read(bad)
        with patch.object(witness, "LIMIT", len(raw) - 1), self.assertRaises(Rejected):
            self.seal()

    def test_transfer_key_cannot_authorize_altered_or_foreign_signed_material(self):
        record = dict(binding=self.binding, tip=TIP)
        signed = signing.sign(record, KIND, self.signer)
        changed = record | {"tip": TIP | {"asset_id": 1008}}
        for envelope in (
            signed | {"payload": signing.encode64(canonical(changed))},
            signing.sign(record, KIND, self.other),
            signing.sign(record, journal.KIND, self.signer),
            signing.sign(record | {"unknown": 1}, KIND, self.signer),
            signing.sign(
                record | {"binding": self.binding | {"origin": fixture.PIN}}, KIND, self.signer
            ),
            signed | {"extra": True},
        ):
            with self.assertRaises(Rejected):
                self.read(self.wrap(canonical(envelope)))

    def test_reject_noncanonical_signed_and_encrypted_json(self):
        record = dict(binding=self.binding, tip=TIP)
        signed = signing.sign(record, KIND, self.signer)
        noncanonical = canonical(record) + b" "
        private = signing.load_key(self.signer)
        signature = private.sign(signing.pae(signed["payloadType"], noncanonical))
        altered = signed | {
            "payload": signing.encode64(noncanonical),
            "signatures": [signed["signatures"][0] | {"sig": signing.encode64(signature)}],
        }
        # A 64-byte Ed25519 signature has four unused bits before its final "==".
        signature_text = signed["signatures"][0]["sig"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        alternate = alphabet[alphabet.index(signature_text[-3]) + 1]
        alias = signature_text[:-3] + alternate + "=="
        self.assertEqual(signing.decode64(alias), signing.decode64(signature_text))
        aliased = signed | {"signatures": [signed["signatures"][0] | {"sig": alias}]}
        for plain in (canonical(signed) + b"\n", canonical(altered), canonical(aliased)):
            with self.assertRaises(Rejected):
                self.read(self.wrap(plain))


if __name__ == "__main__":
    unittest.main()
