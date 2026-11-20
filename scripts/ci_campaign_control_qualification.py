"""Synthetic control transport with real envelope, signature and cross-attempt checks."""

import copy
import unittest
from unittest.mock import patch

from mlsecops import ci_transfer
from mlsecops.contracts import Rejected, digest
from scripts import ci_campaign_control as control
from scripts import ci_candidate_transfer as candidate
from scripts import frozen_candidate_transfer as transfer

KEY = bytes(range(32))
NOW = 1800000000


class CampaignControlTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("time.time_ns", return_value=NOW * 10**9))
        self.enterContext(patch("time.time", return_value=NOW))
        self.run = dict(
            repository=ci_transfer.REPOSITORY, run_id=31, run_attempt=2, producer_job="producer"
        )
        expected = dict.fromkeys(transfer.IDENTITY, "f" * 64)
        expected.update(source_revision="b" * 40, image_id="sha256:" + "c" * 64)
        self.source = {k: expected[k] for k in transfer.delivery.SOURCE}
        self.owner = dict(
            freeze_pin="a" * 64,
            freeze=dict.fromkeys(transfer.delivery.FILES, "b" * 64),
            expected=expected,
            run_owner=self.run,
        )
        self.origin = dict(workspace_id="a" * 32, container_id="b" * 64, offline_pin="c" * 64)
        self.reports = dict.fromkeys(("M02", "M03", "M07"), "a" * 64)
        self.packets = {}
        for name, phase in control.PHASES.items():
            raw = b"private controlled plaintext: " + (
                b"original" if name.startswith("candidate-") else name.encode()
            )
            ctx = candidate._context(self.owner, phase, digest(raw), NOW - 1, NOW + 1600)
            encrypted = ci_transfer.seal(raw, key=KEY, context=ctx)
            self.packets[name] = dict(
                context=ctx,
                envelope=encrypted,
                ciphertext_sha256=digest(encrypted),
                handling="private",
                release_ready=False,
            )
            if name.startswith("candidate-"):
                self.packets[name]["manifest_sha256"] = "d" * 64

        self.storage = dict(
            schema_version=1,
            expected=self.run | {"source_revision": self.source["source_revision"]},
            repository_id=1465012664,
            tag="ci-candidate-31-2",
            private_head="c" * 40,
            release_id=23,
            issued_at=NOW - 1,
            expires_at=NOW - 1 + 1800,
            assets={
                name: dict(id=i, size=len(v["envelope"]), sha256=v["ciphertext_sha256"])
                for i, (name, v) in enumerate(self.packets.items(), start=901)
            },
        )

    def issue(self):
        return control.issue(
            origin=self.origin,
            storage=self.storage,
            owner=self.owner,
            reports=self.reports,
            packets=self.packets,
            key=KEY,
        )

    def read(self, blob, public, **overrides):
        values = dict(key=KEY, trusted_public=public, run_owner=self.run, source=self.source)
        return control.read(blob, **(values | overrides))

    def test_original_authority_and_both_consumers(self):
        blob, public = self.issue()
        record = self.read(blob, public)
        self.assertNotIn(self.owner["expected"]["candidate_reference"].encode(), blob)
        self.assertEqual(record["origin"], self.origin)
        self.assertEqual(record["owner"], self.owner)
        self.assertEqual(record["reports"], self.reports)
        for name, value in self.packets.items():
            packet = control.attach(record, name, value["envelope"])
            self.assertEqual(packet, value)
            self.assertTrue(
                ci_transfer.open(
                    packet["envelope"],
                    key=KEY,
                    expected_context=packet["context"],
                    expected_ciphertext_sha256=packet["ciphertext_sha256"],
                ).startswith(b"private")
            )

    def test_another_writer_knowing_aes_key_cannot_authorize_replacement(self):
        blob, original = self.issue()
        self.owner["freeze_pin"] = "f" * 64
        replacement, foreign = self.issue()
        self.assertNotEqual(original, foreign)
        with self.assertRaises(Rejected):
            self.read(replacement, original)
        with self.assertRaises(Rejected):
            self.read(blob, foreign)

    def test_reader_rejects_wrong_run_source_job_key_or_modified_bytes(self):
        blob, public = self.issue()
        for changes in (
            dict(run_owner=self.run | {"run_attempt": 3}),
            dict(run_owner=self.run | {"run_id": 32}),
            dict(run_owner=self.run | {"producer_job": "receiver"}),
            dict(run_owner=self.run | {"run_attempt": True}),
            dict(source=self.source | {"source_revision": "a" * 40}),
            dict(key=b"k" * 32),
            dict(key=b"wrong length"),
        ):
            with self.subTest(fields=list(changes)), self.assertRaises(Rejected):
                self.read(blob, public, **changes)
        for raw in (b"", blob[:-1], blob[:-1] + bytes([blob[-1] ^ 1]), b"Z" * 70000):
            with self.assertRaises(Rejected):
                self.read(raw, public)
        with patch("time.time_ns", return_value=(NOW + 1600) * 10**9), self.assertRaises(Rejected):
            self.read(blob, public)

    def test_producer_requires_the_exact_packet_set_and_same_candidate(self):
        for field, value in (
            ("context", self.packets["candidate-shared"]["context"]),
            ("release_ready", True),
            ("handling", "public"),
            ("envelope", b"bad"),
            ("ciphertext_sha256", "0" * 64),
            ("private_key", "private"),
            ("manifest_sha256", "bad"),
        ):
            bad = copy.deepcopy(self.packets)
            bad["candidate-serving"][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                control.issue(
                    origin=self.origin,
                    storage=self.storage,
                    owner=self.owner,
                    reports=self.reports,
                    packets=bad,
                    key=KEY,
                )
        for removed in self.packets:
            with self.assertRaises(Rejected):
                control.issue(
                    origin=self.origin,
                    storage=self.storage,
                    owner=self.owner,
                    reports=self.reports,
                    packets={k: v for k, v in self.packets.items() if k != removed},
                    key=KEY,
                )
        with self.assertRaises(Rejected):
            control.issue(
                origin=self.origin,
                storage=self.storage,
                owner=self.owner,
                reports=self.reports | {"other": "x"},
                packets=self.packets,
                key=KEY,
            )
        with self.assertRaises(Rejected):
            control.issue(
                origin=self.origin,
                storage=self.storage,
                owner=self.owner | {"freeze": None},
                reports=self.reports,
                packets=self.packets,
                key=KEY,
            )

    def test_attach_fails_before_passing_changed_or_foreign_ciphertext_to_reader(self):
        record = self.read(*self.issue())
        first = self.packets["candidate-shared"]["envelope"]
        for name, raw in (
            ("extra", first),
            ("candidate-serving", first),
            ("candidate-shared", first + b"a"),
            ("candidate-shared", bytes([first[0] ^ 1]) + first[1:]),
        ):
            with self.assertRaises(Rejected):
                control.attach(record, name, raw)

    def test_origin_requires_only_the_observed_producer_identities(self):
        for changes in (
            {"offline_pin": ""},
            {"container_id": "unowned"},
            {"workspace_id": 1},
            {"key": "extra"},
        ):
            original = self.origin
            self.origin = original | changes
            with self.assertRaises(Rejected):
                self.issue()
            self.origin = original

    def test_other_storage_attempt_or_asset_pin_refuses(self):
        for field, value in (("size", 104), ("sha256", "c" * 64)):
            row = self.storage["assets"]["candidate-serving"]
            old = row[field]
            row[field] = value
            with self.assertRaises(Rejected):
                self.issue()
            row[field] = old
        self.storage["expected"]["run_id"] += 1
        with self.assertRaises(Rejected):
            self.issue()

    def test_different_candidate_archive_or_manifest_refuses_even_with_matching_storage_pins(self):
        row = self.packets["candidate-serving"]
        original = row["manifest_sha256"]
        row["manifest_sha256"] = "a" * 64
        with self.assertRaises(Rejected):
            self.issue()
        row["manifest_sha256"] = original
        replacement = b"private controlled replacement"
        row["context"]["payload_sha256"] = digest(replacement)
        row["envelope"] = ci_transfer.seal(replacement, key=KEY, context=row["context"])
        row["ciphertext_sha256"] = digest(row["envelope"])
        self.storage["assets"]["candidate-serving"].update(
            size=len(row["envelope"]), sha256=row["ciphertext_sha256"]
        )
        with self.assertRaises(Rejected):
            self.issue()
