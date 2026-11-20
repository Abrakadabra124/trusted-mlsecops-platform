"""Offline campaign composition with real frozen readers, signed fixtures and AES-GCM."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import ci_transfer, signing
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, write_json
from scripts import candidate_lineage_qualification as lineage
from scripts import ci_campaign_producer as producer
from scripts import ci_upstream_transfer_qualification as upstream_fixture
from scripts import frozen_candidate_transfer as transfer

KEY = bytes(range(32))  # Public test vector.
ENV = dict(
    GITHUB_REPOSITORY=ci_transfer.REPOSITORY,
    GITHUB_RUN_ID="123456",
    GITHUB_RUN_ATTEMPT="1",
    GITHUB_JOB="candidate",
)
SOURCE = dict(source_revision="a" * 40, source_fingerprint="b" * 64, image_id="sha256:" + "c" * 64)


class ProducerCase(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, ENV))
        self.enterContext(patch.object(producer, "hosted"))
        self.enterContext(patch.object(producer.storage_bootstrap, "validate"))

    def prepare(self, key=KEY):
        return producer.prepare(self.root, self.state, key=key)


class Refusals(ProducerCase):
    def setUp(self):
        super().setUp()
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / ".runtime"
        self.state.mkdir()
        self.enterContext(patch.object(producer, "source", return_value=SOURCE))
        self.propose = self.enterContext(patch.object(producer.release_native, "qualify"))

    def test_invalid_external_key_fails_before_creating_authority(self):
        for key in (None, b"", b"a" * 31, bytearray(KEY), "a" * 32):
            with self.subTest(key_type=type(key)), self.assertRaises(Rejected):
                self.prepare(key)
        self.propose.assert_not_called()
        self.assertEqual(list(self.state.iterdir()), [])

    def test_foreign_run_fails_before_proposal(self):
        with patch.dict(os.environ, GITHUB_REPOSITORY="another/repo"), self.assertRaises(Rejected):
            self.prepare()
        self.propose.assert_not_called()

    def test_existing_proposal_freeze_or_campaign_is_preserved(self):
        for name in (transfer.delivery.PROPOSAL, transfer.RECEIPT, "release-proposals/old/report"):
            with self.subTest(name=name):
                path = self.state / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"previous attempt")
                with self.assertRaises(Rejected):
                    self.prepare()
                self.assertEqual(path.read_bytes(), b"previous attempt")
                self.propose.assert_not_called()
                path.unlink()

    def test_overlapping_call_and_retry_after_interruption_cannot_repropose(self):
        def interrupted(*args):
            with self.assertRaises(Rejected):
                self.prepare()
            raise InterruptedError("proposal may already have reached storage")

        self.propose.side_effect = interrupted
        with self.assertRaises(InterruptedError):
            self.prepare()
        with self.assertRaises(Rejected):
            self.prepare()
        self.propose.assert_called_once()

    def test_another_writer_claiming_after_preflight_wins_exclusively(self):
        check = producer.require_unproposed

        def competing_claim(state):
            check(state)
            (state / producer.CLAIM).mkdir()

        with (
            patch.object(producer, "require_unproposed", competing_claim),
            self.assertRaises(Rejected),
        ):
            self.prepare()
        self.propose.assert_not_called()

    def test_proposal_changed_during_write_refuses_before_freeze(self):
        self.propose.return_value = dict(status="pass", source=SOURCE, source_dirty=False)
        with (
            patch.object(producer, "write_json", lambda path, value: path.write_bytes(b"other")),
            self.assertRaises(Rejected),
        ):
            (self.state / "evidence").mkdir()
            self.prepare()
        self.assertFalse((self.state / transfer.RECEIPT).exists())

    def test_dirty_failed_or_foreign_proposal_cannot_freeze(self):
        valid = dict(status="pass", source=SOURCE, source_dirty=False)
        for change in (
            dict(source_dirty=0),
            dict(status="fail"),
            dict(source=SOURCE | {"image_id": "foreign"}),
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                self.state = Path(directory)
                self.propose.return_value = valid | change
                with self.assertRaises(Rejected):
                    self.prepare()
                self.assertFalse((self.state / transfer.RECEIPT).exists())


class PacketTests(ProducerCase):
    @classmethod
    def setUpClass(cls):
        upstream_fixture.UpstreamTransferTests.setUpClass()
        cls.addClassCleanup(upstream_fixture.UpstreamTransferTests.doClassCleanups)

    def setUp(self):
        super().setUp()
        self.content = canonical(
            [dict(entity_id=1000 + i, features=[0.5] * 6, label=i % 2) for i in range(32)]
        )
        self.sample = upstream_fixture.UpstreamTransferTests()
        with patch.object(
            lineage.CandidateLineageContracts,
            "split_contents",
            {"validation": self.content},
            create=True,
        ):
            self.sample.setUp()
        self.addCleanup(self.sample.doCleanups)
        self.root, self.state = self.sample.root, self.sample.state
        fx = self.sample.fx
        campaign = fx.verified["manifest"]["release_id"]
        self.proposal = fx.proposal | dict(campaign_id=campaign)
        (self.state / transfer.delivery.PROPOSAL).unlink()
        (self.state / transfer.RECEIPT).unlink()
        self.source = self.enterContext(patch.object(producer, "source", return_value=fx.source))
        capture = producer.m18_delivery_freeze
        self.enterContext(patch.object(capture, "source", return_value=fx.source))
        self.enterContext(patch.object(capture.release_bundle, "load", return_value=fx.package))
        self.capture = self.enterContext(patch.object(capture, "capture", wraps=capture.capture))

        def propose(root, state, image):
            write_json(
                state / "release-proposals" / campaign / "policy-envelope.json",
                fx.release.policy_envelope,
            )
            return self.proposal

        self.propose = self.enterContext(
            patch.object(producer.release_native, "qualify", side_effect=propose)
        )
        self.fetch = self.enterContext(
            patch.object(producer.storage, "get", return_value=self.content)
        )

    def test_same_original_archive_in_both_phases_and_one_validation_fetch(self):
        result = self.prepare()
        self.assertEqual(result.keys(), {"owner", "reports", "sealed"})
        owner, packets = result["owner"], result["sealed"]
        self.assertEqual(owner["expected"], self.sample.owner["expected"])
        self.assertEqual(owner["run_owner"], self.sample.owner["run_owner"])
        self.assertEqual(result["reports"], self.sample.reports)
        self.assertEqual(owner["freeze_pin"], digest(bounded_read(self.state / transfer.RECEIPT)))
        self.capture.assert_called_once()
        self.fetch.assert_called_once_with(
            self.state.resolve() / "storage-clients/publisher", "validation", digest(self.content)
        )
        phases = {
            "candidate-shared": "M11-M12",
            "candidate-serving": "M13",
            "upstream-serving": "upstream-M13",
            "validation-serving": "validation-M13",
        }
        self.assertEqual(packets.keys(), phases.keys())
        plaintext = {}
        for name, phase in phases.items():
            packet = packets[name]
            context = packet["context"]
            self.assertEqual(context["phase"], phase)
            self.assertEqual(context["proposal_sha256"], self.proposal["proposal_reference"])
            self.assertFalse(packet["release_ready"])
            plaintext[name] = ci_transfer.open(
                packet["envelope"],
                key=KEY,
                expected_context=context,
                expected_ciphertext_sha256=packet["ciphertext_sha256"],
            )
        self.assertEqual(plaintext["candidate-shared"], plaintext["candidate-serving"])
        receipts = decode(plaintext["upstream-serving"])
        self.assertEqual((receipts["authority"], receipts["reports"]), (owner, self.sample.reports))
        validation = decode(plaintext["validation-serving"])
        self.assertEqual(validation["authority"], owner)
        self.assertEqual(signing.decode64(validation["validation"]), self.content)
        self.assertEqual(
            packets["candidate-shared"]["manifest_sha256"],
            packets["candidate-serving"]["manifest_sha256"],
        )
        for name in ("candidate-shared", "candidate-serving"):
            manifest, _ = transfer.unpack(plaintext[name], packets[name]["manifest_sha256"])
            self.assertEqual(manifest["freeze_sha256"], owner["freeze_pin"])
            self.assertEqual(manifest["run_owner"], owner["run_owner"])
        with self.assertRaises(Rejected):
            self.prepare()
        self.capture.assert_called_once()
        self.propose.assert_called_once()

    def test_wrong_storage_bytes_refuse_without_seed_reconstruction(self):
        self.fetch.return_value = canonical([])
        with self.assertRaises(Rejected):
            self.prepare()
        self.fetch.assert_called_once()
        with self.assertRaises(Rejected):
            self.prepare()
        self.capture.assert_called_once()

    def test_different_candidate_archive_between_phases_refuses_handoff(self):
        seal = producer.bridge.seal

        def substituted(*args, **kwargs):
            packet = seal(*args, **kwargs)
            if kwargs["phase"] == "M13":
                packet["manifest_sha256"] = "0" * 64
            return packet

        with patch.object(producer.bridge, "seal", substituted), self.assertRaises(Rejected):
            self.prepare()

    def test_changed_source_after_sealing_refuses_batch(self):
        self.source.side_effect = [self.sample.fx.source, SOURCE]
        with self.assertRaises(Rejected):
            self.prepare()
        self.fetch.assert_called_once()

    def test_fractional_loss_of_last_reserved_second_after_last_packet_refuses_batch(self):
        expires = self.sample.fx.values["proposal_expires_at"]
        original = producer.validation.seal

        completed = []

        def last_packet(*args, **kwargs):
            value = original(*args, **kwargs)
            completed.append(value["context"]["phase"])
            self.enterContext(
                patch.object(time, "time_ns", return_value=(expires - 600) * 10**9 + 1)
            )
            return value

        self.sample.clock = expires - 600
        with patch.object(producer.validation, "seal", last_packet), self.assertRaises(Rejected):
            self.prepare()
        self.fetch.assert_called_once()
        self.assertEqual(completed, ["validation-M13"])


if __name__ == "__main__":
    unittest.main()
