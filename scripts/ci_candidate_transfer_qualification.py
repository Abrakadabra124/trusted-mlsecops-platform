"""Offline bridge contracts: real signed controlled fixtures and real AESGCM only."""

import copy
import inspect
import io
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import ci_transfer, signing
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from scripts import ci_candidate_transfer as bridge
from scripts import frozen_candidate_transfer as transfer
from scripts import frozen_candidate_transfer_qualification as fixtures

KEY = bytes(range(32))  # Public deterministic test vector, never a deployment key.


class CandidateTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.fixtures.FinalEvidenceContracts.setUpClass()
        cls.addClassCleanup(fixtures.fixtures.FinalEvidenceContracts.tearDownClass)

    def setUp(self):
        self.fixture = fixtures.TransferTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.state = self.fixture.root, self.fixture.state
        self.authority = copy.deepcopy(self.fixture.owner)
        self.authority["run_owner"]["repository"] = ci_transfer.REPOSITORY
        self.clock = self.fixture.clock
        self.time_patch = patch.object(time, "time_ns", side_effect=lambda: self.clock * 10**9)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)
        self.phase = "M11-M12"

    def seal(self, **changes):
        return bridge.seal(
            self.root,
            self.state,
            **(dict(key=KEY, phase=self.phase, **self.authority) | changes),
        )

    def materialize(self, result, **changes):
        arguments = (
            dict(
                key=KEY,
                phase=self.phase,
                **self.authority,
                expected_context=result["context"],
                ciphertext_pin=result["ciphertext_sha256"],
                manifest_pin=result["manifest_sha256"],
            )
            | changes
        )
        return bridge.materialize(self.root, result["envelope"], **arguments)

    def verify(self, result, **changes):
        with self.materialize(result, **changes) as (_, summary):
            return summary

    def no_temporary_state(self):
        self.assertFalse(list((self.root / ".runtime/ci-candidate-transfers").glob("*")))
        parent = self.root / ".runtime/frozen-transfers"
        self.assertFalse(list(parent.glob("reader-*")))
        self.assertFalse(list(parent.glob("verify-*")))

    def archive(self, result):
        return ci_transfer.open(
            result["envelope"],
            key=KEY,
            expected_context=result["context"],
            expected_ciphertext_sha256=result["ciphertext_sha256"],
        )

    def reencrypt(self, result, raw, **context_changes):
        ctx = result["context"] | dict(payload_sha256=digest(raw)) | context_changes
        envelope = ci_transfer.seal(raw, key=KEY, context=ctx)
        return result | dict(envelope=envelope, context=ctx, ciphertext_sha256=digest(envelope))

    def test_wrong_key_pin_and_manifest_pin_block_materialization(self):
        result = self.seal()
        for changes in (
            dict(key=b"x" * 32),
            dict(ciphertext_pin="0" * 64),
            dict(manifest_pin="0" * 64),
            dict(manifest_pin=None),
        ):
            with self.subTest(fields=tuple(changes)), self.assertRaises(Rejected):
                self.verify(result, **changes)
            self.no_temporary_state()

    def test_all_three_receiver_expectations_are_required(self):
        result = self.seal()
        arguments = dict(
            key=KEY,
            phase=self.phase,
            **self.authority,
            expected_context=result["context"],
            ciphertext_pin=result["ciphertext_sha256"],
            manifest_pin=result["manifest_sha256"],
        )
        for field in ("expected_context", "ciphertext_pin", "manifest_pin"):
            reduced = arguments.copy()
            del reduced[field]
            with self.subTest(field=field), self.assertRaises(TypeError):
                with bridge.materialize(self.root, result["envelope"], **reduced):
                    self.fail("missing independent expectation accepted")

    def test_external_owner_attempt_candidate_source_and_phase_mismatch(self):
        result = self.seal()
        for field in transfer.IDENTITY:
            value = "0" * (40 if field == "source_revision" else 64)
            if field == "image_id":
                value = "sha256:" + value
            changed = self.authority["expected"] | {field: value}
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify(result, expected=changed)
        for field, value in (
            ("run_id", 123457),
            ("run_attempt", 2),
            ("repository", "other/platform"),
            ("producer_job", "other"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify(result, run_owner=self.authority["run_owner"] | {field: value})
        with self.assertRaises(Rejected):
            self.verify(result, phase="M13")
        self.no_temporary_state()

    def test_frozen_authority_is_not_recovered_from_the_archive(self):
        result = self.seal()
        for changes in (
            dict(freeze_pin="0" * 64),
            dict(freeze=self.authority["freeze"] | {transfer.delivery.PROPOSAL: "0" * 64}),
            dict(freeze=None),
            dict(expected=None),
            dict(run_owner=None),
        ):
            with self.subTest(fields=tuple(changes)), self.assertRaises(Rejected):
                self.verify(result, **changes)
        self.no_temporary_state()

    def test_context_mutations_are_not_accepted_from_encrypted_metadata(self):
        result = self.seal()
        for field, value in (
            ("candidate_sha256", "a" * 64),
            ("run_attempt", 2),
            ("phase", "M13"),
            ("purpose", "evidence"),
            ("payload_sha256", "a" * 64),
            ("extra", "ignored"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify(result, expected_context=result["context"] | {field: value})
        for ctx in (None, [], {}):
            with self.assertRaises(Rejected):
                self.verify(result, expected_context=ctx)
        self.no_temporary_state()

    def test_ciphertext_mutation_and_repinning_cannot_bypass_aes(self):
        result = self.seal()
        altered = bytearray(result["envelope"])
        altered[-1] ^= 1
        forged = result | dict(envelope=bytes(altered))
        with self.assertRaises(Rejected):
            self.verify(forged)
        with self.assertRaises(Rejected):
            self.verify(forged, ciphertext_pin=digest(bytes(altered)))
        self.no_temporary_state()

    def test_bad_archive_and_rehashed_inner_file_are_rejected(self):
        result = self.seal()
        with self.assertRaises(Rejected):
            self.verify(self.reencrypt(result, b"not a zip"))
        manifest, files = transfer.unpack(self.archive(result), result["manifest_sha256"])
        files[transfer.CAS + self.authority["expected"]["model_sha256"]] += b"mutation"
        manifest["files"] = transfer.inventory(files)
        manifest_raw = canonical(manifest) + b"\n"
        forged = self.reencrypt(result, transfer.pack(manifest_raw, files))
        forged["manifest_sha256"] = digest(manifest_raw)
        with self.assertRaises(Rejected):
            self.verify(forged)
        self.no_temporary_state()

    def test_real_signature_failure_survives_repinning_all_outer_layers(self):
        result = self.seal()
        manifest, files = transfer.unpack(self.archive(result), result["manifest_sha256"])
        authority = copy.deepcopy(self.authority)
        old = authority["expected"]["proposal_reference"]
        envelope = decode(files.pop(transfer.CAS + old))
        envelope["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        raw = canonical(envelope)
        proposal_pin = digest(raw)
        files[transfer.CAS + proposal_pin] = raw
        authority["expected"]["proposal_reference"] = proposal_pin
        proposal = decode(files[transfer.delivery.PROPOSAL])
        proposal["proposal_reference"] = proposal_pin
        files[transfer.delivery.PROPOSAL] = canonical(proposal) + b"\n"
        authority["freeze"][transfer.delivery.PROPOSAL] = digest(files[transfer.delivery.PROPOSAL])
        index = decode(files[transfer.RECEIPT])
        index["freeze"] = authority["freeze"]
        files[transfer.RECEIPT] = canonical(index) + b"\n"
        authority["freeze_pin"] = digest(files[transfer.RECEIPT])
        manifest.update(
            identity=authority["expected"],
            freeze=authority["freeze"],
            freeze_sha256=authority["freeze_pin"],
            files=transfer.inventory(files),
        )
        manifest_raw = canonical(manifest) + b"\n"
        forged = self.reencrypt(
            result, transfer.pack(manifest_raw, files), proposal_sha256=proposal_pin
        )
        forged["manifest_sha256"] = digest(manifest_raw)
        with (
            self.assertRaises(Rejected),
            patch.object(
                transfer.release_bundle, "index", wraps=transfer.release_bundle.index
            ) as signed_reader,
        ):
            self.verify(forged, **authority)
        self.assertTrue(signed_reader.called)
        self.no_temporary_state()

    def test_expiry_less_than_600_seconds_is_rejected_before_and_after_materialization(self):
        result = self.seal()
        original = transfer.materialize
        for remaining in (599, 0):
            self.clock = self.fixture.fx.values["proposal_expires_at"] - remaining
            with self.subTest(remaining=remaining), self.assertRaises(Rejected):
                self.verify(result)
        self.clock = self.fixture.clock

        @contextmanager
        def delayed(*args, **kwargs):
            with original(*args, **kwargs) as item:
                self.clock = self.fixture.fx.values["proposal_expires_at"] - 599
                yield item

        with patch.object(transfer, "materialize", side_effect=delayed):
            with self.assertRaises(Rejected):
                self.verify(result)
        self.no_temporary_state()

    def test_sender_rechecks_current_window_after_export_and_encryption(self):
        original_export, original_seal = transfer.export, ci_transfer.seal
        for target, original in (("export", original_export), ("seal", original_seal)):
            self.clock = self.fixture.clock

            def delayed(*args, **kwargs):
                value = original(*args, **kwargs)
                self.clock = self.fixture.fx.values["proposal_expires_at"] - 599
                return value

            module = transfer if target == "export" else ci_transfer
            with patch.object(module, target, side_effect=delayed), self.assertRaises(Rejected):
                self.seal()
        self.no_temporary_state()

    def test_sender_checks_window_after_hashing_final_ciphertext(self):
        original = bridge.digest

        def delayed(raw):
            value = original(raw)
            if raw.startswith(ci_transfer.MAGIC):
                self.clock = self.fixture.fx.values["proposal_expires_at"] - 599
            return value

        with patch.object(bridge, "digest", side_effect=delayed), self.assertRaises(Rejected):
            self.seal()

    def test_reencrypted_transport_cannot_extend_or_change_original_expiry_rule(self):
        self.clock += 10  # Leave room below AES's 1800-second bound to isolate the inner expiry.
        result = self.seal()
        raw = self.archive(result)
        for delta in (-1, 1):
            forged = self.reencrypt(result, raw, expires_at=result["context"]["expires_at"] + delta)
            with self.assertRaises(Rejected):
                self.verify(forged)
        self.no_temporary_state()

    def test_source_clean_failure_before_and_after_materialization(self):
        result = self.seal()
        self.fixture.clean.side_effect = Rejected("controlled source change")
        with self.assertRaises(Rejected):
            self.verify(result)
        with self.assertRaises(Rejected):
            self.seal()
        self.fixture.clean.side_effect = None
        original = transfer.materialize

        @contextmanager
        def changed(*args, **kwargs):
            with original(*args, **kwargs) as item:
                self.fixture.clean.side_effect = Rejected("controlled late source change")
                yield item

        with (
            patch.object(transfer, "materialize", side_effect=changed),
            self.assertRaises(Rejected),
        ):
            self.verify(result)
        self.no_temporary_state()

    def test_bad_key_phase_and_authority_fail_before_export(self):
        with patch.object(transfer, "export") as exporter:
            for changes in (
                dict(key=None),
                dict(key=b"x" * 31),
                dict(key=bytearray(KEY)),
                dict(phase="unknown"),
                dict(phase=[]),
                dict(freeze=None),
                dict(expected=None),
                dict(run_owner=None),
            ):
                with self.assertRaises(Rejected):
                    self.seal(**changes)
            exporter.assert_not_called()

    def test_archive_readback_mutation_is_rejected_before_encryption(self):
        original = transfer.export

        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            Path(result["path"]).write_bytes(b"changed export")
            return result

        with patch.object(transfer, "export", side_effect=changed), self.assertRaises(Rejected):
            self.seal()

    def test_owned_staging_cleans_up_on_write_failure(self):
        result = self.seal()
        with patch.object(bridge, "atomic_write", side_effect=OSError("controlled write failure")):
            with self.assertRaises(Rejected):
                self.verify(result)
        self.no_temporary_state()

    def test_inner_archive_limit_still_blocks_before_plaintext_staging(self):
        result = self.seal()
        size = len(self.archive(result))
        with (
            patch.object(transfer, "MAX_ARCHIVE", size - 1),
            patch.object(bridge, "atomic_write") as writer,
        ):
            with self.assertRaises(Rejected):
                self.verify(result)
            writer.assert_not_called()
        self.no_temporary_state()

    def test_exact_archive_roundtrip_keeps_original_bytes_and_identities(self):
        result = self.seal()
        raw = self.archive(result)
        original = bounded_read(
            self.root / ".runtime/frozen-transfers" / (result["manifest_sha256"] + ".zip"),
            transfer.MAX_ARCHIVE,
        )
        self.assertEqual(raw, original)
        manifest, files = transfer.unpack(raw, result["manifest_sha256"])
        with self.materialize(result) as (view, summary):
            self.assertFalse(summary["release_ready"])
            self.assertEqual(summary["handling"], "private")
            self.assertEqual(summary["manifest_sha256"], result["manifest_sha256"])
            for name, data in files.items():
                self.assertEqual(bounded_read(view / name, transfer.MAX_ARCHIVE), data)
                self.assertEqual(bounded_read(self.state / name, transfer.MAX_ARCHIVE), data)
            self.assertEqual(manifest["identity"], self.authority["expected"])
        self.assertFalse(view.exists())
        self.no_temporary_state()
        self.assertTrue(self.fixture.clean.called)

    def test_caller_exception_propagates_and_owned_plaintext_is_removed(self):
        result = self.seal()
        with self.assertRaisesRegex(RuntimeError, "consumer stopped"):
            with self.materialize(result) as (view, _):
                raise RuntimeError("consumer stopped")
        self.assertFalse(view.exists())
        self.no_temporary_state()

    def test_repeated_seal_changes_nonce_only_not_original_proposal(self):
        first, second = self.seal(), self.seal()
        self.assertNotEqual(first["envelope"], second["envelope"])
        self.assertNotEqual(first["ciphertext_sha256"], second["ciphertext_sha256"])
        self.assertEqual(first["context"], second["context"])
        self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
        self.assertEqual(
            first["context"]["candidate_sha256"], self.authority["expected"]["candidate_reference"]
        )
        self.assertEqual(
            first["context"]["proposal_sha256"], self.authority["expected"]["proposal_reference"]
        )
        self.assertEqual(
            first["context"]["expires_at"],
            min(self.fixture.fx.values["proposal_expires_at"], self.clock + 1800),
        )

    def test_exact_600_second_inner_window_is_accepted_without_extension(self):
        self.clock = self.fixture.fx.values["proposal_expires_at"] - 600
        result = self.seal()
        self.assertEqual(result["context"]["expires_at"] - self.clock, 600)
        self.verify(result)

    def test_fractional_second_cannot_loosen_the_600_second_minimum(self):
        result = self.seal()
        self.clock = self.fixture.fx.values["proposal_expires_at"] - 600
        with patch.object(time, "time_ns", return_value=self.clock * 10**9 + 1):
            with self.assertRaises(Rejected):
                self.seal()
            with self.assertRaises(Rejected):
                self.verify(result)

    def test_no_clock_cli_network_or_authority_minting_and_no_output(self):
        self.assertNotIn("clock", inspect.signature(bridge.seal).parameters)
        self.assertNotIn("clock", inspect.signature(bridge.materialize).parameters)
        output, errors = io.StringIO(), io.StringIO()
        with (
            redirect_stdout(output),
            redirect_stderr(errors),
            patch.object(signing, "create_key", side_effect=AssertionError("minted key")),
            patch.object(signing, "sign", side_effect=AssertionError("new signature")),
            patch("socket.socket", side_effect=AssertionError("network")),
        ):
            self.verify(self.seal())
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")
        self.time_patch.stop()
        self.assertLessEqual(abs(bridge._now() - int(time.time())), 1)


if __name__ == "__main__":
    unittest.main()
