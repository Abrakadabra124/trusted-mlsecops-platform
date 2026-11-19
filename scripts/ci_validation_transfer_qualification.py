"""Private validation companion: signed controlled fixtures, real AES, no infrastructure."""

import copy
import io
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import ci_transfer, signing, storage
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from scripts import candidate_lineage_qualification as lineage
from scripts import ci_validation_transfer as companion
from scripts import frozen_candidate_transfer as transfer
from scripts import frozen_candidate_transfer_qualification as fixtures

KEY = bytes(range(32))  # Public test vector, not a deployment secret.


class ValidationTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.TransferTests.setUpClass()
        cls.addClassCleanup(fixtures.TransferTests.doClassCleanups)

    def setUp(self):
        self.rows = [
            {"entity_id": index + 1000, "features": [0.5] * 6, "label": index % 2}
            for index in range(32)
        ]
        self.content = canonical(self.rows)
        self.build(self.content)
        self.enterContext(patch.object(time, "time_ns", side_effect=lambda: self.clock * 10**9))
        self.phase = "M13"

    def build(self, content):
        self.fixture = fixtures.TransferTests()
        with patch.object(
            lineage.CandidateLineageContracts,
            "split_contents",
            {"validation": content},
            create=True,
        ):
            self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.state = self.fixture.root, self.fixture.state
        self.owner = copy.deepcopy(self.fixture.owner)
        self.owner["run_owner"]["repository"] = ci_transfer.REPOSITORY
        self.clock = self.fixture.clock

    def retain(self, content=None, **changes):
        return companion.retain(
            self.root,
            self.state,
            self.content if content is None else content,
            **(self.owner | changes),
        )

    def seal(self, packet=None, **changes):
        return companion.seal(
            self.root,
            self.state,
            self.retain() if packet is None else packet,
            **(dict(key=KEY, phase=self.phase, **self.owner) | changes),
        )

    def materialize(self, sealed, **changes):
        return companion.materialize(
            self.root,
            self.state,
            sealed["envelope"],
            **(
                dict(
                    key=KEY,
                    phase=self.phase,
                    **self.owner,
                    expected_context=sealed["context"],
                    ciphertext_pin=sealed["ciphertext_sha256"],
                )
                | changes
            ),
        )

    def verify(self, sealed, **changes):
        with self.materialize(sealed, **changes) as (path, summary):
            self.assertEqual(bounded_read(path), self.content)
            return summary

    def no_plaintext(self):
        self.assertFalse(list((self.root / ".runtime/ci-validation-transfers").glob("*")))

    def reencrypt(self, sealed, packet, **changes):
        context = sealed["context"] | dict(payload_sha256=digest(packet)) | changes
        envelope = ci_transfer.seal(packet, key=KEY, context=context)
        return sealed | dict(envelope=envelope, context=context, ciphertext_sha256=digest(envelope))

    def rejected(self):
        return self.assertRaisesRegex(Rejected, "^ci_validation_transfer_rejected$")

    def test_tamper_foreign_split_and_wrong_types_before_retention(self):
        for raw in (
            b"train",
            b"holdout",
            self.content[:-1] + b"!",
            self.content + b"\n",
            bytearray(self.content),
            self.content.decode(),
            b"",
            3,
        ):
            with self.subTest(kind=type(raw).__name__), self.rejected():
                self.retain(raw)
        self.no_plaintext()

    def test_original_signed_descriptor_rows_and_canonical_bytes_are_enforced(self):
        bad = [canonical(self.rows[:-1]), canonical(self.rows) + b"\n", b"not-json", b"{}"]
        rows = copy.deepcopy(self.rows)
        rows[-1]["entity_id"] = rows[0]["entity_id"]
        bad.append(canonical(rows))
        rows = copy.deepcopy(self.rows)
        rows[0]["label"] = True
        bad.append(canonical(rows))
        rows = copy.deepcopy(self.rows)
        rows[0]["credentials"] = "forbidden-extra-field"
        bad.append(canonical(rows))
        for raw in bad:
            with self.subTest(length=len(raw)):
                self.build(raw)  # Real upstream signatures commit to these exact invalid bytes.
                with self.rejected():
                    self.retain(raw)
        self.no_plaintext()

    def test_oversize_inputs_fail_before_crypto_or_plaintext_files(self):
        with self.rejected():
            self.retain(b"x" * (companion.MAX_VALIDATION_BYTES + 1))
        with self.rejected():
            self.seal(b"x" * (companion.MAX_PACKET_BYTES + 1))
        sealed = self.seal()
        with patch.object(ci_transfer, "open", side_effect=AssertionError("must bound first")):
            with self.rejected():
                self.verify(sealed | dict(envelope=b"x" * (companion.MAX_ENVELOPE_BYTES + 1)))
        self.no_plaintext()

    def test_ciphertext_tamper_wrong_key_pin_and_bad_types(self):
        sealed = self.seal()
        for changes in (
            dict(key=b"x" * 32),
            dict(key=b"short"),
            dict(ciphertext_pin="0" * 64),
            dict(ciphertext_pin=None),
            dict(expected_context=None),
        ):
            with self.subTest(fields=tuple(changes)), self.rejected():
                self.verify(sealed, **changes)
        for raw in (sealed["envelope"][:-1] + bytes([sealed["envelope"][-1] ^ 1]), b"", "text"):
            with self.rejected():
                self.verify(sealed | dict(envelope=raw))
        changed = sealed["envelope"][:-1] + bytes([sealed["envelope"][-1] ^ 1])
        with self.rejected():
            self.verify(sealed | dict(envelope=changed, ciphertext_sha256=digest(changed)))
        self.no_plaintext()

    def test_external_owner_candidate_source_freeze_and_phase_mismatch(self):
        sealed = self.seal()
        for field in transfer.IDENTITY:
            value = "0" * (40 if field == "source_revision" else 64)
            if field == "image_id":
                value = "sha256:" + value
            with self.subTest(field=field), self.rejected():
                self.verify(sealed, expected=self.owner["expected"] | {field: value})
        for field, value in (
            ("run_id", 567),
            ("run_attempt", 2),
            ("producer_job", "foreign"),
            ("repository", "other/platform"),
        ):
            with self.subTest(field=field), self.rejected():
                self.verify(sealed, run_owner=self.owner["run_owner"] | {field: value})
        for changes in (
            dict(freeze_pin="0" * 64),
            dict(freeze={}),
            dict(phase="M14"),
            dict(phase="M11-M12"),
            dict(phase="M23"),
            dict(phase=None),
        ):
            with self.subTest(fields=tuple(changes)), self.rejected():
                self.verify(sealed, **changes)
        self.no_plaintext()

    def test_malformed_authority_and_extra_fields_rejected(self):
        for field in ("freeze", "expected", "run_owner"):
            for value in (None, [], self.owner[field] | {"extra": "field"}):
                with self.subTest(field=field), self.rejected():
                    self.retain(**{field: value})
        for owner in (
            self.owner["run_owner"] | {"run_attempt": True},
            self.owner["run_owner"] | {"repository": "other/platform"},
        ):
            with self.rejected():
                self.retain(run_owner=owner)

    def test_packet_binding_survives_valid_reencryption_by_wrong_owner(self):
        packet = decode(self.retain())
        sealed = self.seal()
        changes = [
            dict(kind="train"),
            dict(schema_version=True),
            dict(extra="field"),
            dict(split_manifest="0" * 64),
            dict(validation=signing.encode64(b"train")),
            dict(validation=None),
            dict(authority=self.owner | {"freeze_pin": "0" * 64}),
        ]
        for field in ("run_id", "run_attempt", "producer_job"):
            changed = self.owner["run_owner"] | {field: 2 if field != "producer_job" else "foreign"}
            changes.append(dict(authority=self.owner | {"run_owner": changed}))
        for change in changes:
            raw = canonical(packet | change)
            with self.subTest(fields=tuple(change)), self.rejected():
                self.verify(self.reencrypt(sealed, raw))
            with self.rejected():
                self.seal(raw)
        self.no_plaintext()

    def test_packet_closed_canonical_json_and_types(self):
        packet = self.retain()
        for raw in (
            bytearray(packet),
            [],
            b"{}",
            b"[]",
            packet + b"\n",
            b"not-json",
            b'{"kind":1,"kind":1}',
        ):
            with self.subTest(kind=type(raw).__name__), self.rejected():
                self.seal(raw)

    def test_context_closed_and_all_external_expectations_mandatory(self):
        sealed = self.seal()
        for ctx in (
            [],
            {},
            sealed["context"] | {"extra": 1},
            sealed["context"] | {"purpose": "evidence"},
            sealed["context"] | {"phase": "M13"},
            sealed["context"] | {"run_attempt": True},
        ):
            with self.rejected():
                self.verify(sealed, expected_context=ctx)
        arguments = dict(
            key=KEY,
            phase=self.phase,
            **self.owner,
            expected_context=sealed["context"],
            ciphertext_pin=sealed["ciphertext_sha256"],
        )
        for field in ("expected_context", "ciphertext_pin", "freeze_pin", "run_owner"):
            reduced = arguments.copy()
            del reduced[field]
            with self.assertRaises(TypeError):
                with companion.materialize(self.root, self.state, sealed["envelope"], **reduced):
                    self.fail("required receiver expectation missing")

    def test_original_signature_and_split_manifest_cannot_be_replaced(self):
        packet = self.retain()
        pin = decode(packet)["split_manifest"]
        path = self.state / transfer.CAS / pin
        original = bounded_read(path)
        path.write_bytes(original[:-1] + b"!")
        with self.rejected():
            self.seal(packet)
        path.write_bytes(original)
        keys = self.state / "trusted-keys.json"
        keys.write_bytes(b"{}")
        with self.rejected():
            self.retain()

    def test_actual_source_clean_rejection_is_preserved(self):
        with patch.object(transfer.final, "clean", side_effect=Rejected("private-source-detail")):
            with self.rejected():
                self.retain()
        self.no_plaintext()

    def test_foreign_valid_rows_from_another_signed_dataset_are_rejected(self):
        packet = self.retain()
        sealed = self.seal(packet)
        foreign = copy.deepcopy(self.rows)
        foreign[0]["features"][0] = 0.7
        self.build(canonical(foreign))
        # The new dataset is fully signed and valid; it cannot adopt the old
        # bytes, even if an AES key holder rewrites all companion metadata.
        changed = decode(packet) | dict(
            authority=self.owner,
            split_manifest=self.fixture.fx.values["integrity_snapshot"]["manifest"],
        )
        with self.rejected():
            self.seal(canonical(changed))
        with self.rejected():
            self.verify(sealed)
        with self.rejected():
            self.retain(self.content)

    def test_packet_capacity_exact_boundary_and_retention_bound(self):
        packet = self.retain()
        with patch.object(companion, "MAX_PACKET_BYTES", len(packet)):
            self.assertEqual(self.retain(), packet)
            self.verify(self.seal(packet))
        with patch.object(companion, "MAX_PACKET_BYTES", len(packet) - 1), self.rejected():
            self.retain()
        with patch.object(companion, "MAX_VALIDATION_BYTES", len(self.content)):
            self.assertEqual(self.retain(), packet)

    def test_source_is_rechecked_after_materialization(self):
        sealed = self.seal()
        with patch.object(transfer.final, "clean", side_effect=[None, Rejected("source changed")]):
            with self.rejected():
                self.verify(sealed)
        self.no_plaintext()

    def test_stale_original_window_blocks_all_stages(self):
        packet = self.retain()
        sealed = self.seal(packet)
        self.clock = self.fixture.fx.values["proposal_expires_at"] - 599
        for action in (
            lambda: self.retain(),
            lambda: self.seal(packet),
            lambda: self.verify(sealed),
        ):
            with self.rejected():
                action()
        self.no_plaintext()

    def test_exact_600_second_boundary_and_transport_expiry(self):
        packet = self.retain()
        self.clock = self.fixture.fx.values["proposal_expires_at"] - 600
        sealed = self.seal(packet)
        self.assertEqual(
            sealed["context"]["expires_at"], self.fixture.fx.values["proposal_expires_at"]
        )
        self.verify(sealed)
        self.clock += 1
        with self.rejected():
            self.verify(sealed)

    def test_transport_cannot_extend_or_shorten_original_bound_expiry(self):
        self.clock = self.fixture.fx.values["proposal_expires_at"] - 900
        sealed = self.seal()
        packet = self.retain()
        for expiry in (sealed["context"]["expires_at"] - 1, sealed["context"]["expires_at"] + 1):
            with self.rejected():
                changed = self.reencrypt(sealed, packet, expires_at=expiry)
                self.verify(changed)
        self.clock += 1800
        with self.rejected():
            self.verify(sealed)

    def test_clock_rechecked_after_retention_and_encryption(self):
        original = companion._validation

        def delayed(*args):
            value = original(*args)
            self.clock = self.fixture.fx.values["proposal_expires_at"] - 599
            return value

        with patch.object(companion, "_validation", side_effect=delayed), self.rejected():
            self.retain()
        self.clock = self.fixture.clock
        packet = self.retain()
        encrypt = ci_transfer.seal

        def delayed_encrypt(*args, **kwargs):
            value = encrypt(*args, **kwargs)
            self.clock = self.fixture.fx.values["proposal_expires_at"] - 599
            return value

        with patch.object(ci_transfer, "seal", side_effect=delayed_encrypt), self.rejected():
            self.seal(packet)

    def test_clock_and_readback_rechecked_after_materialization_with_cleanup(self):
        sealed = self.seal()
        write = companion.atomic_write
        for damage in (False, True):
            self.clock = self.fixture.clock

            def delayed_write(path, content):
                write(path, b"tamper" if damage else content)
                if not damage:
                    self.clock = self.fixture.fx.values["proposal_expires_at"] - 599

            with (
                patch.object(companion, "atomic_write", side_effect=delayed_write),
                self.rejected(),
            ):
                self.verify(sealed)
            self.no_plaintext()

    def test_failure_messages_and_streams_do_not_disclose_inputs(self):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            with patch.object(transfer.final, "clean", side_effect=OSError("PRIVATE-marker")):
                with self.rejected() as caught:
                    self.retain()
        self.assertEqual(str(caught.exception), "ci_validation_transfer_rejected")
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(output.getvalue(), "")

    def test_write_failure_and_consumer_exception_cleanup_owned_files_only(self):
        sealed = self.seal()
        sentinel = self.root / ".runtime/sibling-private.txt"
        sentinel.write_bytes(b"keep")
        with (
            patch.object(companion, "atomic_write", side_effect=OSError("no space")),
            self.rejected(),
        ):
            self.verify(sealed)
        self.no_plaintext()
        with self.assertRaisesRegex(RuntimeError, "consumer"):
            with self.materialize(sealed) as (path, _):
                self.assertTrue(path.is_file())
                raise RuntimeError("consumer")
        self.assertFalse(path.exists())
        self.assertEqual(sentinel.read_bytes(), b"keep")
        self.no_plaintext()

    def test_retain_is_pure_bytes_and_seals_are_fresh_for_all_consumer_phases(self):
        before = set(self.root.rglob("*"))
        packet = self.retain()
        self.assertEqual(type(packet), bytes)
        self.assertEqual(packet, self.retain())
        self.assertEqual(set(self.root.rglob("*")), before)
        for phase in ("M13", "M14", "M15"):
            self.phase = phase
            sealed = self.seal(packet)
            other = self.seal(packet)
            self.assertNotEqual(sealed["envelope"], other["envelope"])
            self.assertEqual(sealed["context"]["phase"], "validation-" + phase)
            summary = self.verify(sealed)
            self.assertEqual(summary["validation_sha256"], digest(self.content))
            self.assertEqual(summary["rows"], 32)
            self.assertEqual(summary["handling"], "private")
            self.assertIs(summary["release_ready"], False)
            self.no_plaintext()

    def test_original_frozen_archive_and_new_owned_consumer_view_work_unchanged(self):
        sealed = self.seal()
        exported = transfer.export(self.root, self.state, **self.owner, clock=self.clock)
        with transfer.materialize(
            self.root,
            Path(exported["path"]),
            manifest_pin=exported["manifest_sha256"],
            **self.owner,
            clock=self.clock,
        ) as (view, _):
            self.assertNotEqual(view, self.state)
            self.state = view
            with (
                patch.object(signing, "load_key", side_effect=AssertionError("private key read")),
                patch.object(storage, "get", side_effect=AssertionError("SQL read")),
                patch.object(storage, "put", side_effect=AssertionError("SQL write")),
            ):
                self.verify(sealed)
        self.assertFalse(view.exists())
        self.no_plaintext()


if __name__ == "__main__":
    unittest.main()
