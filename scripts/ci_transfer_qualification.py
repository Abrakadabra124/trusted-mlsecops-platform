"""Offline, in-memory transfer contracts; all keys and payloads are public fixtures."""

import hashlib
import io
import json
import time
import traceback
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mlsecops import ci_transfer as transfer
from mlsecops.contracts import Rejected

# Deterministic public test vector, never a deployment credential.
KEY = bytes(range(32))
PAYLOAD = b"synthetic private-transfer canary\x00\xff"
NOW = 1_800_000_000


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def context(payload=PAYLOAD, **changes):
    return {
        "repository": "Abrakadabra124/trusted-mlsecops-platform",
        "run_id": 123456789,
        "run_attempt": 1,
        "source_revision": "1" * 40,
        "source_fingerprint": "2" * 64,
        "image_id": "sha256:" + "3" * 64,
        "candidate_sha256": "4" * 64,
        "proposal_sha256": "5" * 64,
        "payload_sha256": sha256(payload),
        "phase": "m11-m12",
        "purpose": "candidate",
        "issued_at": NOW,
        "expires_at": NOW + 1800,
    } | changes


class TransferTests(unittest.TestCase):
    def seal(self, payload=PAYLOAD, *, ctx=None, key=KEY, clock=lambda: NOW):
        return transfer.seal(
            payload, key=key, context=context(payload) if ctx is None else ctx, clock=clock
        )

    def open(self, envelope, *, ctx=None, key=KEY, pin=None, clock=lambda: NOW):
        return transfer.open(
            envelope,
            key=key,
            expected_context=context() if ctx is None else ctx,
            expected_ciphertext_sha256=sha256(envelope) if pin is None else pin,
            clock=clock,
        )

    def rejected(self, label, action, *args, **kwargs):
        with self.assertRaises(Rejected) as caught:
            action(*args, **kwargs)
        self.assertEqual(caught.exception.args, (label,))
        return caught.exception

    def test_wrong_key_and_valid_pin_rejected(self):
        self.rejected(
            "ci_transfer_authentication", self.open, self.seal(), key=bytes(reversed(KEY))
        )

    def test_private_execution_repository_roundtrip(self):
        ctx = context(repository="Abrakadabra124/trusted-mlsecops-ci-private")
        envelope = self.seal(ctx=ctx)
        self.assertEqual(self.open(envelope, ctx=ctx), PAYLOAD)

    def test_public_envelope_rejects_private_repository_with_authentication_failure(self):
        envelope = self.seal()
        self.rejected(
            "ci_transfer_authentication",
            self.open,
            envelope,
            ctx=context(repository="Abrakadabra124/trusted-mlsecops-ci-private"),
        )

    def test_private_envelope_rejects_public_repository_with_authentication_failure(self):
        ctx = context(repository="Abrakadabra124/trusted-mlsecops-ci-private")
        envelope = self.seal(ctx=ctx)
        self.rejected("ci_transfer_authentication", self.open, envelope, ctx=context())

    def test_foreign_and_noncanonical_execution_repositories_rejected_on_both_paths(self):
        envelope = self.seal()
        repositories = (
            "other/trusted-mlsecops-ci-private",
            "Abrakadabra124/unapproved-private",
            "Abrakadabra124/trusted-mlsecops-ci-private-extra",
            "abrakadabra124/trusted-mlsecops-ci-private",
            "Abrakadabra124/Trusted-mlsecops-ci-private",
            "abrakadabra124/trusted-mlsecops-platform",
            "Abrakadabra124/Trusted-mlsecops-platform",
            "Abrakadabra124/trusted-mlsecops-ci-private ",
            "Abrakadabra124/trusted-mlsecops-ci-private\n",
        )
        for repository in repositories:
            with self.subTest(repository=repository):
                ctx = context(repository=repository)
                self.rejected("ci_transfer_context", self.seal, ctx=ctx)
                self.rejected("ci_transfer_context", self.open, envelope, ctx=ctx)

    def test_execution_repository_requires_exact_string_type_on_both_paths(self):
        class Repository(str):
            pass

        envelope = self.seal()
        for repository in (
            "Abrakadabra124/trusted-mlsecops-platform",
            "Abrakadabra124/trusted-mlsecops-ci-private",
        ):
            with self.subTest(repository=repository):
                ctx = context(repository=Repository(repository))
                self.rejected("ci_transfer_context", self.seal, ctx=ctx)
                self.rejected("ci_transfer_context", self.open, envelope, ctx=ctx)

    def test_every_context_binding_is_authenticated(self):
        envelope = self.seal()
        alternatives = {
            "run_id": 123456790,
            "run_attempt": 2,
            "source_revision": "a" * 40,
            "source_fingerprint": "a" * 64,
            "image_id": "sha256:" + "a" * 64,
            "candidate_sha256": "a" * 64,
            "proposal_sha256": "a" * 64,
            "payload_sha256": "a" * 64,
            "phase": "m13",
            "purpose": "evidence",
            "issued_at": NOW + 1,
            "expires_at": NOW + 1799,
        }
        for field, value in alternatives.items():
            with self.subTest(field=field):
                # Both windows remain valid; change exactly one binding at a time.
                self.rejected(
                    "ci_transfer_authentication",
                    self.open,
                    envelope,
                    ctx=context(**{field: value}),
                    clock=lambda: NOW + 1,
                )

    def test_unknown_or_missing_context_fields_rejected_on_both_paths(self):
        envelope = self.seal()
        variants = [None, [], "context", {}, context(extra="private input")]
        for field in context():
            missing = context()
            del missing[field]
            variants.append(missing)
        wrong_key_type = context()
        del wrong_key_type["phase"]
        wrong_key_type[1] = "phase"
        variants.append(wrong_key_type)
        replaced_field = context()
        del replaced_field["phase"]
        replaced_field["untrusted_phase"] = "m11-m12"
        variants.append(replaced_field)
        for index, ctx in enumerate(variants):
            with self.subTest(index=index):
                self.rejected(
                    "ci_transfer_context",
                    transfer.seal,
                    PAYLOAD,
                    key=KEY,
                    context=ctx,
                    clock=lambda: NOW,
                )
                self.rejected(
                    "ci_transfer_context",
                    transfer.open,
                    envelope,
                    key=KEY,
                    expected_context=ctx,
                    expected_ciphertext_sha256=sha256(envelope),
                    clock=lambda: NOW,
                )

    def test_context_rejects_types_ranges_and_noncanonical_values(self):
        invalid = {
            "repository": [None, [], 1, "abrakadabra124/trusted-mlsecops-platform", "other/repo"],
            "run_id": [True, None, "123", 1.0, 0, -1, 2**53],
            "run_attempt": [True, [], "1", 1.0, 0, -1, 2**53],
            "source_revision": [None, [], 1, "A" * 40, "a" * 39, "a" * 41, "g" * 40],
            "source_fingerprint": [None, 2, "A" * 64, "a" * 63, "a" * 65, "z" * 64],
            "image_id": [
                None,
                [],
                3,
                "image:latest",
                "a" * 64,
                "sha256:" + "A" * 64,
                "sha256:" + "g" * 64,
                "sha512:" + "a" * 64,
                "sha256:" + "a" * 63,
            ],
            "candidate_sha256": [None, True, b"a" * 64, "a" * 63, "a" * 65],
            "proposal_sha256": [None, {}, "a" * 64 + "\n", "A" * 64],
            "payload_sha256": [None, [], "g" * 64, "a" * 63],
            "phase": [
                None,
                [],
                1,
                "",
                ".m11",
                "../m11",
                "m11/m12",
                "a" * 65,
                "m11\n",
                "m11 m12",
                "этап",
            ],
            "purpose": [None, [], 1, "release", "Candidate", "candidate\n"],
            "issued_at": [None, True, str(NOW), float(NOW), -1, 2**53],
            "expires_at": [None, True, str(NOW + 1), float(NOW + 1), -1, 2**53],
        }
        envelope = self.seal()
        for field, values in invalid.items():
            for index, value in enumerate(values):
                with self.subTest(field=field, index=index):
                    ctx = context(**{field: value})
                    self.rejected("ci_transfer_context", self.seal, ctx=ctx)
                    self.rejected("ci_transfer_context", self.open, envelope, ctx=ctx)

    def test_builtin_subclasses_are_rejected(self):
        class CustomBytes(bytes):
            pass

        class CustomDict(dict):
            pass

        class CustomInt(int):
            pass

        class CustomStr(str):
            pass

        self.rejected("ci_transfer_payload", self.seal, CustomBytes(PAYLOAD))
        self.rejected("ci_transfer_key", self.seal, key=CustomBytes(KEY))
        self.rejected("ci_transfer_context", self.seal, ctx=CustomDict(context()))
        for field, value in (("run_id", CustomInt(1)), ("phase", CustomStr("m11"))):
            self.rejected("ci_transfer_context", self.seal, ctx=context(**{field: value}))
        ctx = context()
        del ctx["phase"]
        ctx[CustomStr("phase")] = "m11"
        self.rejected("ci_transfer_context", self.seal, ctx=ctx)
        self.rejected("ci_transfer_envelope", self.open, CustomBytes(self.seal()))

    def test_key_must_be_exactly_32_bytes(self):
        envelope = self.seal()
        for key in (
            None,
            True,
            32,
            "k" * 32,
            bytearray(KEY),
            memoryview(KEY),
            b"",
            b"k" * 16,
            b"k" * 24,
            b"k" * 31,
            b"k" * 33,
        ):
            with self.subTest(type=type(key).__name__):
                self.rejected("ci_transfer_key", self.seal, key=key)
                self.rejected("ci_transfer_key", self.open, envelope, key=key)

    def test_payload_must_be_immutable_bytes(self):
        for payload in (None, True, 1, "private", [], bytearray(PAYLOAD), memoryview(PAYLOAD)):
            self.rejected("ci_transfer_payload", self.seal, payload, ctx=context())

    def test_payload_digest_must_match_before_encrypt(self):
        with patch.object(transfer, "AESGCM") as aes:
            self.rejected(
                "ci_transfer_payload_digest", self.seal, ctx=context(payload_sha256="a" * 64)
            )
            aes.assert_not_called()

    def test_payload_digest_must_match_after_authentication(self):
        ctx = context(payload_sha256="a" * 64)
        # Independent library invocation constructs an authenticated but dishonest sender fixture.
        nonce = bytes(range(12))
        aad = (
            transfer.MAGIC
            + b"\x00"
            + json.dumps(
                ctx, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            ).encode("ascii")
        )
        envelope = transfer.MAGIC + nonce + AESGCM(KEY).encrypt(nonce, PAYLOAD, aad)
        self.rejected("ci_transfer_payload_digest", self.open, envelope, ctx=ctx)

    def test_pin_is_mandatory_even_when_key_and_context_match(self):
        envelope = self.seal()
        with self.assertRaises(TypeError):
            transfer.open(envelope, key=KEY, expected_context=context(), clock=lambda: NOW)
        for pin in (
            None,
            [],
            True,
            b"a" * 64,
            "",
            "a" * 63,
            "a" * 65,
            "A" * 64,
            "g" * 64,
            sha256(envelope) + "\n",
            "0" * 64,
        ):
            self.rejected(
                "ci_transfer_pin",
                transfer.open,
                envelope,
                key=KEY,
                expected_context=context(),
                expected_ciphertext_sha256=pin,
                clock=lambda: NOW,
            )

    def test_pin_is_over_the_entire_envelope_and_checked_before_decrypt(self):
        envelope = self.seal()
        pin = sha256(envelope[len(transfer.MAGIC) + 12 :])
        with patch.object(transfer, "AESGCM") as aes:
            self.rejected("ci_transfer_pin", self.open, envelope, pin=pin)
            aes.assert_not_called()

    def test_every_nonce_ciphertext_and_tag_byte_is_authenticated(self):
        envelope = self.seal()
        for position in range(len(transfer.MAGIC), len(envelope)):
            altered = bytearray(envelope)
            altered[position] ^= 1
            altered = bytes(altered)
            with self.subTest(position=position):
                self.rejected("ci_transfer_pin", self.open, altered, pin=sha256(envelope))
                self.rejected("ci_transfer_authentication", self.open, altered)

    def test_header_version_magic_truncation_and_extra_data_rejected(self):
        envelope = self.seal()
        malformed = [b"", b"{}", b"x" * (len(transfer.MAGIC) + 28)]
        malformed.extend(envelope[:size] for size in range(len(transfer.MAGIC) + 28))
        for position in range(len(transfer.MAGIC)):
            altered = bytearray(envelope)
            altered[position] ^= 1
            malformed.append(bytes(altered))
        for raw in malformed:
            self.rejected("ci_transfer_envelope", self.open, raw)
        for raw in (envelope[:-1], envelope + b"x", envelope + envelope):
            self.rejected("ci_transfer_authentication", self.open, raw)
        injected = transfer.MAGIC + b'{"context":"untrusted"}' + envelope[len(transfer.MAGIC) :]
        self.rejected("ci_transfer_authentication", self.open, injected)

    def test_envelope_requires_exact_bytes(self):
        for raw in (None, True, 1, "envelope", [], bytearray(self.seal()), memoryview(self.seal())):
            self.rejected(
                "ci_transfer_envelope",
                transfer.open,
                raw,
                key=KEY,
                expected_context=context(),
                expected_ciphertext_sha256="0" * 64,
                clock=lambda: NOW,
            )

    def test_transport_ttl_limits_are_purpose_specific(self):
        for purpose, ttl in (("candidate", 1800), ("evidence", 86400)):
            for duration in (-1, 0, ttl + 1):
                ctx = context(purpose=purpose, expires_at=NOW + duration)
                self.rejected("ci_transfer_context", self.seal, ctx=ctx)
                self.rejected("ci_transfer_context", self.open, self.seal(), ctx=ctx)

    def test_future_issued_and_exact_expiry_rejected(self):
        envelope = self.seal()
        for timestamp in (NOW - 1, NOW + 1800, NOW + 1801):
            self.rejected("ci_transfer_time", self.seal, clock=lambda: timestamp)
            self.rejected("ci_transfer_time", self.open, envelope, clock=lambda: timestamp)

    def test_invalid_clock_result_and_callback_fail_closed(self):
        envelope = self.seal()
        for value in (None, True, -1, 2**53, str(NOW), float(NOW), float("nan"), []):
            self.rejected("ci_transfer_clock", self.seal, clock=lambda: value)
            self.rejected("ci_transfer_clock", self.open, envelope, clock=lambda: value)
        for clock in (1, "clock", []):
            self.rejected("ci_transfer_clock", self.seal, clock=clock)
            self.rejected("ci_transfer_clock", self.open, envelope, clock=clock)

        def failed_clock():
            raise RuntimeError("secret callback input")

        self.rejected("ci_transfer_clock", self.seal, clock=failed_clock)
        self.rejected("ci_transfer_clock", self.open, envelope, clock=failed_clock)

    def test_expiry_during_crypto_does_not_return_bytes(self):
        envelope = self.seal()
        for action, args in ((self.seal, ()), (self.open, (envelope,))):
            ticks = iter((NOW, NOW + 1800))
            self.rejected("ci_transfer_time", action, *args, clock=lambda: next(ticks))

    def test_clock_rollback_below_issued_does_not_return_bytes(self):
        envelope = self.seal()
        for action, args in ((self.seal, ()), (self.open, (envelope,))):
            ticks = iter((NOW, NOW - 1))
            self.rejected("ci_transfer_time", action, *args, clock=lambda: next(ticks))

    def test_production_default_clock_is_current_utc(self):
        self.rejected(
            "ci_transfer_time",
            transfer.seal,
            PAYLOAD,
            key=KEY,
            context=context(issued_at=0, expires_at=1),
        )
        timestamp = time.time_ns() // 1_000_000_000
        ctx = context(issued_at=timestamp, expires_at=timestamp + 1800)
        raw = transfer.seal(PAYLOAD, key=KEY, context=ctx)
        self.assertEqual(
            transfer.open(
                raw, key=KEY, expected_context=ctx, expected_ciphertext_sha256=sha256(raw)
            ),
            PAYLOAD,
        )
        # A synthetic-clock ciphertext is still rejected by the production default.
        old = context(issued_at=0, expires_at=1)
        raw = self.seal(ctx=old, clock=lambda: 0)
        self.rejected(
            "ci_transfer_time",
            transfer.open,
            raw,
            key=KEY,
            expected_context=old,
            expected_ciphertext_sha256=sha256(raw),
        )

    def test_no_nonce_override_is_exposed(self):
        with self.assertRaises(TypeError):
            transfer.seal(PAYLOAD, key=KEY, context=context(), nonce=b"n" * 12)

    def test_random_failure_has_fixed_label_without_fallback(self):
        with patch.object(transfer.os, "urandom", side_effect=OSError("private source")):
            self.rejected("ci_transfer_random", self.seal)

    def test_invalid_tag_has_fixed_label_and_no_displayed_cause(self):
        envelope = self.seal()
        with patch.object(transfer, "AESGCM") as aes:
            aes.return_value.decrypt.side_effect = InvalidTag("private key payload input")
            error = self.rejected("ci_transfer_authentication", self.open, envelope)
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)
        self.assertNotIn("private key payload input", "".join(traceback.format_exception(error)))

    def test_hard_size_limits_reject_before_hash_or_crypto(self):
        self.assertEqual(transfer.MAX_PAYLOAD_BYTES, 256 * 1024 * 1024)
        self.assertEqual(
            transfer.MAX_ENVELOPE_BYTES, transfer.MAX_PAYLOAD_BYTES + len(transfer.MAGIC) + 12 + 16
        )
        oversized = b"x" * (transfer.MAX_ENVELOPE_BYTES + 1)
        with patch.object(transfer, "AESGCM") as aes, patch.object(transfer, "sha256") as digest:
            self.rejected("ci_transfer_payload", self.seal, oversized, ctx=context())
            self.rejected(
                "ci_transfer_envelope",
                transfer.open,
                oversized,
                key=KEY,
                expected_context=context(),
                expected_ciphertext_sha256="0" * 64,
                clock=lambda: NOW,
            )
            aes.assert_not_called()
            digest.assert_not_called()

    def test_inclusive_size_boundary_with_reduced_test_cap(self):
        # Exercise off-by-one cheaply; the real 256 MiB overflow is tested separately.
        overhead = len(transfer.MAGIC) + 12 + 16
        with (
            patch.object(transfer, "MAX_PAYLOAD_BYTES", 64),
            patch.object(transfer, "MAX_ENVELOPE_BYTES", 64 + overhead),
        ):
            payload = b"x" * 64
            ctx = context(payload)
            raw = self.seal(payload, ctx=ctx)
            self.assertEqual(len(raw), 64 + overhead)
            self.assertEqual(self.open(raw, ctx=ctx), payload)
            self.rejected("ci_transfer_payload", self.seal, payload + b"x", ctx=ctx)
            self.rejected("ci_transfer_envelope", self.open, raw + b"x", ctx=ctx)

    def test_roundtrip_empty_binary_candidate_and_evidence(self):
        for payload in (b"", PAYLOAD, bytes(range(256)) * 1024):
            for purpose, ttl in (("candidate", 1800), ("evidence", 86400)):
                for duration in (1, ttl):
                    ctx = context(payload, purpose=purpose, expires_at=NOW + duration)
                    raw = self.seal(payload, ctx=ctx)
                    self.assertEqual(
                        self.open(raw, ctx=ctx, clock=lambda: NOW + duration - 1), payload
                    )
                    self.rejected(
                        "ci_transfer_time", self.open, raw, ctx=ctx, clock=lambda: NOW + duration
                    )

    def test_repeated_seal_uses_fresh_96_bit_random_nonce(self):
        with patch.object(transfer.os, "urandom", wraps=transfer.os.urandom) as random:
            envelopes = [self.seal() for _ in range(64)]
        self.assertEqual(random.call_count, 64)
        self.assertTrue(all(call.args == (12,) for call in random.call_args_list))
        self.assertEqual(
            len({raw[len(transfer.MAGIC) : len(transfer.MAGIC) + 12] for raw in envelopes}), 64
        )
        self.assertEqual(len({sha256(raw) for raw in envelopes}), 64)
        for raw in envelopes:
            self.assertEqual(self.open(raw), PAYLOAD)

    def test_minimal_wire_format_and_independent_library_interoperability(self):
        ctx = context()
        raw = self.seal(ctx=ctx)
        self.assertEqual(transfer.MAGIC, b"MLSCIT\x01")
        self.assertEqual(len(raw), len(PAYLOAD) + len(transfer.MAGIC) + 12 + 16)
        nonce, encrypted = raw[7:19], raw[19:]
        canonical = json.dumps(
            ctx, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
        self.assertEqual(
            AESGCM(KEY).decrypt(nonce, encrypted, b"MLSCIT\x01\x00" + canonical), PAYLOAD
        )
        for marker in (PAYLOAD, b"repository", b"source_revision", b"candidate_sha256"):
            self.assertNotIn(marker, raw)

    def test_context_order_is_canonical_and_not_mutated(self):
        original = context()
        reverse = dict(reversed(tuple(original.items())))
        raw = self.seal(ctx=original)
        self.assertEqual(self.open(raw, ctx=reverse), PAYLOAD)
        self.assertEqual(original, context())
        self.assertEqual(reverse, context())

    def test_context_snapshot_prevents_callback_mutation(self):
        original = context()

        def mutating_clock():
            original["candidate_sha256"] = "a" * 64
            return NOW

        raw = self.seal(ctx=original, clock=mutating_clock)
        self.assertEqual(self.open(raw), PAYLOAD)
        original = context()
        self.assertEqual(self.open(raw, ctx=original, clock=mutating_clock), PAYLOAD)

    def test_context_accepts_documented_integer_and_phase_boundaries(self):
        ctx = context(run_id=2**53 - 1, run_attempt=2**53 - 1, phase="M" + "a" * 60 + "._-")
        self.assertEqual(self.open(self.seal(ctx=ctx), ctx=ctx), PAYLOAD)

    def test_roundtrip_is_quiet_and_does_not_touch_files_or_network(self):
        output, errors = io.StringIO(), io.StringIO()
        with (
            redirect_stdout(output),
            redirect_stderr(errors),
            patch("builtins.open") as files,
            patch("socket.socket") as network,
            patch("subprocess.Popen") as processes,
        ):
            raw = self.seal()
            self.assertEqual(self.open(raw), PAYLOAD)
            self.rejected("ci_transfer_authentication", self.open, raw, key=b"z" * 32)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")
        files.assert_not_called()
        network.assert_not_called()
        processes.assert_not_called()


if __name__ == "__main__":
    unittest.main()
