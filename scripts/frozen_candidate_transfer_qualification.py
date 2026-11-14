"""Offline transfer contracts with real signatures; no infrastructure or publication."""

import copy
import io
import os
import runpy
import stat
import sys
import unittest
import warnings
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo

from mlsecops import signing
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, write_json
from scripts import final_evidence_qualification as fixtures
from scripts import frozen_candidate_transfer as transfer


class TransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.FinalEvidenceContracts.setUpClass()
        cls.addClassCleanup(fixtures.FinalEvidenceContracts.tearDownClass)

    def setUp(self):
        self.fx = fx = fixtures.FinalEvidenceContracts()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        fx.build()
        self.root, self.state = fx.root, fx.state
        self.index = {
            k: fx.index[k]
            for k in ("schema_version", *transfer.delivery.SOURCE, "freeze", "policy_reference")
        }
        write_json(self.state / transfer.RECEIPT, self.index)
        self.owner = dict(
            freeze_pin=digest(bounded_read(self.state / transfer.RECEIPT)),
            freeze=fx.freeze.copy(),
            expected={k: fx.values[k] for k in transfer.IDENTITY},
            run_owner=dict(
                repository="example/platform",
                run_id=123456,
                run_attempt=1,
                producer_job="candidate",
            ),
        )
        self.clock = fx.values["captured_at"]
        self.clean = self.enterContext(patch.object(transfer.final, "clean"))

    def export(self, **changes):
        return transfer.export(
            self.root, self.state, **{**self.owner, "clock": self.clock, **changes}
        )

    def verify(self, result, **changes):
        return transfer.verify(
            self.root,
            Path(result["path"]),
            manifest_pin=result["manifest_sha256"],
            **{**self.owner, "clock": self.clock, **changes},
        )

    def contents(self, result):
        return transfer.unpack(
            bounded_read(Path(result["path"]), transfer.MAX_ARCHIVE), result["manifest_sha256"]
        )

    def forged(self, result, change, *, update_inventory=True):
        manifest, files = self.contents(result)
        change(manifest, files)
        if update_inventory:
            manifest["files"] = transfer.inventory(files)
        raw = canonical(manifest) + b"\n"
        path = self.root / "forged.zip"
        path.write_bytes(transfer.pack(raw, files))
        return dict(path=str(path), manifest_sha256=digest(raw))

    def test_wrong_original_bytes_missing_and_external_pins_fail_before_export(self):
        for name in (
            transfer.RECEIPT,
            *self.owner["freeze"],
            transfer.CAS + self.owner["expected"]["model_sha256"],
        ):
            path = self.state / name
            original = path.read_bytes()
            for replacement in (None, original + b"wrong"):
                if replacement is None:
                    path.unlink()
                else:
                    path.write_bytes(replacement)
                with (
                    self.subTest(name=name, missing=replacement is None),
                    self.assertRaises((Rejected, OSError)),
                ):
                    self.export()
                path.write_bytes(original)
        with self.assertRaises(Rejected):
            self.export(freeze_pin="0" * 64)
        changed = dict(self.owner["freeze"], **{"trusted-keys.json": "0" * 64})
        with self.assertRaises(Rejected):
            self.export(freeze=changed)
        self.assertFalse(list((self.root / ".runtime/frozen-transfers").glob("*.zip")))

    def test_expiry_future_clock_and_full_six_hundred_seconds_remain_strict(self):
        result = self.export()
        end = self.fx.values["proposal_expires_at"]
        for clock in (True, self.clock - 1, end - 599, end, end + 1):
            with self.subTest(clock=clock), self.assertRaises(Rejected):
                self.verify(result, clock=clock)
        self.assertFalse(self.verify(result, clock=end - 600)["release_ready"])
        with self.assertRaises(Rejected):
            self.export(clock=end - 599)

    def test_current_policy_and_source_approval_expiry_are_checked(self):
        # Pinned original proposal is still valid. Bound policy/source checks must also reject.
        with patch.object(
            transfer.release_policy, "verify_policy", wraps=transfer.release_policy.verify_policy
        ) as policy:
            result = self.export()
            self.assertIn(self.clock, [call.kwargs.get("clock") for call in policy.call_args_list])
        with patch.object(
            transfer.datasets, "validate_approval", side_effect=Rejected("expired source")
        ):
            with self.assertRaises(Rejected):
                self.verify(result)
        original = transfer.release_policy.verify_policy

        def short_policy(*args, **kwargs):
            return {**original(*args, **kwargs), "expires_at": self.clock + 599}

        with patch.object(transfer.release_policy, "verify_policy", side_effect=short_policy):
            with self.assertRaises(Rejected):
                self.verify(result)

    def test_local_roundtrip_exact_bytes_no_runtime_scan_and_no_private_files(self):
        sentinels = (
            "keys/curator.pem",
            "storage.json",
            "private-review/packet.json",
            "audit/raw.log",
            "source/records.json",
            "candidate-inference/secret/config.json",
        )
        for name in sentinels:
            path = self.state / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"PRIVATE-SENTINEL-NOT-A-KEY")
        reads = []
        reader = transfer.bounded_read

        def guarded(path, limit=16 * 1024**2):
            path = Path(path)
            self.assertNotIn(path, [self.state / name for name in sentinels])
            reads.append(path)
            return reader(path, limit)

        with patch.object(transfer, "bounded_read", side_effect=guarded):
            result = self.export()
        manifest, files = self.contents(result)
        self.assertEqual(self.export(), result)
        self.assertEqual(manifest["identity"], self.owner["expected"])
        self.assertEqual(manifest["run_owner"], self.owner["run_owner"])
        self.assertFalse(manifest["classification"]["public_synthetic_proven"])
        self.assertEqual(manifest["classification"]["handling"], "private-local-only")
        self.assertEqual(manifest["classification"]["model_card_classification"], "synthetic-only")
        self.assertTrue(reads)
        for name, raw in files.items():
            self.assertEqual(raw, bounded_read(self.state / name))
            self.assertNotIn(b"PRIVATE-SENTINEL", raw)
        for name in files:
            (self.state / name).unlink()
        with transfer.materialize(
            self.root,
            Path(result["path"]),
            manifest_pin=result["manifest_sha256"],
            **self.owner,
            clock=self.clock,
        ) as (view, summary):
            observed = {p.relative_to(view).as_posix() for p in view.rglob("*") if p.is_file()}
            self.assertEqual(observed, set(files))
            values, _, _ = transfer.delivery.frozen(self.root, view, self.index)
            self.assertEqual(
                values["proposal_reference"], self.owner["expected"]["proposal_reference"]
            )
            self.assertFalse(summary["release_ready"])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(view.stat().st_mode), 0o700)
                self.assertTrue(
                    all(stat.S_IMODE((view / name).stat().st_mode) == 0o600 for name in files)
                )
        self.assertFalse(view.exists())
        self.assertEqual(self.verify(result)["manifest_sha256"], result["manifest_sha256"])

    def test_external_manifest_run_owner_source_and_candidate_identity_are_required(self):
        result = self.export()
        wrong = dict(result, manifest_sha256="0" * 64)
        with self.assertRaises(Rejected):
            self.verify(wrong)
        for field in transfer.IDENTITY:
            expected = dict(self.owner["expected"])
            expected[field] = (
                "sha256:" + "0" * 64
                if field == "image_id"
                else "0" * (40 if field == "source_revision" else 64)
            )
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.export(expected=expected)
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify(result, expected=expected)
        with self.assertRaises(Rejected):
            self.verify(result, run_owner=dict(self.owner["run_owner"], run_id=123457))
        self.clean.side_effect = Rejected("dirty source")
        with self.assertRaises(Rejected):
            self.verify(result)

    def test_resealed_manifest_cannot_override_original_identity_expiry_or_classification(self):
        result = self.export()
        for field, value in (
            ("proposal_window", dict(issued_at=self.clock, expires_at=self.clock + 86400)),
            ("classification", dict(handling="public")),
            ("freeze_sha256", "0" * 64),
            ("run_owner", dict(self.owner["run_owner"], run_attempt=2)),
        ):
            forged = self.forged(result, lambda m, f: m.update({field: value}))
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify(forged)

    def test_closed_allowlist_rejects_missing_extra_traversal_credentials_and_review_paths(self):
        result = self.export()
        for name in (
            "../escape",
            "/absolute",
            "C:/escape",
            "evidence/../secret",
            "evidence\\M18-objects\\" + "1" * 64,
            "./trusted-keys.json",
            "storage.json",
            "keys/key.pem",
            "passwords.json",
            "review/packet.json",
            "audit/raw.log",
            "candidate-inference/a/config.json",
            transfer.CAS + "0" * 64,
        ):
            forged = self.forged(result, lambda m, f: f.update({name: b"extra"}))
            with self.subTest(name=name), self.assertRaises(Rejected):
                self.verify(forged)
            self.assertFalse((self.root / "escape").exists())
        for name in (transfer.RECEIPT, "trusted-keys.json", transfer.CAS + self.fx.values["model"]):
            forged = self.forged(result, lambda m, f: f.pop(name))
            with self.subTest(name=name), self.assertRaises((Rejected, KeyError)):
                self.verify(forged)

    def test_corrupt_rehashed_or_swapped_preimages_do_not_pass_original_pins(self):
        result = self.export()
        for name in (
            "storage-demo.json",
            transfer.CAS + self.fx.values["model"],
            transfer.CAS + self.index["policy_reference"],
        ):
            for rehash in (False, True):
                forged = self.forged(
                    result,
                    lambda m, f: f.update({name: f[name] + b"wrong"}),
                    update_inventory=rehash,
                )
                with self.subTest(name=name, rehash=rehash), self.assertRaises(Rejected):
                    self.verify(forged)

        def swap(manifest, files):
            files["storage-trust.json"], files["trusted-keys.json"] = (
                files["trusted-keys.json"],
                files["storage-trust.json"],
            )

        with self.assertRaises(Rejected):
            self.verify(self.forged(result, swap))

    def test_signature_mutation_is_rejected_even_after_repinning_outer_owners(self):
        original = self.fx.package["envelope"]
        for target in ("payload", "signature"):
            envelope = copy.deepcopy(original)
            if target == "payload":
                value = decode(signing.decode64(envelope["payload"]))
                value["expires_at"] += 600
                envelope["payload"] = signing.encode64(canonical(value))
            else:
                envelope["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
            ref = transfer.final.retain(self.state, canonical(envelope))
            proposal = dict(self.fx.proposal, proposal_reference=ref)
            write_json(self.state / transfer.delivery.PROPOSAL, proposal)
            freeze = {
                **self.owner["freeze"],
                transfer.delivery.PROPOSAL: digest(
                    bounded_read(self.state / transfer.delivery.PROPOSAL)
                ),
            }
            write_json(self.state / transfer.RECEIPT, dict(self.index, freeze=freeze))
            with self.subTest(target=target), self.assertRaises(Rejected):
                self.export(
                    freeze=freeze,
                    freeze_pin=digest(bounded_read(self.state / transfer.RECEIPT)),
                    expected=dict(self.owner["expected"], proposal_reference=ref),
                )

    def test_duplicate_paths_symlinks_compression_trailers_and_broken_zip_are_rejected(self):
        result = self.export()
        original = bounded_read(Path(result["path"]), transfer.MAX_ARCHIVE)
        for raw in (original + b"hidden", b"prefix" + original, b"broken"):
            with self.assertRaises((Rejected, BadZipFile)):
                transfer.unpack(raw, result["manifest_sha256"])
        manifest, files = self.contents(result)
        files[transfer.MANIFEST] = canonical(manifest) + b"\n"
        for variant in ("duplicate", "symlink", "compressed", "directory"):
            stream = io.BytesIO()
            with ZipFile(stream, "w") as archive:
                for name, raw in files.items():
                    entry = ZipInfo(name)
                    entry.external_attr = (stat.S_IFREG | 0o600) << 16
                    if name == "trusted-keys.json":
                        if variant == "symlink":
                            entry.external_attr = (stat.S_IFLNK | 0o600) << 16
                        elif variant == "compressed":
                            entry.compress_type = ZIP_DEFLATED
                        elif variant == "directory":
                            entry.filename += "/"
                    archive.writestr(entry, raw)
                if variant == "duplicate":
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        archive.writestr("trusted-keys.json", files["trusted-keys.json"])
            with self.subTest(variant=variant), self.assertRaises(Rejected):
                transfer.unpack(stream.getvalue(), result["manifest_sha256"])

    def test_secret_content_in_approved_file_and_invalid_authority_are_rejected(self):
        for raw in (
            b"-----BEGIN " + b"PRIVATE KEY-----",
            b"postgresql://owner:secret@local/db",
            canonical({"password": "secret"}),
            canonical([{"credentials": "secret"}]),
            canonical(
                {
                    "payloadType": "type",
                    "payload": signing.encode64(canonical({"token": "secret"})),
                    "signatures": [],
                }
            ),
        ):
            with self.assertRaises(Rejected):
                transfer.no_credentials(raw)
        for changes in (
            dict(freeze={}),
            dict(expected={}),
            dict(run_owner=dict(self.owner["run_owner"], repository="../escape")),
            dict(run_owner=dict(self.owner["run_owner"], producer_job="x/y")),
            dict(clock=False),
        ):
            with self.assertRaises(Rejected):
                self.export(**changes)
        keys = decode(bounded_read(self.state / "trusted-keys.json"))
        keys["private_key"] = "forbidden"
        write_json(self.state / "trusted-keys.json", keys)
        freeze = dict(
            self.owner["freeze"],
            **{"trusted-keys.json": digest(bounded_read(self.state / "trusted-keys.json"))},
        )
        write_json(self.state / transfer.RECEIPT, dict(self.index, freeze=freeze))
        with self.assertRaises(Rejected):
            self.export(
                freeze=freeze, freeze_pin=digest(bounded_read(self.state / transfer.RECEIPT))
            )

    def test_immutable_local_output_and_cleanup_after_reader_failure(self):
        result = self.export()
        with self.assertRaisesRegex(RuntimeError, "controlled"):
            with transfer.materialize(
                self.root,
                Path(result["path"]),
                manifest_pin=result["manifest_sha256"],
                **self.owner,
                clock=self.clock,
            ) as (view, _):
                raise RuntimeError("controlled")
        self.assertFalse(view.exists())
        Path(result["path"]).write_bytes(b"corrupt")
        with self.assertRaises(Rejected):
            self.export()
        self.assertEqual(Path(result["path"]).read_bytes(), b"corrupt")

    def test_cli_requires_external_authority_and_emits_no_package_contents(self):
        path = self.root / "authority.json"
        write_json(path, self.owner)
        with (
            patch.object(
                transfer, "__file__", str(self.root / "scripts/frozen_candidate_transfer.py")
            ),
            redirect_stdout(io.StringIO()) as output,
        ):
            args = ["--authority", str(path), "--clock", str(self.clock)]
            transfer.main(["export", "--state", str(self.state), *args])
            result = decode(output.getvalue().encode())
            transfer.main(
                [
                    "verify",
                    "--archive",
                    result["path"],
                    "--manifest-pin",
                    result["manifest_sha256"],
                    *args,
                ]
            )
            self.assertNotIn("payloadType", output.getvalue())
            self.assertNotIn("signatures", output.getvalue())
            with self.assertRaises(Rejected):
                transfer.main(["verify", *args])
        with (
            patch.object(
                sys,
                "argv",
                [transfer.__file__, "verify", "--authority", str(path), "--clock", str(self.clock)],
            ),
            self.assertRaisesRegex(SystemExit, "Frozen candidate transfer rejected"),
        ):
            runpy.run_path(transfer.__file__, run_name="__main__")


if __name__ == "__main__":
    unittest.main()
