"""Offline original-receipt transfer: real signed package and AES, controlled gate fixtures."""

import copy
import shutil
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from mlsecops import ci_transfer, evaluation_gate, key_files, release_bundle, signing, storage
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, write_json
from scripts import ci_upstream_transfer as companion
from scripts import consumer_candidate_state as consumer
from scripts import frozen_candidate_transfer as transfer
from scripts import frozen_candidate_transfer_qualification as fixtures
from scripts import m18_delivery_freeze as collector
from scripts import serving_campaign

ROOT = Path(__file__).resolve().parents[1]
KEY = bytes(range(32))  # Public test vector only.


class UpstreamTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.TransferTests.setUpClass()
        cls.addClassCleanup(fixtures.TransferTests.doClassCleanups)

    def setUp(self):
        self.fixture = fixtures.TransferTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fx = self.fixture.fx
        self.root, self.state = self.fixture.root, self.fixture.state
        self.owner = copy.deepcopy(self.fixture.owner)
        self.owner["run_owner"]["repository"] = ci_transfer.REPOSITORY
        self.clock = self.fixture.clock
        self.enterContext(patch.object(time, "time_ns", side_effect=lambda: self.clock * 10**9))
        self.phase = "M13"
        for name in (
            "policies/m18-foundation-intake.json",
            *("scripts/" + name + ".py" for name in evaluation_gate.CONTRACT_FILES),
        ):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.make_intake()
        self.make_integrity()
        report, packet = self.fx.reports["M07"], self.fx.primaries["M07"]
        for name in ("contracts", "native", "budget"):
            raw = transfer.final.blob(self.state, packet["artifact_hashes"][name])
            target = self.state / "evaluation-gate" / packet["campaign_id"] / (name + ".json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        report["artifact_hashes"]["evaluation_gate"] = self.fx.pinfile(
            "evidence/evaluation-gate.json", packet
        )
        self.reports = {
            g: self.fx.pinfile("evidence/" + g + ".json", self.fx.reports[g])
            for g in ("M02", "M03", "M07")
        }

    def make_intake(self):
        expected = decode(bounded_read(self.root / "policies/m18-foundation-intake.json"))["M02"]
        report = self.fx.reports["M02"]
        report["cases"] = [
            dict(id=name, status="pass", actual=value, expected=True if value is True else "reject")
            for name, value in expected.items()
        ]
        report["metrics"]["checks"] = len(report["cases"])
        packet = self.fx.primaries["M02"] | dict(cases=report["cases"])
        report["artifact_hashes"] = {
            "data_qualification": self.fx.pinfile("evidence/data-qualification.json", packet)
        }

    def make_integrity(self):
        # Controlled policy/outcomes, following the existing M18 qualification
        # fixture. These are not observations of a live source SQL experiment.
        report, packet = self.fx.reports["M03"], self.fx.primaries["M03"]
        cases, refs, policy = [], {}, {}
        for name in ("filesystem", "storage", "pipeline"):
            case = dict(id="controlled", status="pass", expected="reject", actual="denied")
            refs[name] = self.fx.pinfile(
                "evidence/M03-" + name + ".json", dict(status="pass", cases=[case])
            )
            policy[name] = digest(canonical({"controlled": ["reject", "denied"]}))
            cases.append(case | {"id": name + ":controlled"})
        snapshot = self.fx.values["integrity_snapshot"]
        for name, value in (
            ("approved-sql-hashes-unchanged", snapshot),
            ("idempotent-sql-publication", self.fx.values["dataset_reference"]),
        ):
            cases.append(
                dict(id="integration:" + name, status="pass", expected=value, actual=value)
            )
        counts = dict(integration=2, filesystem=1, storage=1, pipeline=1)
        report.update(cases=cases, metrics=dict(checks=len(cases), **counts))
        packet.update(
            cases=cases,
            component_checks=counts,
            artifact_hashes=refs,
            approved_sql_hashes_before=snapshot,
            approved_sql_hashes_after=snapshot,
        )
        policy["case_inventory"] = digest(canonical(sorted(c["id"] for c in cases)))
        write_json(self.root / "policies/m18-integrity.json", policy)
        report["artifact_hashes"] = refs | {
            "integrity_qualification": self.fx.pinfile(
                "evidence/integrity-qualification.json", packet
            )
        }

    def seal(self, **changes):
        return companion.seal(
            self.root,
            self.state,
            **(dict(key=KEY, phase=self.phase, reports=self.reports, **self.owner) | changes),
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
                    reports=self.reports,
                    **self.owner,
                    expected_context=sealed["context"],
                    ciphertext_pin=sealed["ciphertext_sha256"],
                )
                | changes
            ),
        )

    def verify(self, sealed, **changes):
        with self.materialize(sealed, **changes) as (view, summary):
            for gate, pin in self.reports.items():
                report = transfer.final.published_report(view, gate, pin)
                serving_campaign.bind_report(gate, report, self.fx.values)
            return summary

    def rejected(self):
        return self.assertRaisesRegex(Rejected, "^ci_upstream_transfer_rejected$")

    def no_temporary(self):
        self.assertFalse(list((self.root / ".runtime/ci-upstream-transfers").glob("*")))

    def packet(self, sealed):
        return decode(
            ci_transfer.open(
                sealed["envelope"],
                key=KEY,
                expected_context=sealed["context"],
                expected_ciphertext_sha256=sealed["ciphertext_sha256"],
            )
        )

    def reencrypt(self, sealed, packet, **changes):
        return self.reencrypt_raw(sealed, canonical(packet), **changes)

    def reencrypt_raw(self, sealed, raw, **changes):
        context = sealed["context"] | dict(payload_sha256=digest(raw)) | changes
        envelope = ci_transfer.seal(raw, key=KEY, context=context)
        return sealed | dict(envelope=envelope, context=context, ciphertext_sha256=digest(envelope))

    def repin(self, gate):
        self.reports[gate] = self.fx.pinfile("evidence/" + gate + ".json", self.fx.reports[gate])

    @contextmanager
    def consumer_view(self):
        campaign = release_bundle.index(self.fx.package["envelope"], self.fx.keys["approver"])[
            "release_id"
        ]
        self.fx.proposal["campaign_id"] = campaign
        self.owner["freeze"][transfer.delivery.PROPOSAL] = self.fx.pinfile(
            transfer.delivery.PROPOSAL, self.fx.proposal
        )
        self.fixture.index["freeze"] = self.owner["freeze"].copy()
        self.owner["freeze_pin"] = self.fx.pinfile(transfer.RECEIPT, self.fixture.index)
        sealed = companion.bridge.seal(
            self.root, self.state, key=KEY, phase=self.phase, **self.owner
        )
        with consumer.materialize(
            self.root,
            sealed["envelope"],
            key=KEY,
            phase=self.phase,
            **self.owner,
            trust_key_path=self.fx.release.authorities.keys["root"],
            expected_context=sealed["context"],
            ciphertext_pin=sealed["ciphertext_sha256"],
            manifest_pin=sealed["manifest_sha256"],
        ) as result:
            yield result

    def test_opt_in_existing_consumer_workspace_preserves_keys_and_cleans_additions(self):
        with self.consumer_view() as (state, owner):
            sealed = self.seal()
            self.state = state
            pin = self.fx.reports["M02"]["artifact_hashes"]["data_qualification"]
            original = bounded_read(self.fx.state / "evidence/data-qualification.json")
            (state / transfer.CAS / pin).write_bytes(original)  # Already retained by this owner.
            before = {
                p.relative_to(state): digest(bounded_read(p))
                for p in state.rglob("*")
                if p.is_file()
            }
            paths = set(state.rglob("*"))
            with patch.object(key_files, "read", side_effect=AssertionError("no trust-key read")):
                with self.materialize(sealed, workspace_id=owner["workspace_id"]) as (
                    view,
                    summary,
                ):
                    self.assertEqual(view, state)
                    self.assertEqual(summary["reports"], self.reports)
                    for gate in companion.GATES:
                        serving_campaign.bind_report(
                            gate,
                            transfer.final.published_report(view, gate, self.reports[gate]),
                            self.fx.values,
                        )
            self.assertEqual(paths, set(state.rglob("*")))
            self.assertEqual(
                before,
                {
                    p.relative_to(state): digest(bounded_read(p))
                    for p in state.rglob("*")
                    if p.is_file()
                },
            )
            with self.assertRaisesRegex(RuntimeError, "consumer"):
                with self.materialize(sealed, workspace_id=owner["workspace_id"]):
                    raise RuntimeError("consumer")
            self.assertEqual(paths, set(state.rglob("*")))
        self.no_temporary()

    def test_consumer_owner_collision_and_existing_cas_tamper_fail_without_overwrite(self):
        with self.consumer_view() as (state, owner):
            sealed = self.seal()
            self.state = state
            for workspace in ("0" * 32, "../elsewhere", True):
                with self.rejected():
                    self.verify(sealed, workspace_id=workspace)
            path = state / "evidence/M02.json"
            path.write_bytes(b"keep-existing")
            with self.rejected():
                self.verify(sealed, workspace_id=owner["workspace_id"])
            self.assertEqual(path.read_bytes(), b"keep-existing")
            path.unlink()
            pin = self.fx.reports["M02"]["artifact_hashes"]["data_qualification"]
            target = state / transfer.CAS / pin
            target.write_bytes(b"wrong-existing-CAS")
            with self.rejected():
                self.verify(sealed, workspace_id=owner["workspace_id"])
            self.assertEqual(target.read_bytes(), b"wrong-existing-CAS")
            self.assertFalse(path.exists())
        self.no_temporary()

    def test_consumer_attachment_rechecks_time_and_rolls_back_partial_write(self):
        with self.consumer_view() as (state, owner):
            sealed = self.seal()
            self.state = state
            paths = set(state.rglob("*"))
            write = companion.atomic_write

            for effect in ("expired", "tampered", "write-failed"):
                self.clock = self.fixture.clock

                def delayed(path, content):
                    if path.is_relative_to(state):
                        if effect == "write-failed":
                            raise OSError("controlled attachment failure")
                        if effect == "tampered":
                            content = b"wrong bytes"
                        self.clock = self.fx.values["proposal_expires_at"] - 599
                    write(path, content)

                with patch.object(companion, "atomic_write", side_effect=delayed), self.rejected():
                    self.verify(sealed, workspace_id=owner["workspace_id"])
                self.assertEqual(paths, set(state.rglob("*")))
        self.no_temporary()

    def test_missing_extra_and_wrong_report_gate_set(self):
        for reports in (
            None,
            [],
            {},
            {"M02": self.reports["M02"]},
            self.reports | {"M01": "a" * 64},
            self.reports | {"M03": "0" * 64},
        ):
            with self.subTest(kind=type(reports).__name__), self.rejected():
                self.seal(reports=reports)
        sealed = self.seal()
        with self.rejected():
            self.verify(sealed, reports=self.reports | {"M07": "0" * 64})
        self.no_temporary()

    def test_foreign_candidate_source_image_and_sql_evidence_cannot_be_rehashed(self):
        report = self.fx.reports["M03"]
        original = copy.deepcopy(report)
        for field, value in (
            ("candidate_reference", "0" * 64),
            ("worker_image", "sha256:" + "0" * 64),
            ("source_fingerprint", "0" * 64),
            ("storage_config", "0" * 64),
        ):
            report["input_digests"][field] = value
            self.repin("M03")
            with self.subTest(field=field), self.rejected():
                self.seal()
            report.clear()
            report.update(copy.deepcopy(original))
        report["source_revision"] = "0" * 40
        self.repin("M03")
        with self.rejected():
            self.seal()
        self.no_temporary()

    def test_original_primary_pin_tamper_missing_and_wrong_outcomes(self):
        path = self.state / "evidence/M03-storage.json"
        raw = bounded_read(path)
        path.write_bytes(raw + b" ")
        with self.rejected():
            self.seal()
        path.unlink()
        with self.rejected():
            self.seal()
        path.write_bytes(raw)
        report = self.fx.reports["M02"]
        negative = next(c for c in report["cases"] if c["expected"] == "reject")
        negative["actual"] = "other_rejection"
        self.repin("M02")
        with self.rejected():
            self.seal()
        self.no_temporary()

    def test_missing_original_cases_not_replaced_with_new_success(self):
        self.fx.reports["M07"]["cases"].pop()
        self.repin("M07")
        with self.rejected():
            self.seal()

    def test_packet_extra_missing_traversal_and_secret_files(self):
        sealed = self.seal()
        original = self.packet(sealed)
        for name in ("evidence/extra.json", "../escape", "storage.json", "keys/trust.pem"):
            changed = copy.deepcopy(original)
            changed["files"][name] = signing.encode64(b"{}")
            with self.subTest(name=name), self.rejected():
                self.verify(self.reencrypt(sealed, changed))
        changed = copy.deepcopy(original)
        del changed["files"]["evidence/M02.json"]
        with self.rejected():
            self.verify(self.reencrypt(sealed, changed))
        changed["files"]["../M02.json"] = original["files"]["evidence/M02.json"]
        with self.rejected():
            self.verify(self.reencrypt(sealed, changed))
        self.no_temporary()

    def test_malformed_private_packet_and_file_encodings(self):
        sealed = self.seal()
        original = self.packet(sealed)
        for raw in (
            b"not-json",
            b"[]",
            b"{}",
            canonical(original) + b"\n",
            b'{"files":{},"files":{}}',
        ):
            with self.subTest(raw_size=len(raw)), self.rejected():
                self.verify(self.reencrypt_raw(sealed, raw))
        for value in (None, "!not-base64!", signing.encode64(b"")):
            changed = copy.deepcopy(original)
            changed["files"]["evidence/M02.json"] = value
            with self.rejected():
                self.verify(self.reencrypt(sealed, changed))
        changed = original | dict(files=[])
        with self.rejected():
            self.verify(self.reencrypt(sealed, changed))
        with patch.object(companion, "MAX_PACKET_BYTES", 1), self.rejected():
            self.verify(sealed)
        self.no_temporary()

    def test_transport_expiry_is_exact_original_bound_and_receiver_pins_mandatory(self):
        self.clock = self.fx.values["proposal_expires_at"] - 900
        sealed = self.seal()
        packet = self.packet(sealed)
        for delta in (-1, 1):
            changed = self.reencrypt(
                sealed, packet, expires_at=sealed["context"]["expires_at"] + delta
            )
            with self.rejected():
                self.verify(changed)
        arguments = dict(
            key=KEY,
            phase=self.phase,
            reports=self.reports,
            **self.owner,
            expected_context=sealed["context"],
            ciphertext_pin=sealed["ciphertext_sha256"],
        )
        for field in ("reports", "expected_context", "ciphertext_pin", "freeze_pin"):
            reduced = arguments.copy()
            del reduced[field]
            with self.assertRaises(TypeError):
                with companion.materialize(self.root, self.state, sealed["envelope"], **reduced):
                    self.fail("required independent expectation missing")
        self.no_temporary()

    def test_packet_and_external_authority_cannot_grant_foreign_ownership(self):
        sealed = self.seal()
        original = self.packet(sealed)
        for changes in (
            dict(schema_version=True),
            dict(kind="other"),
            dict(extra=1),
            dict(reports=self.reports | {"M03": "0" * 64}),
            dict(authority=self.owner | {"freeze_pin": "0" * 64}),
        ):
            with self.rejected():
                self.verify(self.reencrypt(sealed, original | changes))
        for changes in (
            dict(freeze_pin="0" * 64),
            dict(freeze={}),
            dict(expected=self.owner["expected"] | {"candidate_reference": "0" * 64}),
            dict(run_owner=self.owner["run_owner"] | {"run_attempt": 2}),
            dict(run_owner=self.owner["run_owner"] | {"producer_job": "foreign"}),
            dict(expected=self.owner["expected"] | {"source_revision": "0" * 40}),
            dict(phase="M14"),
            dict(phase="M11-M12"),
        ):
            with self.rejected():
                self.verify(sealed, **changes)
        self.no_temporary()

    def test_encrypted_tamper_wrong_key_pin_and_context(self):
        sealed = self.seal()
        for changes in (
            dict(key=b"wrong"),
            dict(key=b"x" * 32),
            dict(ciphertext_pin="0" * 64),
            dict(expected_context=None),
            dict(expected_context={}),
            dict(expected_context=sealed["context"] | {"phase": "M13"}),
        ):
            with self.rejected():
                self.verify(sealed, **changes)
        raw = sealed["envelope"][:-1] + bytes([sealed["envelope"][-1] ^ 1])
        with self.rejected():
            self.verify(sealed | dict(envelope=raw, ciphertext_sha256=digest(raw)))
        self.no_temporary()

    def test_report_and_campaign_path_types_and_bounds(self):
        path = self.state / "evidence/evaluation-gate.json"
        packet = decode(bounded_read(path))
        packet["campaign_id"] = "../outside"
        write_json(path, packet)
        with self.rejected():
            self.seal()
        with self.rejected():
            self.seal(phase=None)
        with self.rejected():
            self.seal(phase="M23")

    def test_oversize_files_packet_and_envelope(self):
        path = self.state / "evidence/data-qualification.json"
        original = bounded_read(path)
        path.write_bytes(b"x" * (transfer.final.LIMIT + 1))
        with self.rejected():
            self.seal()
        path.write_bytes(original)
        with patch.object(companion, "MAX_TOTAL_BYTES", 1), self.rejected():
            self.seal()
        with patch.object(companion, "MAX_PACKET_BYTES", 1), self.rejected():
            self.seal()
        sealed = self.seal()
        with patch.object(companion, "MAX_ENVELOPE_BYTES", 1), self.rejected():
            self.verify(sealed)
        self.no_temporary()

    def test_credential_fields_rejected_even_inside_pinned_reports(self):
        self.fx.reports["M02"]["raw_logs"] = ["private"]
        self.repin("M02")
        with self.rejected():
            self.seal()

    def test_stale_and_source_changes_block_handoff(self):
        sealed = self.seal()
        self.clock = self.fx.values["proposal_expires_at"] - 599
        for action in (self.seal, lambda: self.verify(sealed)):
            with self.rejected():
                action()
        self.clock = self.fixture.clock
        with patch.object(transfer.final, "clean", side_effect=Rejected("source changed")):
            with self.rejected():
                self.verify(sealed)
        self.no_temporary()

    def test_ciphertext_hash_latency_respects_conservative_boundary(self):
        current_ns = (self.fx.values["proposal_expires_at"] - 600) * 10**9
        original = companion.digest

        def delayed(raw):
            nonlocal current_ns
            pin = original(raw)
            if raw.startswith(ci_transfer.MAGIC):
                current_ns += 10_000_000
            return pin

        with (
            patch.object(time, "time_ns", side_effect=lambda: current_ns),
            patch.object(companion, "digest", side_effect=delayed),
            self.rejected(),
        ):
            self.seal()
        self.no_temporary()

    def test_post_materialization_expiry_and_failures_clean_only_owned_files(self):
        sealed = self.seal()
        sentinel = self.root / ".runtime/sibling"
        sentinel.write_bytes(b"keep")
        real_write = companion.atomic_write

        def delayed(path, raw):
            real_write(path, raw)
            self.clock = self.fx.values["proposal_expires_at"] - 599

        with patch.object(companion, "atomic_write", side_effect=delayed), self.rejected():
            self.verify(sealed)
        self.no_temporary()
        self.clock = self.fixture.clock
        with (
            patch.object(companion, "atomic_write", side_effect=OSError("private-detail")),
            self.rejected(),
        ):
            self.verify(sealed)
        with self.assertRaisesRegex(RuntimeError, "consumer"):
            with self.materialize(sealed) as (view, _):
                raise RuntimeError("consumer")
        self.assertFalse(view.exists())
        self.assertEqual(sentinel.read_bytes(), b"keep")
        self.no_temporary()

    def test_existing_early_default_remains_strict_and_intake_is_explicit(self):
        pins = {"M02": self.reports["M02"]}
        with self.assertRaises(Rejected):
            collector.verify_early(self.root, self.state, self.fx.values, pins)
        with self.assertRaises(Rejected):
            collector.verify_early(self.root, self.state, self.fx.values, pins, intake_only=1)
        self.assertEqual(
            collector.verify_early(self.root, self.state, self.fx.values, pins, intake_only=True),
            pins,
        )

    def test_exact_original_bytes_and_sql_pin_survive_new_frozen_view(self):
        originals = {
            str(p.relative_to(self.state)).replace("\\", "/"): bounded_read(p)
            for p in self.state.rglob("*.json")
            if "M18-objects" not in str(p)
        }
        sql_pin = self.fx.reports["M03"]["input_digests"]["storage_config"]
        write_json(self.state / "storage.json", {"workspace_id": "new-consumer-owner"})
        for phase in ("M13", "M14", "M15"):
            self.phase = phase
            sealed = self.seal()
            self.assertNotEqual(sealed["envelope"], self.seal()["envelope"])
            self.assertEqual(sealed["context"]["phase"], "upstream-" + phase)
            with (
                patch.object(storage, "get", side_effect=AssertionError("SQL read")),
                patch.object(storage, "put", side_effect=AssertionError("SQL write")),
                patch.object(signing, "load_key", side_effect=AssertionError("private key")),
            ):
                with self.materialize(sealed) as (view, summary):
                    self.assertNotEqual(view, self.state)
                    for name in self.packet(sealed)["files"]:
                        self.assertEqual(bounded_read(view / name), originals[name])
                    self.assertFalse((view / "storage.json").exists())
                    report = transfer.final.published_report(view, "M03", self.reports["M03"])
                    self.assertEqual(report["input_digests"]["storage_config"], sql_pin)
                    self.assertEqual(summary["reports"], self.reports)
                    self.assertIs(summary["release_ready"], False)
                    self.assertEqual(summary["handling"], "private")
                    for gate in companion.GATES:
                        serving_campaign.bind_report(
                            gate,
                            transfer.final.published_report(view, gate, self.reports[gate]),
                            self.fx.values,
                        )
            self.assertFalse(view.exists())
            self.no_temporary()

    def test_original_delivery_report_projection_preserved_without_reserialization(self):
        report = self.fx.reports["M02"] | dict(report_sha256=self.reports["M02"])
        path = self.state / "evidence/M02.json"
        write_json(path, report)
        original = bounded_read(path)
        sealed = self.seal()
        with self.materialize(sealed) as (view, _):
            self.assertEqual(bounded_read(view / "evidence/M02.json"), original)
            self.assertEqual(
                transfer.final.published_report(view, "M02", self.reports["M02"]),
                self.fx.reports["M02"],
            )


if __name__ == "__main__":
    unittest.main()
