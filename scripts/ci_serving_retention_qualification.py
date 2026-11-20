"""Durable private export: real signatures/readers, controlled native observations."""

import copy
import importlib
import importlib.util
import io
import os
import shutil
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import evaluation_gate, signing
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, write_json
from scripts import ci_upstream_transfer_qualification as upstream_fixtures
from scripts import m18_serving_retention_qualification as serving_fixtures
from scripts import performance_delivery_qualification as delivery_fixtures

ROOT = Path(__file__).resolve().parents[1]


class ServingExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        serving_fixtures.ServingPrimaryTests.setUpClass()
        cls.addClassCleanup(serving_fixtures.ServingPrimaryTests.doClassCleanups)

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("scripts.ci_serving_retention"),
            "durable serving export is required before consumer deletion",
        )
        self.exporter = importlib.import_module("scripts.ci_serving_retention")
        original = delivery_fixtures.DeliveryContracts.runtime
        sequence = iter((0, 60, 120))

        def runtime(fx, gate):
            captured = fx.fx.values["captured_at"]
            fx.fx.values["captured_at"] = captured + next(sequence)
            try:
                return original(fx, gate)
            finally:
                fx.fx.values["captured_at"] = captured

        self.fixture = serving_fixtures.ServingPrimaryTests()
        self.addCleanup(self.fixture.doCleanups)
        with patch.object(delivery_fixtures.DeliveryContracts, "runtime", runtime):
            self.fixture.setUp()
        self.root, self.state = self.fixture.root, self.fixture.state
        self.fx = self.fixture.fixture.fx
        # The existing trio fixture uses controlled native arithmetic/audit I/O;
        # signed package, permit, identity and ordinary replay remain real.
        for name in (
            "policies/m18-foundation-intake.json",
            *("scripts/" + name + ".py" for name in evaluation_gate.CONTRACT_FILES),
        ):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        upstream_fixtures.UpstreamTransferTests.make_intake(self)
        upstream_fixtures.UpstreamTransferTests.make_integrity(self)
        packet = self.fx.primaries["M07"]
        for name in ("contracts", "native", "budget"):
            raw = self.exporter.final.blob(self.state, packet["artifact_hashes"][name])
            path = self.state / "evaluation-gate" / packet["campaign_id"] / (name + ".json")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.fx.reports["M07"]["artifact_hashes"]["evaluation_gate"] = self.fx.pinfile(
            "evidence/evaluation-gate.json", packet
        )
        reports = dict(self.fixture.reports)
        reports.update(
            {
                g: self.fx.pinfile("evidence/" + g + ".json", self.fx.reports[g])
                for g in ("M02", "M03", "M07")
            }
        )
        index = dict(self.fixture.index, schema_version=1)
        freeze_pin = self.fx.pinfile(self.exporter.transfer.RECEIPT, index)
        storage_pin = self.fx.pinfile("storage.json", {"workspace_id": "f" * 32})
        nodes = [
            dict(namespace=digest(bytes([i])), volume=digest(bytes([i + 3]))) for i in range(3)
        ]
        self.owner = dict(
            freeze_pin=freeze_pin,
            freeze=copy.deepcopy(index["freeze"]),
            expected={k: self.fx.values[k] for k in self.exporter.transfer.IDENTITY},
            run_owner=dict(
                repository="example/platform", run_id=123, run_attempt=1, producer_job="candidate"
            ),
            report_pins=reports,
            admission_pins=copy.deepcopy(self.fixture.admissions),
            transitions=[
                dict(before=nodes[i], after=nodes[i + 1], source_sql=storage_pin) for i in range(2)
            ],
            consumer_storage_pin=storage_pin,
        )
        # Move the complete disposable state to an independent owned context.
        # An exporter that writes inside this context will lose its output below.
        self.state = self.root / ".runtime/consumer"
        former = self.root / "fixture-state"
        (self.root / ".runtime").rename(former)
        self.state.parent.mkdir()
        former.rename(self.state)
        self.destination = self.root / ".runtime/durable-serving"
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("no subprocess")))
        self.enterContext(
            patch.object(signing, "create_key", side_effect=AssertionError("no new keys"))
        )
        self.enterContext(
            patch.object(signing, "sign", side_effect=AssertionError("no new signatures"))
        )

    def retain(self, **changes):
        return self.exporter.retain(
            self.root, self.state, self.destination, **(self.owner | changes)
        )

    def replay(self, result, **changes):
        return self.exporter.replay(
            self.root, self.destination, index_pin=result["index_pin"], **(self.owner | changes)
        )

    def test_wrong_report_pin_rejects_without_destination_or_temporary_files(self):
        reports = dict(self.owner["report_pins"], M13="0" * 64)
        with self.assertRaises((Rejected, OSError)):
            self.retain(report_pins=reports)
        self.assertEqual({p.name for p in self.state.parent.iterdir()}, {"consumer"})

    def test_complete_export_survives_context_deletion_and_historical_expiry(self):
        before = {
            p.relative_to(self.state): p.read_bytes() for p in self.state.rglob("*") if p.is_file()
        }
        with redirect_stdout(io.StringIO()) as output:
            result = self.retain()
        self.assertEqual(output.getvalue(), "")
        self.assertFalse(result["release_ready"])
        self.assertEqual(
            before,
            {
                p.relative_to(self.state): p.read_bytes()
                for p in self.state.rglob("*")
                if p.is_file()
            },
        )
        self.assertEqual(self.retain(), result)
        shutil.rmtree(self.state)
        with (
            patch.object(self.exporter.final, "now", return_value="2099-01-01T00:00:00+00:00"),
            patch.object(self.exporter.frozen, "now", return_value="2099-01-01T00:00:00+00:00"),
            patch.object(time, "time_ns", return_value=4070908800 * 10**9),
        ):
            replay = self.replay(result)
        self.assertFalse(replay["release_ready"])
        self.assertEqual(replay["receipt"]["reports"], self.owner["report_pins"])
        self.assertEqual(replay["receipt"]["source_files"], self.owner["freeze"])
        self.assertEqual(
            {p.name for p in self.destination.parent.iterdir()}, {self.destination.name}
        )

    def assert_no_export(self):
        self.assertEqual({p.name for p in self.state.parent.iterdir()}, {"consumer"})

    def archive(self, result):
        return decode(self.exporter.final.blob(self.destination, result["index_pin"]))

    def repin_index(self, result, change):
        record = self.archive(result)
        change(record)
        raw = canonical(record) + b"\n"
        old = self.destination / self.exporter.transfer.CAS / result["index_pin"]
        old.unlink()
        pin = self.exporter.final.retain(self.destination, raw)
        return result | dict(index_pin=pin)

    def test_required_primary_files_and_model_missing_or_tampered_fail_closed(self):
        for name in (
            "evidence/M02.json",
            "evidence/M03-filesystem.json",
            "evaluation-gate/" + self.fx.primaries["M07"]["campaign_id"] + "/budget.json",
            "evidence/M18-frozen-inputs.json",
            "storage.json",
            "evidence/privacy/" + "a" * 32 + "/audit-evidence/packet.json",
            self.exporter.transfer.CAS + self.owner["expected"]["model_sha256"],
        ):
            path = self.state / name
            original = path.read_bytes()
            for replacement in (None, original + b"tamper"):
                with self.subTest(name=name, missing=replacement is None):
                    if replacement is None:
                        path.unlink()
                    else:
                        path.write_bytes(replacement)
                    with self.assertRaises((Rejected, OSError, KeyError)):
                        self.retain()
                    self.assert_no_export()
                    path.write_bytes(original)

    def test_each_external_pin_map_and_source_identity_is_enforced(self):
        changes = [dict(freeze_pin="0" * 64), dict(consumer_storage_pin="0" * 64)]
        for name in ("report_pins", "admission_pins", "freeze"):
            for key in self.owner[name]:
                changes.append({name: self.owner[name] | {key: "0" * 64}})
            changes.extend(({name: {}}, {name: self.owner[name] | {"foreign": "0" * 64}}))
        for key in self.owner["expected"]:
            value = (
                "sha256:" + "0" * 64
                if key == "image_id"
                else "0" * (40 if key == "source_revision" else 64)
            )
            changes.append(dict(expected=self.owner["expected"] | {key: value}))
        for changeset in changes:
            with self.subTest(changes=tuple(changeset)), self.assertRaises((Rejected, OSError)):
                self.retain(**changeset)
            self.assert_no_export()

    def test_replay_uses_external_owner_not_index_authority(self):
        result = self.retain()
        for field, value in (
            ("repository", "foreign/project"),
            ("run_id", 124),
            ("run_attempt", 2),
            ("producer_job", "foreign"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.replay(result, run_owner=self.owner["run_owner"] | {field: value})
        altered = self.repin_index(result, lambda r: r["authority"]["run_owner"].update(run_id=124))
        with self.assertRaises(Rejected):
            self.replay(altered)

    def test_invalid_transition_shape_chain_and_owner_are_rejected(self):
        for steps in ([], self.owner["transitions"][:1], self.owner["transitions"] * 2):
            with self.assertRaises(Rejected):
                self.retain(transitions=steps)
        for key in ("before", "after"):
            steps = copy.deepcopy(self.owner["transitions"])
            steps[0][key]["namespace"] = steps[1]["after"]["namespace"]
            with self.assertRaises(Rejected):
                self.retain(transitions=steps)
        with self.assertRaises(Rejected):
            self.retain(run_owner=self.owner["run_owner"] | dict(run_attempt=True))
        self.assert_no_export()

    def test_destination_cannot_overlap_consumer_or_escape_runtime(self):
        for target in (
            self.state,
            self.state / "archive",
            self.state.parent,
            self.root / "outside",
            self.state.parent / ".." / ".runtime/archive",
            self.state.parent / "missing-parent/archive",
        ):
            with self.subTest(target=target.name), self.assertRaises(Rejected):
                self.exporter.retain(self.root, self.state, target, **self.owner)
        self.assert_no_export()

    def test_foreign_destination_and_mid_export_collision_are_not_overwritten(self):
        self.destination.mkdir()
        foreign = self.destination / "foreign.txt"
        foreign.write_bytes(b"other owner")
        with self.assertRaises((Rejected, OSError)):
            self.retain()
        self.assertEqual(foreign.read_bytes(), b"other owner")
        foreign.unlink()
        self.destination.rmdir()
        replay = self.exporter.replay

        def collision(*args, **kwargs):
            result = replay(*args, **kwargs)
            self.destination.mkdir()
            foreign.write_bytes(b"new foreign owner")
            return result

        with (
            patch.object(self.exporter, "replay", side_effect=collision),
            self.assertRaises(Rejected),
        ):
            self.retain()
        self.assertEqual(foreign.read_bytes(), b"new foreign owner")
        self.assertEqual(
            {p.name for p in self.state.parent.iterdir()}, {"consumer", self.destination.name}
        )

    def test_original_authority_is_snapshotted_before_io(self):
        original = copy.deepcopy(self.owner)
        read = self.exporter.bounded_read
        mutated = False

        def change(path, limit=16 * 1024**2):
            nonlocal mutated
            if not mutated:
                mutated = True
                self.owner["run_owner"]["run_id"] = 999
                self.owner["report_pins"]["M13"] = "0" * 64
                self.owner["transitions"][0]["before"]["volume"] = "0" * 64
            return read(path, limit)

        with patch.object(self.exporter, "bounded_read", side_effect=change):
            result = self.retain()
        self.assertEqual(self.archive(result)["authority"], original)
        self.owner = original
        self.assertFalse(self.replay(result)["release_ready"])

    def test_preimage_deletion_corruption_and_extra_archive_files_reject(self):
        result = self.retain()
        record = self.archive(result)
        pin = record["files"]["evidence/load-contracts.json"]
        path = self.destination / self.exporter.transfer.CAS / pin
        raw = path.read_bytes()
        for changed in (None, raw + b"bad"):
            if changed is None:
                path.unlink()
            else:
                path.write_bytes(changed)
            with self.assertRaises((Rejected, OSError)):
                self.replay(result)
            path.write_bytes(raw)
        for parent in (self.destination, self.destination / "evidence", path.parent):
            foreign = parent / "foreign"
            foreign.write_bytes(b"foreign")
            with self.assertRaises(Rejected):
                self.replay(result)
            foreign.unlink()

    def test_consumer_secrets_logs_and_unrelated_cas_are_never_exported(self):
        for name in (
            "keys/signer.pem",
            "kubeconfig",
            "evidence/private.log",
            self.exporter.transfer.CAS + digest(b"unrelated"),
        ):
            path = self.state / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"-----BEGIN " + b"PRIVATE KEY-----\nnot for export")
        result = self.retain()
        record = self.archive(result)
        self.assertNotIn(digest(b"unrelated"), record["objects"])
        self.assertNotIn("kubeconfig", record["files"])
        self.assertNotIn("evidence/private.log", record["files"])
        for pin in record["objects"]:
            self.assertNotIn(b"BEGIN PRIVATE KEY", self.exporter.final.blob(self.destination, pin))

    def test_write_and_reader_failure_remove_only_owned_staging(self):
        write = self.exporter.atomic_write
        calls = 0

        def fail_write(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("controlled write failure")
            return write(*args, **kwargs)

        with (
            patch.object(self.exporter, "atomic_write", side_effect=fail_write),
            self.assertRaises(OSError),
        ):
            self.retain()
        self.assert_no_export()
        with (
            patch.object(self.exporter.campaign, "replay", side_effect=Rejected("controlled")),
            self.assertRaises(Rejected),
        ):
            self.retain()
        self.assert_no_export()

    def test_source_changed_before_or_after_verification_is_rejected(self):
        with (
            patch.object(self.exporter.final, "clean", side_effect=Rejected("changed")),
            self.assertRaises(Rejected),
        ):
            self.retain()
        self.assert_no_export()
        ordinary = self.exporter.campaign.replay

        def changed(*args, **kwargs):
            result = ordinary(*args, **kwargs)
            self.fixture.clean.side_effect = Rejected("source changed during replay")
            return result

        with (
            patch.object(self.exporter.campaign, "replay", side_effect=changed),
            self.assertRaises(Rejected),
        ):
            self.retain()
        self.assert_no_export()

    def link_directory(self, original, link):
        if os.name == "nt":
            import _winapi

            _winapi.CreateJunction(str(original.resolve()), str(link.absolute()))
        else:
            link.symlink_to(original, target_is_directory=True)
        self.addCleanup(link.rmdir if os.name == "nt" else link.unlink)

    def test_linked_source_parent_is_rejected_before_collecting(self):
        link = self.state.parent / "alias"
        self.link_directory(self.state.parent, link)
        with self.assertRaises(Rejected):
            self.exporter.retain(self.root, link / "consumer", self.destination, **self.owner)

    def test_linked_destination_parent_is_rejected(self):
        link = self.state.parent / "alias"
        self.link_directory(self.state.parent, link)
        with self.assertRaises(Rejected):
            self.exporter.retain(self.root, self.state, link / "archive", **self.owner)

    def test_rehashed_invalid_original_permit_is_rejected_by_ordinary_reader(self):
        path = "candidate-inference/" + "a" * 32 + "/config.json"
        config = decode(bounded_read(self.state / path))
        signature = config["permit_envelope"]["signatures"][0]
        signature["sig"] = ("A" if signature["sig"][0] != "A" else "B") + signature["sig"][1:]
        write_json(self.state / path, config)
        value = self.fixture.values["M13"]
        value["artifact_hashes"]["config.json"] = digest(bounded_read(self.state / path))
        private = "evidence/kubernetes-privacy-private.json"
        write_json(self.state / private, value)
        admission = "evidence/privacy-gate-private.json"
        record = decode(bounded_read(self.state / admission))
        record["private_observation"] = digest(bounded_read(self.state / private))
        write_json(self.state / admission, record)
        self.owner["admission_pins"]["M13"] = digest(bounded_read(self.state / admission))
        with self.assertRaisesRegex(Rejected, "invalid_signature"):
            self.retain()
        self.assert_no_export()

    def test_canonical_contract_preimage_is_distinct_from_file_with_lf(self):
        result = self.retain()
        record = self.archive(result)
        raw = bounded_read(self.state / "evidence/privacy-contracts.json")
        self.assertEqual(record["files"]["evidence/privacy-contracts.json"], digest(raw))
        self.assertIn(digest(raw[:-1]), record["objects"])
        # Removing just the canonical map must fail even though the original LF file remains.
        (self.destination / self.exporter.transfer.CAS / digest(raw[:-1])).unlink()
        with self.assertRaises((Rejected, OSError)):
            self.replay(result)

    def test_index_repin_does_not_authorize_path_escape_extra_object_or_sizes(self):
        result = self.retain()
        record = self.archive(result)
        original = bounded_read(self.destination / self.exporter.transfer.CAS / result["index_pin"])
        one = next(iter(record["objects"]))
        mutations = (
            lambda r: r["files"].update({"../escape": one}),
            lambda r: r["files"].update({"keys/private.pem": one}),
            lambda r: r["objects"].update({"0" * 64: 1}),
            lambda r: r["objects"].update({one: True}),
            lambda r: r["objects"].update({one: 0}),
            lambda r: r["objects"].update({one: self.exporter.LIMIT + 1}),
            lambda r: r["objects"].update({one: r["objects"][one] + 1}),
            lambda r: r.update(files={}),
            lambda r: r.update(objects={}),
            lambda r: r.update(objects={p: self.exporter.LIMIT for p in r["objects"]}),
            lambda r: r.update(files={str(i): one for i in range(self.exporter.MAX_FILES + 1)}),
            lambda r: r.update(
                objects={f"{i:064x}": 1 for i in range(self.exporter.MAX_OBJECTS + 1)}
            ),
            lambda r: r.update(serving_pin="0" * 64),
            lambda r: r.update(unexpected=True),
        )
        for change in mutations:
            altered = self.repin_index(result, change)
            with self.assertRaises((Rejected, KeyError)):
                self.replay(altered)
            (self.destination / self.exporter.transfer.CAS / altered["index_pin"]).unlink()
            self.exporter.final.retain(self.destination, original)
        self.assertFalse((self.destination.parent / "escape").exists())

    def test_noncanonical_index_and_oversize_index_reject(self):
        result = self.retain()
        raw = bounded_read(self.destination / self.exporter.transfer.CAS / result["index_pin"])
        for changed in (raw + b"\n", b" " * (self.exporter.final.LIMIT + 1)):
            pin = self.exporter.final.retain(self.destination, changed)
            with self.assertRaises(Rejected):
                self.replay(result | dict(index_pin=pin))
            (self.destination / self.exporter.transfer.CAS / pin).unlink()

    def test_object_total_and_inventory_budgets_fail_before_publication(self):
        path = self.state / "evidence/M13.json"
        raw = path.read_bytes()
        path.write_bytes(b" " * (self.exporter.LIMIT + 1))
        with self.assertRaises(Rejected):
            self.retain()
        path.write_bytes(raw)
        for name, limit in (
            ("LIMIT", 1),
            ("TOTAL", self.exporter.final.LIMIT + 100),
            ("MAX_FILES", 1),
            ("MAX_OBJECTS", 1),
        ):
            with patch.object(self.exporter, name, limit), self.assertRaises(Rejected):
                self.retain()
        self.assert_no_export()

    def test_permit_outside_original_window_is_not_reauthorized(self):
        # Rehashed observation/admission still fails the original signed permit clock.
        private = "evidence/kubernetes-privacy-private.json"
        value = decode(bounded_read(self.state / private))
        value["finished_at"] = "2099-01-01T00:00:00+00:00"
        write_json(self.state / private, value)
        admission = "evidence/privacy-gate-private.json"
        record = decode(bounded_read(self.state / admission))
        record["private_observation"] = digest(bounded_read(self.state / private))
        write_json(self.state / admission, record)
        self.owner["admission_pins"]["M13"] = digest(bounded_read(self.state / admission))
        with self.assertRaises(Rejected):
            self.retain()
        self.assert_no_export()

    def test_foreign_artifact_reference_needs_preimage_and_original_reader_acceptance(self):
        path = self.state / "evidence/M03.json"
        report = decode(path.read_bytes())
        extra = canonical({"foreign": "artifact"})
        pin = digest(extra)
        report["artifact_hashes"]["foreign"] = pin
        write_json(path, report)
        self.owner["report_pins"]["M03"] = digest(path.read_bytes())
        with self.assertRaises((Rejected, OSError)):
            self.retain()
        self.exporter.final.retain(self.state, extra)
        with self.assertRaisesRegex(Rejected, "integrity-artifacts"):
            self.retain()
        self.assert_no_export()

    def test_rename_failure_cleans_staging_without_deleting_consumer(self):
        with (
            patch.object(Path, "rename", side_effect=OSError("controlled rename failure")),
            self.assertRaises(OSError),
        ):
            self.retain()
        self.assert_no_export()

    def test_foreign_archive_entry_stops_directory_enumeration_immediately(self):
        result = self.retain()
        original = Path.iterdir

        def entries(path):
            if path == self.destination.resolve():
                yield path / "foreign"
                raise AssertionError("continued enumerating a foreign archive")
            yield from original(path)

        with patch.object(Path, "iterdir", entries), self.assertRaises(Rejected):
            self.replay(result)


if __name__ == "__main__":
    unittest.main()
