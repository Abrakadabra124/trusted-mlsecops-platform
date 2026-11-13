"""Signed fixture composition. Native campaign entry points are replaced before capture."""

import copy
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from mlsecops import security_gate_sources as gate
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import security_event_sequence_native_qualification as seq_fixtures
from scripts import security_identity_evidence_qualification as id_fixtures
from scripts import security_source_campaign_qualification as intake_fixtures
from scripts import security_trust_evidence_qualification as trust_fixtures


class GateSources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        cls.root = Path(stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        cls.state = cls.root / ".runtime"
        for name in {
            *gate.identity.METHOD_FILES,
            *gate.trust.METHOD_FILES,
            "scripts/security_event_sequence_native.py",
            "scripts/security_source_campaign.py",
            "mlsecops/security_gate_sources.py",
            "data.lock",
            "uv.lock",
            "pyproject.toml",
            ".python-version",
            "Dockerfile",
            "policies/local-cpu.json",
        }:
            destination = cls.root / name
            destination.parent.mkdir(exist_ok=True)
            destination.write_bytes((gate.CHECKOUT / name).read_bytes())
        cls.source = dict(source="a" * 40, fingerprint=gate.source_fingerprint(cls.root))
        cls.methods = gate.materials(cls.root)
        stack.enter_context(
            patch.object(
                gate,
                "command",
                side_effect=lambda argv: "" if "status" in argv else cls.source["source"],
            )
        )
        stack.enter_context(patch.object(gate, "CHECKOUT", cls.root))

        def fixture(test):
            instance = test("runTest")
            stack.callback(instance.doCleanups)
            instance.setUp()
            return instance

        # Serialize the native file contracts using in-memory observations and fresh
        # synthetic signing keys. No process, store or network is started.
        intake = fixture(intake_fixtures.SourceCampaign)
        intake.expected.update(**cls.source, materials=cls.methods, transport="owned-linux-http")
        intake.packet.update(
            **cls.source,
            fingerprint_after=cls.source["fingerprint"],
            method_materials=cls.methods,
            materials_after=cls.methods,
        )
        campaign = intake.packet["campaign"]
        campaign["transport_scope"] = intake.expected["transport"]
        # A valid, slower manual delivery must never enter artifact.rejected's maximum.
        bundle = campaign["bundle"]
        record = bundle["collector"]["records"][-1]
        receipt = signing.verify(
            record["receipt"], "security-event-receipt", intake.publics["receipt"]
        )
        receipt["routed_at_ms"] = receipt["ingested_at_ms"] + 5000
        signed = signing.sign(receipt, "security-event-receipt", intake.keys["receipt"])
        for document in (bundle["collector"], bundle["outboxes"][0]):
            document["records"][-1]["receipt"] = signed
            document["updated_at_ms"] = receipt["routed_at_ms"]
        bundle["incidents"][-1]["receipt"] = signed
        bundle["registry"]["clock_ms"] = receipt["routed_at_ms"]
        intake.refresh_delivery(intake.packet)

        identity = fixture(id_fixtures.IdentityEvidence)
        identity.owner.update(
            **cls.source, method_materials={k: cls.methods[k] for k in gate.identity.METHOD_FILES}
        )
        # A middle denial is the slowest, independently of the last identity receipt.
        ingested = identity.packet["delivery"]["collector"]["records"][2]["ingested_at_ms"]
        identity.packet = identity.receipt_packet(
            2, ingested_at_ms=ingested, routed_at_ms=ingested + 9
        )
        identity.packet.update(**cls.source, method_materials=identity.owner["method_materials"])
        identity.packet["summary"].update(cls.source)
        trust = fixture(trust_fixtures.TrustEvidence)
        trust_pins = trust.options()
        trust_pins.update(
            expected_fingerprint=cls.source["fingerprint"],
            expected_materials=gate.trust_native.method_materials(cls.root),
        )
        trust.packet.update(**cls.source, materials=trust_pins["expected_materials"])
        sequence = fixture(seq_fixtures.SequencePacketContracts)
        seq_packet = sequence.packet()
        seq_packet.update(**cls.source, fingerprint_after=cls.source["fingerprint"])
        # Give the first scheduled sequence notice a distinct, larger signed delay.
        mode = seq_packet["modes"][0]
        old = mode["captures"]["noticed"]["state"]["records"][-1]
        timing = signing.verify(
            old["receipt"], "security-event-receipt", sequence.fx.publics["receipt"]
        )
        timing["routed_at_ms"] = timing["ingested_at_ms"] + 17
        new = signing.sign(timing, "security-event-receipt", sequence.fx.keys["receipt"])
        for phase in ("noticed", "healed", "final"):
            sample = mode["captures"][phase]
            for row in [*sample["state"]["records"], *sample["incidents"]]:
                if row["envelope"] == old["envelope"]:
                    row["receipt"] = new
            sample["state"]["updated_at_ms"] = max(
                sample["state"]["updated_at_ms"], timing["routed_at_ms"]
            )

        cls.calls = []

        def retain(name, fn):
            def run():
                cls.calls.append(name)
                return fn()

            return run

        for name, module, fn in (
            (
                "intake",
                gate.intake_native,
                lambda: gate.intake_native.retain(
                    intake.packet, cls.root / gate.intake_native.PACKET, expected=intake.expected
                ),
            ),
            (
                "identity",
                gate.identity_native,
                lambda: gate.identity.retain(cls.root, identity.packet, expected=identity.owner),
            ),
            (
                "trust",
                gate.trust_native,
                lambda: gate.trust_native.retain_packet(cls.root, trust.packet, **trust_pins),
            ),
            (
                "sequence",
                gate.sequence,
                lambda: gate.sequence.retain_packet(
                    seq_packet,
                    cls.root / gate.sequence.PACKET_PATH,
                    expected_source=cls.source["source"],
                    expected_fingerprint=cls.source["fingerprint"],
                ),
            ),
        ):
            stack.enter_context(patch.object(module, "qualify", side_effect=retain(name, fn)))
        cls.manifest = gate.capture(cls.root, cls.state)
        cls.capture_order = tuple(cls.calls)
        cls.golden = {
            p.relative_to(cls.state).as_posix(): p.read_bytes() for p in cls.state.rglob("*.json")
        }
        cls.intake_routes = {}
        for row in campaign["delivery_verification"]["events"]:
            kind = row["kind"]
            cls.intake_routes[kind] = max(cls.intake_routes.get(kind, 0), row["delivery_ms"])
        cls.foreign_sequence = fixture(seq_fixtures.SequencePacketContracts).packet()
        cls.foreign_sequence.update(**cls.source, fingerprint_after=cls.source["fingerprint"])

    def setUp(self):
        self.pins = copy.deepcopy(self.manifest)

    def change(self, name, raw):
        path = self.state / name
        self.addCleanup(path.write_bytes, path.read_bytes())
        path.write_bytes(raw)
        return digest(raw)

    def replay(self):
        return gate.replay(self.root, self.state, self.pins)

    def test_actual_file_contract_and_worst_signed_route(self):
        self.assertEqual(self.capture_order, ("intake", "identity", "trust", "sequence"))
        value = self.replay()
        self.assertEqual(
            set(value),
            {
                "cases",
                "routes",
                "artifact_hashes",
                "sequence_notice_seconds",
                "heartbeat_notice_seconds",
            },
        )
        self.assertEqual(len(self.golden), 7)
        self.assertEqual(
            value["artifact_hashes"], {k: digest(raw) for k, raw in self.golden.items()}
        )
        self.assertEqual(len(value["cases"]), len(set(value["cases"])))
        self.assertEqual(
            [
                sum(case.startswith(name + ":") for case in value["cases"])
                for name in self.capture_order
            ],
            [3, 46, 17, 25],
        )
        self.assertEqual(
            value["routes"],
            {**self.intake_routes, "trust.revoked": 0, "identity.denied": 9, "telemetry.gap": 17},
        )
        self.assertLess(value["routes"]["artifact.rejected"], 5000)
        self.assertTrue(all(type(v) is int for v in value["routes"].values()))
        self.assertAlmostEqual(value["heartbeat_notice_seconds"], 90.1)
        self.assertEqual(
            value["sequence_notice_seconds"], {"ingest-hole": 90.101, "heartbeat-head-only": 90.101}
        )

    def test_rejects_summary_unknown_stage_and_foreign_runtime(self):
        for state, manifest in (
            (self.state, {"status": "pass"}),
            (self.root / "external", self.pins),
            (self.state, {**self.pins, "foo": {}}),
        ):
            with self.subTest(state=state), self.assertRaises(Rejected):
                gate.replay(self.root, state, manifest)
        with self.assertRaises(Rejected):
            gate.capture(self.root.parent, self.root.parent / ".runtime")

    def test_all_seven_exact_byte_pins_and_missing_owner(self):
        for name, raw in self.golden.items():
            with self.subTest(name=name):
                self.change(name, raw + b" ")
                with self.assertRaises(Rejected):
                    self.replay()
                (self.state / name).write_bytes(raw)
        name = next(n for n in self.golden if n.endswith(".binding.json"))
        (self.state / name).unlink()
        self.addCleanup((self.state / name).write_bytes, self.golden[name])
        with self.assertRaises(Rejected):
            self.replay()

    def test_rehashed_noncanonical_source_primary_and_swapped_digests(self):
        name = "evidence/security-source-private.json"
        pins = self.pins["intake"]
        self.assertEqual(pins["primary_sha256"], digest(self.golden[name][:-1]))
        pins["primary_file_sha256"] = self.change(name, self.golden[name].rstrip())
        with self.assertRaises(Rejected):
            self.replay()

    def test_foreign_sequence_is_valid_under_own_keys_but_rejected_by_first_pin(self):
        foreign = self.foreign_sequence
        result = gate.sequence.verify(
            foreign,
            expected_source=self.source["source"],
            expected_fingerprint=self.source["fingerprint"],
        )
        self.assertNotEqual(result["primary_sha256"], self.pins["sequence"]["primary_sha256"])
        self.change("evidence/security-sequence-private.json", canonical(foreign))
        with self.assertRaises(Rejected):
            self.replay()

    def test_rehashed_owner_cannot_be_replaced_with_packet_authority(self):
        for stage, key, value in (
            ("intake", "pin", "0" * 64),
            ("identity", "registry_sha256", "0" * 64),
            ("trust", "expected_trust_root", "bogus"),
        ):
            with self.subTest(stage=stage):
                name = next(
                    n
                    for n, raw in self.golden.items()
                    if digest(raw) == self.manifest[stage]["binding_sha256"]
                )
                owner = decode(self.golden[name])
                owner.get("expected", owner)[key] = value
                raw = canonical(owner) + (b"\n" if stage == "intake" else b"")
                self.pins[stage]["binding_sha256"] = self.change(name, raw)
                with self.assertRaises(Rejected):
                    self.replay()
                (self.state / name).write_bytes(self.golden[name])
                self.pins[stage] = self.manifest[stage].copy()

    def test_rehashed_nonhosted_transport_and_unconfirmed_cleanup(self):
        name = "evidence/security-source-private.json"
        owner_name = "evidence/security-source-private.bindings.json"
        for change in ("controlled", "cleanup", "case"):
            packet, owner = decode(self.golden[name]), decode(self.golden[owner_name])
            campaign = packet["campaign"]
            if change == "controlled":
                owner["expected"]["transport"] = campaign["transport_scope"] = (
                    "controlled-in-memory"
                )
            elif change == "cleanup":
                campaign["cleanup"]["fixture_cleanups_confirmed"] = False
            else:
                campaign["source_observations"].pop()
            content = canonical(packet)
            file_pin = self.change(name, content + b"\n")
            owner["primary_sha256"] = file_pin
            self.pins["intake"].update(
                primary_sha256=digest(content),
                primary_file_sha256=file_pin,
                binding_sha256=self.change(owner_name, canonical(owner) + b"\n"),
            )
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.replay()

    def test_current_source_methods_and_exact_manifest(self):
        for mutate in (
            lambda m: m["source"].update(source="0" * 40),
            lambda m: m["source"].update(methods_sha256="0" * 64),
            lambda m: m["identity"].update(primary_sha256="../outside"),
            lambda m: m["intake"].update(primary_sha256=m["intake"]["primary_file_sha256"]),
            lambda m: m["sequence"].update(status="pass"),
            lambda m: m["trust"].update(run_id="../../outside"),
            lambda m: m["trust"].pop("binding_sha256"),
        ):
            self.pins = copy.deepcopy(self.manifest)
            mutate(self.pins)
            with self.assertRaises(Rejected):
                self.replay()

    def test_capture_rejects_summary_status_and_nonunique_trust_pair(self):
        with (
            patch.object(gate.intake_native, "qualify", return_value={"status": "fail"}),
            self.assertRaises(Rejected),
        ):
            gate.capture(self.root, self.state)
        stub = dict(status="pass", release_ready=False, cases=[], **self.source)
        with ExitStack() as patches:
            for name, module in (
                ("intake", gate.intake_native),
                ("identity", gate.identity_native),
                ("trust", gate.trust_native),
            ):
                patches.enter_context(
                    patch.object(module, "qualify", return_value={**stub, **self.pins[name]})
                )
            with self.assertRaises(Rejected):
                gate.capture(self.root, self.state)

    def test_method_drift_and_dirty_source_reject_offline(self):
        path = self.root / "scripts/security_event_sequence_native.py"
        self.addCleanup(path.write_bytes, path.read_bytes())
        path.write_bytes(path.read_bytes() + b"# changed method\n")
        with self.assertRaises(Rejected):
            self.replay()
        with (
            patch.object(gate, "command", return_value=" M tracked.py"),
            self.assertRaises(Rejected),
        ):
            self.replay()

    def test_capture_rejects_substitution_between_qualify_and_manifest(self):
        name = "evidence/security-sequence-private.json"

        def swap():
            self.change(name, canonical(self.foreign_sequence))
            return dict(
                status="pass",
                release_ready=False,
                cases=[],
                **self.source,
                **self.manifest["sequence"],
            )

        with patch.object(gate.sequence, "qualify", side_effect=swap):
            with patch.object(gate.sequence, "verify", wraps=gate.sequence.verify) as verify:
                with self.assertRaisesRegex(Rejected, "M23_source_replay_invalid"):
                    gate.capture(self.root, self.state)
                verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
