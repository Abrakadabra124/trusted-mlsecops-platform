"""Fixed phase protocol; no infrastructure is started by these tests."""

import copy
import tempfile
import unittest
from pathlib import Path

from mlsecops import security_outage_exchange as exchange
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json


class PhaseContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.clock = 10.0
        self.channel = exchange.Channel(self.root, "a" * 32, clock=lambda: self.clock)

    def ack(self, **changes):
        request = read_json(self.root / "request.json")
        value = dict(
            phase=request["phase"],
            request_sha256=digest(canonical(request)),
            status="pass",
            result={"accepted": True},
        )
        value.update(changes)
        write_json(self.root / (request["phase"] + "-ack.json"), value)

    def test_all_phases_require_exact_ack_and_cannot_reuse_previous_result(self):
        for phase in exchange.PHASES:
            self.channel.begin(phase, {"context": "b" * 64})
            self.assertIsNone(self.channel.poll())
            self.ack()
            self.assertEqual(self.channel.poll(), {"accepted": True})
        with self.assertRaises(Rejected):
            self.channel.begin("finish", {})

    def test_reordered_repeated_or_overlapping_request_rejected_before_write(self):
        with self.assertRaises(Rejected):
            self.channel.begin("outage", {})
        self.assertFalse((self.root / "request.json").exists())
        self.channel.begin("ready", {})
        original = (self.root / "request.json").read_bytes()
        for phase in ("ready", "outage"):
            with self.assertRaises(Rejected):
                self.channel.begin(phase, {})
            self.assertEqual((self.root / "request.json").read_bytes(), original)

    def test_changed_ack_or_failed_result_cannot_advance(self):
        for changes in (
            {"phase": "outage"},
            {"request_sha256": "b" * 64},
            {"status": "fail"},
            {"result": []},
            {"extra": "PRIVATE"},
        ):
            with self.subTest(changes=changes):
                self.channel = exchange.Channel(self.root, "a" * 32, clock=lambda: self.clock)
                self.channel.begin("ready", {})
                self.ack(**changes)
                with self.assertRaises(Rejected):
                    self.channel.poll()
                with self.assertRaises(Rejected):
                    self.channel.begin("outage", {})

    def test_deadline_covers_ack_read_and_late_existing_ack_is_rejected(self):
        self.channel.begin("ready", {})
        self.ack()
        self.clock += exchange.TIMEOUT
        with self.assertRaises(Rejected):
            self.channel.poll()

    def test_deadline_missing_ack_and_poll_without_request(self):
        with self.assertRaises(Rejected):
            self.channel.poll()
        self.channel.begin("ready", {})
        self.clock += exchange.TIMEOUT
        with self.assertRaises(Rejected):
            self.channel.poll()

    def test_request_and_ack_contracts_are_bounded_and_strict(self):
        for campaign in ("", "g" * 32, "a" * 31, True, ["a" * 32]):
            with self.assertRaises(Rejected):
                exchange.Channel(self.root, campaign)
        with self.assertRaises(Rejected):
            self.channel.begin("ready", [])
        with self.assertRaises(Rejected):
            self.channel.begin("ready", {"huge": "x" * exchange.MAX_PACKET})
        self.assertFalse((self.root / "request.json").exists())
        valid = {"phase": "ready", "campaign": "a" * 32, "payload": {}}
        self.assertEqual(exchange.request(valid), valid)
        for field, value in (("phase", "start"), ("campaign", "a" * 33), ("payload", [])):
            bad = copy.deepcopy(valid)
            bad[field] = value
            with self.assertRaises(Rejected):
                exchange.request(bad)


if __name__ == "__main__":
    unittest.main()
