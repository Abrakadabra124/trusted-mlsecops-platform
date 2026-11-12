"""Controlled lifecycle checks for the actual-candidate M23 probe."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import security_outage_probe as probe
from mlsecops.contracts import Rejected
from scripts.security_outage_packet_qualification import fixture


class ProbeContracts(unittest.TestCase):
    def test_child_failure_keeps_only_public_locations_without_exception_text(self):
        with (
            patch.object(probe, "enforce", side_effect=KeyError("PRIVATE-marker")),
            patch("sys.stdout", io.StringIO()) as output,
        ):
            self.assertEqual(probe.main(), 1)
        value = json.loads(output.getvalue())
        self.assertNotIn("PRIVATE-marker", output.getvalue())
        self.assertEqual(value["locations"][0]["exception"], "KeyError")
        self.assertEqual(value["locations"][0]["source_file"], "mlsecops/security_outage_probe.py")
        self.assertGreater(value["locations"][0]["source_line"], 0)

    def test_cleanup_context_is_bounded_and_cycles_do_not_expose_messages(self):
        first, second = KeyError("PRIVATE-first"), RuntimeError("PRIVATE-second")
        first.__cause__ = second
        second.__context__ = first
        value = probe.locations(first)
        self.assertEqual(len(value), 2)
        self.assertEqual([entry["exception"] for entry in value], ["KeyError", "other"])
        self.assertNotIn("PRIVATE", json.dumps(value))

    def test_phase_campaign_keeps_observing_until_ack_and_records_all_fault_boundaries(self):
        value, ref, trace, golden = fixture()
        channel = Mock()
        channel.poll.side_effect = [
            None,
            {},
            None,
            {},
            None,
            {},
            None,
            {},
        ]
        items = []

        def cycle(*args):
            phase = args[-1]
            items.append(phase)
            return {"phase": phase}

        with patch.object(probe, "cycle", side_effect=cycle):
            result = probe.campaign(1, "t", "o", Mock(), {}, channel)
        self.assertEqual(
            [call.args[0] for call in channel.begin.call_args_list],
            ["ready", "outage", "attempt", "recover"],
        )
        self.assertEqual(
            items,
            [
                "ready",
                "ready",
                "ready",
                "ready",
                "ready",
                "outage",
                "outage",
                "outage",
                "attempt",
                "attempt",
                "attempt",
                "recover",
            ],
        )
        self.assertEqual(result, [{"phase": phase} for phase in items])

    def test_failed_operator_ack_stops_before_next_transition(self):
        channel = Mock()
        channel.poll.side_effect = Rejected("security_exchange_refused")
        with patch.object(probe, "cycle", return_value={}), self.assertRaises(Rejected):
            probe.campaign(1, "t", "o", Mock(), {}, channel)
        self.assertEqual(channel.begin.call_count, 1)

    def test_lost_monitor_or_missing_window_rejected(self):
        expected = {
            "features": [[0.1] * 6],
            "monitoring": {"rows": [{"features": [0.1] * 6}] * 1000},
        }
        response = {"schema_version": 1}
        for state in (
            {"faults": ["clock"]},
            {"faults": [], "observations": 0, "pending_windows": 1},
        ):
            with (
                patch.object(probe, "request", return_value=response),
                patch.object(probe, "capture", return_value={"state": state, "windows": []}),
                patch.object(probe.time, "sleep"),
                patch.object(probe.time, "monotonic", side_effect=[0, 11]),
                self.assertRaises(Rejected),
            ):
                probe.cycle(1, "t", "o", Mock(), expected, "outage")

    def test_preexisting_worker_refuses_before_monitor_or_trust_creation(self):
        client = Mock()
        client.request.return_value = {"items": [{}]}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(probe, "DIRECTORY", Path(temporary) / "exchange"),
            patch.object(probe, "Client", return_value=client),
            patch.object(probe.trust_session, "Session") as session,
            self.assertRaises(Rejected),
        ):
            probe.qualify({}, {})
        session.assert_not_called()


if __name__ == "__main__":
    unittest.main()
