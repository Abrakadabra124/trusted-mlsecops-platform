"""Controlled lifecycle checks for the actual-candidate M23 probe."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import security_outage_probe as probe
from mlsecops.contracts import Rejected
from scripts.security_outage_packet_qualification import fixture


class ProbeContracts(unittest.TestCase):
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
