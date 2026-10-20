import unittest
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical
from scripts import audit_http_observation, serving_native
from scripts import serving_core_qualification as core
from scripts.audit_evidence_qualification import expected
from scripts.audit_export_qualification import records
from scripts.audit_http_observation import Ledger, ObservedJournal


class HttpObservationContracts(unittest.TestCase):
    def test_real_admission_ack_and_wire_response_join_without_payload(self):
        ledger, journal = Ledger(), Mock()
        journal.emit.return_value = 41
        observed = ObservedJournal(journal, ledger)
        event = records(bound=expected())[0]["event"]
        self.assertEqual(observed.emit(event, ticket="owned"), 41)
        journal.emit.assert_called_once_with(event, ticket="owned")
        ledger.response("/v1/predict?secret=PRIVATE", 503, canonical({"request_id": "1" * 32}))
        ledger.response("/unknown/PRIVATE", 404, b'{"detail":"Not Found"}')
        ledger.response("/metrics", 200, b"private-is-not-parsed-as-json")
        result = ledger.snapshot()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["admitted"], True)
        self.assertEqual(result[0]["status"], 503)
        self.assertEqual(result[1]["request_id"], None)
        self.assertEqual(result[1]["exchange"], 2)
        self.assertNotIn(b"PRIVATE", canonical(result))
        result[0]["admitted"] = False
        self.assertTrue(ledger.snapshot()[0]["admitted"])

    def test_failed_emit_does_not_invent_admission_and_non_start_is_not_new_admission(self):
        ledger, journal = Ledger(), Mock()
        journal.emit.side_effect = Rejected("controlled")
        observed = ObservedJournal(journal, ledger)
        with self.assertRaises(Rejected):
            observed.emit(records(bound=expected())[0]["event"])
        journal.emit.side_effect = None
        observed.emit(records(bound=expected())[2]["event"])
        ledger.response("/v1/predict", 503, canonical({"request_id": "1" * 32}))
        self.assertFalse(ledger.snapshot()[0]["admitted"])

    def test_unobserved_admission_duplicate_response_and_late_records_reject(self):
        ledger = Ledger()
        ledger.admit(records(bound=expected())[0]["event"])
        with self.assertRaises(Rejected):
            ledger.snapshot()
        with self.assertRaises(Rejected):
            ledger.snapshot()
        ledger = Ledger()
        ledger.admit(records(bound=expected())[0]["event"])
        ledger.response("/v1/predict", 200, canonical({"request_id": "1" * 32}))
        with self.assertRaises(Rejected):
            ledger.response("/v1/predict", 200, canonical({"request_id": "1" * 32}))
        with self.assertRaises(Rejected):
            ledger.snapshot()
        ledger = Ledger()
        ledger.snapshot()
        with self.assertRaises(Rejected):
            ledger.response("/readyz", 401, canonical({"request_id": "4" * 32}))
        with self.assertRaises(Rejected):
            ledger.admit(records(request="5" * 32, bound=expected())[0]["event"])

    def test_caught_observation_failure_permanently_rejects_snapshot(self):
        for body in (b"not-json", b"x" * 65537, b"{}", b"[]"):
            ledger = Ledger()
            ledger.response("/readyz", 401, canonical({"request_id": "4" * 32}))
            with self.assertRaises(Rejected):
                ledger.response("/readyz", 401, body)
            with self.subTest(body=body[:8]), self.assertRaises(Rejected):
                ledger.snapshot()

    def test_caught_http_read_failure_permanently_rejects_snapshot(self):
        fixture = core.ServingCoreContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        ledger = Ledger()
        with serving_native.site(fixture.engine, http_ledger=ledger) as request:
            self.assertEqual(request("/readyz")[0], 200)
            with (
                patch.object(
                    serving_native.http.client.HTTPConnection,
                    "getresponse",
                    side_effect=OSError("controlled read failure"),
                ),
                self.assertRaises(OSError),
            ):
                request("/readyz", authorized=False)
        with self.assertRaises(Rejected):
            ledger.snapshot()

    def test_wrong_route_unknown_body_duplicate_admission_and_bounds_reject(self):
        for path, status, body in (
            ("/unknown", 404, canonical({"request_id": "1" * 32})),
            ("/readyz", 200, b"not-json"),
            ("/v1/predict", 200, canonical({"request_id": "PRIVATE"})),
        ):
            with self.assertRaises(Rejected):
                Ledger().response(path, status, body)
        ledger = Ledger()
        event = records(bound=expected())[0]["event"]
        ledger.admit(event)
        with self.assertRaises(Rejected):
            ledger.admit(event)
        with self.assertRaises(Rejected):
            ledger.response("/readyz", 200, canonical({"request_id": "1" * 32}))
        with patch.object(audit_http_observation, "LIMIT", 0):
            with self.assertRaises(Rejected):
                Ledger().admit(event)
            with self.assertRaises(Rejected):
                Ledger().response("/unknown", 404, b'{"detail":"Not Found"}')

    def test_real_http_observes_admission_without_exposing_headers_or_features(self):
        fixture = core.ServingCoreContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        ledger = Ledger()
        with serving_native.site(fixture.engine, http_ledger=ledger) as request:
            self.assertEqual(request("/readyz")[0], 200)
            self.assertEqual(request("/readyz", authorized=False)[0], 401)
            self.assertEqual(request("/unknown/PRIVATE")[0], 404)
        outcomes = ledger.snapshot()
        self.assertEqual([item["admitted"] for item in outcomes], [True, False, False])
        self.assertEqual([item["status"] for item in outcomes], [200, 401, 404])
        self.assertNotIn(b"PRIVATE", canonical(outcomes))


if __name__ == "__main__":
    unittest.main()
