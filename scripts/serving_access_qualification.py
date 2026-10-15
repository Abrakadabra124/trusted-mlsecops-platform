import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

from mlsecops import serving_access
from mlsecops.contracts import Rejected


def credentials():
    return {
        "schema_version": 1,
        "clients": [
            {
                "principal_id": marker * 32,
                "token": marker * 64,
                "requests_per_second": 2,
                "burst": 2,
                "max_in_flight": 1,
            }
            for marker in ("a", "b")
        ],
    }


class AccessContracts(unittest.TestCase):
    def test_bad_clock_is_sticky_but_retained_tickets_can_still_release(self):
        for sample in (-1, True, 1.0, float("nan"), 2**63, 999, RuntimeError("private")):
            with self.subTest(sample_type=type(sample)):
                clock = Mock(return_value=1000)
                access = serving_access.Access(credentials(), clock=clock)
                ticket = access.acquire("a" * 32)
                if isinstance(sample, Exception):
                    clock.side_effect = sample
                else:
                    clock.return_value = sample
                with self.assertRaisesRegex(Rejected, "http_quota_clock"):
                    access.acquire("b" * 32)
                ticket.release()
                clock.side_effect, clock.return_value = None, 2000
                with self.assertRaisesRegex(Rejected, "http_quota_clock"):
                    access.acquire("a" * 32)

    def test_concurrent_admissions_never_exceed_limit(self):
        access = serving_access.Access(credentials())
        barrier = threading.Barrier(16)

        def attempt():
            barrier.wait(timeout=5)
            try:
                return access.acquire("a" * 32)
            except serving_access.Limited:
                return None

        with ThreadPoolExecutor(max_workers=16) as executor:
            tickets = [ticket for ticket in executor.map(lambda _: attempt(), range(16)) if ticket]
        self.assertEqual(len(tickets), 1)
        tickets[0].release()
        access.acquire("a" * 32).release()

    def test_invalid_configuration_never_creates_unlimited_or_ambiguous_access(self):
        samples = [None, {}, {"schema_version": True, "clients": []}]
        for field, value in (
            ("principal_id", "private-user"),
            ("token", "weak"),
            ("requests_per_second", 0),
            ("requests_per_second", True),
            ("requests_per_second", 1001),
            ("burst", 2.0),
            ("burst", 1001),
            ("max_in_flight", 5),
            ("max_in_flight", 0),
            ("unknown", 1),
        ):
            sample = credentials()
            sample["clients"][0][field] = value
            samples.append(sample)
        samples.extend(
            [
                {**credentials(), "clients": []},
                {**credentials(), "clients": credentials()["clients"] * 17},
                {**credentials(), "extra": 1},
            ]
        )
        for field in ("principal_id", "token"):
            sample = credentials()
            sample["clients"][1][field] = sample["clients"][0][field]
            samples.append(sample)
        for sample in samples:
            with self.subTest(sample_type=type(sample)), self.assertRaises(Rejected):
                serving_access.Access(sample)

    def test_authentication_is_bounded_exact_and_does_not_create_unknown_buckets(self):
        access = serving_access.Access(credentials())
        for values in (
            [],
            ["Bearer " + "a" * 64] * 2,
            ["Basic " + "a" * 64],
            ["Bearer " + "c" * 64],
            ["Bearer " + "a" * 63],
            ["Bearer " + "A" * 64],
        ):
            self.assertIsNone(access.authenticate(values))
        self.assertEqual(access.authenticate(["Bearer " + "a" * 64]), "a" * 32)
        with self.assertRaises(Rejected):
            access.acquire("c" * 32)
        self.assertNotIn("a" * 64, repr(access))

    def test_refill_separation_and_idempotent_release(self):
        clock = Mock(return_value=1_000_000_000)
        config = credentials()
        access = serving_access.Access(config, clock=clock)
        config["clients"][0]["burst"] = 1000
        first = access.acquire("a" * 32)
        self.assertEqual(access.admissions(), {"a" * 32: 1, "b" * 32: 0})
        with self.assertRaises(serving_access.Limited):
            access.acquire("a" * 32)
        access.acquire("b" * 32).release()
        self.assertEqual(access.admissions(), {"a" * 32: 1, "b" * 32: 1})
        first.release()
        first.release()
        snapshot = access.admissions()
        snapshot.clear()
        self.assertEqual(access.admissions(), {"a" * 32: 1, "b" * 32: 1})
        access.acquire("a" * 32).release()
        with self.assertRaises(serving_access.Limited):
            access.acquire("a" * 32)
        clock.return_value += 499_999_999
        with self.assertRaises(serving_access.Limited):
            access.acquire("a" * 32)
        clock.return_value += 1
        access.acquire("a" * 32).release()
        with self.assertRaises(serving_access.Limited):
            access.acquire("a" * 32)
        clock.return_value = 2**63 - 1
        access.acquire("a" * 32).release()
        access.acquire("a" * 32).release()
        with self.assertRaises(serving_access.Limited):
            access.acquire("a" * 32)


if __name__ == "__main__":
    unittest.main()
