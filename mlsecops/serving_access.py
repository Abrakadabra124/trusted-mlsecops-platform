import re
import secrets
import threading
import time
from dataclasses import dataclass

from mlsecops.contracts import Rejected, require_fields

UNIT = 1_000_000_000


class Limited(Rejected):
    pass


@dataclass
class Bucket:
    rate: int
    burst: int
    limit: int
    updated: int
    credits: int
    inflight: int = 0
    admitted: int = 0


class Ticket:
    def __init__(self, owner, bucket):
        self.owner, self.bucket = owner, bucket
        self.released = False

    def release(self):
        with self.owner.lock:
            if not self.released:
                self.bucket.inflight -= 1
                self.released = True


class Access:
    def __init__(self, document, *, clock=time.monotonic_ns):
        require_fields(document, ("schema_version", "clients"))
        if type(document["schema_version"]) is not int or document["schema_version"] != 1:
            raise Rejected("http_clients_schema")
        clients = document["clients"]
        if not isinstance(clients, list) or not 1 <= len(clients) <= 32:
            raise Rejected("http_clients_bound")
        self.lock = threading.Lock()
        self.clock, self.broken, self.previous = clock, False, 0
        self.credentials, self.buckets = [], {}
        now = self.sample()
        for client in clients:
            require_fields(
                client, ("principal_id", "token", "requests_per_second", "burst", "max_in_flight")
            )
            principal, token = client["principal_id"], client["token"]
            if (
                not isinstance(principal, str)
                or re.fullmatch(r"[a-f0-9]{32}", principal) is None
                or not isinstance(token, str)
                or re.fullmatch(r"[a-f0-9]{64}", token) is None
            ):
                raise Rejected("http_client_identity")
            for field, maximum in (
                ("requests_per_second", 1000),
                ("burst", 1000),
                ("max_in_flight", 4),
            ):
                if type(client[field]) is not int or not 1 <= client[field] <= maximum:
                    raise Rejected("http_client_limits")
            encoded = ("Bearer " + token).encode("ascii")
            if principal in self.buckets or any(
                secret == encoded for _, secret in self.credentials
            ):
                raise Rejected("http_client_duplicate")
            self.credentials.append((principal, encoded))
            self.buckets[principal] = Bucket(
                client["requests_per_second"],
                client["burst"],
                client["max_in_flight"],
                now,
                client["burst"] * UNIT,
            )

    @classmethod
    def single(cls, token):
        return cls(
            {
                "schema_version": 1,
                "clients": [
                    {
                        "principal_id": "0" * 32,
                        "token": token,
                        "requests_per_second": 20,
                        "burst": 40,
                        "max_in_flight": 4,
                    }
                ],
            }
        )

    def sample(self):
        if self.broken:
            raise Rejected("http_quota_clock")
        try:
            now = self.clock()
            if type(now) is not int or not self.previous <= now <= 2**63 - 1:
                raise ValueError
        except Exception as failure:
            self.broken = True
            raise Rejected("http_quota_clock") from failure
        self.previous = now
        return now

    def authenticate(self, values):
        if len(values) != 1 or re.fullmatch(r"Bearer [a-f0-9]{64}", values[0]) is None:
            return None
        selected = None
        supplied = values[0].encode("ascii")
        for principal, secret in self.credentials:
            if secrets.compare_digest(supplied, secret):
                selected = principal
        return selected

    def admissions(self):
        with self.lock:
            return {principal: bucket.admitted for principal, bucket in self.buckets.items()}

    def acquire(self, principal):
        with self.lock:
            if principal not in self.buckets:
                raise Rejected("http_client_unknown")
            now = self.sample()
            bucket = self.buckets[principal]
            bucket.credits = min(
                bucket.burst * UNIT, bucket.credits + (now - bucket.updated) * bucket.rate
            )
            bucket.updated = now
            if bucket.inflight >= bucket.limit or bucket.credits < UNIT:
                raise Limited("http_client_limited")
            bucket.credits -= UNIT
            bucket.inflight += 1
            bucket.admitted += 1
            return Ticket(self, bucket)
