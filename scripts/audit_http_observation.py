import threading

from mlsecops import audit_event, audit_evidence, audit_export
from mlsecops.contracts import Rejected, canonical, decode

LIMIT = audit_export.MAX_REQUESTS


class Ledger:
    def __init__(self):
        self.lock = threading.Lock()
        self.admissions = {}
        self.responses = []
        self.identifiers = set()
        self.sealed = False
        self.failed = False

    def fail(self):
        with self.lock:
            self.failed = True

    def admit(self, event):
        with self.lock:
            try:
                event = audit_event.checked(event)
                if event["stage"] != "request_started":
                    return
                identifier = event["request_id"]
                if (
                    self.failed
                    or self.sealed
                    or identifier in self.admissions
                    or len(self.admissions) >= LIMIT
                ):
                    raise Rejected("audit_http_admission")
                self.admissions[identifier] = event["route"]
            except Exception:
                self.failed = True
                raise

    def response(self, path, status, content):
        route = path.split("?", 1)[0]
        if route == "/metrics":
            return
        with self.lock:
            try:
                if self.failed or self.sealed or len(self.responses) >= LIMIT:
                    raise Rejected("audit_http_response_capacity")
                route = {"/v1/predict": "predict", "/readyz": "ready"}.get(route, "other")
                value = decode(content, 65536)
                if type(value) is not dict or route == "other" and value != {"detail": "Not Found"}:
                    raise Rejected("audit_http_response")
                identifier = value.get("request_id")
                outcome = audit_evidence.checked_outcome(
                    {
                        "exchange": len(self.responses) + 1,
                        "request_id": identifier,
                        "route": route,
                        "status": status,
                        "admitted": identifier in self.admissions,
                    }
                )
                if identifier is not None:
                    if identifier in self.identifiers or (
                        identifier in self.admissions and self.admissions[identifier] != route
                    ):
                        raise Rejected("audit_http_response_binding")
                    self.identifiers.add(identifier)
                self.responses.append(outcome)
            except Exception:
                self.failed = True
                raise

    def snapshot(self):
        with self.lock:
            if self.failed or set(self.admissions) != {
                item["request_id"] for item in self.responses if item["admitted"]
            }:
                self.failed = True
                raise Rejected("audit_http_unobserved_admission")
            self.sealed = True
            return decode(canonical(self.responses))


class ObservedJournal:
    def __init__(self, journal, ledger):
        self.original_emit, self.ledger = journal.emit, ledger

    def emit(self, value, *, ticket=None):
        sequence = self.original_emit(value, ticket=ticket)
        self.ledger.admit(value)
        return sequence
