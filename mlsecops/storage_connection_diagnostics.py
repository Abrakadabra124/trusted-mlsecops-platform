"""Bounded connection failure facts, never a budget receipt or a driver-message export."""

import psycopg

from mlsecops.contracts import Rejected

SQLSTATES = frozenset(
    {
        "08000",
        "08001",
        "08003",
        "08004",
        "08006",
        "08007",
        "08P01",
        "28000",
        "28P01",
        "53300",
        "53400",
        "57P01",
        "57P02",
        "57P03",
        "XX000",
    }
)
DRIVERS = frozenset({"connection-timeout", "operational", "interface", "database", "other"})
HINTS = {
    "timeout-reported": ("timeout expired", "connection timed out"),
    "refusal-reported": ("connection refused",),
    "capacity-reported": ("too many clients", "remaining connection slots"),
    "tls-reported": (
        "ssl error",
        "ssl syscall",
        "certificate verify failed",
        "tls alert",
        "ssl connection",
    ),
    "authentication-reported": ("authentication failed", "no pg_hba.conf entry"),
    "server-close-reported": ("server closed the connection",),
}
FIELDS = {"stage", "driver", "sqlstate", "message_hint", "elapsed_ms", "slot", "prior_conflicts"}


class ConnectionRejected(Rejected):
    def __init__(self, diagnostic, slot=None):
        super().__init__("storage_connection_rejected")
        self.diagnostic, self.slot = diagnostic, slot

    def __reduce__(self):
        # Keep diagnostics across process boundaries without serializing the raw cause.
        return type(self), (self.diagnostic, self.slot)


def describe(error, elapsed_ns):
    driver = "other"
    for kind, label in (
        (psycopg.errors.ConnectionTimeout, "connection-timeout"),
        (psycopg.OperationalError, "operational"),
        (psycopg.InterfaceError, "interface"),
        (psycopg.DatabaseError, "database"),
    ):
        if isinstance(error, kind):
            driver = label
            break
    state = error.sqlstate
    state = state if state in SQLSTATES else "unavailable" if state is None else "unclassified"
    text = str(error)[:8192].lower()
    hint = next(
        (label for label, markers in HINTS.items() if any(m in text for m in markers)),
        "unclassified",
    )
    return dict(
        stage="connect",
        driver=driver,
        sqlstate=state,
        message_hint=hint,
        elapsed_ms=min(60000, max(0, elapsed_ns // 1_000_000)),
    )


def checked(value, limit):
    """A closed schema before any diagnostic crosses into the parent report."""
    return (
        type(value) is dict
        and set(value) == FIELDS
        and value["stage"] == "connect"
        and type(value["driver"]) is str
        and value["driver"] in DRIVERS
        and type(value["sqlstate"]) is str
        and value["sqlstate"] in SQLSTATES | {"unavailable", "unclassified"}
        and type(value["message_hint"]) is str
        and value["message_hint"] in {*HINTS, "unclassified"}
        and type(value["elapsed_ms"]) is int
        and 0 <= value["elapsed_ms"] <= 60000
        and type(value["slot"]) is int
        and 1 <= value["slot"] <= limit
        and type(value["prior_conflicts"]) is int
        and value["prior_conflicts"] == value["slot"] - 1
    )
