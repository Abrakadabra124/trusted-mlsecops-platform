"""Actual collector outage around the real SQL commit boundary on owned hosted CI.

Signed authorization/trust use controlled fixtures. This is not full M10/M23/R1.
"""

import os
import sys
import uuid
from pathlib import Path

from mlsecops import promotion, promotion_state, security_event_admission, storage
from mlsecops.contracts import Rejected, canonical
from mlsecops.inventory import command, source_fingerprint
from scripts import promotion_qualification as fixtures
from scripts import security_event_audit_fixture as audit_fixture
from scripts.release_reader_native import disposable


def qualify():
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("security_promotion_hosted_required")
    root = Path(__file__).resolve().parents[1]
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("security_promotion_dirty_source")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    cases = []

    def check(name, condition):
        if not condition:
            raise Rejected("security_promotion_case:" + name)
        cases.append(name)

    fixtures.PromotionAdmissionContracts.setUpClass()
    f = fixtures.PromotionAdmissionContracts()
    try:
        f.setUp()
        with disposable(root, root / ".runtime", uuid.uuid4().hex, "audit", 15448) as state:
            promotion_state.install(state)
            promotion_state.configure(state, "local-cpu", f.arguments["expected_policy"])
            promoter, serving = (
                state / ("storage-clients/" + role) for role in ("promoter", "serving")
            )

            def snapshot():
                with storage.connect(serving) as connection:
                    head = connection.execute(
                        "SELECT sequence, request_sha256 FROM ml_promotion.heads WHERE environment = 'local-cpu'"
                    ).fetchone()
                    events = connection.execute(
                        "SELECT sequence, request_sha256 FROM ml_promotion.events WHERE environment = 'local-cpu' ORDER BY sequence"
                    ).fetchall()
                return head, events

            initial = snapshot()
            with audit_fixture.live() as fx:

                def submit(audit):
                    return promotion.promote(
                        promoter, trust_lease=f.lease, audit=audit, **f.arguments
                    )

                def outbox():
                    return security_event_admission.emitter(str(fx.audit_config)).store.snapshot()

                try:
                    promotion.promote(
                        promoter,
                        trust_lease=f.lease,
                        audit=fx.audit,
                        **{**f.arguments, "assurance_envelope": None},
                    )
                except Rejected as error:
                    check(
                        "authorization-denial-reported", str(error) == "release_assurance_required"
                    )
                else:
                    raise Rejected("security_promotion_authorization_bypass")
                first = outbox()["records"][0]
                check("authorization-denial-has-durable-receipt", first["receipt"] is not None)
                check("authorization-denial-does-not-select", snapshot() == initial)

                fx.stop()
                try:
                    submit(fx.audit)
                except Rejected as error:
                    check(
                        "offline-audit-denies", str(error) == "promotion_denial_audit_unconfirmed"
                    )
                else:
                    raise Rejected("security_promotion_outage_bypass")
                check("offline-head-and-events-unchanged", snapshot() == initial)
                pending = outbox()["records"][-1]
                check("offline-denial-retained-before-network", pending["receipt"] is None)
                fx.start()
                audit_fixture.heartbeat(fx, 2)

                class DropAfterWrite:
                    calls = 0

                    def check(self, reference):
                        self.calls += 1
                        if self.calls == 3:
                            # A second SQL connection must not see uncommitted data.
                            check("uncommitted-selection-invisible", snapshot() == initial)
                            fx.stop()
                        return fx.audit.check(reference)

                    def denied(self, **arguments):
                        return fx.audit.denied(**arguments)

                drop = DropAfterWrite()
                try:
                    submit(drop)
                except Rejected as error:
                    check(
                        "audit-loss-after-sql-denies",
                        str(error) == "promotion_denial_audit_unconfirmed",
                    )
                else:
                    raise Rejected("security_promotion_commit_bypass")
                check("all-three-audit-boundaries-reached", drop.calls == 3)
                check("real-sql-transaction-rolled-back", snapshot() == initial)
                records = outbox()["records"]
                check(
                    "prior-denial-flushed-before-new-challenge",
                    records[1]["envelope"] == pending["envelope"]
                    and records[1]["receipt"] is not None,
                )
                fx.start()
                audit_fixture.heartbeat(fx, 3)
                result = submit(fx.audit)
                recorded = snapshot()
                check(
                    "recovered-release-recorded-not-activated",
                    result["release_ready"] is False
                    and result["state"] == "recorded-not-activated",
                )
                check(
                    "exact-head-and-one-event",
                    recorded == ((1, result["request_sha256"]), [(1, result["request_sha256"])]),
                )
                check(
                    "exact-retry-idempotent", submit(fx.audit) == result and snapshot() == recorded
                )
                fx.stop()
                try:
                    submit(fx.audit)
                except Rejected as error:
                    check(
                        "retry-cannot-use-cached-health",
                        str(error) == "promotion_denial_audit_unconfirmed",
                    )
                else:
                    raise Rejected("security_promotion_cached_bypass")
                check("denied-retry-keeps-prior-release", snapshot() == recorded)
                fx.start()
                audit_fixture.heartbeat(fx, 4)
                fx.audit.check(result["request_sha256"])
                records = outbox()["records"]
                check(
                    "all-four-denials-retained-and-delivered",
                    len(records) == 4 and all(record["receipt"] is not None for record in records),
                )
                reasons = []
                for record in records:
                    event = fx.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
                    fx.registry.receipt(record["receipt"], event)
                    value = event.document()
                    check(
                        "denial-route-and-subject-" + str(value["sequence"]),
                        value["kind"] == "promotion.denied"
                        and event.route == "security.releases"
                        and value["bundle_sha256"] == result["proposal_reference"],
                    )
                    reasons.append(value["reason"])
                check(
                    "bounded-denial-reasons",
                    reasons == ["authorization"] + ["audit_unavailable"] * 3,
                )
            check("collector-cleanup-confirmed", fx.process is None and not fx.directory.exists())
        check("owned-sql-and-volume-cleanup-confirmed", not state.exists())
        check(
            "runtime-source-unchanged",
            source_fingerprint(root) == fingerprint
            and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
            and not command(["git", "-C", str(root), "status", "--porcelain"]),
        )
        return dict(
            source=revision,
            fingerprint=fingerprint,
            cases=cases,
            status="pass",
            release_ready=False,
            scope="controlled-auth-real-audit-and-SQL",
        )
    finally:
        f.doCleanups()
        fixtures.PromotionAdmissionContracts.tearDownClass()


if __name__ == "__main__":
    print(canonical(qualify()).decode())
