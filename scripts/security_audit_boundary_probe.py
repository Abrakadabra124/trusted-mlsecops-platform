"""Fixed-path outage probe with controlled authorization, never actual ML assurance.

Parent owns the promoter Pod, SQL/CAS snapshots, live ML/dashboard and sink outage.
This probe never configures policy/head and aborts an unexpectedly healthy check
before publication. Mount the existing qualification fixtures with this script.
"""

import sys

from mlsecops import promotion
from mlsecops import security_event_admission as admission
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.process_privacy import enforce
from scripts import promotion_qualification as fixtures

CLIENT = "/client"
AUDIT = "/security/audit.json"


class TrackedAudit:
    def __init__(self, bundle):
        self.audit = admission.Configured(AUDIT)
        self.bundle = bundle
        self.checks = self.denials = 0
        self.check_error = None
        self.denial_arguments = None

    def check(self, reference):
        self.checks += 1
        if self.checks != 1:
            raise Rejected("audit_boundary_check_count")
        try:
            self.audit.check(reference)
        except Rejected as error:
            self.check_error = str(error)
            raise
        # Never let an accidentally healthy collector allow fixture publication.
        raise Rejected("audit_boundary_unexpected_healthy")

    def denied(self, *, reason, bundle_sha256):
        self.denials += 1
        self.denial_arguments = (reason, bundle_sha256)
        if (
            self.checks != 1
            or self.check_error != "promotion_audit_unavailable"
            or self.denials != 1
            or self.denial_arguments != ("audit_unavailable", self.bundle)
        ):
            raise Rejected("audit_boundary_denial_mismatch")
        return self.audit.denied(reason=reason, bundle_sha256=bundle_sha256)


def observe(fixture):
    source = admission.emitter(AUDIT)
    before = source.store.snapshot()
    if any(item["receipt"] is None for item in before["records"]):
        raise Rejected("audit_boundary_prior_pending")
    bundle = digest(canonical(fixture.arguments["package"]["envelope"]))
    tracked = TrackedAudit(bundle)
    try:
        promotion.promote(CLIENT, trust_lease=fixture.lease, audit=tracked, **fixture.arguments)
    except Rejected as error:
        refusal = str(error)
    else:
        raise Rejected("audit_boundary_unexpected_promotion")
    if (
        refusal != "promotion_denial_audit_unconfirmed"
        or tracked.checks != 1
        or tracked.check_error != "promotion_audit_unavailable"
        or tracked.denials != 1
        or tracked.denial_arguments != ("audit_unavailable", bundle)
    ):
        raise Rejected("audit_boundary_not_proven")
    recovered = admission.emitter(AUDIT)
    after = recovered.store.snapshot()
    if (
        recovered.store.pin != source.store.pin
        or recovered.store.registry.sha256 != source.store.registry.sha256
        or after["producer_id"] != before["producer_id"]
        or after["config_sha256"] != before["config_sha256"]
        or len(after["records"]) != len(before["records"]) + 1
        or after["records"][:-1] != before["records"]
    ):
        raise Rejected("audit_boundary_outbox_changed")
    record = after["records"][-1]
    event = recovered.store.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
    value = event.document()
    if (
        record["receipt"] is not None
        or event.route != "security.releases"
        or value["kind"] != "promotion.denied"
        or value["reason"] != "audit_unavailable"
        or value["asset_sha256"] != bundle
        or value["bundle_sha256"] != bundle
        or value["producer_id"] != before["producer_id"]
    ):
        raise Rejected("audit_boundary_pending_binding")
    return dict(
        schema_version=1,
        status="pass",
        scope="controlled-authorization-and-trust-real-sql-audit-boundary",
        release_ready=False,
        fixture_bundle_sha256=bundle,
        audit_checks=tracked.checks,
        audit_denials=tracked.denials,
        audit_check_error=tracked.check_error,
        promotion_error=refusal,
        registry_sha256=recovered.store.registry.sha256,
        outbox_pin=recovered.store.pin,
        pending=dict(
            event_id=value["event_id"],
            envelope_sha256=digest(canonical(record["envelope"])),
            kind=value["kind"],
            reason=value["reason"],
            receipt=None,
        ),
    )


def qualify():
    fixtures.PromotionAdmissionContracts.setUpClass()
    fixture = fixtures.PromotionAdmissionContracts()
    try:
        fixture.setUp()
        return observe(fixture)
    finally:
        try:
            if not fixture.doCleanups():
                raise Rejected("audit_boundary_fixture_cleanup_failed")
        finally:
            fixtures.PromotionAdmissionContracts.tearDownClass()


def main():
    try:
        enforce()
        print(canonical(qualify()).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("security_audit_boundary_probe_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
