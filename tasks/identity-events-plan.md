# Identity source Implementation Plan

> For agentic workers: use superpowers:executing-plans inline; external models forbidden.

**Goal:** реальные HTTP credential/role denials доставляются bounded serving producer.
**Architecture:** explicit serving profile -> async owned child -> existing outbox/HTTP/receipt.
**Tech Stack:** Python3.12.15, asyncio subprocess, FastAPI, existing Ed25519 journal.
**Spec:** [ADR0063](../docs/decisions/0063-identity-security-source.md).

## Global Constraints

No local Docker/WSL/Kubernetes/SQL. Native infrastructure only disposable hosted
CI. No external models/cost/reset. Pause at50%remaining. Full R1/M18 unchanged.

## Review Focus

Cancellation during spawn must retain ownership; child output must never be retained/forwarded;
busy source must not enqueue unlimited waiters; tokens/body must not enter event;
startup/shutdown failure must clean other managed resources. Test every case.

## Implementation

- [x] RED tests scripts/security_identity_events_qualification.py for finite
  producer/config/role/receipt contract and scripts/security_identity_http_qualification.py
  for actual auth and subprocess lifecycle.
- [x] mlsecops/security_identity_events.py: pinned private config, serving-only
  durable emit/retry, bounded safe CLI acknowledgment.
- [x] mlsecops/security_identity_http.py: one owned child, DEVNULL output,
  cancellation/deadline/shutdown cleanup, explicit startup probe.
- [x] mlsecops/serving_http.py: identity_audit_file profile, lifespan ownership,
  credential/role denial paths before engine/body access; existing pure profile preserved.
- [x] GREEN: source branches>=95% separately, existing HTTP/lifecycle/access,
  monitoring and privacy regressions; no weakened gates.
- [ ] Hosted real HTTP/child/collector outage/restart/cleanup; clean checkout,
  runbook/playbook/evidence, commit/push/CI terminal. M23/R1 stay open.
