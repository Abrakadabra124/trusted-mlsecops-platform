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
- [x] Hosted real HTTP/child/collector outage/restart/cleanup; clean checkout,
  runbook/playbook/evidence, commit/push/CI terminal. M23/R1 stay open.

## Evidence and rulings

Sourceb12ae89, CI43078796931success551Linux/0skip +38identity native assertions,
6receipts/3server cleanup; regression43078796872success54unit+37inventory+45promotion.
Clean new locked Windows checkout159tests/3Linux skips. Two runtime modules
148statements/40branches100%. [Evidence](../docs/evidence/identity-security-events-2026-11-11.md).

Ruling: reviewed inline under the owner's no-external-model constraint; this is
self-review, not independent M22 acceptance. No source behavior waived.
Two failed qualification runs are retained: pinned Uvicorn STARTUP_FAILURE3
was misclassified by harness expecting1. Actual Uvicorn unit RED->GREEN plus
hosted refusal/recovery verifies the correction. Mandatory deployment and
fresh M13/M14 remain separate required work, not deferred optional polish.
