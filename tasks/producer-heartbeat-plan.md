# Producer heartbeat Implementation Plan

> For agentic workers: use superpowers:executing-plans inline; external models forbidden.

**Goal:** serving lifecycle отправляет durable signed heartbeat, restart не сбрасывает counter.
**Architecture:** outbox schema2 -> bounded /heartbeat -> actual collector; existing identity child and owned scheduler.
**Tech Stack:** locked Python3.12.15, Ed25519, asyncio, existing fsync journal and Uvicorn.
**Spec:** [ADR0064](../docs/decisions/0064-producer-heartbeat.md).

## Global Constraints

No local Docker/WSL/Kubernetes/SQL. Native infrastructure only owned hosted CI.
No external models/cost/reset. Pause at50%remaining. Full M01-M23/R1 unchanged.
Existing schema1 has no trusted heartbeat counter: refuse, no implicit upgrade.

## Review Focus

Atomic head/counter, unknown network outcome, forged/stale echo, clock rollback,
busy/delayed child, scheduler startup failure and shutdown cancellation must be tested.
HTTP echo is not signed receipt or permission to promote.

## Implementation

- [x] RED/GREEN scripts/security_producer_heartbeat_qualification.py: persistent
  sequence, exact head, reopen, schema/role/key/time/capacity, corrupt state and echo.
- [x] security_event_outbox.py schema2 latest heartbeat under existing Store lock;
  security_event_delivery.py bounded /heartbeat and validated echo, no health grant.
- [x] security_identity_events.py uses producer heartbeat for probe/denials/tick;
  security_identity_http.py owns30s scheduler, busy/failure/cancel/shutdown contracts.
- [x] Extend actual hosted identity harness: periodic heartbeat, offline/restart,
  head/counter/collector readback/owned cleanup; maintain all event negative cases.
- [x] Required coverage>=95% per changed logical module, related regressions,
  fresh locked checkout, runbook/evidence, commit/push and CI terminal.

Ruling: use existing scoped branch; protected AGENTS/GOAL changes untouched.
Owner opted out of repeated approval and external models; review inline and
do not describe it as independent assurance. This increment advances M23,
does not redefine full R1 acceptance around component tests.

Evidence: [8b04684 /43083688017](../docs/evidence/producer-heartbeat-2026-11-11.md)
success571Linux/0skips,46native assertions,30.096s period/90.412271147s gap.
Clean final74/4Linux skips, previous same-runtime201/6, CLI43082185574success.
Inline review found transient readback handling gap; actual parent-context and
POSIX flock tests plus bounded2s retry verify that correction. Original c313
failure had no precise diagnostic; exact attribution remains unproven and is
recorded rather than erased by later green runs. No runtime gate weakened.
