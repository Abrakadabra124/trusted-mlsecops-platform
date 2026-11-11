# Periodic trust observer implementation plan

> Executor: superpowers:executing-plans, inline. Владелец разрешил продолжать без
> новых согласований и внешних моделей. Self-review не заменяет independent M22.

**Goal:** постоянно доставлять committed trust revocations и показывать потерю наблюдения.
**Architecture:** один supervisor, bounded child, существующие SQL reader/outbox/collector.
**Tech Stack:** Python 3.12.15, POSIX flock, subprocess, существующий psycopg/TLS.
**Spec:** [ADR 0065](../docs/decisions/0065-periodic-trust-observer.md), [M23](../docs/acceptance.md#m23).

## Global constraints

Не запускать локальные Docker/WSL/Kubernetes/SQL; только disposable hosted CI.
Не менять thresholds, роли, keys/epoch, protected AGENTS/GOAL или enterprise repo.
Интервал30s, child10s, terminate1s/kill1s; один child, без backlog.
Новая security logic >=95% statements и branches, без coverage waivers.

## Review focus

Config substitution; signal during spawn; cleanup failure; alive supervisor with
broken source must not heartbeat; restart must preserve events and heartbeat counter.

## Task 1: bounded service and source heartbeat

Consumes existing configured/sync/Emitter. Produces pinned configured heartbeat
and standalone service CLI. Files: mlsecops/security_trust_events.py,
mlsecops/security_trust_service.py, scripts/security_trust_service_qualification.py.

- [ ] RED: configured(..., expected=pin, heartbeat=True), no heartbeat after source failure;
  changed config denied before source; serial ticks, timeout, signal and child reap.
- [ ] GREEN: source pin validation and post-sync heartbeat; supervisor lifecycle/lock.
- [ ] Run targeted unittest -W error and per-module coverage; review failure branches.
- [ ] Commit scoped implementation and plan.

## Task 2: real SQL/collector qualification and handoff

Consumes service CLI, current native fixtures. Produces measured hosted evidence.
Files: scripts/security_trust_service_native.py, security-events-contracts workflow,
operations/evidence documents and current STATUS/tasks links.

- [ ] Hosted-only guard test before infrastructure. Native actual periodic read,
  receipts/routes, unchanged event IDs on outage/recovery, stopped observer gap.
- [ ] Observe terminal CI, cleanup and unchanged source; preserve any failed attempts.
- [ ] Clean checkout with fresh locked environment, only allowed local tests.
- [ ] Publish runbook/evidence, verify final CI and remote HEAD. Full M23/R1 stays open.

## Ledger

Preflight: source child and supervisor share exact config SHA; heartbeat only after
sync; lock uses a dedicated config parent, not outbox directory (child needs its lock).
Reuse current feature branch; protected owner edits excluded from staging.
