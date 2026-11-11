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

- [x] RED: configured(..., expected=pin, heartbeat=True), no heartbeat after source failure;
  changed config denied before source; serial ticks, timeout, signal and child reap.
- [x] GREEN: source pin validation and post-sync heartbeat; supervisor lifecycle/lock.
- [x] Run targeted unittest -W error and per-module coverage; review failure branches.
- [x] Commit scoped implementation and plan.

## Task 2: real SQL/collector qualification and handoff

Consumes service CLI, current native fixtures. Produces measured hosted evidence.
Files: scripts/security_trust_service_native.py, security-events-contracts workflow,
operations/evidence documents and current STATUS/tasks links.

- [x] Hosted-only guard test before infrastructure. Native actual periodic read,
  receipts/routes, unchanged event IDs on outage/recovery, stopped observer gap.
- [x] Observe terminal CI, cleanup and unchanged source; preserve any failed attempts.
- [x] Clean checkout with fresh locked environment, only allowed local tests.
- [ ] Publish runbook/evidence, verify final CI and remote HEAD. Full M23/R1 stays open.

## Ledger

Preflight: source child and supervisor share exact config SHA; heartbeat only after
sync; lock uses a dedicated config parent, not outbox directory (child needs its lock).
Reuse current feature branch; protected owner edits excluded from staging.

Task1 complete: df8ce0d. Tests exposed absent pinned heartbeat and absent supervisor
before implementation; separate RED caught optional heartbeat registry. Native
first attempt43087026043 failed at Store constructor in harness before source
launch; deterministic regression -> correction25371bf. Runtime unchanged by fix.
Task2 in progress: clean25371bf freshlockedPython3.12.15,83tests2.890s-Werror,
3Linux-only skips, interpreter/import paths and clean git verified. No local infra.
Self-review checked config pin, source failure, child ownership/signal/finally,
required registry heartbeat and no-state-reset. This is not independent M22 review.

Task2 qualification complete:25371bf,43087532653 both jobs success.593Linux/0skips,
15native assertions (includes repeated cleanup), measured30.022s period,
29.77508551599999s commit delivery,90.93080405500004s stopped-source notice.
Source/owned group/collector/SQL network+volume cleanup verified. Public evidence
and runbook ready; final documentation publication verification remains.
