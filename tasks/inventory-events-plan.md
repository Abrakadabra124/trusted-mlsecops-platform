# Inventory security source Implementation Plan

> For agentic workers: use superpowers:executing-plans inline. External models are forbidden.

**Goal:** связать реальные inventory rejection predicates с durable security events.
**Architecture:** typed decisions в существующих validators, bounded observer с
operator pins, прежние outbox/HTTP/receipt. Pure validation сохраняет отказ.
**Tech Stack:** Python3.12.15, PostgreSQL TLS clients, Ed25519, existing event journal.
**Spec:** [ADR0062](../docs/decisions/0062-inventory-security-source.md).

## Global Constraints

Локальные Docker/WSL/Kubernetes/SQL не запускать и не менять. Infrastructure
validation только owned disposable hosted CI; внешние модели/расходы запрещены.
M18 последний, остальные gates не ослаблять; pause при50%remaining.

## Review Focus

Не классифицировать I/O по строке; не выдавать graph fixture за live inventory;
не публиковать source payload; не потерять pending при retry; wrong role/pin
должны остановить source до чтения. Все пункты включить в negative contracts.

## 1. Источник и CLI

- [x] RED: scripts/security_inventory_events_qualification.py проверяет реальные
  asset_graph/candidate_lineage predicates, finite output и outage refusal.
- [x] mlsecops/asset_graph.py: InventoryMismatch с категорией; прежние error codes.
- [x] mlsecops/candidate_lineage.py: typed digest failures и optional audit на collect.
- [x] mlsecops/security_inventory_events.py: capture, configured operator CLI,
  request pin, exact fields, private error, final summary без raw projection.
- [x] GREEN: прежние asset_graph/candidate/material/release tests плюс новая
  security source coverage>=95% statements и branches раздельно.

## 2. Фактическая доставка и публикация

- [ ] Hosted actual collector/outbox/SQL candidate checks, negative fixtures
  обозначены отдельно, исходные event ID/receipt и cleanup подтверждены.
- [ ] Clean checkout с новой locked venv, docs/ruff/diff checks.
- [x] Ранбук/плейбук: diagnostics, existing-outbox retry, bounded CLI,
  unknown outcome, no reset и пределы восстановления.
- [ ] Commit/push, CI terminal/evidence/source binding; M19/M23/R1 не закрывать.
