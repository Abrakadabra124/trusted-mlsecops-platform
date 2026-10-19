# T16: public audit export, 2026-10-19

Статус: **native verified f0d0542**, [полная CI matrix, failed attempt и candidate report](audit-export-f0d0542-native.md). [ADR 0045](../decisions/0045-public-audit-export.md), [RB-64/PB-38](../operations/audit-export-troubleshooting.md). Полные M13/T16/R1 открыты.

## Итог Linux CI

**46 tests / 0 skips**, exporter/snapshot/probe **99/99/100% mixed coverage**, thresholds 95/95/100 сохранены. Actual-candidate **80 unique cases pass**, source_dirty=false, release_ready=false. Production public export: **332 events / 83 completed requests / 0 aborted / 0 unresolved**, predict=78/ready=5, observed candidate context=57/none=26. Все 10 workflows terminal: **6 success / 4 failure** по latest attempts; M03 431/M07 97/M06 18/M20 725/M21 122 pass.

Storage **attempt 1 failed на M07**: один storage_connection_rejected среди 32 concurrent attempts, candidate step skipped. **Один** rerun того же code SHA, attempt 2, прошёл M07 и actual export. Первая попытка сохранена; причина connection failure не установлена, M07 reliability debt не закрыт. Полные logs не копируются в public evidence, sanitized failure report сохранён. Image/poisoning/evasion/paired failures остаются блокирующими.

## Scope и реализация

- `mlsecops.audit_snapshot`: отдельный reader закрытого owned Linux spool. Exclusive lease, pinned FD/nonce, bounded no-follow snapshot, manifest/sequence/digest/identity checks. Payload/manifest не переписываются, текущий boot/clock не используется для writer retention.
- `mlsecops.audit_export`: fixed allowlist projection без private IDs/hashes/URLs/timestamps/features, transition graph и retained boundaries. Guard до private I/O, constant diagnostic, bounded canonical output после cleanup. Exit 0/pass, 2/inconclusive, 1/rejected, 130/cancel.
- `scripts.audit_export_probe`: независимая public schema/accounting/canary проверка, сопоставление source counts, реальный CLI subprocess и повторный неизменный source snapshot.
- `scripts.serving_native.site`: opt-in callback после HTTP stop и `Journal.close()`, до удаления owned fixture. Actual-candidate report получает `runtime.public_audit_window` и два finite case IDs, но не release approval.

`context_kinds` отражает присутствовавший context, включая intent перед 503/aborted; completed считает завершённые HTTP responses, не успешный inference. Counters не являются DP/анонимизацией; integrity не является authenticated producer proof. Full private source/run/report/approval/release/request correlation и all-output privacy остаются обязательными зависимостями.

## Наблюдавшиеся проверки

- Failure-first: отсутствовавшие projection/snapshot/probe modules дали import failures; новый fixture callback дал 4 expected TypeError до реализации. Boundary regression отдельно воспроизведена failing assertion `Rejected not raised`, затем исправлена.
- Локальная смежная regression Windows: **130 tests, 17 skipped, 0 failures/errors, 12.324 s**. Skips сохраняют native/POSIX границу и не считаются Linux pass.
- Отдельная controller/transport/lifecycle/HTTP/core regression: **75 tests, 1 skipped, 0 failures/errors, 12.482 s**. Новый focused suite: **41 tests, 14 skipped, 0 failures/errors, 0.219 s**. Focused входит в первые 130, не суммируется как независимые тесты.
- Отдельный coverage snapshot до трёх дополнительных native fixture methods: **38 tests, 11 skipped, 0 failures/errors, 0.241 s**; projection 98% mixed statements/branches (`__main__` выполняется в subprocess), independent probe 100%. Windows snapshot coverage не принимается как filesystem proof.
- Linux acceptance: real writer lease conflict, mode/owner, symlink/hardlink/FIFO, short write/fsync/unlink/cancellation/replaced lease, changing bytes/manifest/inventory, multiple segments, real guard/CLI и owned loopback post-close export. **46 methods / 0 skips**, 0.860 s в attempt 1 и 0.920 s в attempt 2; actual-candidate integration подтверждена attempt 2.
- После cycle 2: **46 focused tests, 14 skips, 0 failures/errors, 0.575 s**; **135 adjacent tests, 17 skips, 0 failures/errors, 13.294 s**. Focused входит в adjacent. Отдельный final coverage run **23 tests / 0 skips, 0.597 s**: exporter **99% (96 statements, 40 branches)**, independent probe **100% (46 statements, 20 branches)**. Единственная непокрытая exporter строка вызывает CLI из `__main__`; fresh subprocess tests её выполняют вне parent coverage.
- Cross-model не запускался по выбору пользователя. Same-model cycle 1: 6 actionable/contract clarification findings отражены в ADR и реализации. Cycle 2: 4 findings воспроизведены в **4 red methods / 6 failures**, затем исправлены и проверены green suite. Import bootstrap, deferred stdout flush, положительные manifest times и independent event/context accounting имеют regressions. Cycle 3 завершён без новых воспроизводимых нарушений в scoped review; четвёртый цикл не запускался. Linux acceptance ревью не заменяет.
- При проверке нового child-теста обнаружен runpy warning из повторного импорта тестового helper, а не из production CLI. Fixture освобождает только соответствующий `sys.modules` entry перед `run_module`; runtime warnings глобально не подавляются. Повторный 46-test suite прошёл.

## Ограничения и blockers

Исторический baseline: [fe1437e](controller-privacy-fe1437e-native.md). Текущий [f0d0542 native evidence](audit-export-f0d0542-native.md) отдельно связывает source, обе Storage attempts и все 10 terminal workflows. Image security, poisoning, evasion и paired failures сохраняют release block. Локальные Docker/WSL/Kubernetes/SQL, исходная enterprise-devsecops-platform, зависимости и user-owned AGENTS/GOAL не изменялись.

Проверенный code commit `f0d054275ae095ec90c4eb41b323d7533d2b17db`. Последующая docs-only публикация не является новым runtime прогоном, R1 acceptance или release approval.
