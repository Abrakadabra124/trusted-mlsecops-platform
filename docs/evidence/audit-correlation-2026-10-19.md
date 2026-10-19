# Private audit correlation: ADR 0046

Дата разработки: 2026-10-19. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR](../decisions/0046-private-audit-correlation.md), [RB-65/PB-39](../operations/audit-correlation-troubleshooting.md).

## Статус

Реализовано локально, native CI и публикация этого increment ещё не подтверждены. Не переносить результаты f0d0542 на новый код. Полные M13/T16/R1 открыты; image/ML blockers и прежний M07 reliability debt сохраняются.

## Реализация

- Immutable Lineage содержит восемь точно определённых source/dataset/run/evaluation ссылок. Production Reader создаёт ReleaseTrace с authorization/assurance/approval, CandidateReader - QualificationTrace без release approval.
- Context schema 2, audit event schema 2, private bound <=2048 bytes; public HTTP и export schema не меняются. Legacy context v1 читается для structural export, но не проходит новую correlation qualification.
- Независимый probe получает ожидаемые значения из первичных подписанных материалов, сверяет каждое observed context и повторно читает закрытый неизменный snapshot. Он не вызывает production Lineage builder и не является standalone authorization verifier.
- Actual-candidate и controlled signed-release HTTP получают post-close callbacks. Public summary содержит finite counters, но не private graph. Public export probe теперь проверяет все вложенные Lineage canaries, включая 40-hex source revision.

## Локально проверено

- RED: отсутствовавший schema/probe module; readers отдавали schema 1 вместо 2. Исправления namespace evaluation и test no-op mutation сохранены в [runbook](../operations/audit-correlation-troubleshooting.md).
- Финальный focused CI-equivalent suite: 64 methods, 0 skips, 11.975 s: pass. Coverage с branch collection: audit_lineage 30 statements / 4 branches, serving_context 52 / 8, audit_event 44 / 22, correlation_probe 70 / 28; все statements/branches covered, 100%.
- Финальный расширенный прогон: 175 methods, 16 platform skips, 19.937 s, без failures/errors. Focused methods входят в него; результаты не складывать. Дополнительно production Reader coverage: 20 methods, 136 statements / 38 branches, 100%; public export probe 47 statements / 20 branches, 100% (его Windows suite 47 methods / 14 skips).
- Максимальный JSONL record с предельными sequence/timestamp: release 1539 bytes, qualification 1366 bytes; существующий MAX_RECORD=2048 не изменён.
- Frozen source lock, Ruff check/format и git diff whitespace проверены. Windows не доказывает Linux ownership, no-follow, fsync и process guards.
- AGENTS.md и GOAL.md содержат исходные пользовательские изменения; в патч реализации не входят. Локальная инфраструктура не изменялась.

## Оставшаяся проверка

Same-model review завершён в пределах трёх циклов, внешняя модель не использовалась по выбору владельца. Первый цикл уточнил byte/source approval и payload/envelope semantics. Второй обнаружил mutable deepcopy bypass и false pass после retention полных начальных requests; оба RED tests падали до исправления. Третий цикл повторил 15 tests без failures/skips и не нашёл actionable issues в изменённой границе. Это не независимая внешняя security certification.

Native coverage/contracts, actual-candidate/controlled-release summaries, все terminal CI и привязка опубликованного evidence к точному SHA пока ожидаются.

## Границы гарантии

Source bytes удостоверяет существующая curator-signed lineage; отдельный intake snapshot на serving boundary не перечитывается. Trusted-key compromise и hostile same-UID/host admin не покрыты. Probe проверяет окно конкретного verified campaign, не произвольную смену поколений и не историческое переодобрение. HTTP completed_200 включает readiness и не доказывает получение ответа клиентом. Корреляция не означает semantic poisoning resistance, privacy acceptance или release approval.

