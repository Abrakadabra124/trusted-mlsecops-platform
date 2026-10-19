# Private audit correlation: ADR 0046

Дата разработки: 2026-10-19. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR](../decisions/0046-private-audit-correlation.md), [RB-65/PB-39](../operations/audit-correlation-troubleshooting.md).

## Статус

**Native verified 54cbe5028ad0e042f23cfc96ada18a64b543704f**. [Полный report и все terminal CI](audit-correlation-54cbe50-native.md): 64 correlation tests / 0 skips / 100% coverage, 47 export tests / 0 skips; 81 actual-candidate case pass. Все 10 workflows завершены с первой попытки: 6 success / 4 failure. Полные M13/T16/R1 открыты; image/ML blockers и прежний M07 reliability debt сохраняются.

Actual qualification: 332 events / 58 correlated HTTP 200 / 25 requests without context; public window 83 completed, 0 unresolved. Отдельный controlled signed release: 56 events / 8 correlated HTTP 200 / 6 without context. Никакого approval реального candidate не создавалось; в обоих reports release_ready=false. Private graph не публикуется. Полные отчёты, exact digests, native timings и ограничения доступны по ссылке выше.

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

## Review и оставшаяся работа

Same-model review завершён в пределах трёх циклов, внешняя модель не использовалась по выбору владельца. Первый цикл уточнил byte/source approval и payload/envelope semantics. Второй обнаружил mutable deepcopy bypass и false pass после retention полных начальных requests; оба RED tests падали до исправления. Третий цикл повторил 15 tests без failures/skips и не нашёл actionable issues в изменённой границе. Это не независимая внешняя security certification.

Native проверки выполнены на 54cbe50, source_dirty=false. Reports/counters и outage assessment независимо перепроверены локально, complete workflow matrix сохранена. M03 431/M07 97/M06 18/M20 725/M21 122 pass в своих scoped profiles; они не являются единой release acceptance.

Следующий increment: единая карта output channels и недостающие сквозные canary checks для stdout/stderr/logs/traces/metrics/public evidence, затем отдельный M13 acceptance runner с candidate/source binding и честными pass/fail/inconclusive. Наличие компонентных проверок ещё не закрывает эту приёмку. M07 first-attempt pass здесь не устраняет неизвестную причину прошлого connection rejection.

## Границы гарантии

Source bytes удостоверяет существующая curator-signed lineage; отдельный intake snapshot на serving boundary не перечитывается. Trusted-key compromise и hostile same-UID/host admin не покрыты. Probe проверяет окно конкретного verified campaign, не произвольную смену поколений и не историческое переодобрение. HTTP completed_200 включает readiness и не доказывает получение ответа клиентом. Корреляция не означает semantic poisoning resistance, privacy acceptance или release approval.

