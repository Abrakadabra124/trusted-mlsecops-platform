# Audit retention: qualification, 2026-10-16

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». База `09b535f`, [ADR 0037](../decisions/0037-audit-retention.md), [RB-56/PB-30](../operations/audit-retention-troubleshooting.md). Статус: реализация и локальные contracts, native qualification не завершена. Полная задача T16/M13/R1 остаётся открытой.

## Реализованный scope

Explicit `Journal(..., retention=Policy(...))`: fd-relative Linux spool, bounded segments и metadata, exclusive ownership до snapshot, per-record sync, byte/age rotation, maintenance без новых requests, минимальная retention и clean same-boot restart без reset sequence/age/budget. Queue admission по-прежнему не делает I/O. Legacy single-file contract сохранён.

Повторный запуск после crash/reboot не объявляется автоматическим recovery; unknown/stale lease требует reconciliation. Windows native retained mode отвергается, не имитируется через permissive paths. Нет HTTP integration, новой release authority или обхода failed/inconclusive gates.

## Failure-first и review

Отсутствие модуля и retention keyword дали первые RED tests. Затем tests воспроизвели leaked cleanup exception и отсутствие явного closed guard. Исправления возвращают bounded error и запрещают вызовы после освобождения directory FD. Design review выявил два уточнения: lease-before-snapshot и точка handoff до завершающего fsync/close. Порядок подтверждается отдельными interleaving scenarios в native suite; внешний reviewer/model не используется по решению владельца.

## Локальная проверка

Windows после первого implementation review: **45 methods, 29 pass / 16 explicit POSIX skips**, 2.136 s. Из них 21 прежний core contract и 24 retention contracts; 15 новых native filesystem cases ещё требуют Linux. До добавления cursor regression смежная suite дала 229 methods, 214 pass / 15 skips за 26.566 s. Предыдущий coverage checkpoint: serving_audit **98%**; audit_retention **27%** на Windows не достигает native threshold и не принимается за доказательство filesystem поведения. Ruff lint/format проходят. Native Linux результаты, exact revision и CI matrix добавляются только после фактического прогона.

Implementation review выявил shared directory cursor у повторного `scandir(fd)`. Controlled regression сначала получил пустой второй inventory вместо `.lease`. Теперь каждый bounded scan открывает независимый `.` относительно owned directory FD; отдельный native regression добавлен для Linux. Это исправление подтверждено controlled test, но исходный дефект не воспроизводился в локальном Linux runtime, который не запускался.

Рабочие Docker/WSL/Kubernetes и enterprise foundation не изменялись. В `AGENTS.md` и `GOAL.md` обнаружены отдельные пользовательские изменения правил отчётности: они соблюдаются, но не включаются автоматически в code commit этого increment.
