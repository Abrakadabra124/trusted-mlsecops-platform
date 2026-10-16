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

## Корректирующий review после первого CI

На `e67223996ddfa7be5d4ae6d19f81c179fe0134c4` [storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38926452268), job `117059112163`, завершён success: **45 tests pass**, serving_audit coverage **97%**, audit_retention **92%**, actual-candidate regression **67 cases pass**, release_ready=false. Это исторический первый прогон, не qualification исправлений ниже. Candidate campaign `636ff75401b54c08b1d6c71704a0dabc`.

Второй review нашёл два новых validation defects: null clock принимался как новый anchor; manifest head мог отставать от фактических records и повторно выдать sequence. Controlled RED cases воспроизвели clock bypass, duplicate head, duplicate/gapped records. Исправления требуют persisted clock и проверяют bounded canonical lines, непрерывность sequences и exact head. Дополнительно проверен O_NONBLOCK при чтении: FIFO не должен блокировать до fstat. Native FIFO и real-clock idle-expiry tests добавлены, но ещё не выполнены в corrected Linux CI.

Заключительный review 3/3 завершён без новых конкретных воспроизводимых дефектов в заявленном контракте. Внешняя модель не использовалась. Три bounded implementation review cycles закончены; это не независимый человеческий security audit.

Corrected local Windows checkpoint: **51 methods, 33 pass / 18 explicit native skips**, 2.194 s. Смежная suite перед добавлением последнего Linux-only timer test: **236 methods, 219 pass / 17 skips**, 34.286 s. Coverage checkpoint на 50 methods: serving_audit **98%**, audit_retention **44%**; native threshold по-прежнему не считается пройденным на Windows. Ruff и docs checker проходят: 383 files, 148 Markdown documents, 1069 local links, включая локальные пользовательские instructions. Native corrected qualification pending.

Рабочие Docker/WSL/Kubernetes и enterprise foundation не изменялись. В `AGENTS.md` и `GOAL.md` обнаружены отдельные пользовательские изменения правил отчётности: они соблюдаются, но не включаются автоматически в code commit этого increment.
