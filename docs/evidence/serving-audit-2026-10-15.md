# Private serving audit core: evidence, 2026-10-15

Increment после `1e8bb1f`. [ADR 0036](../decisions/0036-serving-audit-journal.md), [RB-55/PB-29](../operations/serving-audit-troubleshooting.md). Scope T16 storage/lifecycle core. HTTP audit, verified Engine correlation, time-based retention, all-output canaries и полный M13 ещё не реализованы.

## Failure-first и реальные наблюдения

- Первые tests падали из-за отсутствующего модуля. После реализации schema/queue/private file paths проверены собственные snapshots, active I/O accounting, immutable sequence и сохранение ошибочного health.
- Windows test сравнил размер реального файла с durable_bytes: **502 против 503 bytes**. CRT text mode добавлял CR к LF. Добавлен O_BINARY; теперь short-write/fsync readback совпадает с byte accounting.
- Ошибка конструктора Thread воспроизвела исходное исключение и незакрытый descriptor. Создание и dispatch помещены в один защищённый lifecycle; tested failures до и после фактического start.
- Детерминированная пауза между shape check и snapshot показала добавление `raw_payload` в уже проверенный dict. Fixed-field capture больше не переносит позднее добавленное поле. Mutation после validation, но до serialization также проверяется.
- Scoped reviewer нашёл stale Queue.Empty race: после наблюдения empty producer принимает запись, затем close разрешает выход writer. Regression сначала получила **durable=0 вместо 1**, а close возвращал success. Stop decision теперь проверяет pending под admission lock; close отдельно запрещает success при accepted!=durable.
- POSIX design review указал на parent-path substitution. Создание перенесено на fd-relative open после fstat. Native rename-between-check-and-create test включён для Linux CI; на Windows он явно skipped, а syscall contract проверяется контролируемым тестом.

## Проверка и ограничения доказательства

Локальная проверка Windows: 21 methods, 20 pass / 1 native POSIX skip за 2.352 s; core coverage 98% (188 statements, 70 branches; не покрыты строки 102 и 232). Смежная regression suite: 207 methods, 206 pass / 1 тот же POSIX skip за 25.828 s. Ruff lint/format и git diff whitespace check проходят. Documentation checker: 377 files, 144 Markdown documents, 1042 local links. Это локальные real-filesystem и controlled-failure tests, не HTTP traffic или power-loss durability trial. Native Linux CI и exact code revision пока не подтверждены.

Первый implementation review выявил четыре конкретных замечания: stale Empty, mutable input, Windows text mode и Thread construction. Все воспроизведены regression tests и исправлены. Второй review нашёл необработанный OverflowError у `close(10**1000)` и отсутствие sticky unhealthy у неправильного timeout. Regression воспроизвела оба случая; теперь диапазон проверяется без float conversion и ошибка закрытия сохраняется. Native Windows ACL enforcement был отдельно поднят reviewer: это явно оставленный platform prerequisite, не реализованный механизм. Healthy означает writer health при приватном parent, не подтверждение Windows ACL; privacy qualification Windows остаётся открытой. Третий, последний bounded review завершён: новых конкретных воспроизводимых bounds/lifecycle defects не обнаружено. Внешняя модель не использовалась по решению владельца. Self/same-model review не заменяет независимый человеческий audit.

Неизвестные exceptions не экспортируются; typed stage/status/refs только проверяют форму доверенного producer event. Это не доказательство реального response status или криптографически проверенной release chain. Journal не подписан, не multi-process и не допускает restart append. File contents остаются private; публично публикуются counts/результаты, а не IDs или байты журнала. Existing image/ML failures и общий R1 status не меняются.
