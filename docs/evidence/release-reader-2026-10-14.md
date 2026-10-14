# Current release reader: 2026-10-14

Scope: T15 component от signed SQL selection до immutable model handoff. Это не HTTP endpoint и не завершённые M11/M12/R1. Parent checkout: `94e45c343b15526949f9fd72d221ed90b3805eb2`; runtime commit будет указан после CI.

## Проверено локально

- Negative-first suite сначала не могла импортировать отсутствующий reader; после реализации 19 reader methods pass. Ещё 5 diagnostic CLI/ownership methods проверяют явное подтверждение, redaction, ownership и path escape до bootstrap. Используются настоящие signatures и hashes, controlled storage/SQL/clock; это не native database tests.
- Reader Python branch coverage: 129 statements / 38 branches, 100% в controlled suite. Итог повторяется в CI.
- Отсутствующая assurance, изменённый selection/decision, malformed authorization, каждый отсутствующий/повреждённый CAS object, oversized reports, wrong role, external sequence floor, same-sequence equivocation после failed load, смена head, SQL errors/redaction, revocation, offline reload и lease expiry отклоняются.
- Exact model bytes возвращаются как immutable bytes, frozen handoff запрещает field mutation, последующее повреждение CAS не меняет уже переданные bytes. Новая загрузка повреждённого объекта отказывает и удаляет current handoff. Это ещё не доказательство ONNX execution тех же bytes.
- Delayed final trust refresh и storage clock rollback проверяются отдельно. Tuple conversion исправляет integration bug с lease scope. Первый неверный delay fixture и его исправление сохранены в [RB-47](../operations/release-reader-troubleshooting.md).
- Fresh-context automated reviewer завершился ошибкой инструмента без review result. Независимый review не считается пройденным; выполнены локальное source review и исполняемые проверки. Внешние модели/CLI не запускались.
- Итоговая объединённая локальная suite: **86 methods pass за 7.008 s**. Ruff check pass; 300 файлов уже отформатированы. Documentation check: 329 files, 119 Markdown documents, 849 local links pass. Эти числа не являются измерением production нагрузки или общей приёмкой ML release.

## Native qualification

Статус до публикации: не запущена. Локальный working Docker/WSL не изменялся. Добавлен disposable CI runner с двумя owned SQL workspace и независимыми CA. Positive chain содержит generated signed **contract fixture**, а не реальные acceptance reports. Нельзя использовать этот pass для promotion текущего ML candidate. Все реальные блокирующие gates остаются без изменений.

Native report обязан сохранять scope, source_revision/fingerprint, clean checkout, campaign/timestamps, count/case labels, `release_ready=false` и `full_M12=inconclusive`. Raw logs, keys, generated models и report bodies не публикуются.

## Остаётся

Изолированный runtime loader/session handshake, strict bounded worker response, HTTP contract/readiness, auth/quotas/privacy, before/after-inference trust checks, load benchmark, root rotation и разрешённый rollback. Текущий reader выполняет fresh DB reads, но не даёт распределённой атомарности между head, authority и будущим HTTP response. Полная цель остаётся активной.

[ADR 0030](../decisions/0030-current-release-reader.md) и [PB-24/RB-46/RB-47](../operations/release-reader-troubleshooting.md) описывают границы, действия при отказе и безопасное восстановление.
