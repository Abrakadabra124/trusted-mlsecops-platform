# Current release reader: 2026-10-14

Scope: T15 component от signed SQL selection до immutable model handoff. Это не HTTP endpoint и не завершённые M11/M12/R1. Parent checkout: `94e45c343b15526949f9fd72d221ed90b3805eb2`; runtime commit: `37397ce92153089642ccc1c4057d35e451a6cdea`.

## Проверено локально

- Negative-first suite сначала не могла импортировать отсутствующий reader; после реализации 19 reader methods pass. Ещё 5 diagnostic CLI/ownership methods проверяют явное подтверждение, redaction, ownership и path escape до bootstrap. Используются настоящие signatures и hashes, controlled storage/SQL/clock; это не native database tests.
- Reader Python branch coverage: 129 statements / 38 branches, 100% в controlled suite. Итог повторяется в CI.
- Отсутствующая assurance, изменённый selection/decision, malformed authorization, каждый отсутствующий/повреждённый CAS object, oversized reports, wrong role, external sequence floor, same-sequence equivocation после failed load, смена head, SQL errors/redaction, revocation, offline reload и lease expiry отклоняются.
- Exact model bytes возвращаются как immutable bytes, frozen handoff запрещает field mutation, последующее повреждение CAS не меняет уже переданные bytes. Новая загрузка повреждённого объекта отказывает и удаляет current handoff. Это ещё не доказательство ONNX execution тех же bytes.
- Delayed final trust refresh и storage clock rollback проверяются отдельно. Tuple conversion исправляет integration bug с lease scope. Первый неверный delay fixture и его исправление сохранены в [RB-47](../operations/release-reader-troubleshooting.md).
- Fresh-context automated reviewer завершился ошибкой инструмента без review result. Независимый review не считается пройденным; выполнены локальное source review и исполняемые проверки. Внешние модели/CLI не запускались.
- Итоговая объединённая локальная suite: **86 methods pass за 7.008 s**. Ruff check pass; 300 файлов уже отформатированы. Documentation check: 329 files, 119 Markdown documents, 849 local links pass. Эти числа не являются измерением production нагрузки или общей приёмкой ML release.

## Native qualification

В [storage CI 38624026031](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624026031) **18 native checks pass**, workflow completed/success. Локальный working Docker/WSL не изменялся. Disposable CI runner использовал два owned SQL workspace и независимые CA. Positive chain содержит generated signed **contract fixture**, а не реальные acceptance reports. Нельзя использовать этот pass для promotion текущего ML candidate. Все реальные блокирующие gates остаются без изменений.

- Campaign: `d435a0949aa0434bb653bf329a649b5a`.
- Source fingerprint: `12e2b3499e2fc599880b4ed89d72596bbd285fefe7c83f70d932de50645df698`, `source_dirty=false`.
- Начало: 2026-10-14 19:34:29.588219 UTC; завершение: 19:34:41.246989 UTC.
- Проверены настоящий TLS current-head query, SDK-recorded positive contract fixture, exact immutable bytes, repeated read/no writes, отсутствие runtime readiness, запрет прежнего handoff после reload, serving identity и внешний sequence floor.
- Actual authority model revocation запрещает существующий handoff и новый load. SQL function принимает структурный selection без assurance, но reader его отвергает: journal не подменяет независимое разрешение. Failed load не оставляет current object.
- Оба owned test workspace удалены, source storage ledger и checkout не изменены. Private logs остаются локально, не добавлены в Git.
- Regression в том же storage job: M03 **431**, M07 **97**, SQL journal **108**, recovery **36**, online trust **45** checks pass. В trust outage первый отказ через **59.990437104 s** после последнего успешного online read; это SQL component, не HTTP endpoint.

Native report сохраняет scope, source_revision/fingerprint, clean checkout, campaign/timestamps, count/case labels, `release_ready=false` и `full_M12=inconclusive`. Raw logs, keys, generated models и report bodies не публикуются.

## Регрессии и blockers на runtime commit

Developer qualification: 74 checks, 3 fresh training runs, maximum probability difference 0, ONNX parity error `2.086162567138672e-07`. Tracking M06: 18 cases pass. Kubernetes M20: 723 cases pass, завершён 19:42:51.362276 UTC; M21: 122 cases pass, source_dirty=false, завершён 19:45:08.777058 UTC. Все результаты относятся к `37397ce`, не к общей приёмке одного ML release.

Все десять workflows completed: **6 success / 4 failure**.

| Workflow | Run | Итог |
| --- | --- | --- |
| Documentation integrity | [38624025986](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624025986) | success |
| Intake evidence contracts | [38624025858](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624025858) | success |
| Developer runtime qualification | [38624025873](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624025873) | success |
| Storage role and TLS qualification | [38624026031](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624026031) | success |
| Tracking compatibility and service | [38624025771](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624025771) | success |
| Kubernetes isolation qualification | [38624025920](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624025920) | success |
| Worker and storage image audit | [38624026234](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624026234) | failure |
| Frozen poisoning research matrix | [38624026256](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624026256) | failure |
| Frozen evasion and domain guard | [38624025607](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624025607) | failure |
| Paired robust training research | [38624025835](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38624025835) | failure |

Для M20/M21 raw job log прочитан через GitHub API job `116058498811`: в сохранённом выводе `gh run view --log` эти полные JSON reports отсутствовали, хотя stage summary показывал pass. Причина расхождения CLI/API не установлена; отсутствие отчёта в локальном выводе не было принято за отсутствие результата и не запускало rerun. В repository опубликованы только выбранные безопасные метрики и ссылки.

- Poisoning campaign `9cac555e2cdc4b56b9d2e89a89435815`: execution complete; primary reconciliation 35 cases / 251 files, evidence integrity pass, 10 violating scenarios, 0 inconclusive. Gate остаётся fail.
- Baseline evasion campaign `9cabefda94ca42809cdf7c9a044b6ed7`: execution complete, source_dirty=false, recall drop `0.07183673469387755` при максимуме `0.05`, fail.
- Paired robustness campaign `cdef0dc15c2a4e289f40c3b4643f0024`: execution complete, source_dirty=false, candidate recall drops `0.052244897959183675`, `0.06224066390041494`, `0.06143344709897611`, fail. Не объявляется adoption candidate.
- Image audit workflow completed/failure на шаге `Audit exact worker and PostgreSQL images`; в отчётах присутствует `scan_executed=true`. Severity policy и dependency acceptance exceptions не изменялись этим increment.

## Остаётся

Изолированный runtime loader/session handshake, strict bounded worker response, HTTP contract/readiness, auth/quotas/privacy, before/after-inference trust checks, load benchmark, root rotation и разрешённый rollback. Текущий reader выполняет fresh DB reads, но не даёт распределённой атомарности между head, authority и будущим HTTP response. Полная цель остаётся активной.

[ADR 0030](../decisions/0030-current-release-reader.md) и [PB-24/RB-46/RB-47](../operations/release-reader-troubleshooting.md) описывают границы, действия при отказе и безопасное восстановление.
