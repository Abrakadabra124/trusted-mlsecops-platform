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

Локальная проверка Windows: 21 methods, 20 pass / 1 native POSIX skip за 2.352 s; core coverage 98% (188 statements, 70 branches; не покрыты строки 102 и 232). Смежная regression suite: 207 methods, 206 pass / 1 тот же POSIX skip за 25.828 s. Ruff lint/format и git diff whitespace check проходят. Documentation checker до публикации кода: 377 files, 144 Markdown documents, 1042 local links. Это локальные real-filesystem и controlled-failure tests, не HTTP traffic или power-loss durability trial. Native Linux проверка приведена отдельно ниже.

Первый implementation review выявил четыре конкретных замечания: stale Empty, mutable input, Windows text mode и Thread construction. Все воспроизведены regression tests и исправлены. Второй review нашёл необработанный OverflowError у `close(10**1000)` и отсутствие sticky unhealthy у неправильного timeout. Regression воспроизвела оба случая; теперь диапазон проверяется без float conversion и ошибка закрытия сохраняется. Native Windows ACL enforcement был отдельно поднят reviewer: это явно оставленный platform prerequisite, не реализованный механизм. Healthy означает writer health при приватном parent, не подтверждение Windows ACL; privacy qualification Windows остаётся открытой. Третий, последний bounded review завершён: новых конкретных воспроизводимых bounds/lifecycle defects не обнаружено. Внешняя модель не использовалась по решению владельца. Self/same-model review не заменяет независимый человеческий audit.

Неизвестные exceptions не экспортируются; typed stage/status/refs только проверяют форму доверенного producer event. Это не доказательство реального response status или криптографически проверенной release chain. Journal не подписан, не multi-process и не допускает restart append. File contents остаются private; публично публикуются counts/результаты, а не IDs или байты журнала. Existing image/ML failures и общий R1 status не меняются.

## Native Linux и regression на 0841786

Код: `08417867ff324e43264ebb41ebc27d3d79fb46a5`. [Storage workflow](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232968), job `116626318445`, success. Python 3.12.15. Новый audit step: **21 tests pass, 0 skipped, 1.498 s**, coverage **97%**, 188 statements / 70 branches, threshold 95% сохранён. Uncovered: Windows-specific строки 101-103 и pending-close branch 232. Native parent rename test выполнился: созданный файл остался в проверенном directory identity, а не в каталоге, подставленном по прежнему path. Это не Windows ACL qualification.

Смежные CI suites: serving 77 methods / 94%, access 29 methods / 100%. Actual candidate повторно прошёл **67 cases**: это regression существующего serving, не ещё не реализованная HTTP audit интеграция. [Полный sanitized report](serving-audit-0841786.md) сохранён с canonical SHA-256 `c99dad8286cd411f68a02804261a423c3f42c8a35ea10d261d7c4899b2eb20a5`.

- Campaign `def48727685d4edf984c4943bce59a84`, UTC `2026-10-15T19:36:44.716186Z` - `2026-10-15T19:38:30.019333Z`; source_dirty=false, release_ready=false.
- Source fingerprint `083ed073ad75764fa290c4db6b4e797cec82c209ee9327e202e9bf5b23a8a19d`; worker image `sha256:58677cc0527df166ee8830c3bf5b2571c4c4234b35355b88d850e4237ea16b8e`.
- Model SHA-256 `b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634`. Совпадение с предыдущим конкретным run не означает гарантию bit-for-bit reproducibility на других средах.
- Quota: 422/429/422/429 за 0.003538592 s, после refill 200/200; admissions [2,2,4]. Production quota и polling thresholds не изменены.
- Trust outage: 43 observations, первый 503 через 59.777426017 s от last verified trust; последний 200 через 59.726164268 s. Saved trace assessment pass, failures пусты.
- Paused established SQL query: completed 503 за 10.003181715 s при ещё активном query. Short signed policy: 503 за 5.703748229 s, на 0.248407603 s раньше local lease deadline и на 0.654819251 s раньше wall policy expiry. ACTIVE наблюдался до completion; повторный 503 после expiry, explicit renewal version 3/recovery и final revocation проверены. Исходные ресурсы сохранены.

## CI matrix и незакрытые gates

Все 10 workflows exact `0841786` завершены: **6 success / 4 failure**, pending/cancelled нет. M21 report finished `2026-10-15T19:44:36.040866Z`; docs-only evidence публикуется после terminal state. Это не новая runtime qualification и не общий M18 pass.

| Workflow | Результат для 0841786 |
|---|---|
| [Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232968) | success; audit 21 без skip, M03 431/M07 97, actual candidate 67 |
| [Developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232716) | success; 3 fresh trainings, max probability difference 0, parity 2.086162567138672e-7 |
| [Tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794233011) | success; M06 18 |
| [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232914) | success; M20 723/M21 122, exact clean 0841786 binding, job 116626318108 |
| [Intake](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232847) | success |
| [Docs](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232895) | success |
| [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232978) | failure; Critical/High worker 0/56, storage 9/131, candidates 0/55 и 1/85; все 4 scans executed, SBOM validated, exit 2 |
| [Poisoning](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232902) | failure; complete, primary integrity pass 35 cases/251 files, 10 violating scenarios, 0 inconclusive |
| [Evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232921) | failure; complete/primary pass, recall drop 0.07183673469387755 >0.05 |
| [Paired research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232699) | failure; complete/primary pass, candidate recall drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 >0.05 |

Campaign IDs: poisoning `ce5ee2ae453b4012b9479b8a4f05ae3e`, evasion `bd09cf10a27a4a7dab987bc714843f20`, paired `c3e9bece52444d43b00f1173320a72be`. Эти failures не являются неожиданными audit-core regressions, но остаются реальными запретами final release, а не зелёными checks. Thresholds/exception policy не ослаблялись.

## Следующий increment

Owned rotation/retention с общим storage budget, затем actual ASGI correlation и all-output canaries. [План T16](../../tasks/plan.md) фиксирует отрицательные сценарии и отдельную проблему correlation: candidate permit нельзя выдавать за promotion selection/approval. Существующий journal проверяет форму refs, а не их provenance. До этой интеграции T16/M13 и общая цель R1 остаются открытыми. Рабочие Docker/WSL/Kubernetes пользователя в этом increment не запускались и не изменялись.
