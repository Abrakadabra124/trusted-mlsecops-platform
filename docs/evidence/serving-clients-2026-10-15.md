# Serving client admission: evidence, 2026-10-15

Increment после `3c9da7a`. [ADR 0035](../decisions/0035-serving-client-quotas.md), [RB-54/PB-28](../operations/serving-client-troubleshooting.md). Scope T16 identity/quotas, не full M13/R1.

## Реализация и failure-first проверки

Bounded credential allowlist, независимые integer token buckets и per-client retained tickets. Explicit limits действуют также в старом single-token config. Clock rollback/invalid values блокируют admission; ticket release остаётся возможным. Body error, global overload и cancellation не дают refund использованного rate token. После dispatch client ticket, как и global slot, живёт до completion настоящего task, не до окончания HTTP wait.

Первые тесты воспроизвели отсутствие access module и multi-client API. После реализации проверены malformed/duplicate config, foreign/duplicate auth, identity separation, exact refill boundary, huge clock jump capped at burst, rollback/NaN/bool/overflow/clock exception, 16 concurrent admissions, double release, body-before-quota denial, HTTP cancel/deadline retention, trust-before-quota priority, private config и conflicting credentials. Тест loopback HTTP проверяет 200/429/401 и refill двух clients с controlled Engine; это не native SQL/ONNX.

Локально после всех harness corrections: **186 adjacent methods pass за 24.270 s**. Новый access core: **29 methods, 100% statement/branch coverage** (93 statements, 30 branches). Финальная serving suite на `f273fd5`: **77 methods pass за 14.842 s**, combined coverage **94%** (707 statements, 204 branches). Команда диагностики RB-54 отдельно повторена: **36 methods pass за 11.468 s**; она использует временный loopback и controlled Engine, не Docker/SQL/ONNX. Ruff lint/format, diff check и docs check code increment прошли: 370 files, 139 Markdown, 1010 local links. Native CI после code push ещё нужен, его результаты здесь не предполагаются.

Scoped same-model review access module не нашёл конкретных воспроизводимых замечаний. HTTP/native review выявил две ошибки первоначального испытания: inference >1 s успевал восстановить bucket, а большой burst другого клиента скрывал cross-charge. Harness исправлен: два fresh 1/s burst-1 clients, последовательность invalid A/A/B/B в измеренном окне <1 s, ожидаемые 422/429/422/429; затем refill и valid inference. Regression с замедлением inference 1.1 s проходит, deliberate cross-charge отвергается, позднее окно остаётся inconclusive. Внешняя модель не используется по решению владельца. Это не независимый человеческий security audit.

Следующий scoped review воспроизвёл ещё один пробел harness: чужое списание только при valid inference, скрытое последующим refill. Regression сначала получил ложный pass. Добавлены cumulative admitted counters под тем же lock, изолированные копии snapshots и native сверка `[2,2,4]` без IDs/tokens. После исправления такой delayed cross-charge отвергается, а медленный корректный inference проходит. Это усиление доказательства, не обнаруженный cross-charge в production Access.

Третий bounded harness review обнаружил интеграционную ошибку: `functools.partial` не переносил диагностический атрибут исходного HTTP client. Полный HTTP-prefix regression воспроизвёл AttributeError до quota checks; исправлено передачей исходного transport в диагностический helper. Этот regression после исправления проходит до границы container probes; Docker в нём не запускается. Дополнительные reviewer cycles не запускались; финальная adjacent suite включает все найденные regression cases.

## Native failure и correction

На `f273fd5` storage CI завершился failure после quota checks: прежний trust-outage diagnostic опрашивал HTTP каждые 5 ms около lease expiry. Новый primary budget 20/s burst 40 ограничил такой поток. [Неизменённый failed trace](serving-clients-f273fd5-failure.md): 144 observations, 15 ответов 429, первый 503 за 59.742117598 s; assessment правильно отверг неожиданные статусы. Общий actual-candidate report не получил pass, последующие pause/expiry/revoke/source-preservation checks не завершены. Отдельный controlled-fixture HTTP/ONNX/TLS профиль прошёл 39 cases, включая quota statuses `[422,429,422,429]`, refill `[200,200]` и admissions `[2,2,4]`, window 0.004150635 s; его нельзя подменять actual-candidate acceptance.

Исправление меняет только native probe cadence: около deadline пауза 50 ms после ответа вместо 5 ms. Quotas не повышены, 429 не добавлен в разрешённые outage outcomes, bound 60 s и production код не изменены. В существующую exercise regression добавлен настоящий Access 20/s burst 40 с controlled clock и production-equivalent 250 ms deadline guard. Старый cadence воспроизвёл 429/failure. После correction 11 outage methods pass, coverage 92% (171 statements, 68 branches); negative cleanup delay 0.5 s по-прежнему подтверждает failure `first_http_503_exceeds_60_seconds`, recovery failure остаётся inconclusive. Adjacent suite повторена: **186 methods pass за 24.617 s**. Из опубликованного failed trace пересчитан прежний assessment, canonical SHA-256 `6eb781ae94c9c57b8999ddc5d9778c1a6bbac89760f6d9d80ccb17db7371d309`. Новый clean-checkout CI ещё необходим.

## Terminal matrix f273fd5

Все 10 workflows завершены: **5 success / 5 failure**, cancelled/pending нет. Дополнительный storage failure сохранён отдельно от прежних четырёх image/ML failures. M21 report завершён `2026-10-15T18:44:24.294917Z`; corrective push выполняется после terminal state.

| Workflow | Результат |
|---|---|
| [Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840394) | failure; 46 actual-candidate cases pass, следующий outage case fail; M03 431/M07 97, trust 45, Reader 18, fixture HTTP 39 pass |
| [Developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840432) | success; 3 fresh trainings, probability difference 0, parity 2.086162567138672e-7 |
| [Tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840389) | success; M06 18 |
| [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840808) | success; M20 723/M21 122, exact f273fd5 binding |
| [Intake](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840561) | success |
| [Docs](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840685) | success |
| [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840477) | failure; Critical/High: worker 0/56, storage 9/131, candidates 0/55 и 1/85 |
| [Poisoning](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840506) | failure; complete, integrity pass 35 cases/251 files, 10 violations, 0 inconclusive |
| [Evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840751) | failure; complete/primary pass, recall drop 0.07183673469387755 >0.05 |
| [Paired research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840642) | failure; complete/primary pass, candidate recall drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 >0.05 |

Campaign IDs: poisoning `0e970bc365d54bd282a960640d6ebc0c`, evasion `270077e81021486db41e9b4e00388af1`, paired `e399c34785034810a3e21da521f8e487`. Изменение cadence не исправляет уязвимости образов или статистические нарушения ML gates; пороги сохраняются.

## Остаточные границы

Только один loopback process и trusted host administrator. Quotas volatile, reset при process restart, не distributed/fairness SLA; скомпрометированный credential использует бюджет своего principal. Rate ограничивает запросы, не отдельные rows, но batch/body имеют независимые bounds. Общий отказ trust/worker затрагивает всех клиентов независимо от quotas. Anonymous connection flood не устраняется credential table.

Полный audit, retention, private release-chain correlation, cardinality instrumentation и all-output canary/export qualification ещё не реализованы. Прежние image/ML failures сохраняются; qualification не разрешает реальную release promotion. Working Docker/WSL/Kubernetes пользователя не запускались.
