# Serving client admission: evidence, 2026-10-15

Increment после `3c9da7a`. [ADR 0035](../decisions/0035-serving-client-quotas.md), [RB-54/PB-28](../operations/serving-client-troubleshooting.md). Scope T16 identity/quotas, не full M13/R1.

## Реализация и failure-first проверки

Bounded credential allowlist, независимые integer token buckets и per-client retained tickets. Explicit limits действуют также в старом single-token config. Clock rollback/invalid values блокируют admission; ticket release остаётся возможным. Body error, global overload и cancellation не дают refund использованного rate token. После dispatch client ticket, как и global slot, живёт до completion настоящего task, не до окончания HTTP wait.

Первые тесты воспроизвели отсутствие access module и multi-client API. После реализации проверены malformed/duplicate config, foreign/duplicate auth, identity separation, exact refill boundary, huge clock jump capped at burst, rollback/NaN/bool/overflow/clock exception, 16 concurrent admissions, double release, body-before-quota denial, HTTP cancel/deadline retention, trust-before-quota priority, private config и conflicting credentials. Тест loopback HTTP проверяет 200/429/401 и refill двух clients с controlled Engine; это не native SQL/ONNX.

Локально после всех harness corrections: **186 adjacent methods pass за 24.270 s**. Новый access core: **29 methods, 100% statement/branch coverage** (93 statements, 30 branches). Serving suite до последних дополнительных harness/overload tests: 72 methods pass, combined coverage 93% (707 statements, 204 branches); это исторический промежуточный coverage run, не финальное число methods. Ruff lint/format, diff check и docs check прошли: 370 files, 139 Markdown, 1010 local links. Native CI после code push ещё нужен, его результаты здесь не предполагаются.

Scoped same-model review access module не нашёл конкретных воспроизводимых замечаний. HTTP/native review выявил две ошибки первоначального испытания: inference >1 s успевал восстановить bucket, а большой burst другого клиента скрывал cross-charge. Harness исправлен: два fresh 1/s burst-1 clients, последовательность invalid A/A/B/B в измеренном окне <1 s, ожидаемые 422/429/422/429; затем refill и valid inference. Regression с замедлением inference 1.1 s проходит, deliberate cross-charge отвергается, позднее окно остаётся inconclusive. Внешняя модель не используется по решению владельца. Это не независимый человеческий security audit.

Следующий scoped review воспроизвёл ещё один пробел harness: чужое списание только при valid inference, скрытое последующим refill. Regression сначала получил ложный pass. Добавлены cumulative admitted counters под тем же lock, изолированные копии snapshots и native сверка `[2,2,4]` без IDs/tokens. После исправления такой delayed cross-charge отвергается, а медленный корректный inference проходит. Это усиление доказательства, не обнаруженный cross-charge в production Access.

Третий bounded harness review обнаружил интеграционную ошибку: `functools.partial` не переносил диагностический атрибут исходного HTTP client. Полный HTTP-prefix regression воспроизвёл AttributeError до quota checks; исправлено передачей исходного transport в диагностический helper. Этот regression после исправления проходит до границы container probes; Docker в нём не запускается. Дополнительные reviewer cycles не запускались; финальная adjacent suite включает все найденные regression cases.

## Ограничения

Только один loopback process и trusted host administrator. Quotas volatile, reset при process restart, не distributed/fairness SLA; скомпрометированный credential использует бюджет своего principal. Rate ограничивает запросы, не отдельные rows, но batch/body имеют независимые bounds. Общий отказ trust/worker затрагивает всех клиентов независимо от quotas. Anonymous connection flood не устраняется credential table.

Полный audit, retention, private release-chain correlation, cardinality instrumentation и all-output canary/export qualification ещё не реализованы. Прежние image/ML failures сохраняются; qualification не разрешает реальную release promotion. Working Docker/WSL/Kubernetes пользователя не запускались.
