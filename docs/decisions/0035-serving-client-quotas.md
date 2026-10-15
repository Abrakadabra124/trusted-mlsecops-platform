# ADR 0035: bounded local client admission

Дата: 2026-10-15. Статус: implemented, scoped native qualification на `687a7c7`. Scope: T16 identity/quotas, не полный M13. [Evidence](../evidence/serving-clients-2026-10-15.md) сохраняет исходный native failure и correction.

## Контракт

Один loopback HTTP process получает immutable allowlist из 1-32 clients. Каждый client имеет opaque 32-hex `principal_id`, случайный 64-hex bearer token и целочисленные `requests_per_second`/`burst` (1-1000), `max_in_flight` (1-4). Duplicate IDs/tokens, лишние поля, bool/floats и невалидные bounds отвергаются при запуске. Identity выводится только из одного точного Authorization header; IP, forwarded/client-ID headers не участвуют.

На `/v1/predict` и `/readyz` после auth и проверки serving deadline, но до body/executor применяется один общий для principal token bucket. Один запрос расходует один token, включая invalid body и отказ global overload; batch остаётся ограничен 100 строками/64 KiB. Credits считаются целыми nanounits от `monotonic_ns`, refill ограничен burst. Отказ admission не возвращает потраченные tokens. Clock rollback/invalid sample запрещает дальнейший admission до перезапуска, без изменения serving trust.

Отдельный per-client in-flight ticket освобождается идемпотентно. До dispatch им владеет HTTP handler, после dispatch - completion callback реального task. HTTP cancellation/timeout не освобождает ticket при pending SQL. Global 8-slot bound, generation fence и before-send trust check остаются независимыми. Principal не может занять все 8 slots один, но quotas не гарантируют scheduler fairness или доступность при общей неисправности authority/worker.

Каждый bucket также считает cumulative successful admissions под тем же lock, что списывает credit. Release/refill не сбрасывают count; read-only snapshot возвращает копию. Это bounded-cardinality private accounting, не готовый audit/metrics endpoint. Native helper сверяет дельты двух diagnostic clients и общего числа admissions: строго `[2,2,4]` за boundary + refill requests. Так медленный inference не скрывает дополнительное чужое списание, даже если token успел восстановиться. Public report содержит только эти counts, не IDs или tokens.

429 `client_limited` обозначает rate/in-flight отказ, 503 - недействующий serving budget или ошибка quota clock. Retry-After не обещается: completion pending SQL не имеет надёжной оценки. `/livez` остаётся без auth и не вызывает inference. Network connection/anonymous flood protection остаётся задачей bounded server/ingress, не этой таблицы.

## Конфигурация и совместимость

Новый `principals_file` заменяет `token_file`, но оба вместе запрещены. Private JSON содержит `schema_version=1`, `clients` с полями выше; strict schema, absolute path, bounded read 64 KiB, POSIX group/other permissions запрещены. Windows ACL проверяется оператором. Credentials/IDs не печатаются и не входят в public evidence. Файл читается при старте, не hot reload; смена/отзыв credentials требует контролируемого restart. Host administrator остаётся trusted.

Прежний `token_file` и `create_app(engine, token)` остаются поддержаны с **явными default limits: 20 requests/s, burst 40, max_in_flight 4**. Ранее rate limit отсутствовал; это намеренное ужесточение, а не обещание прежней пропускной способности. Engine reload не сбрасывает quotas; process restart сбрасывает volatile counters. Нельзя применять этот профиль к нескольким workers/replicas как distributed quota.

## Проверка и следующие границы

Failure-first tests: foreign/duplicate auth, bounded table, чужой bucket, refill/rollback/overflow, concurrent admissions, double release, body rejection, deadline/cancellation и удержанный executor task. Native disposable HTTP: два diagnostic clients по 1/s burst 1, boundary A/A/B/B через invalid body даёт 422/429/422/429 в измеренном окне <1 s; затем refill и valid inference 200 обоих. Основной client использует отдельные 20/s burst 40. Просроченное окно даёт inconclusive, а не ложный rate failure. Secrets не выводятся. Scoped review и evidence обязательны. Audit/canary export, retention, telemetry cardinality и full M13 выполняются следующими slices, не считаются реализованными этим ADR.

## Источники и выбор

- [OWASP API4](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/) рекомендует ограничивать частоту клиентских запросов и размер batch. Наши конкретные bounds являются lab policy, не универсальной рекомендацией OWASP.
- [Python 3.12 time](https://docs.python.org/3.12/library/time.html#time.monotonic_ns) предоставляет monotonic integer nanoseconds; не используем wall clock и float refill.
- [RFC 6585](https://www.rfc-editor.org/rfc/rfc6585.html#section-4) определяет 429 и допускает Retry-After, но не требует его.

Проверено 2026-10-15. Для одного процесса bounded table проще Redis и не добавляет новый network authority. При multi-process потребуется отдельное решение, admission в ingress или shared atomic store, а не копирование этой таблицы.
