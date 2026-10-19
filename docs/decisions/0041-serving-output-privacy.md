# ADR 0041: явная privacy boundary для существующего serving

Дата: 2026-10-19. Статус: implemented, local qualification pass; native actual-candidate verification pending. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Продолжает [ADR 0040](0040-serving-http-audit.md), не принимает полный M13/R1.

## Требование и обнаруженная проблема

Запрет raw payload в собственном audit недостаточен: framework, access logger или redirect могут независимо сохранить/отразить вход. На закреплённом FastAPI 0.142.2 controlled recorder увидел synthetic marker из path/query в native span. Default slash redirect вернул 307 с marker из query в Location. Это воспроизведения на синтетике, не обнаруженная отправка пользовательских данных наружу.

FastAPI - Python web framework. Его встроенный OpenTelemetry поддерживает traces, metrics и logs, включая глобальные providers; автоматическую настройку exporter можно включить environment. OpenTelemetry - API и набор стандартов наблюдаемости, а не механизм анонимизации. Основание: [официальная документация FastAPI](https://fastapi.tiangolo.com/advanced/opentelemetry/), сверенная 2026-10-19, плюс код закреплённого пакета и positive control.

## Решение

1. `create_app` задаёт `tracing`, `metrics`, `logs`, `operation_spans`, `auto_configure` равными false. Это явное отключение native FastAPI instrumentation, даже при `FASTAPI_OTEL_AUTO_CONFIGURE=true`, а не надежда на отсутствие SDK сегодня. Собственный bounded audit, liveness, readiness, quotas и trust checks остаются.
2. `redirect_slashes=False`: неканонический route возвращает 404 вместо Location с raw query/Host. Клиент использует точные `/livez`, `/readyz`, `/v1/predict`. Поведение параметра описано в [FastAPI reference](https://fastapi.tiangolo.com/reference/fastapi/).
3. Существующий Uvicorn остаётся с `access_log=False`, `proxy_headers=False`, `server_header=False`. Access logger и error logger различаются: отключение первого не доказывает приватность второго, см. [Uvicorn settings](https://uvicorn.dev/settings/). Условия проверяются исполнением, а не только конфигурацией.
4. `serving_privacy_probe.exercise` пропускает 12 запросов через реальный loopback HTTP и неизменённые auth/ML/audit. Только recorders и output capture контролируются тестом. Native candidate запускает ту же матрицу после восстановления signed trust window, без fixture approval и подмены модели.

## Проверяемые каналы и bounds

Синтетические probes покрывают body, unknown field, feature type, malformed JSON, query, path, Content-Type, forged bearer, Cookie, Baggage, Traceparent, X-Request-Id и Host/slash redirect. Ожидаемые статусы: 200, 200, 422, 422, 422, 422, 422, 401, 404, 404, 413, 200. Девять admitted requests должны добавить ровно 36 accepted и 36 durable audit events после drain; auth/404 не создают reservations.

Проверяются HTTP headers/body, controller stdout/stderr, Python logging и принадлежащий тесту временный audit directory. Native telemetry не должна даже использовать controlled global providers. Positive control на default FastAPI доказывает, что recorder действительно способен обнаружить span.

- stdout/stderr/logs: максимум 65536 символов на канал; overflow запрещает pass. Logging interception не добавляет handlers: добавленный handler мог бы включить `uvicorn.access` через `hasHandlers()` и изменить проверяемую систему.
- HTTP transport: максимум 65536 bytes body; дополнительный байт или неполный Content-Length запрещает приёмку, префикс не считается целым ответом. Общий capture headers/body также bounded. JSON нормализуется для поиска полного feature object независимо от whitespace/key order.
- Headers проверяются до JSON escaping: raw names/values сканируются отдельно. Разрешены только bounded Date, application/json Content-Type, точный Content-Length, no-store Cache-Control и close Connection; duplicates/unknown headers отклоняются. Это контролируемый контракт loopback qualification, не произвольного reverse proxy.
- Markers, forged и действующий тестовый credential, SHA-256 marker не допускаются в наблюдаемых выходах. Действующий credential передаётся только приватным ephemeral атрибутом HTTP helper; credential-wrapper явно выбирает используемый token, не публикуя его. Полный feature object запрещён и в response. Exact response schema дополнительно запрещает features в иных структурах, top-level полях или prediction entries. Одиночное числовое feature значение не ищется в response: легальный score может совпасть; в logs/audit его наличие запрещено.
- Audit scanner читает только owned temporary fixture после drain: максимум 66 regular files, 17 MiB совокупно, без nested directories, symlinks и hardlinks. Empty/missing/oversized source, invalid needles и malformed receipt запрещают pass. Это не race-free scanner произвольного hostile filesystem и не разрешение читать реальный audit каталог.
- Public summary имеет конечный набор counts/flags, не содержит markers, feature rows, credentials или audit events; `release_ready=false` остаётся обязательным.

## Альтернативы и цена решения

Одна denylist для query/headers ненадёжна: новые framework attributes и произвольные имена полей обходят её. «Не установлен exporter» зависит от окружения. Поэтому сначала исключены неуправляемые native channels, затем проверены реально используемые выходы. Замена framework, установка SDK/collector и новый orchestration stack для этого не нужны.

Цена - native FastAPI telemetry недоступна. Следующий отдельный slice должен определить разрешённые metrics/traces с bounded labels, безопасным export и negative tests. Нельзя объявить cardinality requirement выполненным просто из-за отключения всех native metrics.

## Проверка и остаточные ограничения

[Evidence](../evidence/serving-privacy-2026-10-19.md) фиксирует red/green, adversarial review и coverage. [RB-60/PB-34](../operations/serving-privacy-troubleshooting.md) описывает воспроизведение и безопасные действия.

Не доказаны privacy всех worker subprocess outputs, полной source/run/report/approval/release/request цепочки, public export всей платформы, будущих telemetry wrappers или privileged host instrumentation. Canary suite не доказывает отсутствие любой возможной утечки, membership inference или differential privacy. Полный M13, image/ML gates и R1 остаются открытыми.
