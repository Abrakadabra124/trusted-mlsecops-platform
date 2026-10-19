# ADR 0043: ограниченные метрики serving без request identities

Дата: 2026-10-19. Статус: implemented, native verified на 93de1b6: 35 metrics tests / 0 skips / 100%, 78 actual-candidate cases и 69 approved samples. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Продолжает [ADR 0041](0041-serving-output-privacy.md) и [ADR 0042](0042-worker-process-privacy.md); не принимает полный M13/R1. [Evidence, failed attempt и обе matrix](../evidence/serving-metrics-2026-10-19.md), [RB-62/PB-36](../operations/serving-metrics-troubleshooting.md).

## Требование

Оператору нужны ответы на три вопроса: сколько HTTP-запросов завершилось, какова доля отказов/прерванных ответов, как распределена задержка. Автоматические FastAPI/OpenTelemetry exporters остаются выключены: request URLs, query, headers, features, principal/request/release IDs и exception text не должны становиться metric labels или exemplars.

## Решение

- Отдельный in-memory collector на экземпляр приложения. Только routes predict/ready/live/other и outcomes 2xx/3xx/4xx/5xx/aborted. Histogram имеет фиксированные buckets, включая +Inf. С учётом diagnostic counter экспорт содержит ровно 69 series; все series существуют с нулевыми значениями до первого запроса.
- Использовать закреплённый prometheus-client 0.26.0 как serializer стандартного формата и parser в проверках. Собственный collector хранит только фиксированные числовые агрегаты, без глобального registry, process/python/gc metrics, exemplars, timestamps или multiprocess files. Не запускать Prometheus/Grafana или дополнительный HTTP server этим slice.
- ASGI wrapper находится снаружи всего FastAPI stack, включая ServerErrorMiddleware, и наблюдает фактически прошедший через send статус после audit replacement или server error handling. Успех final body send обозначает завершённый ASGI response, не доставку клиенту. Outcome/duration записываются немедленно после этого send, до последующей background/audit работы; исключение после завершения не создаёт второй aborted. Незавершённый/отменённый transport считается aborted при выходе из приложения. Метрики не читают body и не вызывают engine, SQL или audit sink. Ошибка измерения учитывается отдельным bounded counter, не разрешает обход serving deadline и не меняет HTTP outcome. Wrapper делегирует атрибуты внутреннему приложению, сохраняя доступ к state/router/lifespan; create_app возвращает ASGI wrapper, не экземпляр FastAPI.
- GET /metrics включается только с отдельным операторским credential. Data-plane token не разрешает scrape, operator token не разрешает inference; совпадающий token отклоняется при конфигурации. Отдельная локальная quota: 4 requests/s, burst 8, не более 2 in-flight. Ticket удерживается до окончания/прерывания send, включая error responses после admission; отдельный cooperative deadline отправки 2 s, не model/trust budget. No-store, отсутствие redirect и query/body input. Scrape не зависит от готовности модели и не входит в собственные request metrics.
- Existing config без metrics_token_file сохраняет выключенный endpoint. При явном включении проверяются абсолютный путь, bounded read, POSIX permissions и формат token. Это opt-in управляемый экспорт, не неявный открытый endpoint. Runtime остаётся loopback-only; TLS/proxy/multi-process deployment требуют отдельного профиля.

## Почему так

Наблюдаемый приложением `http.disconnect` до final send исключает completed outcome: wrapper прозрачно наблюдает существующие receive calls, не делает дополнительных чтений и не анализирует body. Если разрыв не был замечен receive/send, успешный ASGI send остаётся только серверным наблюдением. Все ответы обработчика scrape, включая 401/429/503 до admission, имеют cooperative send deadline; только admitted responses владеют ticket.

Schema: `mlsecops_http_responses_total` - counter с labels route/outcome (4 × 5 = 20); `mlsecops_http_duration_seconds` - histogram только с route, buckets **0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1, 5, 10, +Inf секунд** (4 × (10 buckets + sum + count) = 48); `mlsecops_http_metrics_errors_total` - один counter без labels. Всего **69 samples**, без `_created`, timestamp и exemplars. Полный набор sample names/labels проверяется независимым ожидаемым набором, не только числом 69. HTTP wrapper использует monotonic clock от входа до завершённого final send либо abort; missing measurement увеличивает diagnostic counter.

[Prometheus instrumentation guidance](https://prometheus.io/docs/practices/instrumentation/) рекомендует counters/errors/duration, согласованное время учёта и малую cardinality. [Custom collectors](https://prometheus.github.io/client_python/collector/custom/) позволяют экспортировать фиксированный snapshot. Отдельный collector не использует default registry или зависящие от environment multiprocess Counter storage. Версия и отсутствие обязательных дополнительных зависимостей проверены по PyPI metadata; lock добавляет один пакет, не обновляет прежние зависимости.

Private audit сохраняет детальную correlation отдельно; public metrics не являются способом её публикации. Самописный Prometheus wire format не нужен, а стандартная автоинструментация с произвольными URL/labels нарушает privacy boundary.

Порядок внешнего wrapper выбран по [Starlette middleware](https://starlette.dev/middleware/): user middleware не охватывает внешний ServerErrorMiddleware. Отдельный send deadline не подменяется keep-alive timeout; [Uvicorn server behavior](https://uvicorn.dev/server-behavior/) различает keep-alive и write flow control.

## Контракт проверки

1. Failure-first: fixed series до/после множества уникальных URL/header/query canaries; чужой глобальный registry не попадает в output; environment не создаёт multiprocess files; invalid route/outcome/duration не создаёт series.
2. Actual ASGI send: normal/error status, audit 200 -> 503 replacement, send failure, cancellation, incomplete body и исключение после completed body. Один request учитывается один раз, event-loop cancellation не скрывается.
3. Endpoint: отдельные credentials/quotas, duplicate authorization, token collision, model unavailable, query/body rejection, отключённый endpoint. Probe принимает только ожидаемые parsed families/type/documentation/labels, включая проверку пустых families и комментариев с whitespace. Все headers ограничены cache-control/content-type/content-length/date с точными либо ограниченными значениями, duplicates запрещены; canaries и operator credential проверяются и в headers, и в body. Это профиль текущего loopback server, не произвольного reverse proxy.
4. Canary/export qualification на actual candidate в disposable Linux CI с очищенным summary. Повторить прежние worker/privacy/HTTP/audit/serving gates и сохранить полную matrix, включая image/ML failures.

## Ограничения

Один процесс, reset counters при restart, нет durable audit в metrics. Не учитываются запросы, отвергнутые Uvicorn до приложения. Серверное измерение не заменяет клиентский нагрузочный профиль M14; Prometheus/Grafana/alerts этим решением не объявляются развёрнутыми. Controller memory/core policy, прочие сторонние streams и full-chain export/correlation остаются открытыми. Synthetic-only проверка не доказывает differential privacy или отсутствие membership inference.
