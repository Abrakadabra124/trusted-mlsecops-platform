# Release Risk Advisor: локальный API

Privacy boundary (2026-10-19): routes точные, `/v1/predict/` и `/readyz/` не перенаправляют raw query/Host, а возвращают 404. Native FastAPI traces/metrics/logs/operation spans и environment auto-configuration явно отключены. Private bounded audit остаётся обязательным; Uvicorn access logging отключён отдельно от error logging. [ADR 0041](decisions/0041-serving-output-privacy.md), [проверки и ограничения](evidence/serving-privacy-2026-10-19.md). Это не полная M13-приёмка всех каналов платформы.

Реализован `mlsecops.serving_http` поверх проверенного Reader и isolated ONNX worker. Это ещё не принятый R1: реальный candidate с failed gates не должен становиться ready. Положительная native демонстрация использует отдельные test roots и явно обозначенные contract fixtures, а не фиктивное разрешение настоящего release.

## Запрос и ответ

`POST /v1/predict`, `Content-Type: application/json`, `Authorization: Bearer <локальный token>`:

```json
{
  "schema_version": 1,
  "instances": [{
    "change_size": 0.4,
    "failed_checks": 0.1,
    "dependency_changes": 0.2,
    "test_coverage": 0.8,
    "change_entropy": 0.3,
    "prior_failure_rate": 0.1
  }]
}
```

Это нормализованные synthetic features, не реальные business attributes или подтверждённый прогноз промышленного релиза. До 100 строк и 65 536 actual body bytes; строго шесть полей в каждой строке, конечные числа, не boolean. Внутри `[0,1]` модель возвращает score; finite values за границей дают `abstain/outside-support`. Это range guard, не универсальное обнаружение неизвестных распределений.

Успешный ответ содержит `schema_version`, новый `request_id`, `bundle_sha256`, `model_sha256` и ordered `predictions`. Каждая prediction: `decision=score|abstain`, `score` в `[0,1]` или null, `reason=null|outside-support`. Модель нельзя передать в запросе: `model_url`, path, дополнительные поля и другая version отвергаются.

| HTTP | Значение |
| --- | --- |
| 200 | score/abstain после trust checks, либо проверенный `/readyz` |
| 401 | отсутствующий/неверный bearer token |
| 413 | body превышает 64 KiB, в том числе chunked без Content-Length |
| 422 | schema/число/версия/JSON/encoding/Content-Length/body deadline не соответствует contract |
| 429 | исчерпана client quota, заняты admission slots или Engine lock |
| 503 | нет проверенной модели, trust failure, worker failure, audit unavailable или неопределённый cleanup |

Error response содержит только schema version, server request ID и bounded `error.code`. `/livez` возвращает только process liveness без авторизации, не digest или readiness. `/readyz` требует bearer и проверяет действующую worker session; docs/OpenAPI endpoints отключены. Ответы prediction/readiness/error используют `Cache-Control: no-store`.

## Deadline и незавершённые операции

После auth фиксируется общий response budget <=10 s, дополнительно ограниченный trust lease и approval expiry с запасом 250 ms. Текущий более короткий lease учитывается во время ожидания и после serialization; прежний budget не продлевается. Expired/fenced generation даёт 503 до body/overload. HTTP timeout не отменяет синхронный SQL thread: pending task и один из 8 slots сохраняются до его завершения, поздний результат не возвращает поколение в ready. Требуется explicit verified reload после восстановления и cleanup. Это не real-time delivery SLA и не bounded shutdown guarantee. [ADR 0034](decisions/0034-serving-response-deadline.md), [RB-53](operations/serving-deadline-troubleshooting.md).

## Конфигурация

Сохранить private JSON вне Git, например `.runtime/serving/config.json`. Полный набор полей:

```json
{
  "storage_client": "<absolute path to model-storage serving TLS identity>",
  "trust_client": "<absolute path to separate authority serving TLS identity>",
  "context": {"<same complete verified promotion context>": "<not a placeholder at runtime>"},
  "trusted_root": "<externally pinned promotion public key>",
  "expected_policy": "<externally pinned SHA-256>",
  "expected_serving_image": "sha256:<verified local image ID>",
  "minimum_sequence": 1,
  "trust_root": "<externally pinned authority public key>",
  "minimum_trust_version": 1,
  "audit_directory": "<absolute owned private Linux directory for retained audit>",
  "token_file": "<absolute private file containing 64 lowercase hex characters>"
}
```

Шаблон намеренно не является работоспособной конфигурацией. Использовать реальные внешние pins и тот же полный context, с которым проверялся promotion, не данные из отвергнутой модели. Context включает candidate/evaluation references, evaluation policy, curator/evaluator public keys/source approval, expected training source/image bindings и owners. Не понижать minimum versions при восстановлении. Client directory содержит только TLS client identity/config, не model/trust signing keys. Local host/administrator остаются доверенными; POSIX mode check не заменяет Windows ACL или production identity isolation.

Token генерировать криптографически случайно, не копировать значение из примера, не печатать и не коммитить. На POSIX права файла 0600; Windows ACL ограничить владельцем. Public roots не секретны, но их подмена нарушает trust anchor. Не передавать signing keys API или worker.

```powershell
uv run --locked python -m mlsecops.serving_http --config .runtime/serving/config.json --port 8080
```

CLI всегда слушает `127.0.0.1`, не предоставляет `--host`, не включает access log или доверие к forwarded headers. Local HTTP не защищает от привилегированного host attacker. Remote/TLS ingress, полноценный audit и production deployment ещё не квалифицированы.

### Несколько локальных клиентов и quotas

Вместо `token_file` можно передать `principals_file` с absolute path к отдельному private JSON (до 64 KiB). Оба поля одновременно запрещены. Файл имеет `schema_version: 1` и массив `clients` из 1-32 объектов:

```json
{
  "schema_version": 1,
  "clients": [{
    "principal_id": "<random 32 lowercase hex characters>",
    "token": "<random 64 lowercase hex characters>",
    "requests_per_second": 20,
    "burst": 40,
    "max_in_flight": 4
  }]
}
```

Это шаблон, не готовые credentials. Генерировать IDs/tokens криптографически случайно, хранить owner-only и вне Git. Rate/burst - целые 1-1000, in-flight - 1-4. Unknown fields, duplicate IDs/tokens и bool/floats запрещены. Identity определяется bearer credential, не клиентским заголовком или IP. Файл читается только при старте; [RB-54/PB-28](operations/serving-client-troubleshooting.md) описывает rotation/recovery и ограничения.

Один principal делит quota между predict/ready; `/livez` не расходует её и не делает ML. Legacy `token_file` теперь имеет limits **20 requests/s, burst 40, 4 in-flight**, без режима unlimited. Один запрос расходует один token независимо от batch, invalid body или global overload; 100-row/64-KiB bounds сохраняются. 429 `client_limited` возвращается до body/executor; это rate либо in-flight denial. 503 по trust/deadline имеет приоритет. Pending task сохраняет client ticket даже после HTTP timeout/cancel, поэтому 429 не лечится обнулением счётчика.

Quotas process-local: Engine reload не сбрасывает их, restart сбрасывает. Это не multi-replica rate limit или гарантия доступности других клиентов при общей неисправности runtime. [ADR 0035](decisions/0035-serving-client-quotas.md), [evidence](evidence/serving-clients-2026-10-15.md). Full M13 privacy/audit остаётся открыт.

Engine cold-start rejection оставляет API живым, но `/readyz` и predictions возвращают 503. Ошибка конфигурации или открытия owned audit journal не даёт серверу стартовать; liveness в этом случае не обещается. Автоматического trust bypass/reload на HTTP endpoint нет. Для нового разрешённого release подготовить проверенную конфигурацию и контролируемо перезапустить сервис; не редактировать SQL head вручную. [PB-25/RB-48/RB-49](operations/serving-troubleshooting.md) описывает диагностику и обязательную проверку конечного состояния.

## Обязательный protected-request audit

`audit_directory` - absolute path к owned private Linux retained storage. Writer открывается только при запуске lifespan и закрывается после Engine cleanup; конфигурация сама не создаёт файлов. Для программного API допустим отдельный уже запущенный injected `Journal`, который закрывает его владелец, не приложение. Отсутствие journal в `create_app` даёт protected 503 до body/executor, а не silent fallback. Windows single-file tests не квалифицируют production retention.

Перед отправкой 200 записывается собственный intent с проверенным private context; приложение ждёт его fsync в пределах прежнего budget и повторно проверяет deadline/generation. Actual start/completed фиксируются после ASGI send, cancel не превращается в completed. Успешный send не доказывает получение клиентом. После network send отказ sink даёт evidence gap и запрет следующих admissions, не возможность отозвать уже отправленный ответ.

Уже выданные global/client slots сохраняются до завершения BOTH HTTP и executor, в том числе при зависшей отправке audit-denied 503. `/livez`, anonymous auth и отказы до global admission не создают audit entries. При восьми admitted audit waiters проверяется headroom health с Uvicorn limit 16; произвольный connection flood этим не исключается. [ADR 0040](decisions/0040-serving-http-audit.md), [RB-59/PB-33](operations/serving-http-audit-troubleshooting.md), [evidence](evidence/serving-http-audit-2026-10-18.md). All-output canaries, export/cardinality и полный M13 остаются незавершёнными.

## Воспроизведение

На чистом owned disposable storage стенде после стандартных bootstrap/build:

```powershell
uv run --locked python -m scripts.release_reader_native --state .runtime --confirm-disposable --worker-image trusted-mlsecops:dev
```

Runner создаёт две отдельные SQL БД, random test roots, generated ONNX и временный loopback API. Проверяет real CPU parity, same persistent worker, named features, 401/413/422, malformed model, worker stop/deadline/cleanup, explicit verified reload и actual revocation -> 503. Это механизм qualification, **не startup shortcut или готовый M12 pass**. Не запускать на working Docker/единственном state без согласования; CI использует отдельную машину. Результаты и ограничения: [evidence](evidence/serving-api-2026-10-14.md).
