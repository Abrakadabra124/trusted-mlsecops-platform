# Release Risk Advisor: локальный API

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
| 429 | заняты admission slots или Engine lock |
| 503 | нет проверенной модели, trust failure, worker failure или неопределённый cleanup |

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
  "token_file": "<absolute private file containing 64 lowercase hex characters>"
}
```

Шаблон намеренно не является работоспособной конфигурацией. Использовать реальные внешние pins и тот же полный context, с которым проверялся promotion, не данные из отвергнутой модели. Context включает candidate/evaluation references, evaluation policy, curator/evaluator public keys/source approval, expected training source/image bindings и owners. Не понижать minimum versions при восстановлении. Client directory содержит только TLS client identity/config, не model/trust signing keys. Local host/administrator остаются доверенными; POSIX mode check не заменяет Windows ACL или production identity isolation.

Token генерировать криптографически случайно, не копировать значение из примера, не печатать и не коммитить. На POSIX права файла 0600; Windows ACL ограничить владельцем. Public roots не секретны, но их подмена нарушает trust anchor. Не передавать signing keys API или worker.

```powershell
uv run --locked python -m mlsecops.serving_http --config .runtime/serving/config.json --port 8080
```

CLI всегда слушает `127.0.0.1`, не предоставляет `--host`, не включает access log или доверие к forwarded headers. Local HTTP не защищает от привилегированного host attacker. Remote/TLS ingress, scoped service identity, per-client quotas/audit и production deployment ещё не квалифицированы.

Startup failure оставляет API живым, но `/readyz` и predictions возвращают 503. Автоматического trust bypass/reload на HTTP endpoint нет. Для нового разрешённого release подготовить проверенную конфигурацию и контролируемо перезапустить сервис; не редактировать SQL head вручную. [PB-25/RB-48/RB-49](operations/serving-troubleshooting.md) описывает диагностику и обязательную проверку конечного состояния.

## Воспроизведение

На чистом owned disposable storage стенде после стандартных bootstrap/build:

```powershell
uv run --locked python -m scripts.release_reader_native --state .runtime --confirm-disposable --worker-image trusted-mlsecops:dev
```

Runner создаёт две отдельные SQL БД, random test roots, generated ONNX и временный loopback API. Проверяет real CPU parity, same persistent worker, named features, 401/413/422, malformed model, worker stop/deadline/cleanup, explicit verified reload и actual revocation -> 503. Это механизм qualification, **не startup shortcut или готовый M12 pass**. Не запускать на working Docker/единственном state без согласования; CI использует отдельную машину. Результаты и ограничения: [evidence](evidence/serving-api-2026-10-14.md).
