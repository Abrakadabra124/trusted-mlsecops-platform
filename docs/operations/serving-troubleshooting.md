# PB-25 / RB-48 / RB-49: API, worker lifecycle и безопасный отказ

Владельцы: platform owner, release approver; при corruption/revoke - security owner. Это local CPU lab, не production incident guide. Симптомы ниже воспроизведены контролируемыми tests; native статус указан в [evidence](../evidence/serving-api-2026-10-14.md).

## PB-25: Повторить qualification без изменения рабочего runtime

Prerequisites: Python 3.12 и `uv.lock`, checkout проекта. Первые проверки не требуют работающего Docker и не запускают текущую платформу:

```powershell
git status --short
git rev-parse HEAD
uv run --locked coverage run --data-file=.coverage-serving --source=mlsecops.serving_protocol,mlsecops.serving_worker,mlsecops.serving_runtime,mlsecops.serving,mlsecops.serving_http -m unittest scripts.serving_session_qualification scripts.serving_runtime_qualification scripts.serving_core_qualification scripts.serving_http_qualification scripts.serving_native_qualification
uv run --locked coverage report --data-file=.coverage-serving --fail-under=85
```

Проверять exit code каждой команды. Unit/controlled process/loopback HTTP tests не доказывают Docker isolation. Зависший Python child test завершается принудительно; это отдельный test subprocess без storage/signing credentials. Privacy canary проверяется в error response, не является полной M13 log/metrics/traces кампанией.

Native этап только на disposable CI/согласованном стенде после owned storage bootstrap и build. Read-only prerequisites: clean Git, `docker info`, свободные loopback 15444/15445. Не перезапускать чужие контейнеры, Docker/WSL или исходную enterprise платформу.

```powershell
uv run --locked python -m scripts.release_reader_native --state .runtime --confirm-disposable --worker-image trusted-mlsecops:dev
```

Изменения: создаются два новых owned SQL workspace, временный API на случайном loopback port и session workers. Native probe посылает STOP **только своему** worker, проверяет timeout/503/removal и новый verified load. Затем отзывает test model в своей authority и проверяет 503. Не применять эти fault commands вручную к рабочим контейнерам.

Ожидаемый report `.runtime/evidence/release-reader-qualification.json`: scope `serving-HTTP-ONNX-TLS-controlled-fixture-not-full-M12`, `release_ready=false`, `full_M12=inconclusive`, отдельные cases и runtime measurements. Положительная цепочка содержит synthetic contract reports с одноразовыми test roots, не реальную acceptance. Ready=true внутри этой fixture не разрешает настоящий candidate. Проверка без `--worker-image` остаётся старой reader-only qualification.

Сохранить terminal CI link/commit, case labels и очищенные metrics. Не публиковать private state, keys, tokens, raw HTTP body, generated models или raw logs. Повторный запуск создаёт новый campaign, не использует прежний ready state. Source storage/checkout должны остаться неизменными; cleanup проверяется readback.

## RB-48: Процесс жив, но API возвращает 503

**Симптом:** `/livez` 200, `/readyz` или predict 503. Влияние: ML-ответов нет, случайной fallback модели не будет. Это правильное безопасное состояние при отсутствии approved release.

1. Read-only: проверить действующий commit, local bind/port и наличие external policy/image/sequence pins. Не выводить token, TLS private key или полный config в общие логи.
2. Разделить config error до запуска (`serving_configuration_rejected`) и runtime activation failure. Проверить private token file, типы/полный набор config fields и serving-only client identities. На Windows отдельно проверить ACL, автоматического доказательства здесь нет.
3. Проверить SQL/trust reachability и валидность сертификатов. Использовать [RB-46/RB-47](release-reader-troubleshooting.md) для missing material, signature/assurance, head change и clock; [RB-44/RB-45](trust-troubleshooting.md) для revoke/outage. Не отключать TLS verification, не продлевать lease и не снижать minimum sequence.
4. Если настоящее ML evidence fail, исправить исходный gate и пройти независимый approval. Не импортировать тестовые all-pass reports из PB-25.
5. Если authorization валиден, проверить availability именно pinned image и соответствие source fingerprint. Не подменять digest тегом latest. Worker load может отказать из-за malformed ONNX, другой runtime version, unsupported operators или неверного load acknowledgment; отсутствие подписи нельзя компенсировать успешным parser.
6. После устранения причины выполнить контролируемый restart с той же или новой одобренной конфигурацией. Проверить authenticated `/readyz`, expected bundle/model digests и golden predictions. `/livez` 200 или exit code launcher сами по себе недостаточны.

**Rollback:** не править head вручную, не восстанавливать отозванную модель и не очищать sequence history ради green. Разрешённый release rollback protocol остаётся отдельной работой. При неясной trust причине эскалировать владельцу ключей/approval, оставаясь unready.

## RB-49: Worker timeout, overload и cleanup

**Симптом:** 429, 503 после зависания worker, несовпадающий response digest или остановка session. Parent ждёт worker reply максимум 2 s, но полный HTTP отказ может включать SQL/trust checks и cleanup. Это не измеренный M14 SLO.

1. Read-only: различить invalid client data (422), body limit (413), admission/lock pressure (429) и потерю runtime (503). Invalid request не должен выключать здоровую модель. Не обходить bounds увеличением memory/body/timeout без отдельного измерения и ADR.
2. При 429 снизить частоту/параллелизм клиента. У API восемь admitted operations, один persistent worker, serialized Engine. Per-client quotas пока отсутствуют, benchmark ещё обязателен.
3. При timeout/EOF/malformed/late reply session терминальна. Не читать поздний reply как ответ новому request и не продолжать использовать старый handoff. Runtime code автоматически завершает Docker CLI и удаляет только собственный полный container ID, затем проверяет отсутствие.
4. Если cleanup не подтверждён, сохранить private owned container ID и config readback, оставить API unready. Сначала проверить daemon availability и соответствие ID/session label. Не применять global prune и не удалять контейнер по случайному user-supplied name. Handle сохраняется для повторной cleanup; reset working state не нужен.
5. После подтверждённой cleanup и устранения причины запустить полный verified load/restart. Он снова проверит current SQL head, signatures/approval и свежий trust, затем новый session nonce/model digest и runtime. Прежний cached ready/старая session не используются.
6. Если клиент оборвал HTTP запрос, работающий thread не считается завершённым. Admission slot освобождается только по фактическому завершению фоновой операции; повторные cancellations не должны обходить лимит. При shutdown дождаться закрытия worker, а не просто исчезновения HTTP socket.

**Критерий восстановления:** expected readiness/digest, successful golden response, negative invalid-input/revocation test остаётся отказом, собственные старые worker containers отсутствуют. Сравнение состояния после cleanup обязательно. Нативная тестовая STOP-инъекция проверяет этот путь, а не production capacity или универсальную защиту от произвольного native exploit.

## Встреченные проблемы и исправления

- Regression test показал slot leak в обратную сторону: отменённый HTTP task освобождал слот, хотя synchronous inference продолжался. Исправлено shielded execution с deferred release callback; callback также забирает exception, не печатая private detail.
- AutoRemove может удалить контейнер между `container ls` и `rm`. Ошибка rm не считается доказательством живого orphan: проверяется конечное отсутствие. Если контейнер всё ещё есть, cleanup остаётся unconfirmed и handle сохраняется.
- Positive reader fixture раньше содержала opaque `controlled-no-model-parser`, а не ONNX. Для runtime campaign создана отдельная настоящая synthetic модель и заново связаны model/capsule/release/report subjects. Test assurance остаётся явно fixture; его не выдают за реальную M01-M23 приёмку.
- [Evidence](../evidence/serving-api-2026-10-14.md) хранит фактические local/native результаты и ограничения, включая отсутствие независимого review и production deployment.
