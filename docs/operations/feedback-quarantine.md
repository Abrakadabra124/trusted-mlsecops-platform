# Приём обратной связи в карантин

Владелец приёма - ingestor, проверки сохранённой записи - curator. Команды
работают с существующим SQL storage через TLS 1.3 с проверкой имени сервера и
клиентским сертификатом. Новая база, очередь или HTTP endpoint не создаются.
Процесс inference не получает credentials на запись. Локальные Docker, WSL,
Kubernetes и SQL для этой задачи запускать или менять запрещено; ниже команды
для уже подготовленного разрешённого Linux runner.

Обратная связь является утверждением отправителя. Digest, request ID и подпись
транспорта сами по себе не подтверждают существование запроса или правильность
метки. Этот интерфейс не выдаёт source attestation, signed ground truth,
approved dataset или разрешение promotion. Результат всегда содержит
`training_eligible=false`, `verified_labels=false`, `release_ready=false`.

## Предварительная проверка

1. Проверить владельца окружения и абсолютный путь к существующему client
   directory. Для submit требуется `ml_ingestor`, для inspect - `ml_curator`.
   Client directory содержит connection config и сертификаты; не копировать
   его содержимое в shell, issue или отчёт. Проверку файлов и TLS выполняет
   существующий storage client. Ошибка подключения не является проверкой прав.
2. Подготовить приватный JSON в `.runtime`, не добавлять его в Git. Ровно поля
   `schema_version: 1`, `model_sha256`, `bundle_sha256`, `records`. Два digest -
   lowercase SHA-256. Каждый элемент records содержит только `request_id`
   (32 lowercase hex), `row_index` (целое 0..99), `label` (целое 0 или 1).
   Boolean вместо integer, дополнительные поля, признаки и свободный текст
   отклоняются. Максимум 100 записей и 16384 байта входа, без повторов пары
   request_id/row_index внутри одного сообщения.
3. Сопоставить идентификаторы с доступным журналом фактического prediction,
   указать их в приватном файле. CLI валидирует форму claims; проверка их
   достоверности и curator approval остаются отдельной обязанностью.

## Исполняемый плейбук

На разрешённом runner из checkout с locked dependencies:

```sh
uv run --locked python -m mlsecops.feedback submit \
  --client "$GITHUB_WORKSPACE/.runtime/storage-clients/ingestor" \
  --file "$GITHUB_WORKSPACE/.runtime/operator-feedback.json"
```

Изменяющее действие: append-only INSERT в `ml.quarantine`. Сервер проверяет
SHA-256 payload, клиент читает записанные байты обратно до завершения transaction.
Успех - exit 0 и ограниченная JSON receipt: status=quarantined, record_sha256,
submitted_records и три false-флага выше. Метки, признаки, request IDs и ключи
не печатаются. При отказе exit 1 и постоянный текст `feedback_rejected`; SIGINT
даёт 130. Не публиковать traceback/connection config для диагностики.

Для проверки конечного состояния другой ролью взять record_sha256 из receipt:

```sh
uv run --locked python -m mlsecops.feedback inspect \
  --client "$GITHUB_WORKSPACE/.runtime/storage-clients/curator" \
  --reference "$FEEDBACK_RECORD_SHA256"
```

`FEEDBACK_RECORD_SHA256` - полученный digest, не секрет. Inspect повторно читает
SQL, проверяет digest, схему и false-флаги. Он выводит receipt, а не raw claims;
это проверка сохранности, не интерфейс рассмотрения или одобрения ground truth.
Identical canonical payload даёт тот же digest и не добавляет SQL row. Другое
сообщение, даже с противоречащей меткой для прежнего ID, является новым claim;
между сообщениями конфликты не решаются автоматически. Такие claims нельзя
превращать в truth простым выбором последнего сообщения.

## Отказы и восстановление

| Симптом | Проверка и действие | Критерий восстановления |
| --- | --- | --- |
| Ошибка формы, размера или роли | Проверить поля, границы и назначенную роль без вывода payload; исправить только собственный submission | Curator inspect читает ожидаемый digest; approved tables не менялись |
| Потерян ответ после submit | Повторить тот же файл и сверить receipt; не создавать новую метку для обхода отказа | Один canonical payload, один digest, одна SQL row |
| Нет связи с SQL или TLS отказ | Проверить разрешённый endpoint, срок сертификата и owned storage health; не отключать verify-full | Успешное чтение curator и проверка digest после восстановления |
| Readback не совпал или получены authority-флаги | Сохранить приватные evidence, остановить обработку этого claim и передать владельцу storage | Исследована причина; подмена не переименована в корректную запись |
| Карантин растёт или содержит противоречия | Ограничить приём у владельца ingestor, разобрать claims отдельно от approved sources | Новый согласованный curator/source процесс; автоматического обучения нет |

Rollback не удаляет сохранённые claims: write role не имеет UPDATE/DELETE.
Отключить использование команды можно без изменения существующих prediction,
dataset и release. Массовое удаление карантина, расширение SQL grants, отключение
проверок и silent conversion в dataset в этот плейбук не входят.

## Проверки и границы доказательств

```sh
uv run --locked python -m unittest scripts.feedback_qualification scripts.feedback_native_qualification
```

Controlled tests проверяют границы, dedup retry, redaction, role selection,
подмену сохранённых данных, отрицание authority и обязательность primary packet.
Это не доказательство реальных SQL grants. Hosted `kubernetes-monitoring.yml`
добавляет к [monitoring campaign](model-monitoring.md) фактический CLI submit,
повтор, curator inspect и 15 непосредственных SQL-запросов, для которых требуется
именно SQLSTATE 42501. Сверяются все source tables и cluster promotion snapshot;
меняется ровно одна quarantine row. После остановки SQL и удаления кластера
private proof перечитывается и сопоставляется с сохранёнными actual HTTP IDs.
Raw payloads и proof остаются приватными. Принятие этого компонента не закрывает
полный M15, независимый review или R1; актуальные результаты в [STATUS](../../STATUS.md).
