# T29/M23: ранбук событий безопасности

Текущий статус: проверены контракт v1, pinned producer registry и постоянный журнал.
Полный collector runtime, реальные source adapters и promotion outage
gate ещё не приняты. Приведённые команды проверяют компоненты; не считать их
подтверждением работающей доставки или завершённого M23.

Bounded journal и atomic Linux store [проверены как компонент](../evidence/security-event-journal-2026-11-07.md):
`d17434b` /42347317046,70Linux tests/0skips; clean Windows70tests/17skips.
Windows запуск пропускает Linux cases, не подтверждая их завершение.

Подтверждённое [component evidence](../evidence/security-event-contract-2026-11-07.md):
runtime `c2f7bf9`, Linux CI 42345739729 success,21 новых+25 смежных tests/0skips;
чистый Windows checkout46tests/3POSIX skips с новой `.venv`.

## Назначение и ответственность

Platform-owner управляет отдельным registry root и receipt authority; владельцы
компонентов отвечают за producer keys и корректное происхождение событий.
Model worker не является доверенным producer. Подпись Ed25519 связывает сообщение
с ключом, а DSSE отделяет типы сообщения. Полномочия определяет подписанный
registry, а не поле из stdout или имя файла с ключом.

Схема, допустимые причины, роли, маршруты и полный порядок дальнейшей работы
зафиксированы в [ADR 0058](../decisions/0058-security-event-contract.md).
Дополнительный процент готовности из покрытия тестов не рассчитывается.

## Плейбук проверки контракта

В чистом checkout установить locked dependencies, затем выполнить:

```text
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.security_events_qualification
uv run --locked python -m unittest scripts.key_files_qualification scripts.monitoring_alerts_qualification scripts.release_policy_qualification
uv run --locked python -m coverage run --branch --source=mlsecops.security_events,mlsecops.security_event_config -m unittest scripts.security_events_qualification
uv run --locked python -m coverage report --fail-under=100
uv run --locked python scripts/check_docs.py
```

Тесты создают временные синтетические ключи, применяют реальные подписи и
удаляют собственную временную директорию. Они не запускают Docker, WSL,
Kubernetes, SQL или внешние модели. Не подставлять production keys в тестовые
фикстуры. Coverage относится только к двум названным модулям.

Ожидается 21 tests, 0 skips; все негативные случаи приводят к `Rejected`,
а успешные fixtures имеют только фиксированные поля. После выполнения
проверить exit code и отсутствие оставшихся test processes. Успешный builder
или verifier не доказывает запись в collector и не разрешает выпуск.

## Диагностика отказа

Сначала сохранить только конечный reason code, source revision и разрешённые
artifact/config digests в приватный incident record. Не копировать envelopes,
private keys, сырые features, labels, headers или произвольное исключение в тикет.

| Ошибка | Причина и безопасное действие | Критерий восстановления |
| --- | --- | --- |
| `security_config_pin` | Registry не совпадает с ожидаемым digest. Проверить источник operator configuration; не брать pin из полученного сообщения | Проверена та же подписанная конфигурация и её ожидаемый pin |
| `security_config_expired_or_future` | Срок registry не включает момент проверки | Исправлены часы либо оператор выпустил новую конфигурацию; expiry не отключён |
| `security_producer_authority` / `security_unknown_producer` | Ключ повторяется, роль запрещена или sender не зарегистрирован | Уникальный разрешённый producer; worker key остаётся отвергнутым |
| `security_event_role` | Подписант не имеет права утверждать данный тип события | Событие формирует действительная доверенная граница; не расширять роли ради pass |
| `security_producer_binding` | Не совпал sender ID, epoch или policy | Установлена правильная конфигурация процесса и повторены неизменные допустимые байты |
| `security_event_identity` | Изменились поля сохранённого события при том же ID | Не перезаписывать intent; расследовать конфликт и состояние записи |
| `security_envelope_shape` / `security_envelope_size` | Вложенное либо слишком большое сообщение | Источник выдаёт конечный контракт, parser limits не увеличены ради payload |
| `security_heartbeat_required` | Registry отключил наблюдение за всеми producers | Явно выбран обязательный непрерывный producer; пустота не считается здоровьем |
| `security_delivery_deadline` / `security_receipt_binding` | Неверный срок, event, маршрут, config или время квитанции | Фактическая доставка и точная подписанная квитанция подтверждены; не менять timestamps вручную |

## Журнал: диагностика и восстановление

Проверки журнала выполняются командами:

```text
uv run --locked python -m unittest scripts.security_event_ledger_qualification scripts.security_event_store_qualification
```

На Linux suite должна выполнять filesystem cases без skips. На Windows
storage намеренно возвращает `security_store_platform`, без попытки записи.
Журнал не запускает SQL/Docker/WSL/Kubernetes; hosted CI проверяет частичную
запись, ошибку до rename, неизвестный итог после rename, отдельный child process,
symlinks/hardlinks/permissions и lock contention.

При `security_store_missing`, `security_store_pin`, `security_store_canonical`
или отказе проверки подписей остановить новые admission и сохранить каталог
целиком вне публичного репозитория. Не удалять `state`, `identity` или записи
дедупликации. Без проверенной резервной копии восстановление не объявляется
успешным; применять R1 recovery procedure после её отдельной приёмки.

При I/O failure исход операции может быть неизвестен. Повторить те же подписанные
байты через существующий Store; он сначала проверит committed state. После сбоя
до rename восстановится старая версия, после rename может обнаружиться уже
сохранённое событие. Остаточный `.pending` очищается только после успешной
проверки состояния. Ожидаемый итог: один event ID и первоначальный receipt,
а не второй incident. Повреждение state не должно запускать автоматический reset.

`security_store_full` означает предел1024 событий; retries не расходуют новый
slot, новые события отвергаются. `security_sequence_window` ограничивает окно
перестановки64. Оба отказа требуют расследования producer/collector continuity;
увеличивать лимит после наблюдения failure ради pass или удалять историю нельзя.
Постоянный volume, внешний backup, routing scheduler и promotion fail-closed
integration пока остаются отдельной обязательной работой.

## Heartbeat, gap episodes и journal v3

Persistent control state [проверен в Linux](../evidence/security-event-health-2026-11-07.md):
`d7ccb42` /42349487413 success84tests/0skips, clean Windows84tests/18skips.
Воспроизведение проверок:

```text
uv run --locked python -m unittest scripts.security_event_health_qualification scripts.security_event_ledger_qualification scripts.security_event_store_qualification
```

`Store.heartbeat` проверяет подпись и counter, сохраняет исходный admission time;
повтор не является новой активностью. `Store.poll` записывает clock checkpoint
и gap episodes, поэтому это не read-only diagnostic. Runtime должен сам брать
clock из доверенного источника; HTTP client не задаёт момент poll.

При `security_heartbeat_conflict` или `security_heartbeat_regressed` сохранить
producer/config/epoch reference и конечный reason code, проверить источник
повторных сообщений. Не переподписывать старый heartbeat с новым counter ради
healthy. При `security_heartbeat_claim_window` расследовать расхождение event
stream с claim; не расширять окно после получения failed case.

При `security_telemetry_episode`, `security_telemetry_identity` или
`security_telemetry_time` admission должен оставаться запрещённым до проверки
state и producer ownership. Нельзя очищать episode, менять deadline вручную или
заменять потерянный control state пустым словарём. Journal v1/v2 отвергается schema
v3; автоматическая миграция с обнулением telemetry отсутствует. Сохранить старый
volume и его source/config pins; не запускать initialize поверх него.

Controlled тесты сверяют inclusive90s detection boundary и120s hard deadline,
сохранение notice ID при restart,
late recovery и новый ID при повторном outage после восстановления. Это ещё не
измерение scheduler latency: периодический runtime, доставка и promotion gate
остаются обязательными следующими этапами.

## История проблем реализации

На промежуточном a08c3f1 детекция выполнялась на120s без запаса для scheduler.
До live campaign добавлен failure-first test на90s и выбран профиль90s detection
с120s hard deadline. Schemav3 отвергает старые сохранённые timestamps вместо
их неявного толкования по новым правилам. Новый CI d7ccb42 подтвердил controlled
границы; actual scheduler latency по-прежнему требует отдельной проверки.

Первый journal CI на `b6d0365` /42347131488 выполнил19tests без пропусков,
но завершился failure на coverage gate: store имел30/36покрытых branches.
Порог95% не уменьшен. Добавлены отдельные fault checks изменения файла при
чтении, short/zero writes, readback mismatch и oversized snapshot. Это пробел
проверок, а не доказанный сбой durability. Следующий CI на `d17434b` /42347317046
прошёл24journal tests без skips, store139/140statements и36/36branches.
Полный M23 по этому результату не закрыт.

Controlled проверка выявила принятие registry, где все heartbeat requirements
выключены, и receipt с ingest раньше issued-at конфигурации. Добавлены отдельные
отрицательные тесты и проверки. Это ошибки нового компонента в ходе разработки,
а не утверждение о production incident. Вложенные значения envelope теперь
отклоняются до JSON serialization, без надежды на перехват рекурсивной ошибки.

Файловые recovery и deduplication проверены; для полного runtime остаются
обязательными их интеграция, gap/heartbeat evidence и проверка запрета
promotion при недоступном sink. До подключения этих компонентов команд reset,
автоматического очистителя или аварийного обхода контроля в этом ранбуке нет.

## Проверка нового collector runtime

Runtime `1a234fe` проверен настоящим Linux процессом:
[104 tests/0skips, measured delivery/restart/cleanup](../evidence/security-event-collector-2026-11-07.md).
Fixture cleanup исправлена в `fb8a5e1`; clean Windows104tests/22skips без
ResourceWarning. Проверка из checkout с locked environment:

```text
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.security_event_routes_qualification scripts.security_event_runtime_qualification scripts.security_event_http_qualification
uv run --locked python -m unittest scripts.security_event_live_qualification
```

Последняя команда выполняется только на разрешённом Linux host. На Windows она
пропускается, что не является успешной native проверкой. Test harness создаёт
private synthetic keys/config/state, запускает настоящий child collector на
свободном loopback порту, проверяет HTTP receipts, duplicate/reorder, реальный
heartbeat timeout до120s, restart и закрытие PID/порта. Нужны примерно90s ожидания
потери heartbeat. Docker, Kubernetes и SQL не используются. Секреты и process log
не выводятся и удаляются вместе с принадлежащим тесту temporary directory.

Для уже явно подготовленного журнала entry point:

```text
uv run --locked python -m mlsecops.security_event_server --config /absolute/private/collector.json
```

Файл config содержит ровно `schema_version`=1, `registry_file`, `registry_root`,
`registry_sha256`, `state_directory`, `state_sha256`, `receipt_key_file`,
`collector_key_file`, `ingress_token_file`, `operator_token_file`, `port`.
Все file paths абсолютные, registry подписан выделенным operator root,
`registry_sha256` связан с canonical payload. State pin возвращает явный
`security_event_store.initialize`; повторно вызывать initialize для рабочего
журнала запрещено. Token files содержат ровно64 lowercase hex символа без newline,
ключи и tokens имеют private permissions. Port1024..65535, bind127.0.0.1.
Полный воспроизводимый synthetic provisioning находится в live qualification;
он не заменяет production key management и не разрешает production promotion.

Отправителю доступны POST `/events` и `/heartbeat`, оператору GET `/health` и
`/incidents/0` с последующим `next_offset`. Заголовок Authorization передаётся
из private token file, его значение не печатать. Ingress/оператор имеют разные
tokens; ключи события и receipt также разделены. HTTP200 `/events` содержит
подписанную квитанцию сохранённого маршрута. HTTP401 означает неверный transport
credential,400 malformed framing/JSON,429 исчерпанную quota,503 runtime refusal
или недоступное состояние. Body503 не раскрывает внутреннюю причину.

При503 не переиздавать событие с новым ID. Сначала оператор проверяет PID/порт,
срок registry, clocks и private volume. Затем повторяет исходный signed envelope:
после неизвестного результата commit будет возвращена та же квитанция. Для
`health.healthy=false` проверить pending, heartbeat и gaps, а не только process
liveness. Исчезновение state, нарушение pin и corruption требуют сохранения
доказательств и эскалации владельцу; автоматического reset/обхода нет.

Останавливать только PID собственного collector через SIGTERM, дождаться exit и
проверить закрытие принадлежащего порта. Уничтожение task или потеря ответа не
являются доказательством отсутствия commit. После restart перечитать исходный
event ID/receipt и incident page. Внешняя SIEM, подключение всех семи реальных
источников, promotion outage test и полная M23/R1 приёмка ещё не заявлены.

## Producer outbox и отказ intake

Новый путь описан в [ADR0059](../decisions/0059-security-event-producer-outbox.md).
Ответственный за provisioning - оператор controller, не trainer/worker.
Native source `a205646` [проверен в CI43057291164](../evidence/security-event-sources-2026-11-11.md):
213tests/0skips, actual source/outbox/HTTP и outage retry. Команды ниже разделяют
controlled tests и настоящий Linux collector.

```text
uv run --locked python -W error -m unittest scripts.security_event_outbox_qualification scripts.security_event_delivery_qualification scripts.security_event_wire_qualification scripts.security_event_source_qualification
uv run --locked python -W error -m unittest scripts.security_event_source_live_qualification
```

Вторая команда создаёт собственные private state/keys и loopback collector,
проверяет фактический путь intake отказа, outage/restart/retry и cleanup.
Scanner executor в ней synthetic, в harness; это не доказательство Kubernetes
изоляции worker. На Windows native cases пропускаются, локальные containers/SQL
для этой проверки не требуются и не запускаются.

Подключение к уже подготовленному controller:

```text
python -m mlsecops.controller --request /private/scorer-request.json --security-event-config /private/security-producer.json
```

Producer config содержит ровно `schema_version`=1, `registry_file`,
`registry_root`, `registry_sha256`, `state_directory`, `state_sha256`,
`producer_key_file`, `ingress_token_file`, `port`. Пути абсолютные; registry,
port и ingress token согласованы с collector. Producer key имеет роль controller,
не receipt/collector. Secrets/outbox монтируются только в controller; worker
не должен получать эти mounts. Loopback требует общего сетевого namespace с
collector. Изменение manifests/mounts всего стенда ещё не выполнено, отсутствие
параметра сохраняет старый профиль и не подтверждает M23.

Outbox создаётся **один раз в новой пустой директории** через
`security_event_outbox.initialize(root, registry, producer_id, clock_ms=...)`;
возвращённый state pin сохраняется в operator config. `producer_id` - SHA256
public key, byte identity проверяет `key_identity`. Воспроизводимый synthetic
provisioning находится в live test. Этот шаг не подходит для восстановления
потерянной существующей очереди. На рабочем state его не повторять.

Диагностика начинает с `configured(absolute_config).store.snapshot()` в private
процессе: проверяются pin/signatures/permissions/counters. Не печатать весь
snapshot, ключи, bearer token, model bytes или raw exception. Посчитать только
число pending records и сверить event IDs с операторским incident inbox.
`security_delivery_unconfirmed` значит неизвестный итог отправки; запрет
оценки сохраняется. После устранения причины вызвать `configured(...).retry()`
в том же разрешённом Linux окружении. Это **изменяющий** шаг: отправляет до16
событий и сохраняет receipts. Затем повторно проверить отсутствие pending и
совпадение original event ID/receipt с collector. Success command без readback
недостаточен. Повторный вызов `inspect_candidate` означает новую попытку
инспекции; для доставки старого события нужен retry, не повторная инспекция.

Если registry истёк, clock регрессировал, pending старше freshness, outbox
полон, state повреждён или утерян, не обнулять counters/историю и не заменять
timestamp. Сохранить private evidence и эскалировать оператору. Без проверенной
миграции registry/epoch или восстановления из доверенного backup автоматического
лечения нет. Crash до rename оставляет предыдущий commit; после rename исход
может быть неизвестен. Retry использует сохранённый envelope и исходную receipt.

В тестировании обнаружен отказ binding: valid receipt другого pending event
могла засчитаться как текущая доставка. Negative test воспроизвёл ошибку;
Emitter теперь проверяет receipt именно относительно отправленного event до
изменения outbox. Случай зафиксирован как ошибка разработки, не production incident.

## Аудит на границе promotion

Ответственный: оператор collector и доверенного promotion controller. Условия:
разрешённый Linux стенд, существующий private journal, pinned registry, отдельный
promoter key и ingress token. На текущей Windows локальные SQL/Docker/WSL не
запускать. Воспроизведение SQL fault campaign выполняется job
`audit-promotion-sql` в [workflow](../../.github/workflows/security-events-contracts.yml).

Operator promotion config теперь schema_version=2 и требует абсолютный
`security_audit_config`. Audit config schema1 имеет ровно: schema_version,
registry_file, registry_root, registry_sha256, producer_key_file,
ingress_token_file, port. Registry/token/key paths абсолютные; key принадлежит
producer роли promoter, root/receipt key ему не передаются. Значения tokens и
private keys не помещать в JSON/Git/командную строку. Этот профиль предполагает
общий loopback namespace с collector, не remote HTTP без TLS.

Симптом: CLI возвращает `promotion_rejected`; внутренний безопасный код
`promotion_online_audit_required` либо `promotion_audit_unavailable`. Возможные
причины: отсутствующая конфигурация, недоступный процесс, неверный pin/роль,
истёкший registry, пропуск heartbeat, pending/gap, заполненный или повреждённый
journal, ошибка I/O, задержанный scheduler, слишком медленный/повторный ответ.
Здоровая ML dashboard эти причины не отменяет.

Плейбук восстановления:

1. Сначала без изменений сверить принадлежность PID/port, пути и внешние pins,
   наличие файлов, права и срок registry. Не выводить содержимое credentials.
2. Через существующий operator endpoint проверить bounded `/health` и inbox.
   Health poll обновляет checkpoint, поэтому это не строго read-only операция.
   Не очищать журнал, counters или pending и не отключать freshness.
3. По конкретной причине восстановить тот же owned collector/state и доставку
   producer heartbeat/pending; для corruption/expiry использовать описанную
   выше эскалацию. Автоматической rotation или reset здесь нет.
4. Сверить SQL head/events и CAS для прежнего request SHA256. Ошибка до/во время
   commit не доказывает отсутствие записи; не выдавать новый sequence вслепую.
5. Повторить исходную promotion CLI команду с теми же signed references.
   Это изменяющий шаг. Проверить точный request digest, одну запись events и
   состояние recorded-not-activated; Reader/serving readiness проверяется отдельно.

Новая проверка перед commit откатывает незавершённый selection при потере
collector. Она не отзывает уже существующий release и не гарантирует атомарность
с collector после последней проверки. [ADR0060](../decisions/0060-promotion-audit-admission.md)
фиксирует эту границу. Полная интеграция семи источников/M23 ещё не завершена.
