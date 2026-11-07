# ADR 0058: доверенные события безопасности

Дата: 2026-11-07. Задача: неделя 11/T29, критерий M23. Контракт v1 реализован;
доставка, постоянное хранение и release integration ещё не приняты. Это решение
не ослабляет [M23](../acceptance.md#m23) и не объявляет общий R1 завершённым.

## Требование

Система должна отличать подтверждённый отказ доверенного компонента от строки
в stdout недоверенной модели. Подпись подтверждает отправителя и байты, но сама
по себе не подтверждает причину отказа, сохранение события или доставку реакции.
Поэтому отдельно проверяются source adapter, контракт, сохранение, маршрут и
фактическая реакция. Monitoring alerts M15 остаются самостоятельным протоколом.

## Фиксированные события и полномочия

| Тип | Допустимый producer role | Причины | Маршрут |
| --- | --- | --- | --- |
| `artifact.rejected` | intake, promoter, serving, controller | integrity, signature, unsupported_format | security.artifacts |
| `promotion.denied` | promoter | authorization, trust, audit_unavailable, policy | security.releases |
| `trust.revoked` | trust | key, artifact, policy | security.trust |
| `identity.denied` | promoter, serving, controller | credential, role | security.identity |
| `inventory.mismatch` | promoter, serving, controller | digest, dangling, owner, cycle | security.inventory |
| `worker.policy_violation` | controller | isolation, output_schema, quota | security.workers |
| `telemetry.gap` | collector | sequence, heartbeat, restart | security.telemetry |

Маршрут, action и outcome определяются контрактом. Producer не передаёт
произвольный URL, severity, сообщение или stack trace. Ключ worker отсутствует
среди доверенных ролей; о нарушении сообщает контроллер, проверивший наблюдение.
Компрометация доверенного producer остаётся отдельной границей угроз.

## Поля и идентичность

Event содержит ровно: schema version, event ID, kind, producer ID, epoch,
sequence, occurred/observed time, correlation ID, asset digest, nullable bundle
digest, policy digest, action, outcome, reason. Время выражено целым числом
миллисекунд UTC Unix epoch, положительные sequence не превышают `2**53-1`.
Дайджесты имеют 64 строчных hex-символа; epoch и correlation ID - 32.
Bundle может отсутствовать до его формирования; asset digest обязателен.

Event ID - SHA-256 канонического JSON остальных полей. Отправитель создаёт
событие один раз и повторяет неизменные байты при retry. Это стабильная
идентичность намерения; дедупликацию должен выполнять постоянный collector,
она не появляется автоматически от наличия поля event ID.

Данные, метки, токены, пути, исключения и произвольный текст не входят в схему.
Digest не является анонимизацией произвольного секрета: адаптер должен передавать
только разрешённые artifact/policy references, а не хешировать сырой payload.

## Ключи, policy и время

Используется существующая реализация Ed25519/DSSE. DSSE связывает подпись с типом
payload; домены `security-event`, `security-heartbeat`, `security-event-receipt`
и `security-event-config` различаются. Monitoring alert нельзя принять как
security event, heartbeat не создаёт incident.

Оператор подписывает registry отдельным root. Ожидаемые root public key и digest
registry поступают из доверенной конфигурации запуска. Registry содержит
1-16 уникальных producer keys, роли, epochs, heartbeat requirements, общий
policy digest, отдельный receipt public key и период действия до 24 часов.
Повторное использование root/receipt/producer key между ролями запрещено.
Конфигурация должна требовать heartbeat хотя бы от одного producer.

Registry неизменяемый после проверки; изменение исходного словаря не меняет
права работающего verifier. Каждое сообщение проверяет срок registry, подпись,
producer/key binding, роль, epoch и policy. Event не может предшествовать
конфигурации, возраст при ingest ограничен пятью минутами, future skew - пятью
секундами. Доставка измеряется отдельно от возраста события. Эти lab limits
фиксируются до runtime campaign, не подбираются для получения pass.

Envelope ограничен 4096 байтами, canonical event - 2048. Registry envelope
ограничен 32768 байтами. Вложенные значения в строковых полях DSSE отклоняются
до рекурсивной сериализации. Неизвестные и отсутствующие поля запрещены.

## Подтверждение доставки

Signed receipt связывает event ID, producer, epoch, sequence, registry digest,
фиксированный маршрут, время ingest и routing, признак late. Интервал должен
быть от 0 до 60000 ms включительно, оба момента находятся внутри срока registry.
Receipt всегда имеет `release_ready=false`. Получение корректной подписи или
сравнение двух timestamps само по себе не доказывает измеренную доставку:
настоящий collector должен сформировать квитанцию после сохранения реакции.

Heartbeat имеет отдельную sequence и сообщает last event sequence. Он не
занимает номер в event stream. Константы профиля: heartbeat period 30 s,
gap deadline 120 s. Контракт ещё не реализует scheduler и не заявляет обнаружение
пропуска по одному валидному heartbeat.

## Порядок оставшейся реализации без сокращения M23

1. **Контракт**: проверка семи типов, registry, domain separation, immutable
   values и receipts. Реализован в текущем increment, проверки компонентные.
2. **Постоянный collector**: атомарная фиксация event ID/sequence/content,
   original receipt при точном повторе, отказ при конфликте, bounded retention,
   crash recovery. Потеря или повреждение журнала запрещает здоровый статус.
3. **Порядок и время**: ограниченное окно перестановки, late marker, открытые
   sequence gaps, heartbeat expiry и отдельный `telemetry.gap` без бесконечного
   цикла self-alerts. Реальные часы и time budget принадлежат процессу, не HTTP input.
4. **Доставка**: аутентифицированный bounded HTTP ingress, durable alert routing,
   retry без дублирования incident, timeout/cancellation и owned shutdown.
5. **Source adapters**: actual artifact rejection, promoter denial, trust
   revocation, serving identity denial, inventory mismatch, controller-observed
   worker violation и collector gap. Raw worker text не повышается до finding.
6. **Promotion boundary**: durable audit admission перед новой selection,
   подтверждение актуальности на последней изменяющей границе; недоступность,
   неполная запись, backlog/gap или неизвестный итог запрещают новую promotion.
   Повтор должен восстанавливать тот же intent, а не создавать новый выпуск.
7. **Полная приёмка**: семь actual/negative fixtures, forgery/duplicate/reorder,
   missing sequence/heartbeat <=120 s и route delivery <=60 s с измерением;
   outage при здоровом drift dashboard блокирует promotion. Fresh hosted
   disposable campaign, cleanup, retained primary replay и clean checkout.

Часть этих проверок требует нового collector и адаптеров; функция проверки
schema не заменяет их. До общей приёмки T29 и M23 остаются unchecked.

## Проверка и альтернативы

### Durable heartbeat и gap state

Следующий increment добавляет `security_event_health` в тот же atomic Store.
Проверка Linux пока ожидается. Journal schema v2 хранит время начала наблюдения
и ровно один control record на зарегистрированный producer: последний signed
heartbeat с исходным admission time, открытые sequence/heartbeat episodes и
монотонные generation counters. State v1 не получает автоматически пустую
telemetry: несовместимый журнал отклоняется. Исторические v1 evidence сохраняют
свой source; для живого v1 volume требуется отдельная проверенная миграция,
её этот increment не заявляет.

Heartbeat counter независим от event counter. Exact retry возвращает исходное
подтверждение и не продлевает deadline; другой payload с тем же counter,
обратный counter/time/last-event claim и слишком далёкий claim отвергаются.
Время heartbeat expiry отсчитывается от меньшего observed/ingested timestamp,
поэтому разрешённый clock skew не добавляет времени. До первого обязательного
heartbeat состояние unhealthy. Initial deadline: время начала наблюдения+120 s.

Missing sequence определяется из уже принятых event positions и signed
last-event claim, без цикла по потенциально огромному числу из сообщения.
Новый claim ограничен received high+64. Первое время незакрытого пропуска
сохраняется, пока continuity не восстановлена; новые claims и частичное заполнение
не перезапускают120s timer. Запоздавшее событие сохраняет исходный late flag.

`Store.poll(clock_ms=...)` является изменяющей операцией: атомарно сохраняет
clock checkpoint и открытие/закрытие episodes, затем возвращает bounded health
projection. Истёкший heartbeat остаётся тем же outage episode при получении
другого уже старого heartbeat. После свежего heartbeat следующий outage получает
новый notice ID. Snapshot/повтор не должны терять незакрытый episode при restart.
Сохранённые counters/timestamps и привязка heartbeat к stream вновь проверяются.

Health unhealthy при любом незакрытом sequence gap, отсутствии/expiry обязательного
heartbeat, pending delivery или полной ёмкости журнала. Projection всегда содержит
`release_ready=false`: она не заменяет release authorization. Signature/clock/file
ошибка не преобразуется в healthy. Переполнение generation counter не коммитит
часть события или квитанции.

Контракт вычисляет deadline при вызове poll с доверенным временем процесса.
Он ещё не запускает periodic scheduler, не формирует signed telemetry.gap event
и не подтверждает реальную доставку<=60s/наблюдение<=120s. Эти свойства проверяются
следом на живом runtime вместе с HTTP, source adapters и audit admission.

### Постоянный журнал: решение следующего increment

Добавлены `security_event_ledger` и Linux `security_event_store`; [native filesystem
проверка](../evidence/security-event-journal-2026-11-07.md) прошла на `d17434b`.
Ledger отдельно описывает переходы
состояния, но не обещает durability. Store держит эксклюзивный неблокирующий
`flock` на pinned directory descriptor, читает только фиксированные файлы без
следования symlinks и принимает только private owner-controlled regular files
с одним hardlink. Registry и случайная identity привязаны внешним digest.

Provisioning явный и только в новом каталоге. Runtime не создаёт пропавший
state. Каждая изменяющая операция пишет `.pending`, выполняет file fsync,
atomic rename, directory fsync и readback. После неопределённого исхода повтор
перечитывает состояние. Незавершённый `.pending` удаляется только после полной
проверки старого committed state; повреждённый или отсутствующий state не чинится
автоматически. При чтении вновь проверяются подписи, роли, порядок записей,
sequence uniqueness и квитанции. Это не защита от rollback диска host-admin.

Профиль фиксирован до runtime campaign: максимум 1024 события на registry,
snapshot <=16 MiB, reorder window64. Старые event IDs не вытесняются: при
заполнении новые события отвергаются, exact retries ещё доступны. Нет тихого
reset или автоматического нового epoch. Перед rollover необходим операторский
handoff pending records, новый registry и отдельное доказательство continuity;
этот lifecycle ещё не реализован. Переполнение должно блокировать здоровый
статус будущего runtime и новую promotion, а не терять аудит.

Ingest сохраняет pending record. Отдельный `acknowledge` принимает подписанную
квитанцию только для того же события, ingest timestamp, late flag и fixed route;
изменённая повторная квитанция отвергается. Точный retry после пяти минут
проверяет исходную подпись на сохранённом admission time при ещё действующем
registry. Это не позволяет принять новое старое событие. Late flag сохраняется
в момент первого ingest и не пересчитывается после закрытия sequence gap.

Выбран bounded snapshot вместо нового SQL service: небольшой security-event
поток и один collector не требуют отдельной базы. Цена - O(n) verification/write
и лимит ёмкости, которые должны быть измерены в общей M23 campaign. Native
Windows durability, network filesystem, volume loss/HA и реальная доставка
внешнему получателю этим компонентом не заявляются.

В первом increment 21 controlled test с реальными подписями. Два модуля:
206 statements, 74 branches, 100% каждого. Проверки включают неверные роли,
ключи, domains, policy/epoch, expiry/skew, mutable input, nested/oversized data,
случайное отключение всех heartbeat и недопустимые receipts. Отдельный негатив
воспроизвёл квитанцию до начала конфигурации и был исправлен.

Не выбран произвольный JSON logging: он не задаёт доверенного producer и
конечную схему. Не переиспользован `monitor-alert` как security протокол:
полномочия, семантика последовательностей и deadlines различаются. Общими
остаются существующие signing и canonical JSON primitives. Новый оркестратор,
SIEM/Sigma backend и внешние модели не нужны для этих требований и не внедрены.
