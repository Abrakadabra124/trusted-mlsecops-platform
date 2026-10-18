# ADR 0039: audit admission и versioned events перед HTTP producer

Историческая граница этого component: HTTP producer реализуется следующим [ADR 0040](0040-serving-http-audit.md). Формулировки о неподключённом HTTP ниже относятся к исходному admission increment `01ec902`.

Дата: 2026-10-18. Статус: реализованы journal API и event schema; HTTP integration ещё не выполнена. Продолжает [ADR 0036](0036-serving-audit-journal.md), [ADR 0037](0037-audit-retention.md) и [ADR 0038](0038-serving-audit-context.md). Не закрывает M13 или R1.

## Требование

Нельзя начать защищённый HTTP request, записать только начало и обнаружить, что для terminal event уже нет места. Постановка в очередь не подтверждает сохранение на диске. Qualification permit нельзя выдавать за promotion selection. Новый producer должен сохранять bounded memory/storage и исходный trust deadline.

## Реализованное решение

- `Journal.reserve()` атомарно резервирует четыре queue slots и `4 * MAX_RECORD` bytes. `MAX_RECORD=2048`, максимальная queue capacity 64, общий byte cap не выше 16 MiB. Учитываются accepted pending bytes, retained bytes и unused holds. Это admission capacity, не гарантия исправности диска или монотонности wall clock.
- Ticket - непрозрачный process-local object. Journal хранит не более `capacity // 4` активных tickets, у каждого максимум четыре номера событий. Даже полностью использованный, но не освобождённый ticket занимает bounded metadata slot. Это защита от ошибок producer, не от произвольного исполнения Python в том же процессе.
- `emit(value, ticket=ticket)` расходует один slot только после успешной постановки в FIFO queue, заменяет worst-case byte hold фактической длиной. Без ticket producer не может занять чужой резерв. При активных reservations обычное переполнение даёт `audit_admission_full` без sticky fault; legacy-only overflow сохраняет прежний sticky contract.
- `confirmed(ticket, sequence)` принимает только номер, выданный этому live ticket этим Journal. Ответ true возможен после writer write + fsync и только при здоровом, не закрывающемся writer. Retained sequence prefix учитывается отдельно от session durable count. Старый номер из предыдущего запуска нельзя использовать вместо нового подтверждения.
- `release(ticket)` идемпотентно возвращает только неиспользованные holds. Accepted bytes и pending records не освобождаются. Чужой/неизвестный ticket ничего не меняет. Emit/confirmed с чужим, закрытым или исчерпанным ticket отвергаются. Close с незакрытой reservation фиксирует `reservations_open`, не clean success.
- Status разделяет `held_slots`, `held_bytes`, `reservations` и прежние `reserved_bytes` (accepted + retained), `pending`, `durable`, `unconfirmed`. Для полного storage budget складываются `reserved_bytes + held_bytes`. Нельзя вычитать pending bytes при освобождении ticket.

## Версии событий

Outer journal record остаётся schema 1: sequence, timestamp, event. Старый event allowlist без version сохраняется. Новый **event schema 2** содержит только `schema_version`, server request ID, authenticated principal ID, конечный route, stage, status и context. Routes - `ready`/`predict`, stages - `request_started`, `response_intended`, `response_started`, `response_completed`, `aborted`.

Для статуса 200 обязателен один из точных contexts ADR 0038: `release-selection` с selection/bundle/model или `candidate-qualification` с permit/proposal/bundle/model. Обе ветви имеют `release_ready=false`. Для остальных статусов context отсутствует. `request_started` имеет status null; null также допустим у `aborted` до отправки заголовков. Payload, features, scores, raw URLs, tokens, exception text и дополнительные fields отвергаются, а не хешируются.

Validation schema не доказывает происхождение request/principal/context: это обязанность будущего authenticated HTTP producer и immutable reader handoff. Journal смешивает старые и новые события без перезаписи истории. Private journal не является публичным evidence export.

## Контракт следующего HTTP slice

1. После authentication, quota и global slot, но до body/executor, получить reservation; при отказе вернуть bounded 503, не выполнить prediction. `/livez` и anonymous/over-quota traffic не создают individual audit queue entries.
2. Записать `request_started`. Перед защищённым 200 записать `response_intended` с immutable context и дождаться `confirmed` без блокировки event loop, в пределах прежнего response budget. После ожидания повторно проверить generation/trust deadline, не продлевать его.
3. `response_started` означает, что `send(http.response.start)` вернулся; `response_completed` - что завершился final body send. На cancellation/send exception - `aborted`, но не фиктивный completed. Изменение intended 200 в actual 503 должно остаться видимым, context у actual denial отсутствует.
4. Освобождать unused reservation в finally; поздний executor result не пишет новое успешное HTTP event. При sink failure после отправки 200 нельзя отозвать уже отправленные байты: durable intent остаётся, terminal outcome может быть неизвестен, новые admissions запрещаются. Не обещать атомарную транзакцию filesystem + network или подтверждение получения клиентом.

Это выбранная политика, **не реализованный HTTP lifecycle**. [ASGI 2.5](https://asgi.readthedocs.io/en/latest/specs/www.html) различает response start и final body send; успешный send не доказывает client receipt. Не применять `BaseHTTPMiddleware` для наблюдения streaming/cancellation, не добавлять отдельный thread на каждое ожидание fsync.

## Альтернативы и риски

Просто увеличить очередь недостаточно: terminal capacity по-прежнему могут занять другие запросы. Синхронный fsync в event loop блокирует liveness и deadlines. Unbounded queue переносит отказ в OOM. Reserve full worst-case record консервативнее подсчёта средней длины, зато даёт проверяемый верхний предел.

Retention/ownership остаются в прежнем backend. Настройка retention, исключение raw payload и private file permissions не являются differential privacy, production KMS или crash/reboot reconciliation. Same-process corruption и отказ файловой системы могут нарушить дальнейшую запись; это deny/gap, не pass.

## Проверка

Новые failure-first suites: `scripts.audit_admission_qualification`, `scripts.audit_event_qualification`. Проверяют конкурентный admission, pending writer, starvation, overload после полного расходования hold, чужой/старый ack, same-boot retained reopen на Linux, mixed event versions и strict field allowlist. Существующий >=95% branch gate отдельно по journal и retention сохранён; новый event module имеет отдельный 100% coverage gate. Native CI и all-output HTTP canaries не подменяются локальным Windows результатом.

Эксплуатация: [RB-58/PB-32](../operations/audit-admission-troubleshooting.md).
