# Producer heartbeat: диагностика и восстановление

Ответственные: serving operator и security collector operator.
Статус: реализация T29, native qualification ещё не подтверждена.
[ADR0064](../decisions/0064-producer-heartbeat.md), [план](../../tasks/producer-heartbeat-plan.md).

Heartbeat сообщает об активности trusted producer и последнем выделенном event
sequence, не о качестве/готовности модели. Его counter и последний signed
envelope сохраняются в outbox schema2 вместе с event records, под прежним lock
с fsync до HTTP. Неизвестный результат не откатывает counter. Это latest state,
не incident queue; heartbeat не расходует event capacity и не удаляет receipts.

Startup probe повторяет pending и отправляет heartbeat до engine activation.
После каждого успешно доставленного identity denial также отправляется heartbeat.
Если этот шаг не подтверждён, HTTP возвращает503 даже при существующей receipt:
всегда проверять queue. Owned scheduler внутри serving lifecycle использует
период30s и тот же single-child slot. Busy проверяется снова через1s, очередь
не создаётся. При смерти/закрытии serving heartbeat прекращается.

Ответ /heartbeat проверяется по envelope/time, но это HTTP echo, не signed
collector receipt и не право promotion. Collector independently проверяет
signature/epoch/sequence/time. Promotion по-прежнему требует fresh signed audit
challenge и остальных gates. Локальная отправка не заменяет collector readback.

## Диагностика без изменения состояния

1. Подтвердить ownership serving/collector processes и используемых private paths.
2. Прочитать `security_event_delivery.configured(absolute_config).store.snapshot()`.
   Не выводить весь документ: сверить schema2, producer/registry pins, число
   events/pending и signed heartbeat sequence/head/time.
3. Сверить heartbeat с collector telemetry stream по producer_id. Выделенный
   локальный counter сам по себе не означает delivery. Проверить /health и
   signed telemetry.gap/receipt через operator route, не ingress token.
4. Проверить source lifecycle и bounded child. Зелёная model/drift dashboard
   не доказывает работоспособность security producer.

## Восстановление

1. Восстановить принадлежащий задаче collector с прежним state/registry.
2. После подтверждения завершения прежнего serving/child запустить тот же config.
   Startup probe доставит pending и увеличит прежний heartbeat counter.
3. Сверить original envelopes/receipts, монотонность heartbeat, фактический
   collector head и отсутствие нового gap. Event retry не создаёт incident.
4. Получить новую signed promotion-audit observation отдельно. Прежний health
   ответ или HTTP200 heartbeat не являются разрешением promotion.

При corrupt/lost state, unknown reap, expired registry, rollback clock,
exhausted counter или schema1 отказаться от запуска и сохранить private evidence.
Автоматического reset/migration нет. Не создавать второй outbox с использованным
key/epoch. V1 journal допускает прежние event operations, но не heartbeat;
migration требует отдельного проверенного плана registry/epoch и сохранения evidence.

Shutdown сначала останавливает scheduler, затем pending operation/child. Отмена
close сохраняет reference неподтверждённого scheduler; child cleanup всё равно
выполняется. Чужие процессы не завершаются по имени. Rollback к unaudited profile
не закрывает M23 и не является восстановлением аудита.

## Проверки

```text
python -W error -m unittest scripts.security_producer_heartbeat_qualification scripts.security_event_outbox_qualification scripts.security_event_delivery_qualification scripts.security_event_wire_qualification scripts.security_identity_events_qualification scripts.security_identity_http_qualification
```

POSIX persistence/crash checks выполняются только на Linux. Hosted identity
qualification измеряет настоящий30s tick, restart counter и signed gap после
остановки producer <=120s; искусственное ускорение clock это не заменяет.
Mandatory deployment/periodic trust observer и fresh M13/M14/full M23 остаются
обязательными; весь R1 этим компонентом не принимается.

## Диагностика qualification readback

Первый c313a86 native run остановился после36 assertions на периодическом
readback; исходный диагностический код не сохранил тип/место исключения.
Следующий6774fc7 с такой диагностикой прошёл без изменения runtime. Это само
по себе не доказывает причину первого сбоя.

При разборе найден и детерминированно воспроизведён отдельный дефект harness:
ошибка nonblocking flock внутри общего parent context становится
artifact_unavailable, тогда как прежний polling распознавал только
security_store_unavailable. Readback теперь повторяет только эти два отказа
не более2s; неправильные pins/signatures/state не повторяются и не принимаются.
POSIX-тест удерживает настоящий exclusive lock. Persistent I/O refusal остаётся
failure, успешный повтор требует полной прежней валидации snapshot. Это изменение
проверочного сценария, не отключение locking или security checks в runtime.
