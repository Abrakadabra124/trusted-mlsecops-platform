# ADR0064: heartbeat принадлежит producer и его durable outbox

Статус: реализация T29/M23. Полная приёмка R1 остаётся прежней.

Collector уже проверяет signed heartbeat и обнаруживает пропуск за90s с
hard deadline120s. Реальные producers пока не отправляли периодический heartbeat.
Serving с identity audit теперь владеет scheduler, который запускает тот же
bounded child. Heartbeat прекращается вместе с lifecycle serving, не с отдельным
независимым sidecar. Он показывает работу trusted producer, не готовность модели.

Свежий outbox schema2 содержит прежние records и один последний signed heartbeat.
Его sequence сохраняется атомарно до HTTP, last_event_sequence берётся из того же
locked snapshot и включает pending. Новая отправка increment sequence; неизвестный
результат не откатывает counter. Это latest state, не incident queue. Старые
события/receipts/sequence не удаляются; heartbeat не расходует MAX_RECORDS.

Schema1 читается для прежних event operations, но heartbeat запрещён: у него нет
доказанного counter. Автоматического upgrade/reset нет. Для существующего v2
используется сохранный state; для прежнего v1 нужен отдельный операторский план
registry/epoch migration. Новый v2 нельзя создавать с уже использованным key/epoch.

Используется существующий bounded loopback transport и route /heartbeat.
Ответ проверяется по точному envelope и временным границам. Это HTTP echo,
не signed collector receipt и не health grant. Promotion по-прежнему требует
собственный fresh signed admission. Native qualification сверяет действительный
collector journal отдельно от ответа producer.

Startup probe повторяет pending events и отправляет heartbeat до engine activation.
Период30s; нет очереди дочерних процессов, общий слот с identity denials.
При busy scheduler пробует позже без создания child. Успешные identity events
также отправляют heartbeat; ошибки не обновляют успешный таймер. Persistent
outage/failure вызывает collector gap и блокирует promotion, а не сброс состояния.
Shutdown прекращает scheduler, сохраняет ownership операции и reap child.

Отдельная state file рассинхронизировала бы event head и heartbeat; timestamp
вместо counter не гарантировал бы монотонность после restart/clock rollback.
Standalone sidecar мог бы скрыть смерть producer. Поэтому выбран единый журнал
и lifecycle hook. Полный mandatory deployment, периодический trust observer и
свежие M13/M14/full M23 остаются обязательными следующими интеграциями.
