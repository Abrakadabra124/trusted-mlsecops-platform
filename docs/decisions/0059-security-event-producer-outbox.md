# ADR 0059: очередь событий на стороне контроллера

Дата:2026-11-11. Статус: implemented, native validation pending.
Неделя11, T29, обязательный M23. Продолжение [ADR0058](0058-security-event-contract.md).

## Требование и решение

Рабочий intake должен сообщать подтверждённые отказы в collector. Потеря
соединения или ответа после commit не должна терять событие, менять его ID или
создавать второй incident. Событие подписывает контроллер с правом на его kind;
worker не получает ключ и не управляет event fields.

Producer хранит отдельный private Linux outbox. В snapshot фиксируются registry
pin, producer identity, последовательные номера, исходные signed envelopes,
enqueue timestamps и проверенные receipts. Используются существующие private
directory handles, nonblocking flock, fsync/rename/readback; decoder outbox
отделён от decoder collector. Конфигурация и источник state должны совпадать.
Автоинициализации, очистки и сброса counters нет.

Предел1024 records/16pending ограничивает память, replay и работу filesystem.
Retry occurrence определяется producer/kind/correlation ID; изменение остальных
полей при том же occurrence отвергается. Очередь не перезаписывает event time,
даже если накопившееся событие больше нельзя впервые принять по freshness.
Это требует диагностики, а не автоматического переиздания старого инцидента.

Квитанция collector использует реальный receiver ingest time, отдельный от
enqueue time. Подпись, registry, event ID, fixed route, timing и late flag
проверяются до settlement. Receipt другого pending event не подтверждает
текущий запрос. После неизвестного исхода производитель отправляет тот же
envelope, а collector возвращает первоначальную квитанцию.

## Подключение рабочего источника

`artifact_intake.inspect_candidate` формирует projection после собственного
решения. Digest mismatch даёт artifact.rejected/integrity; валидированный
отказ scanner даёт artifact.rejected/unsupported_format; нарушение протокола
worker, установленное controller, даёт worker.policy_violation/output_schema.
Scanner unavailable/timeout/crash не называются доказанным security violation.
Payload содержит только kind/reason/correlation/asset digest/bundle digest;
текст исключения, модель, путь, labels и stdout не переносятся в событие.

Путь `controller -> storage_pipeline.evaluate -> pipeline -> artifact_intake`
передаёт operator-configured emitter отдельным аргументом. CLI controller
получил `--security-event-config`; request worker не может выбрать keys/config.
Конфигурация обязана обозначать producer с ролью controller. В этом increment
параметр остаётся явным подключением: отсутствие параметра сохраняет старый
unaudited profile и не считается M23-ready. Native deployment/mounts/network
этого профиля и enforcement для всех deployments ещё обязательны.

Emitter сначала сохраняет envelope, затем отправляет. Отказ аудита сохраняет
denial и возвращает постоянный `intake_security_audit_unavailable`; prediction
после отказа не выполняется. Последующая доставка запускается явным `retry()`;
самостоятельного background thread/service у producer нет.

## Transport и границы

Только127.0.0.1, port1024..65535, private ingress bearer token, полный deadline2s
на одну попытку, request/response<=4096bytes и header<=8192bytes. Redirect,
proxy/DNS, content/transfer encoding и неоднозначный Content-Length запрещены.
Это loopback authentication, не TLS/confidentiality для remote deployment.
Pending batch имеет до16 попыток; это не гарантия2s на всю очередь.

Один host, filesystem honoring fsync и общий администратор остаются допущениями.
Same-user rollback/state substitution/volume loss требуют другого trust boundary.
Outbox живёт в пределах pinned registry epoch; rotation/migration не выполнена.
Нет claims о внешней SIEM, полной M13 privacy, всём M23 или R1. Далее нужны
остальные источники, heartbeat producer, audit admission на promotion boundary,
elapsed sequence-gap/outage и общая source-bound приёмка.
