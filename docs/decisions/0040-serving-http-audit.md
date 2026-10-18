# ADR 0040: audit admission и фактический HTTP lifecycle

Дата: 2026-10-18; native verification 2026-10-19 Europe/Moscow. Статус: implemented, native HTTP qualification pass на `281e902`. Scope: неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Продолжает [ADR 0039](0039-audit-admission.md); не принимает полный M13/R1.

## Требование и решение

Успешные protected responses должны иметь собственный durable intent до отправки HTTP 200. Отказ журнала не должен пропускать ML без аудита, продлевать исходный trust budget или освобождать квоты незавершённого запроса. Отдельный ASGI middleware наблюдает настоящий `send`, а не только возвращённый endpoint объект.

ASGI (Asynchronous Server Gateway Interface) связывает Python-приложение и сервер через сообщения. Возврат response object ещё не означает отправку; start и final body различаются. Даже успешный `send` не доказывает получение клиентом. Это следует из [ASGI HTTP specification 2.5](https://asgi.readthedocs.io/en/latest/specs/www.html), проверенной 2026-10-18. Uvicorn остаётся существующим loopback-сервером, отдельный сервер или middleware framework не добавлены.

## Последовательность

1. После auth и проверки исходного budget применяются client/global limits. До чтения body и создания worker task объект Delivery получает владение уже выданными ресурсами и сохраняется в request scope.
2. Затем `start()` резервирует четыре события и пишет `request_started`. Даже если journal отсутствует, reserve или первый emit отказали, scope сохраняет владельца global/client ticket до завершения или отмены HTTP 503. Неиспользованный audit reserve освобождается отдельно.
3. Engine возвращает immutable generation-bound context. VerifiedResponse проверяет поколение после serialization и передаёт context только внутреннему Delivery, не public JSON.
4. Перед 200 middleware пишет `response_intended`, ждёт `confirmed(own_ticket, own_sequence)` без отдельного thread на каждый запрос и повторно проверяет исходный и текущий более короткий budget. Timeout, generation change или sink failure заменяет response на bounded 503 без private context. Уже записанный intended 200 не переписывается.
5. `response_started` записывается только после возврата реального start send; `response_completed` только после возврата последнего body send. Cancel/exception до завершения даёт `aborted`, но не вымышленный completed. Неизвестный actual status остаётся null. Body до start, повторный start и trailers отклоняются; API не реализует trailers. Дополнительное body после completed игнорируется.
6. Finally освобождает audit reservation. Global slot и client ticket освобождаются однократно только после BOTH HTTP completion/cancellation и завершения реального executor task. Поздний SQL result не реактивирует fenced generation.

Отказы до global admission, `/livez`, anonymous auth и quota denials не создают audit reservations. Это bounded protected-request audit, не журнал каждого сетевого обращения. Отсутствующий или неисправный journal не допускает защищённый успех. Отказ записи ПОСЛЕ отправки не может отозвать байты: остаётся evidence gap, backend запрещает следующие admissions. Filesystem и сеть не образуют атомарную транзакцию.

## Ownership и конфигурация

`configured()` требует absolute `audit_directory`. Чтение config и `create_app` ещё не открывают writer. Lifespan создаёт retained Linux Journal с прежней Policy, запускает его и закрывает в nested finally даже при ошибке Engine. Injected Journal принадлежит вызывающей стороне и не закрывается приложением. Смешивать `audit` и `audit_path` запрещено.

Неверный owned journal не даёт стартовать серверу; это не Engine cold-start rejection, при котором liveness остаётся доступной. Windows single-file fixture используется только в локальных contracts. Она не является fallback production retention. Permissions, caps, same-boot restart и запрет unsafe reset сохраняются по [ADR 0037](0037-audit-retention.md).

## Bounds и альтернативы

Остаются 8 global requests и Uvicorn `limit_concurrency=16`. Controlled real-HTTP test удерживает восемь admitted requests на audit writer, проверяет отказ девятого и `/livez` при всё ещё остановленном writer. Linux-вариант использует настоящий retained writer/fsync. Это не защита от произвольного connection flood и не новый latency SLO.

Синхронный fsync в event loop блокировал бы health/deadline; unbounded queue теряла бы memory bound; fire-and-forget intent разрешал бы неаудированный успех. Middleware сохраняет bounded backend и await с прежним budget. Четыре события дают верхнюю границу на request без записи body, features, scores, bearer, raw URL или exception text.

## Проверка и ограничения

[Evidence](../evidence/serving-http-audit-2026-10-18.md) хранит failure-first результаты, coverage, review и различие Windows/контролируемых/Linux сценариев. [RB-59/PB-33](../operations/serving-http-audit-troubleshooting.md) описывает diagnosis/recovery.

Открыты all-output canaries, public export/cardinality, полная source/run/report/approval/release/request корреляция и M13 acceptance. Не заявлены crash/reboot reconciliation, remote production deployment, differential privacy, client receipt или устранение image/ML failed gates.
