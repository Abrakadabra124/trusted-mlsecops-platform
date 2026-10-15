# ADR 0034: HTTP deadline и fencing поколения serving

Дата: 2026-10-15. Scope: T14/T15, component increment; не полная M11/M12-приёмка.

## Проблема и источники

Предыдущий stopped-authority тест проверял быстрый connection refusal. При установленном соединении зависший SQL read держит Engine/Lease lock. Отдельный cleanup thread из ADR 0033 не ограничивает время такого чтения; HTTP handler раньше ждал его завершения.

`connect_timeout` относится к установлению соединения, а не ко всему запросу: [PostgreSQL 18, connection parameters](https://www.postgresql.org/docs/18/libpq-connect.html). Серверный statement timeout не обеспечивает wall-clock deadline клиента при остановленном сервере. Перенос операции в Python thread сам по себе также не ограничивает ожидание результата.

[Python 3.12 asyncio](https://docs.python.org/3.12/library/asyncio-task.html) различает `wait_for`, ожидающий cancellation, и `wait`, не отменяющий pending tasks при timeout. Фоновые tasks требуют сильных ссылок. Это основание для разделения HTTP-ожидания и ownership незавершённой синхронной операции, а не обещание отменить Python thread.

## Решение

1. У каждой успешно активированной модели собственный `threading.Event`. Invalidation/reload/close навсегда устанавливают прежний event; новая activation публикует новый immutable admission snapshot. Старый запрос передаёт свой event в Engine, под lock сравнивается именно identity. Запрос старого поколения не исполняется на новом worker и не инвалидирует его.
2. После auth, до body/slot admission, фиксируется request budget: минимум `now_monotonic + 10 s`, trust deadline минус `250 ms`, approval/permit expiry минус `250 ms`. Expiry однократно переводится из проверенного wall-time в monotonic при activation. Откат часов не продлевает опубликованное разрешение.
3. Снимок - дополнительный запрет, не замена signature/SQL/worker checks. Во время ожидания каждые максимум `50 ms` по таймеру проверяется текущий более короткий budget без Engine/Lease lock и без I/O. Исходный request deadline никогда не продлевается новым trust read. Проверка повторяется после сериализации, перед ASGI `http.response.start`.
4. При истечении устанавливается sticky fence и возвращается bounded 503. Неблокирующая попытка передать worker в retained cleanup не ждёт занятого Engine lock. После позднего чтения Engine снова проверяет fence до inference/публикации результата. Поздний fresh SQL read может обновить внутренний Lease, но не снимает fence и не разрешает auto-activation.
5. После dispatch единственный владелец освобождения semaphore slot - completion callback retained task. Timeout/cancel HTTP не освобождает слот раньше завершения thread. До dispatch slot освобождает handler. Максимум 8 таких HTTP operations, без включения отдельного heartbeat/lifecycle. Body coroutine отменяется отдельно; это не отмена SQL thread.
6. Auth failure остаётся 401. Fenced/expired admission имеет приоритет 503 перед overload/body. 429 означает перегрузку действующего поколения, а 422 body timeout - самостоятельный лимит 5 s при ещё действительном общем budget.

## Почему не другие решения

Просто увеличить SQL timeout или убрать trust checks нельзя: это продлевает недоверенное обслуживание. `wait_for(to_thread(...))` с ранним освобождением слота скрывает ещё работающий thread. Полная замена SQL-драйвера на async API не нужна для этого slice и сама требует отдельной проверки отмены, Windows event loop и shutdown. Process-isolated authority client может понадобиться для жёстко ограниченного shutdown, но здесь не реализован.

## Проверка и ограничения

Failure-first regressions: old-generation replay после reload, wall rollback, pending ownership после timeout/cancel, deadline во время body, expiry/fence после serialization, сокращение trust lease после admission. Сначала воспроизведены late response/неверный статус; затем исправлены. [Evidence](../evidence/serving-deadline-2026-10-15.md) отделяет локальные contracts от native CI.

Native harness [serving_pause_native.py](../../scripts/serving_pause_native.py) инструментирует только точный disposable trust client и thread одного настоящего HTTP predict. TLS connection создаётся штатно; затем Docker pause останавливает проверенную owned authority перед штатным SQL query. Не подменяются подписи, результаты SQL или model predictions. На момент HTTP 503 соединение уже установлено, чтение ещё не завершено. Finally снимает pause до drain/закрытия HTTP; затем проверяются cleanup, запрет auto-recovery, explicit fresh activation и прежние golden scores.

Pause/restore сериализуются отдельным guard; `closed` запрещает поздний pause, если connect закончился после выхода из injection context. Метка входа ставится в обёртке фактического `execute`, но сама по себе недостаточна. На момент 503 дополнительно требуется `Connection.info.transaction_status == ACTIVE`: [libpq status](https://www.postgresql.org/docs/18/libpq-status.html) определяет это как отправленную, ещё незавершённую SQL-команду. Это может быть implicit BEGIN драйвера, а не уже исполненный сервером SELECT; тест доказывает зависшую SQL-операцию внутри trust read после установленного соединения. Никакой успешный policy refresh из ACTIVE не выводится.

`250 ms` - инженерный запас, не real-time SLA. Планировщик, event loop, сериализация и сеть не дают абсолютной гарантии доставки клиенту к наносекунде. Native приёмка отдельно измеряет окончание чтения HTTP-ответа клиентом: stopped-authority <=60 s от последнего verified read; paused established query <=10.25 s от запроса и до прежнего lease deadline. Нельзя вычитать cleanup/transport latency из результата. Не доказаны все packet-loss/blackhole сценарии, bounded startup/shutdown бесконечно зависшего DB, root rotation, production Reader end-to-end rollback или общий R1 release.

Операционная процедура: [RB-53/PB-27](../operations/serving-deadline-troubleshooting.md).
