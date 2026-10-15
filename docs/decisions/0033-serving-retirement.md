# ADR 0033: Отказ в inference не ждёт удаления Docker worker

Дата: 2026-10-15. Статус: implemented, native component requalification pass на `e9120e0`. Scope: same Engine для production Reader и qualification Reader, без изменения политики доверия. Полные M11/M12 ещё открыты.

## Наблюдение

На `2905e70` реальный endpoint вернул первый 503 через 60.082361397 s от последней verified read, превышая заданные 60 s. Последний 200 получен до исходного lease deadline; lease не продлевался. [Полный санитизированный trace](../evidence/http-trust-outage-2905e70.md) сохраняет failure. Recovery прошёл, но не отменяет deadline failure.

`Engine.predict/check` при ошибке синхронно вызывали `Worker.close()` перед возвратом отказа. Этот путь ждёт channel/process shutdown и Docker removal/readback. Controlled regression с заблокированным cleanup воспроизводит задержку отказа независимо от сети и модели. Это дефект разделения API availability и resource cleanup, не обход подписей или выдача ML после подтверждённого expiry в данном trace.

## Решение и порядок

1. Под Engine lock немедленно убрать loaded handoff и active worker. После этого predict/readiness не могут обратиться к прежней модели.
2. Передать точный worker в один retained retirement slot. Отдельный owned thread выполняет существующий `Worker.close()` без удержания Engine lock во время Docker operations.
3. Успешный cleanup очищает только свой retained slot. Ошибка сохраняет handle для explicit retry, а не выдаёт ложный cleanup success. До подтверждённого завершения activation запрещён.
4. Thread handle сохраняется до start. Неудачный start не теряет worker; drain различает не запущенный thread и запущенный, не делает join unstarted thread и не запускает конкурентный close.
5. Explicit `drain()` ждёт retirement до 45 s вне Engine lock и проверяет конечное состояние. При незавершённом thread или ошибке удаления возвращает отказ; handle не забывается. Shutdown тоже выполняет drain, затем очистку активного worker.

Синхронная очистка при startup/reload сохранена. Background retirement используется только для invalidation действующей сессии. `Channel.exchange` и `Worker.send` при ошибке сначала запрещают дальнейшие exchanges (`closed=true`) и возвращают отказ Engine, не ожидая process wait/Docker cleanup внутри себя; startup wrappers по-прежнему сами очищают неуспешную загрузку. Standalone callers обязаны вызвать close, Engine сохраняет этот ownership автоматически. Native tests измеряют HTTP latency до drain, а cleanup проверяют отдельно. Это не вычитание времени из старого измерения: новый API действительно возвращает отказ до окончания cleanup, старый trace остаётся fail.

## Почему не альтернативы

- Не увеличить 60 s и не вычитать Docker latency: это скрыло бы найденный отказ.
- Не уменьшать lease произвольно ради одного прогона: авторизационная политика не меняется.
- Не забывать worker после 503: unconfirmed cleanup сохраняет ownership и блокирует новую activation.
- Не держать Engine lock на всё время background close: следующий HTTP запрос снова ожидал бы Docker.
- Не разрешать новый worker параллельно cleanup: один slot ограничивает ресурсы и исключает позднее удаление новой сессии.

## Проверка и ограничения

Failure-first test подтверждает, что synchronous cleanup блокировал отказ. Новые regressions покрывают немедленный отказ при удержанном cleanup, запрет reload, повторное activation после завершения, failed thread start и failed cleanup с retained handle. [Native clean-checkout replay `e9120e0`](../evidence/http-trust-outage-2026-10-15.md) подтвердил 46 cases, первый HTTP 503 через 59.995078784 s и explicit recovery. Отдельные transport failure regressions проверяют Channel/Worker без Docker; observed network-stop не заменяет все возможные отказовые сценарии.

Нет гарантии жёсткого realtime на произвольно зависшем host. Native outage останавливает authority, не моделирует все network blackholes или зависший SQL. Timeout свежего trust read, transport scheduling и production deployment требуют отдельных сценариев полной M11/M12 acceptance. Background cleanup failure пока виден как not-ready и explicit cleanup rejection; полноценная audit/alert delivery остаётся T29.
