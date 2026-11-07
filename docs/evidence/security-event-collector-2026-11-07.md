# T29: настоящий collector, HTTP-доставка и восстановление

Лабораторный collector проверен на Linux. Полные M23, T29 и R1 открыты.
Runtime source: `1a234fe2e725e397629a1c7ebeaf17dfdf7c53a1`.
[CI42351757662](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42351757662),
job128341204706: success. Fresh Ubuntu24.04 checkout, Python3.12.15, uv0.12.23,
locked dependencies. Локальные Docker/WSL/Kubernetes/SQL не запускались.

## Реализованный путь

Подписанный envelope проходит transport admission, bounded ASGI parser,
pinned Registry и durable Store. `admit` ограничивает pending очередь16,
`route` сохраняет signed receipt для фиксированного маршрута до HTTP200.
Повтор возвращает первоначальный результат, late/reorder не переписывает историю.
Оператор читает до четырёх incidents за страницу отдельным token.

Один scheduler принадлежит process lifespan. Он сохраняет gap episodes,
создаёт signed notice один раз на episode и маршрутизирует pending records.
Heartbeat не является событием, retry не продлевает deadline. Self collector
identity зарезервирована. `release_ready=false` сохраняется; health не даёт
полномочия на выпуск модели. Routes - постоянная локальная очередь оператора,
не внешняя SIEM, подтверждение прочтения человеком или multi-host HA.

## Измерения

| Проверка | Результат на `1a234fe` |
| --- | --- |
| Event/config contracts | 21 tests,0skips |
| Смежные signing/monitoring/policy | 25 tests,0skips |
| Journal/health/routes и filesystem faults | 47 tests,0skips |
| Lifecycle/HTTP controlled contracts | 10 tests,0skips |
| Настоящий процесс/HTTP | 1 test,94.733s,0skips |
| Всего | 104 tests,0skips |
| Максимальное HTTP время трёх событий | 0.018888678s |
| Уведомление об исчезновении heartbeat | 90.691677257s, порог120s |
| Duplicate/reorder | последовательность1,3,2, late только для2 |
| Restart | исходные receipt/notice, четыре incidents, без дубля |
| Cleanup | SIGTERM, exit0 либо сигнал15, wait завершён, owned port закрыт |

Delivery измеряется настоящим HTTP round trip и monotonic clock. Heartbeat
campaign ждёт реальные секунды. Это один малый synthetic сценарий, не
percentile/load SLO. Отдельное elapsed-time измерение **sequence** gap ещё нужно;
controlled semantics не заменяет его.

Негативы: token/role/signer, JSON/framing/size/encoding/query, quota/backlog,
receipt key/deadline, чужой notice ID, clock divergence, отказ commit. Файловые
faults до/после rename проверяют retry без дубля. Runtime refusal возвращает
постоянный503 без input/путей/исключений. Canary и transport tokens отсутствуют
в private process log. Полная M13-проверка нового сервиса ещё не выполнена.

Coverage: events105/105statements42/42branches, config101/10132/32,
health134/13454/54, ledger178/17951/52, store149/15036/36. Порог95% не ослаблен.
Эти проценты не относятся ко всему HTTP/CLI/runtime.

## Воспроизведение и исправление тестовой очистки

[Ранбук](../operations/security-events.md) содержит команды/config/recovery,
[ADR0058](../decisions/0058-security-event-contract.md) объясняет local routes.
`scripts/security_event_live_qualification.py` создаёт private synthetic keys,
config/state/process и проверяет закрытие PID/порта. Raw logs/keys не публикуются.

Отдельный Windows checkout `1a234fe` с новой locked `.venv` выполнил104 tests
с22 skips, но interpreter exit показал ResourceWarning временной директории.
Этот запуск не считается полностью чистым воспроизведением. Причина: вложенный
IsolatedAsyncioTestCase использовался как fixture без собственного async runner.
Production collector на Windows не стартовал.

Исправление использует synchronous fixture и async cleanup текущего test case.
`asyncTearDown` проверяет отсутствие принадлежащей fixture директории. Локальные
10 lifecycle/HTTP tests с warnings-as-errors прошли. Runtime bytes не изменены.
Последующая clean проверка должна подтвердить отсутствие stderr warnings,
а не только exit code0.

## Оставшаяся обязательная работа

Семь настоящих source adapters, fail-closed audit admission перед последней
изменяющей операцией promotion, elapsed sequence gaps, outage при исправном
drift UI и общая source-bound M23 campaign. Нужны интеграционные privacy,
capacity/retention/recovery проверки. Actual M10/M19, независимые M22 cases0/2,
M16/M17, image blockers/R1-B08 и финальный M18 на одном candidate сохраняются.
