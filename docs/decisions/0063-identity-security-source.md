# ADR 0063: bounded события отказа HTTP-идентификации

Статус: реализация T29, полный M23/R1 открыт.

Существующие ready/predict и operator routes отклоняют credential до request
audit. Новый явный identity audit profile связывает этот отказ с serving
producer. Никакие headers, tokens, body, IP или user-controlled identifiers
в источник события не передаются: только серверный request ID и конечная
категория credential/role. Known token другой роли не раскрывается в HTTP ответе.

Из HTTP event loop нельзя выполнять синхронные journal/fsync/network операции.
Выбран короткий owned subprocess на попытку аудита с единственным concurrent
слотом и без очереди ожидания. Он использует прежний durable outbox/receipt,
не создаёт второй журнал. Это даёт явную границу terminate/kill/reap при
timeout/cancel/shutdown; цена - запуск Python для каждого audited denial.
Успешные authenticated requests не запускают child. Это bounded lab profile,
его предельную denial throughput нельзя выдавать за production SLO.

Startup probe проверяет private config pin, serving role и pending delivery
до engine activation. В рабочем режиме401 выдаётся после подтверждённой
доставки; busy/outage/invalid output дают503 без доступа к модели. Недоставленное
событие может сохраниться в outbox, тогда применяется original-event retry.
503 не выдаётся за доставленный401-event. Limit защищает от unbounded child
creation; flood всё ещё способен исчерпать конечный outbox, без auto eviction.

Parent сохраняет ownership task/child даже при отмене HTTP waiter. Shutdown
закрывает admission, завершает только свой child и проверяет reap. Неизвестный
cleanup outcome не становится success. Stdout/stderr child направлены в DEVNULL
и вообще не читаются parent: нет входного output protocol, накопления вывода
или его передачи в HTTP/log. Parent использует exit0 собственного trusted child,
который выдаёт его только после проверки role/pin/receipt. Отдельный CLI печатает
конечный bound summary.

Source config schema1 содержит producer_config и public service_sha256.
Оператор задаёт digest не содержащего секретов service descriptor. Parent
закрепляет bytes config, child проверяет pin при каждом запуске. Один
producer/epoch использует прежнюю очередь; root/receipt keys ему не передают.
В исходном94e6d7c identity source не создавал heartbeat. Последующий
[ADR0064](0064-producer-heartbeat.md) добавил durable counter и lifecycle
scheduler; startup теперь обращается к collector даже с пустой очередью.
Heartbeat HTTP echo не заменяет fresh signed promotion audit health.

Проверки: real auth decisions, role misuse, missing/multiple/bad credentials,
no body/engine access, busy/deadline/cancel/output isolation/spawn/shutdown failures,
actual HTTP->child->outbox->collector/restart и privacy canaries. Controlled
unready engine в source harness не является inference/M13/M14 acceptance.
[План](../../tasks/identity-events-plan.md).
