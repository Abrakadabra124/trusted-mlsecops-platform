# ADR 0061: события отзыва из подтверждённой истории доверия

Статус: реализация компонента T29/M23. Полная R1 acceptance остаётся отдельной.

Callback после SQL commit может потерять событие при остановке между commit и
enqueue. Существующие подписанные документы `ml_trust.documents` уже сохраняют
историю отзыва. [Наблюдатель](../../mlsecops/security_trust_events.py) читает её
заново одним SQL statement и сверяет целиком перед отправкой. Новый cursor или
вторая транзакция authority не нужны. Роль `ml_serving` использует существующий
SELECT через проверенный TLS client; миграции и расширение SQL прав не требуются.

Независимый operator pin задаёт первоначальный public root. Все версии от1 до
head обязаны присутствовать, digest/canonical bytes/signatures/environment и
монотонность revocations проверяются. Нельзя продолжить подпись ранее отозванным
корнем. Ротация требует public package с двумя подписями и отдельного next_root
pin оператора; package должен связывать именно соседние сохранённые документы.
Последний корень и SHA совпадают с SQL settings/head. Таблица root_rotations
остаётся недоступной reader; только оператор передаёт ограниченные package files.

Новые revoked_artifacts/revoked_keys и смена promotion_policy_sha256 порождают
соответственно reasons artifact/key/policy. На версию максимум три события
`trust.revoked`, маршрут `security.trust`. asset_sha256 обозначает SHA подписанного
документа, bundle_sha256 отсутствует. Это событие изменения категории, не полный
список объектов. Policy reason означает замену policy данной версией, не вечный
глобальный отзыв предыдущего digest. Продление без новых отзывов не создаёт событие.

Correlation связывает environment, original root, document SHA и reason.
Существующий producer outbox сохраняет envelope до отправки, исходные event ID,
sequence и receipt при retry. Event time означает время обнаружения/постановки
наблюдателем, не SQL commit. Срок исторического trust document может закончиться:
подлинный прошлый отзыв всё равно отражается, но права на выпуск это не даёт.
Будущие issued_at относительно SQL clock отвергаются.

Весь outbox обязан соответствовать повторно построенной истории перед сетевым
I/O. Это выявляет потерю ранее замеченного отзыва. Проверка не доказывает полную
защиту от отката SQL: замена/откат версий без security events и откат всех
доверенных хранилищ администратором не покрыты. Source snapshot может устареть
сразу после чтения, поэтому результат `observed`, release_ready=false, не current
trust lease и не разрешение promotion.

Границы:64 версии,8MiB canonical history,4 ротации,1MiB на документ/package.
SQL LIMIT65 обнаруживает превышение; драйвер может принять до65MiB document
bytes до aggregate проверки. Нет заявления о hard8MiB wire/memory limit.
History/outbox overflow, corruption, expired registry и pending вне freshness
дают отказ; автоматические reset/eviction/epoch migration отсутствуют.

Проверки: [контракты](../../scripts/security_trust_events_qualification.py),
[hosted native campaign](../../scripts/security_trust_events_native.py),
[workflow](../../.github/workflows/security-events-contracts.yml).
[Ранбук и плейбук](../operations/trust-security-events.md) описывают retry,
ротацию и эскалацию. Постоянный scheduler/producer heartbeat, обязательное
развёртывание этого observer и полная M23 latency campaign ещё требуются.
