# ADR 0060: свежий аудит на границе записи выпуска

Статус: реализуется для T29/M23; полная R1 acceptance остаётся отдельной.

Требование GOAL/M23: потеря audit sink запрещает новый выпуск даже при здоровом
ML monitoring. Drift dashboard не имеет полномочий разрешать promotion.

`promotion.promote` требует audit client после ML authorization и online trust.
Нет default-success profile: отсутствие client даёт отказ до CAS writes. При
настроенном, но недоступном collector возможны immutable CAS uploads; head и
events не меняются. Успех по-прежнему recorded-not-activated, release_ready=false.

Promoter подписывает `security-audit-request`: schema, producer/epoch, config pin,
selection SHA256, случайный nonce128bit и время. `POST /admission` использует
существующий ingress bearer, bounded parser и quota. Только зарегистрированный
promoter разрешён. Collector проверяет подпись/role/pin/epoch/freshness, выполняет
durable health poll с fsync/readback и отказывает при pending/gaps/missing
heartbeat/full journal/fault/scheduler lag. Receipt key подписывает отдельный
домен `security-audit-observation`, привязанный к digest запроса и health report.

Ответ ограничен свежестью5s, client требует новую nonce и общий roundtrip<=2s.
Повторный вызов не использует cache. Вызовы идут внутри SQL transaction перед
`record_selection` и после SQL statement перед commit: ожидание row lock не
позволяет использовать старую проверку. Ошибка второй проверки выходит из
транзакции с exception, PostgreSQL должен откатить незавершённую запись.

Это bounded freshness, не распределённая атомарность: collector может упасть
после последней проверки. Нет заявления continuous audit lease или атомарного
commit между SQL и filesystem. Отказ после неизвестного SQL commit требует
readback; retry использует прежние references/sequence. Низкоуровневая SQL
function доступна доверенной identity ml_promoter; компрометация controller
или его credentials находится за этой границей, SQL не проверяет Ed25519.

Новый обязательный `security_audit_config` находится в operator config schema2.
Request schema1 и подписанная ML policy не меняются. Audit registry policy и
ML policy различны; challenge связан с полной selection, содержащей ML policy.
Collector не утверждает сохранение selection в incident journal: сохраняется
health checkpoint. Это не восьмой тип security event и не разрешение ML.

Дополнение producer integration: audit config schema2 включает обязательные
state_directory/state_sha256 для существующего producer outbox. Schema1 без
очереди больше не принимается. Это версия вложенного audit config; основной
promotion config остаётся schema2. Перед challenge доставляются pending события
того же producer, поэтому здоровый collector не скрывает локальный backlog.
Retry batch ограничен16pending и2s на HTTP attempt; это отдельный этап до
fresh challenge, а не обещание2s на всю promotion.

Отказы release_authorization, fresh trust checks и audit checks проецируются в
`promotion.denied` с фиксированным reason authorization/trust/audit_unavailable.
Asset/bundle - digest proposal envelope, correlation - новая попытка, без model
bytes/HTTP body/exception text. Outbox сохраняет событие до network IO; неудачная
доставка даёт `promotion_denial_audit_unconfirmed`, разрешения не создаёт.
Повтор доставки использует прежнее событие; повтор самой promotion является
новой попыткой и при новом отказе создаёт другое событие. Missing assurance теперь
может писать security outbox, но не release CAS/journal и не audit challenge.
Ранние shape/config/SQL operational отказы не классифицируются автоматически
как authorization finding. Crash до durable enqueue и потеря producer state
ещё требуют общей M23 completeness/recovery проверки.

Проверки: unit signatures/bindings/clock/pending/retry, реальные HTTP/collector
и SQL transaction faults в hosted CI, owned cleanup. Controlled all-pass
authorization fixture не является независимой приёмкой модели. Остальные
источники, producer heartbeat automation, deployed mounts/network, полный
M23 и M18 на одном candidate остаются обязательными.
