# Отказы идентификации и восстановление их аудита

Ответственные: оператор serving и оператор security collector.
[ADR0063](../decisions/0063-identity-security-source.md) описывает bounded
child process. Это отдельный T29 source component; общий M23/R1 ещё открыт.

## Настройка

В существующий serving config добавляется абсолютный identity_audit_file.
Он указывает на JSON с ровно schema_version=1, producer_config и service_sha256.
Producer config - абсолютный путь к прежнему schema1 config из
[общего ранбука](security-events.md). Producer обязан иметь роль serving.
Signing key, ingress token, registry root/pin и outbox остаются в отдельных
private files. Операторский и inference bearer не передаются child.

service_sha256 - операторский public reference логического сервиса. Рекомендуется
сохранить соответствующий документ без секретов: имя, environment и назначение
сервиса. Этот adapter проверяет формат pin, но не загружает descriptor и не
сверяет его с deployed runtime; эту границу не выдавать за inventory attestation.
Parent закрепляет точные bytes identity config. Их изменение требует
контролируемого перезапуска serving, иначе child откажет по config pin.

Один producer/epoch использует одну существующую очередь. Не создавать новую
очередь с тем же signing key/epoch ради сброса sequence. Worker модели не получает
event key/token/outbox mounts. Полный mandatory deployment profile пока отдельная
работа; отсутствие identity_audit_file сохраняет прежний профиль без этого source.

Обычный запуск в разрешённой Linux среде остаётся прежним:

```bash
uv run --locked python -m mlsecops.serving_http --config /absolute/private/serving.json --port 8080
```

Lifespan запускает probe до активации engine. Probe проверяет source config,
registry/serving role и повторяет pending delivery. При пустой очереди probe
может не обращаться к collector и не доказывает его health. Fresh promotion
audit остаётся обязательным отдельно.

## Поведение HTTP

Ready/predict/operator routes сначала проверяют bearer. При отказе в source
передаются только серверный request ID и credential/role; тело запроса не
читается, token/IP/headers не сериализуются. Known credential другой роли даёт
тот же внешний401, что неизвестный credential, после подтверждения события.

В audited profile401 означает, что child подтвердил запись/доставку события.
В одной app instance работает максимум один child; очередь ожидания не создаётся.
Busy source, timeout или неподтверждённая доставка дают503
security_audit_unavailable, модель при этом не вызывается. Authenticated requests
не запускают child. Это ограниченный lab profile: повторные неавторизованные
запросы могут исчерпать outbox, автоматической eviction/reset нет.

Child использует закреплённый config и тот же Python/package root. Его stdout,
stderr и stdin направлены в DEVNULL в HTTP-пути, поэтому вывод не накапливается
и не попадает в HTTP/log. Exit0 происходит после проверки роли и подписанной
receipt. Это граница управления ресурсами, не изоляция отдельных OS identities.
HTTP waiter имеет лимит6s; child wait3s, затем terminate/reap1s и kill/reap1s.
Отмена waiter сохраняет ownership фоновой операции. Неизвестный cleanup outcome
не считается успешно завершённым shutdown.

## Диагностика и плейбук

1. Без изменений сверить ownership serving/collector PID и port, private paths,
   права, registry expiry, producer role, config SHA и число pending.
   Для readback использовать
   `security_event_delivery.configured(absolute_producer_config).store.snapshot()`
   в private Python процессе. Не печатать весь snapshot/keys/tokens в общий лог.
2. Проверить service reference, original event ID, correlation с серверным
   request_id и наличие signed receipt в operator inbox. Код503 или timeout
   сам по себе не доказывает отсутствие либо наличие outbox record.
3. При недоступном collector восстановить тот же принадлежащий задаче процесс
   и прежний state. Для доставки существующих pending выполнить изменяющий шаг:
   `security_event_delivery.configured(absolute_producer_config).retry()`.
   Он использует прежний event ID/timestamp; повтор HTTP-запроса создаёт новую
   попытку и не заменяет retry исходного события.
4. Проверить отсутствие pending, исходный envelope, service SHA, correlation,
   маршрут security.identity и подписанную receipt. Повтор retry возвращает0.
   Startup с pending тоже повторяет доставку до engine activation.
5. Если serving сообщает lifecycle failure, сначала подтвердить завершение
   его child и освобождение принадлежащего ему port. Не убивать процессы по
   общему имени python и не запускать вторую instance на той же очереди вслепую.
   После подтверждённой очистки запускать тот же профиль с сохранённым state.

При full/corrupt outbox, expired registry, pending вне freshness, потере state
или неизвестном результате reap сохранить private evidence и эскалировать.
Не удалять очередь/receipts, не менять timestamp/sequence, не отключать
role/pin/signature checks. Автоматической epoch migration здесь нет.
Rollback к unaudited profile не является исправлением и не закрывает M23.

Во время разработки выявлена опасность повторной отмены cleanup при двух
одновременных close во время spawn. Теперь close отменяет owned operation один
раз, сохраняет spawn task до получения process handle и проверяет reap.
Тест воспроизводит этот порядок; это предотвращённый failure mode, не заявленный
production incident. Timeout настоящего owned Python child также проверяется.

Первый hosted qualification остановился на проверке отказа startup: pending
событие при offline collector действительно блокировало сервер и закрывало port,
но fixture ожидала exit1 вместо STARTUP_FAILURE=3 закреплённого Uvicorn0.54.0.
Исправлен только harness: этот код преобразуется в конечный отказ после проверки
очистки. Негативный unit использует настоящий Uvicorn startup, не открывая listener.
Сначала он воспроизвёл SystemExit3, затем прошёл. SIGINT после штатного shutdown
также обрабатывается отдельно; lifecycle failure и неизвестная очистка сохраняют
неуспешный результат. Это ошибка проверки, не исправление разрешения доступа.

## Воспроизведение

```text
python -W error -m unittest scripts.security_identity_events_qualification scripts.security_identity_http_qualification
```

[Hosted workflow](../../.github/workflows/security-events-contracts.yml) запускает
настоящие serving HTTP, source child и collector, outage, restart, pending probe
и cleanup. Source harness использует controlled unready engine: он не заменяет
actual inference/M13/M14 acceptance. На текущей Windows локальные Docker/WSL/
Kubernetes/SQL не запускать. Pure Python unit tests и собственный проверочный
Python child не являются запуском этой инфраструктуры.
