# Постоянный наблюдатель отзывов доверия

T29/M23, Linux reference. [Решение](../decisions/0065-periodic-trust-observer.md),
[исходный SQL observer](trust-security-events.md), [durable heartbeat](producer-heartbeat.md).
[Native25371bf](../evidence/periodic-trust-observer-2026-11-11.md) подтверждён:
CI43087532653success,15assertions, period30.022s, commit delivery29.775085516s,
stopped-source notice90.930804055s, cleanup pass. Full M23/R1 остаются открытыми.

## Запуск и проверка

Ответственный - оператор доверенного control plane. Нужны существующие SQL/TLS
credentials роли `ml_serving`, подписанный registry с отдельным trust producer
и `heartbeat_required=true`, schema2 outbox, ключ producer, ingress token и
работающий loopback collector. У worker этих файлов быть не должно. Это ещё
не доказательство полного deployed profile: mounts/network проверяются отдельно.

Конфигурация соответствует `security_trust_events`: schema_version, trust_client,
environment, initial_root, producer_config, rotations. Хранить её в отдельном
приватном каталоге0700, файл0600, пути абсолютные. Этот каталог не должен быть
самим outbox: supervisor держит directory lock, child нужен свой outbox lock.
Не создавайте новые keys/epoch/state при каждом запуске.

```sh
uv run --locked python -m mlsecops.security_trust_service --config /private/trust-observer/config.json
```

Первый cycle запускается сразу, следующие - каждые30s, один child максимум10s.
Сервис не пишет логи SQL/документы/credentials. Успешный idle supervisor не выводит
сообщения: успех доказывают signed receipt и heartbeat в независимом collector,
а не наличие PID. Свежая подписанная audit-проверка нужна для каждого promotion.
При штатной остановке выводится `state=stopped, release_ready=false`, exit0.

## RB: observer жив, heartbeat или события отсутствуют

1. Проверить только собственный PID и конечный exit status. Не выводить config,
   environment, DSN, ключи или raw process logs в общий терминал/CI.
2. `trust_observer_check_failed` означает отказ child, timeout или failure spawn;
   это не подтверждение конкретной причины. Проверить наличие приватных файлов,
   права, TLS server name и доступность SQL отдельной разрешённой диагностикой.
3. После изменения config работающий supervisor продолжит отказывать: digest
   зафиксирован при старте. Проверить новое содержание, затем штатно остановить
   и запустить тот же profile. Изменение rotation package требует новой операторской
   проверки dual signatures и next-root pin. Автоматического root trust нет.
4. Проверить registry, срок его действия, schema2 и trust heartbeat_required.
   Отказ schema1 не исправляется reset журнала: согласовать миграцию epoch по
   [heartbeat runbook](producer-heartbeat.md). Программа state не инициализирует.
5. При sink outage восстановить тот же collector/state. Следующий cycle повторит
   исходное событие с прежним ID/receipt; pending records не удалять. В истории
   SQL должны сохраниться все версии1..head, иначе наблюдатель отказывает.
6. Убедиться, что collector действительно принял heartbeat и receipts, очередь
   pending пуста и fresh audit response разрешает проверку. HTTP echo отдельно
   не является разрешением release, отсутствие новых отзывов не доказывает здоровье.

## PB: остановка и повторный запуск

Владелец supervisor отправляет SIGTERM именно своему известному PID. Supervisor
останавливает новые cycles, завершает и reap своего child: terminate1s, затем
kill1s. Проверить exit0 и отсутствие дочерних процессов. Exit1 с
`trust_observer_rejected` требует проверки очистки до нового запуска.
SIGKILL supervisor не гарантирует исполнение Python finally; среда развёртывания
должна владеть целой process group/container, а не только потерянным PID.

После остановки heartbeat перестанет приходить. Collector должен создать signed
`telemetry.gap` в пределах120s и отказать свежей audit-проверке. Не отключать
heartbeat_required ради зелёной панели. Запускать ту же конфигурацию с тем же
outbox: счётчик heartbeat увеличивается, события не дублируются.

## Границы проверки

Unit tests проверяют источник/доставку/подмену config/таймаут/сигналы/cleanup и
реальный собственный Python child. POSIX lock и реальный SQL/collector проверяются
только hosted Linux. Полный M23, mandatory deployment и R1 эта процедура не заменяет.

## Ошибка qualification при первом запуске

Run43087026043 на df8ce0d остановился с TypeError до запуска supervisor: native
readback передал `expected_sha256` конструктору Store, который принимает
`root, identity_sha256, registry`. Ошибка воспроизведена отдельным тестом с
реальным конструктором, исправлено только соединение тестового reader. Защиты
runtime не ослаблены. Повторный native25371bf прошёл отдельно; исходный
неуспех сохраняется в [evidence](../evidence/periodic-trust-observer-2026-11-11.md).

## Таймаут доставки в повторной регрессии

Run43102811593 на4aeece4: contracts691Linux executions/0skips pass; native
promotion25 и trust history37 pass. Continuous observer завершился
`trust_observer_case:observation_deadline` при ожидании первого committed
revocation с receipt (45s). Первый heartbeat был получен, supervisor не завершился.
Это отказ проверки, а не успешная доставка; причина из прежнего отчёта не установлена.

Native harness теперь перед cleanup печатает только число неудачных проверок
supervisor и количества записей/receipts в outbox и collector. Ошибка чтения
остаётся null, а не нулём. Raw log, envelopes, keys и tokens не публикуются.
Эти поля помогают отличить отсутствие enqueue от незавершённой доставки, но сами
не доказывают причину. Сохранены исходные45s ожидания,30s period,60s delivery bound
и120s detection bound. Не увеличивать пороги и не объявлять случайный повтор pass
исправлением. Конкуренция диагностического reader с writer пока лишь гипотеза.

Повтор4156d41 /43104110909 завершился success:15continuous assertions,
period30.019s, operation-start->receipt29.85712158s, stopped-source90.759104269s.
Runtime fingerprint не изменился. В этом запуске timeout не повторился, поэтому
новые failure counters не дали сведений о причине первого отказа. Сохранять его
как открытую нестабильность до воспроизведения и проверки причинного исправления.
