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

Повтор6d202b5 /[43139535579](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43139535579)
снова завершился timeout, теперь после восстановления collector. Supervisor
зарегистрировал3 failed checks; outbox содержал2 события/1receipt, collector1/1.
Последующее чтение config, signed SQL history и producer state прошло. Это
подтверждает незавершённую доставку, но не устанавливает причину child failure.

Для следующего запуска добавлены ограниченные диагностические exit codes в
`security_trust_events --heartbeat --config-sha256 ... --diagnostic-exit-code`.
Этот режим допускается только с pinned heartbeat. Обычный CLI сохраняет общий
код1 при ошибке, interruption130. Supervisor получает только числовой результат,
его stdout/stderr по-прежнему направлены в DEVNULL. Публичная диагностика включает
только `source_unavailable`, `journal_busy`, `journal_unavailable`,
`delivery_unconfirmed` либо `unclassified`; пути, SQL, envelopes и исключения
не выводятся. `journal_busy` требует конкретного BlockingIOError EAGAIN/EWOULDBLOCK
в цепочке ошибки journal; произвольный OSError не считается конкуренцией.

При новом отказе сохранить приватный лог и сопоставить `observer_failure_categories`
с `observer_failed_checks` и количествами receipts. Категории считаются только из
строго ограниченных сообщений supervisor. Их отсутствие не доказывает отсутствие
проблемы: spawn/timeout/cleanup могут не иметь child exit code. Последующее здоровое
чтение не отменяет прошлый отказ. После диагностики проверить завершение owned child
и disposable workflow; не выполнять blind retry, reset outbox или смену ключей.
Эта доработка улучшает диагностику, не объявляется исправлением периодического
таймаута.30s period,45s ожидание и исходные delivery/detection bounds сохранены.

Linux test на86a6327 /43141310976 обнаружил ошибку именно диагностики: настоящий
`flock` conflict проходил через общий `_parent`, который преобразовывал OSError
в `artifact_unavailable`. Классификатор ожидал иной wrapper и возвращал unknown.
Исправление перехватывает EAGAIN/EWOULDBLOCK непосредственно у `flock` и сохраняет
конечный `security_store_busy`; другие I/O ошибки остаются общими отказами.
Добавлены реальная двойная блокировка и отрицательная проверка другого errno.
Файловые права, exclusive lock, отсутствие retry и правила записи не изменены.
Существующие bounded readback loops принимают новый код как ту же временную
ошибку чтения, сохраняя прежние интервалы и deadline; pin/identity mismatch
по-прежнему не повторяются автоматически.
Нативная часть того же86a6327 CI прошла; это не устраняет предыдущий45s timeout.

## Подтверждённая конкуренция за journal и ограниченное восстановление

На ad53e3e /[43146211890](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43146211890)
contracts job прошёл. Native observer отказал при ожидании первого committed
события:1 failed check с точной категорией `journal_busy`, outbox0/0 и collector0/0.
Последующее чтение конфигурации, signed SQL history и producer state прошло.
Это наблюдаемый отказ hosted qualification, не production-инцидент.
Конкуренция за lock подтверждена; PID второго держателя в этом запуске не записан.
Прежние отказы без этих diagnostics нельзя автоматически приписать той же причине.

Подготовлен следующий runtime: успешные проверки сохраняют30s cycle. Только после
числового child exit42 разрешаются до двух повторов с1s backoff. Предыдущий child
должен быть подтверждённо завершён и собран; неизвестная очистка остаётся fatal.
Новый child запускается, только если в исходном30s cycle помещаются backoff,
10s child budget и2s на terminate/kill с подтверждением завершения. После backoff
остаток проверяется ещё раз, чтобы задержка планировщика не разрешала поздний
запуск. SIGTERM/stop прекращает повторы. Source unavailable,
delivery error, неизвестный код, timeout и configuration/integrity refusal этим
правилом не повторяются. Повтор сам не публикует heartbeat: это может сделать
только child после обычной проверки источника, history и receipts.

Hosted playbook расширен детерминированным fault: оператор удерживает lock только
своего fixture outbox, commits revocation, дожидается точного `journal_busy` и
подтверждает неизменность heartbeat у независимого collector. Затем освобождает
lock и проверяет доставку исходного события. Общий45s wait отсчитывается от commit,
включая время принудительной конкуренции; он не перезапускается после unlock.
Существующие60s delivery,25-40s periodic observation и120s loss bounds сохранены.
Этот fault выполняется только на разрешённом disposable hosted runner. Локальные
Docker/WSL/Kubernetes/SQL не нужны и не разрешены.

Свежий80dea70 /43149916553 прошёл: восстановление после unlock1.123634229s,
max commit delivery31.000750327s, период31.178s, signed gap90.204897724s;
owned cleanup подтверждён. [Evidence](../evidence/trust-observer-recovery-2026-11-12.md).
Это закрывает воспроизведённый lock-contention case, а не все исторические отказы
или общий M23. Если повтор исчерпан,
сохранять error/gap состояние и действовать по диагностике выше; не сбрасывать
журнал, ключи или sequence и не превращать отсутствие receipt в success.

### Повторение проверки после исправления

Ответственный оператор сначала проверяет, что предыдущие runs этой ветки завершены
и их owned cleanup подтверждён. Из чистого checkout запускается unit suite:

```sh
uv sync --locked --no-build --python 3.12.15
uv run --locked python -W error -m unittest scripts.security_trust_events_qualification scripts.security_trust_service_qualification scripts.trust_observer_diagnostics_qualification scripts.trust_observer_retry_qualification
```

На Windows ожидаются3Linux-dependent skips. Они не заменяют native proof.
Для опубликованного SHA этой ветки оператор запускает hosted workflow, если push
уже не запустил его автоматически; дублировать существующий run не требуется:

```sh
gh workflow run security-events-contracts.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref codex/cp4-m23-security-events-20261107
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --workflow security-events-contracts.yml --branch codex/cp4-m23-security-events-20261107 --limit 5
```

Сверить head SHA выбранного run с проверяемым commit. В native report обязательны
оба `confirmed-lock-contention-*` cases, receipt именно исходного committed event,
`forced_contention_recovery_seconds`, неизменные delivery/period/gap bounds и
подтверждённая очистка child/process group/fixture SQL. Успех одного contracts job
не заменяет success native job. При failure сохранить raw logs приватно, проверить
cleanup и классификацию отказа; retry workflow без установленной причины не считать
исправлением. Откат к предыдущему source возвращает прежнее поведение scheduling,
но не устраняет его подтверждённую проблему с lock contention; журнал и ключи
при откате сохраняются.
