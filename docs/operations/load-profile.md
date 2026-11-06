# Диагностика нагрузочного профиля M14

Статус 2026-11-06: [baseline 5f6fb84](../evidence/m14-load-pass-5f6fb84.md)
прошёл неизменный профиль: 8330 корректных ответов, 0 ошибок, p95=167.744 ms.
Fresh M14 composition реализована, но новый native acceptance ещё не проверен.
Первый [baseline 3861d8a](../evidence/m14-load-baseline-2026-11-06.md) и отказы
ниже сохраняются как история диагностики; они не являются текущим pass.
Ответственный: platform operator. Метод: [ADR 0056](../decisions/0056-load-measurement-profile.md).

## Общая приёмка M14

После штатной подготовки owned disposable CI окружения workflow выполняет:

```sh
uv run --locked python -m mlsecops.acceptance --gate M14 --profile local-cpu --state .runtime --output .runtime/evidence/M14.json
```

Команда требует существующих owned cluster/source storage/candidate markers и
hosted guard. Она сначала выполняет текущие controlled contracts без skips,
затем новый опыт. Старый public baseline не является входом для получения pass.
До и после опыта сверяются source/image и хеши всех Python methods/dependency
descriptors. После worker/controller cleanup перечитываются три operator packets
и четыре candidate artifacts. Из client records повторно вычисляются полный
профиль и latency, из samples - CPU/RAM; clock window должен находиться внутри
свежего опыта. Пакеты связаны с primary через SHA-256, сырые записи не публикуются.

Отсутствующие prerequisites дают inconclusive; несовпадение, неуспешный профиль,
пропуск метода или изменившийся packet блокируют pass. Сохранять private packets
и конечный отказ, проверить source/campaign и не редактировать hashes вручную.
Новый опыт разрешён после подтверждённой очистки предыдущего. Для публикации
приёмки нужны также terminal workflow success и два readback шага SQL/cluster
cleanup. `M14: pass` не закрывает M18/R1 и не выдаёт production approval.

Ни эту команду, ни подготовку инфраструктуры не запускать локально в текущей
Windows. В этой работе инфраструктурная проверка разрешена только в hosted CI.

### Отказ controlled preflight

Первый общий запуск [7abacda / 42287711273](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42287711273)
отказал до нового baseline. Он не является повторным успешным замером latency.
SQL stop 20:24:30 UTC, cluster absence 20:24:33 UTC 2026-11-06. Старый baseline
`5f6fb84` остаётся отдельным измерением. В новом CLI отсутствовал принятый Linux
runtime bootstrap перед импортом fixtures; теперь используется та же pinned
инициализация, что в M13. Связь именно этого отличия с отказом требует повторной CI.

При следующем отказе `M14-contract-diagnostic` публикует только идентификаторы
непрошедших методов из текущего source inventory, код возврата, число bytes и
фиксированные markers stderr. Содержимое child stdout/stderr не выводится.
Не отключать проверку stderr: выяснить marker/метод, исправить startup или тест
и повторить preflight. Теперь он выполняется также до создания инфраструктуры;
внутри свежего gate contracts всё равно запускаются заново. Windows-only
пропуски допустимы в локальном subset, но никогда не дают pass full gate.
Исходные частичные проекции и сравнение изменений:
[диагностика latency и отказов](../evidence/m14-latency-experiments-2026-11-06.md).

`7ddb7a4`, Actions `42275122970`: Linux 75 + 130 tests без пропусков;
native measurement получил 3304 корректных ответа, 40778 client-limited,
12398 ответов 503 и ноль общих overload. Прогрев прошёл без 429/503.
Ресурсная проверка отказала на controller CPU gap с верхней границей 21 s.
SQL и кластер очищены с readback. Предположение о заполнении audit budget
проверяется конечным снимком: counters, reserved/budget bytes, capacity,
healthy/closed/failed. Текст внутренней ошибки не публикуется; оператор
проверяет точную схему и связывает снимок с приватным finish packet.

Диагностический запуск `1749b62`, Actions `42269219751`, остановился с
`load_resource_reset_or_change`. Отдельные 65 контрактных и 49 регрессионных
тестов прошли; SQL и кластер удалены с проверкой конечного состояния.
Точное расхождение соседних снимков в этом запуске не опубликовано, поэтому
на момент этого запуска его причина не была определена. Он не подтверждает нагрузочный профиль.
При повторении оператор сохраняет ресурсные снимки до проверки и выводит
только две конфликтующие строки агрегатов, проверенную клиентскую сводку и
внутренние счётчики времени с меткой `load-resource-rejection-diagnostic`.
Он по-прежнему возвращает отказ и не выдаёт успешную квитанцию. Эти частичные
диагностические данные нельзя считать полной ресурсной приёмкой.

Повтор `2806a12`, Actions `42270925535`, установил расхождение: два снимка
controller имели одинаковые CPU/memory timestamps, при этом CPU counter вырос
с `15571353000` до `15649023000` core-ns, память также изменилась.
Это согласуется с секундной сериализацией `metav1.Time` в закреплённой версии
Kubernetes. Исправление parser описано в ADR 0056: учитывается секундная
неопределённость, сброс CPU и изменение identity по-прежнему запрещены.
Из этого повтора получены только частичные диагностические данные: 1540
корректных ответов за 120 s, p95 успешных ответов 726.907 ms, 57124 ответа 429.
Внутренние timings включают все фазы: 3384 trust reads заняли суммарно
108.860 s, 1692 удержания engine lock - 129.966 s. Вложенные времена нельзя
складывать. Проверка ресурсов не пройдена; SQL и кластер удалены с readback.

После исправления секундной точности запуск `f60ad0b`, Actions `42272026563`,
отказал по `load_resource_sampling_gap`. Порог не увеличен; следующий отчёт
показывает поле и консервативную величину gap. Очистка SQL завершилась
18:40:58 UTC, отсутствие кластера подтверждено 18:41:02 UTC 2026-11-06.

## Проверка повторного использования trust-соединения

Эксперимент `98da2b8`, Actions `42273530278`: 3146 корректных ответов за
120 s, p95 успешных ответов 347.711 ms, 66333 отказа 429. CPU sample gap
worker имеет верхнюю границу 21 s при допустимых 20 s, поэтому полная
ресурсная проверка отклонена. Это частичная диагностика, не M14 acceptance.
SQL остановлен 18:51:20 UTC, отсутствие кластера подтверждено 18:51:29 UTC.
По сравнению с `2806a12` наблюдается снижение latency, но два hosted-запуска
не доказывают стабильный коэффициент ускорения. Следующая проверка использует
десять общих admission slots; по-прежнему требуется ограниченный отказ на
отдельном burst из 40 запросов и успешное восстановление.

`trust_session.Session` принадлежит одному serving Engine. Перед каждым
использованием проверяются параметры, закреплённый host и хеши четырёх файлов
учётных данных, включая закрытый ключ; значения и хеши не публикуются.
После пяти секунд повторного использования, смены файлов или закрытия сокета
следующий read устанавливает новое TLS-соединение. SQL и проверка подписи,
root, версии, digest и server clock выполняются каждый раз. Autocommit исключает
долгую незавершённую транзакцию. Ошибка внутри read закрывает соединение без
скрытого повтора запроса; обычный trust lease продолжает действовать по прежним
правилам. Engine закрывает соединение при shutdown, включая ошибку worker cleanup.

Файловая preflight-проверка до входа в сессию может отказать до закрытия idle
сокета, но не позволяет выполнить запрос через него; финальное закрытие
принадлежит Engine. Пятисекундный предел означает возраст для повторного
использования, а не фоновый таймер удаления idle-сокета. Серверная смена правил
TLS-аутентификации проверяется при следующем handshake; отзыв модели/ключа/root
по trust-документу проверяется при каждом read, без кэша результата.

При проблеме проверить finite error, закрытие принадлежащего Engine соединения
и следующий новый handshake. Не увеличивать lease, не отключать `verify-full`
и не считать pooled-соединение доказательством актуальности документа.
Сравнивать с тем же профилем 10 клиентов / 10+120 s. Реальное ускорение и
поведение при инфраструктурных сбоях требуют hosted-проверки; controlled tests
подтверждают только локальные контракты жизненного цикла и проверки подписи.

## Проверка без инфраструктуры

В checkout с Python 3.12.15 и зафиксированным окружением выполнить:

```powershell
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.load_golden_qualification scripts.load_measurement_qualification scripts.load_resources_qualification
uv run --locked python scripts/check_docs.py
```

Это короткие controlled tests и loopback HTTP fixtures. Они не запускают
Docker/WSL/Kubernetes/SQL и не измеряют производительность настоящего candidate.
Native интеграция выполняется только в разрешённом disposable hosted CI.

## Разбор отказа

1. Сначала сверить source revision, payload/model/bundle digests и полный профиль.
   Отсутствующие binding или resource observations означают неполную проверку.
2. Сверить число попыток с суммой outcomes и status counts; все десять клиентов
   должны быть видны в прогреве и измерении. Не удалять timeout, transport error,
   429, 5xx или медленные tail responses из распределения.
3. `not_capped=false` или неполное окно запрещают pass, даже если p95 хороший.
   Сохранить ограниченный приватный report; исследовать быстрые отказы или
   ошибочный цикл. Не увеличивать cap/порог latency автоматически.
4. При 429 разделить per-client quota и общий overload по конечным кодам сервера.
   Стандартный одиночный token имеет max_in_flight=4, общий HTTP semaphore=8.
   Baseline содержит 112383 ответа 429; split между этими двумя причинами
   ещё не измерен. Нельзя приписывать весь объём одному limiter без проверки.
5. При неправильном digest/schema/score остановить принятие результата и сверить
   frozen reference с candidate. Нельзя заменить ожидаемое значение ответом,
   полученным в том же нагрузочном прогоне.
6. При timeout проверить полный абсолютный бюджет обмена, HTTP response size,
   audit/trust failures и состояние worker. Отказ клиента не доказывает, что
   сервер прекратил уже начатую работу; это проверяется отдельно при cleanup.
7. Resource parser отвергает missing fields, stale/future timestamps, changed
   PodRef/startTime, counter reset, gaps >20 s и отсутствие samples с обеих сторон
   окна. Не заменять их нулями и не называть sampled memory истинным пиком.
8. Если ресурсы или owned cleanup не подтверждены, оставить gate inconclusive
   либо fail по причине, а не объявлять R1 завершённым.

## Встреченные проблемы и исправления

- Первый hosted run `42262806371`, source `cbb62d3`, завершился до HTTP matrix
  после этапа привязки actual proposal. 57 новых и 49 regression tests прошли,
  source SQL остановлен и owned cluster удалён. Причина пока не установлена:
  исходный диагностический фильтр оставил только `load_native_rejected`.
  Добавлена публичная source location (module/line) без exception text/locals;
  повторный запуск нужен для локализации, а не для признания performance pass.
- Повтор `42263863491`, source `e8a936d`, локализовал отказ в строгом SQL command
  runner (`storage_snapshot.py:192`). Проверка сборки сценария обнаружила,
  что before/after snapshot требует `ml_promotion.migrations`, а новый standalone
  runner не устанавливал promotion schema. Добавлен существующий идемпотентный
  `promotion_state.install` с Kubernetes backend, как в privacy runner. Он
  создаёт журнал, но не выбирает release и не создаёт approval. Regression test
  сначала подтвердил отсутствие вызова, затем проверил порядок установки.
  Исправление требует подтверждения следующим hosted запуском.
- Run `42264773700`, source `cadbb12`, прошёл прежний этап и достиг HTTP matrix:
  установка schema подтверждена. Далее возник `load_exchange_read_failed`;
  причина чтения ещё не классифицирована, cleanup SQL/cluster успешен.
  Сборщик использует существующую finite classification ошибки exec. При том же
  UID/spec и исчезнувшем контейнере он ждёт terminal Pod status не более 5 секунд,
  не подтверждая никакой request. Это позволяет прочитать итоговую ошибку probe
  при гонке завершения CRI/Pod status; постоянная ошибка всё равно останавливает run.
  Включена существующая безопасная диагностика отказа активации serving.
- Run `42265653007`, source `e444681`, после обработки exit race показал
  `load_probe_rejected`, `phase=activate`, exit 1. При проверке этого участка
  найден отсутствующий audit directory: `Spool` открывает уже существующий
  приватный каталог и не создаёт его. Probe теперь создаёт `audit` с mode 0700
  до старта lifespan. Проверка существования каталога перед listener сначала
  упала, после исправления прошли все 9 probe tests. Native подтверждение следует
  отдельным запуском; оба cleanup шага `e444681` завершились успешно.
- Первый controlled тест границы прогрева ошибочно создавал две перекрывающиеся
  операции одного клиента. Валидатор отверг данные; fixture исправлен с сохранением
  запрета перекрытия. Это ошибка теста, не отказ production.
- Слишком короткий тест конкурентности зависел от расписания Windows event loop
  и иногда видел peak=5 вместо 10. Добавлен барьер первых десяти controlled calls
  и увеличено только тестовое окно. Native профиль 10+120 секунд не изменён.
- При раннем timeout Windows мог закрыть соединение до чтения заголовка fixture.
  Тестовый сервер теперь обрабатывает EOF/reset и закрывает writer/tasks;
  настоящие timeouts остаются в отчёте как ошибки.

## Восстановление и публикация

Если normal requests корректны, а p95 превышен, отдельно учитывать ожидание
в очереди и время обработки. В `df7ff2f` 6929/6929 measured predictions были
корректны, p95=313.890 ms, p99=352.678 ms; worker/controller resource gap 11 s.
Новый shutdown check прошёл. SQL stopped 19:39:02 UTC, cluster absence 19:39:04 UTC.
Из 128.849 s Engine hold проверка SQL parameters заняла 43.109 s; эта стоимость
частично входит в 31.085 s session_credentials и 72.292 s trust_read.
Не складывать вложенные timings. Первое следующее изменение - порядок HTTP
execution перед executor, без ослабления credential или trust validation.
При queue timeout ожидается ограниченный 429; queued expired generation не
должна войти в executor. Полный повтор обязан сохранить прежние profile/limits.

Отдельная обнаруженная ошибка runner: завершение Uvicorn thread само по себе
не доказывало успешный lifespan shutdown. В закреплённой установленной версии
`uvicorn/lifespan/on.py` исключение teardown сохраняется в `error_occurred`
или `shutdown_failed`; `server.run()` может возвратиться без исключения.
Реальный loopback failure-first test воспроизвёл ложный успешный выход.
Listener теперь проверяет оба terminal flags и возвращает `load_server_lifespan`;
фаза probe становится `shutdown` до закрытия. Проверены как исключение
FastAPI lifespan, так и явный ASGI `lifespan.shutdown.failed`.
Ошибка закрытия audit writer больше не должна исчезать за успешным thread join.

Run `42278800477` на `0d19cfb` остановился до bootstrap: 77 + 130 + 116 Linux
tests прошли без skips, audit core 94/98 branch exits, retention 102/102,
но snapshot coverage был 79% из-за отсутствия существующего packet I/O suite
в новой команде CI. На `77c02af` добавлен этот suite, пороги не изменены.
Никакая инфраструктура не была создана этим неуспешным run.

После исправления причины повторить controlled tests и полный baseline на том же
профиле. Менять только один подтверждённый bottleneck за раз; хранить сравнимые
результаты до/после. Не отключать audit, trust checks или quotas ради p95.
Не выполнять global prune/reset и не удалять чужие ресурсы.

Публиковать только source-bound агрегаты с явным scope и ограничениями.
Сырые latency records, credentials и service logs остаются в `.runtime`.
## Hosted baseline: воспроизводимый порядок

[Workflow](../../.github/workflows/kubernetes-load.yml) сначала проверяет contracts,
coverage >=95% отдельно statements/branches каждого нового модуля, затем собирает
pinned image, создаёт owned disposable cluster и готовит actual candidate.
Нагрузочный шаг использует существующий signed qualification permit; actual release
остаётся запрещён при отсутствии assurance. Это baseline, не полная M14 acceptance.

```powershell
gh workflow run kubernetes-load.yml --ref codex/cp4-m14-load-20261106
gh run list --workflow kubernetes-load.yml --limit 3
gh run view <RUN_ID>
```

Запускать только на уже опубликованном точном source commit и не отправлять новый
push в ту же ветку, пока workflow не завершён. Локальный запуск `kube_load_native`
ограничен hosted guard. Внутри разрешённого CI выполняется
`uv run --locked python -m scripts.kube_load_native`; это не команда для локальной Windows.

Оператор сначала независимо сверяет Job/Pod UID, image/spec, node и restart count.
После стартового resource sample подтверждает приватный start packet. Клиент
фиксирует clock anchors: системное время до/после monotonic origin и завершения.
Нестабильный clock mapping отклоняется; временная неопределённость расширяет
границы требуемого resource observation, а не уменьшает 120-секундную нагрузку.

После нагрузки выполняется отдельный burst из 40 запросов и golden recovery.
Эти запросы не включаются в обычные percentiles. Finish packet с исходными
наблюдениями передаётся только в приватный канал. Оператор пересчитывает summary,
дожидается свежих samples после конца окна, сохраняет и читает evidence обратно.
Только затем probe завершает worker; оператор отдельно проверяет отсутствие
owned Job и Pod и неизменность сохранённых файлов.

`profile_met=false` делает baseline workflow неуспешным, даже если сбор данных
завершён. Значение `full_M14=inconclusive` сохраняется до общей приёмки.
SQL stop и cluster removal запускаются через `always()` и подтверждают конечное
состояние. При ошибке сборщика сначала проверять конечный cleanup; не считать
пустой или старый report доказательством успешной нагрузки.

Raw records находятся только в `.runtime/evidence/load/<campaign>` на CI runner.
Они проверяются после выхода probe; постоянное внешнее хранение приватных packets
этот workflow не обеспечивает. В лог выводится finite aggregate projection.
Controller CPU/RAM включает loopback load generator и короткие operator exec reads;
отдельный model worker измеряется отдельно. Это фиксированная стоимость lab-профиля.

## Диагностика внутренних задержек

### Частота ресурсного наблюдения

Runs `42273530278` и `42275122970` отклонены: верхняя граница одного
CPU sample gap составила 21 s при допустимых 20 s. Summary API отдаёт
кешированные данные; более частый запрос оператора сам по себе не обновляет
источник. В disposable KIND конфигурации теперь задан поддерживаемый
Kubelet CLI flag `housekeeping-interval=5s`. JSON6902 append сохраняет штатные
`node-ip`, `provider-id` и `node-labels` в списке kubeadm v1beta4.

Перед start handshake оператор проверяет owned cluster, читает PID Kubelet
через systemd и требует ровно один соответствующий аргумент в `/proc/PID/cmdline`.
PID проверяется до построения пути; содержимое cmdline не публикуется.
Значение 5 s попадает в compute evidence. Конфигурация не доказывает фактическую
частоту: исходные samples всё равно обязаны пройти прежний консервативный
порог 20 s, покрытие окна и проверки freshness/reset/identity.

Основание: [Kubelet 1.36.4 CLI flags](https://github.com/kubernetes/kubernetes/blob/v1.36.4/cmd/kubelet/app/options/globalflags_linux.go),
[KIND 0.33.0 patch schema](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/apis/config/v1alpha4/types.go)
и [генератор kubeadm config](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/cluster/internal/kubeadm/config.go).
Это явное изменение среды измерения; прежние CPU/RAM показатели не выдаются
за повторение в идентичной конфигурации. Native проверка следует отдельным run.

В run [42277704992](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42277704992)
на `a34516c` CLI readback прошёл, но worker CPU gap всё ещё достиг 28 s.
Настройка 5 s сама по себе проблему не закрыла. Старый audit spool снова
остановился после 15505 durable events; worker большую часть остатка окна не
обрабатывал predictions. Это возможная связь, пока не доказанная причина gap.
После изменения storage sizing требуется новый полный замер. Linux 77+130 tests
без skips; SQL stop 19:19:24 UTC, cluster absence 19:19:28 UTC.

### Timings и причины отказа

[FIFO опыт 506a762](../evidence/m14-fifo-2026-11-06.md) завершил полный профиль
без normal errors, но p95=253.427 ms превышает 200 ms. Повторять старый benchmark
с меньшим числом клиентов или новым latency threshold нельзя. Диагностика
подтвердила повторное чтение TLS-настроек перед Session и внутри неё.
В исправленном пути валидация остаётся внутри Session на каждом read; её отказ
закрывает старое соединение до SQL. Проверять role, точный host, certificate hash,
отсутствующий key и запрещённый password file, затем новый native профиль.
Если файлы/пины неверны, восстановить разрешённую конфигурацию и явно reload
после подтверждённого cleanup; не отключать TLS/role check и не reuse старый transport.
При regression откатить целый проверенный commit с его evidence; незавершённый
M14 не превращается в pass при откате. Native M11/M13 после Session изменений
обязательны до финальной приёмки.

Run [42276686599](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42276686599),
source `941e315`, подтвердил исчерпание старого audit spool: 15506 accepted,
15505 durable, 1 unconfirmed, reserved 16765848 bytes при budget 16777216.
Writer завершился с failure. Это объясняет серию защищённых 503; normal
measurement также достиг max_attempts и не прошёл полное окно. Его successful
p95=160.825 ms не является успешной приёмкой. Resource gap worker 24 s отдельно
нарушил порог 20 s. Linux 76+130 tests прошли без skips; source SQL остановлен
в 19:12:10 UTC, отсутствие owned cluster проверено в 19:12:14 UTC.

HTTP runtime теперь явно использует retained budget 512 MiB, segment 16 MiB,
не более 40 segments, прежние rotate=60 s и minimum retention=300 s.
Расчёт для нормального профиля: `(10*20*300 + 10*40)*4*2048 = 494796800 bytes`.
Это 200 requests/s, aggregate burst 400, четыре события не более 2048 bytes.
Один граничный segment и 64 queue records добавляют 16908288 bytes; сумма
511705088 ниже hard budget 536870912. Это расчёт ёмкости, не обещание throughput.
Другие клиентские quotas требуют отдельного sizing; saturated/full storage
по-прежнему вызывает отказ, не удаление молодых событий.

Legacy single-file budget/default policy и предел payload export остаются
16 MiB. Большой closed spool отклоняется snapshot/export до чтения segments;
постраничный архив большого журнала пока не реализован. Clean reopen требует
точного прежнего policy/budget. Нельзя редактировать manifest, удалять lease
или менять path для обхода старого отказа. Проверочный профиль создаётся только
в новом owned disposable окружении.

Controller `/tmp` имеет bounded memory emptyDir 640 MiB под 512 MiB аудита и
128 MiB прочих temporary files. Container limit остаётся 1 GiB RAM / 2 CPU;
worker limits не изменены. Tmpfs учитывается в памяти контейнера, sampled RSS
не равен полному memory usage. Это ephemeral lab storage: fsync не доказывает
сохранность после удаления Pod/узла. Реальную нагрузку, закрытие writer, CPU/RAM
и cleanup необходимо подтвердить новым native run. Audit admission, queue=64,
durable acknowledgement и fail-closed поведение сохранены.

После baseline `3861d8a` probe собирает фиксированные агрегаты completed calls:
count/failures/total/max nanoseconds для reader check, trust read, worker ping,
worker predict, полного engine predict, ожидания и удержания engine lock.
Это внутрипроцессная диагностика, не независимая latency acceptance. Окно включает
warmup, measurement, отдельный overload и recovery; background heartbeat также
может войти в счётчики. Длительности вложены, их нельзя суммировать как независимые.

Обёртки работают только внутри load probe и восстанавливаются в `finally`.
Аргументы, return values и exception text в агрегаты не записываются. Размер
состояния постоянен: девять timing rows и три набора конечных причин 429.
После `77c02af` добавлены `client_parameters` и `session_credentials`:
они измеряют полную проверку SQL connection parameters и credential fingerprint
внутри disposable probe. Обёртки модульных функций восстанавливаются в finally;
новые строки не содержат имён файлов, certificate/key bytes или SQL arguments.
`overloaded`, `client_limited` и `unrecognized` считаются отдельно для normal
(warmup + measurement), overload и recovery. Оператор сверяет их суммы с
клиентским отчётом и связывает диагностический packet digest с receipt.

Диагностика добавляет небольшую, пока отдельно не измеренную стоимость вызовов
monotonic clock и lock. Внешние client-side latency, ошибки и пороги M14 остаются
основой решения; внутренние timings помогают выбрать одно проверяемое исправление.

После `91039fd` fingerprint вычисляется из тех же байтов, которые проверил
`storage.connection_materials`: четыре fresh bounded reads на validation,
без второго чтения в Session. Timing `client_parameters` теперь включает
fingerprints; сравнивать его прежнее и новое значение как одинаковую операцию
нельзя. При изменении TLS-файла/роли/host ранее открытое соединение закрывается
до SQL. Перепроверка после connect сохранена. JSON settings больше 65536 bytes
отвергается также на fresh-connect пути; превышение диагностировать по размеру
файла без вывода ключей. Нельзя обходить ошибку отключением TLS или fingerprint.

Native `91039fd` / [42289079463](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42289079463)
сохраняется как fail: 7130/7130 correct, 59.416667 RPS, p95=211.132398 ms,
p99=223.147815 ms, 0 wrong/429/5xx/timeouts/transport errors.
Полное окно, resources, overload/recovery и cleanup прошли; latency predicate
не прошёл. Нельзя заменить этот результат более ранним pass `5f6fb84`.
После изменения требуется новый полный M14; до него оптимизация не принята.
