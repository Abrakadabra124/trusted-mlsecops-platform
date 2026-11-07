# ADR 0057: фиксированный контракт ML monitoring

Дата: 2026-11-07. Scope: T18/M15, synthetic local CPU. Решение принято для
статистического ядра, in-process accumulator, signed label join, HTTP collector
и authenticated delivery. [Полный M15](../evidence/m15-monitoring-acceptance-2026-11-07.md)
принят на bd90286; визуальная dashboard и общий R1 ещё не поставлены. Исходные критерии [M15](../acceptance.md#m15) сохраняются.

## Требование и граница доверия

Сдвиг распределения входов или предсказаний не равен ухудшению качества модели.
Для первого нужен frozen reference и последовательность достаточных окон; для
второго нужны отдельно проверенные delayed labels. Успех вычисления PSI не
доказывает ни происхождение наблюдений, ни доставку предупреждения оператору.

Reference связывает model, bundle, dataset, evaluation и source fingerprint по
SHA-256. Его ожидаемый digest приходит из доверенной конфигурации, не из окна.
Reference фиксируется до начала наблюдения и копируется при создании evaluator.
Подпись reference, источник этих пяти bindings и их связь с actual candidate
должны проверяться интеграционным слоем. Одного JSON с правильными полями для
прохождения M15 недостаточно.

## Численный профиль v1

- Шесть признаков берутся из `datasets.FEATURES`; отдельно наблюдается prediction.
- Фиксированные интервалы: underflow `<0`, десять равных интервалов на `[0,1]`,
  overflow `>1`. Внутренние границы относятся к правому интервалу; `1` относится
  к последнему интервалу внутри support. У prediction обе внешние корзины нулевые.
- На каждой серии используется 12 целочисленных счётчиков. Суммы признаков равны
  числу наблюдений, сумма prediction равна числу наблюдений минус abstentions.
  Значения feature и индивидуальные scores evaluator не сохраняет.
- PSI: `sum((current-reference)*ln(current/reference))`. Для нулевых корзин
  прибавляется ровно `0.5` к каждому count, затем проводится нормализация на
  `N + 12*0.5`. Этот профиль не меняется после получения результатов опыта.
- `PSI >=0.2` в двух последовательных достаточных окнах одной и той же серии
  создаёт `data_drift` или `prediction_drift`. Два разных признака в разных
  окнах не являются подтверждением одного сдвига.
- Минимум 1000 observations на окно; prediction дополнительно требует минимум
  1000 действительно рассчитанных scores. Abstention не превращается в score0.
- Максимум 20000 observations/reference, 60 секунд на закрытое окно. Это границы
  lab памяти и времени, не оценка необходимой production выборки. Collector
  должен закрывать непересекающиеся окна по 1000 наблюдений либо по таймеру.
- Recall сравнивается при фиксированном decision threshold0.5, совпадающем с
  evaluation profile. После минимум200 positives падение строго больше0.05
  определяется целочисленным сравнением произведений. Ровно0.05 не даёт alert.

Reference содержит минимум1000 наблюдений без abstention и минимум200 positive
labels для baseline recall. Это два агрегата из train/reference и независимой
evaluation, а не разрешение считать train labels эксплуатационным ground truth.

## Порядок, повторы и неполные данные

Evaluator обслуживает один reference и один последовательно вызываемый поток.
Окно имеет digest, sequence, начало, конец и digest private prediction ledger.
Повтор последнего неизменного окна
идемпотентен; старое окно, конфликт того же sequence, overlap и observation до
freeze отклоняются. Sequence/time gap виден как `telemetry_gap` и сбрасывает
предыдущие streaks. Недостаточное окно имеет `insufficient`, а не `clean`.
Первое достаточное окно после gap может начать новый streak, но не подтвердить
старый. Mutable входы/возвращённые reports не меняют сохранённое состояние.

Ошибочные или отсутствующие inputs не дают положительную M15 evidence. Этот
компонент не импортирует promotion и всегда сообщает `release_ready=false`.
Аутентификация, freshness доставки и хранение checkpoints относятся к следующим
компонентам. До их проверки restart этого in-memory evaluator не доказывает
сохранение истории наблюдений или обнаружение потери telemetry.

## Выбор инструментов

Численный контракт реализован небольшим deterministic модулем на Python внутри
зафиксированного runtime. Это позволяет проверять точные границы, порядок окон,
abstentions и связывание digest независимо от формата отчёта библиотеки.
Prometheus client уже закреплён в lockfile; интеграция ML counters и operator
dashboard остаётся обязательной работой T18. Первоначальное предложение
Evidently/Grafana не является свидетельством их установки. Для R1 выбран
минимальный operator report/dashboard поверх тех же проверенных агрегатов;
Evidently/Grafana могут быть отдельными потребителями после R1, без изменения
acceptance predicates. Новые сервисы и зависимости для вычисления этой формулы
не требуются. Система мониторинга всё равно должна доказывать собственную
работоспособность и подлинную доставку, независимо от выбранного UI.

## Обязательное продолжение до M15

### Транспорт предупреждений

`monitoring_alerts` определяет четыре вида событий: data/prediction drift,
quality degradation и telemetry gap. Подписанный producer envelope связывает
epoch, последовательность, reference/window/evidence digests и время admission.
Срок ровно120s от admission, не от последней попытки отправки. Sink проверяет
отдельный pinned producer key и epoch/reference, принимает последовательность
без пропусков, отклоняет конфликт. Повтор в пределах cache128 событий возвращает
первоначальную подписанную квитанцию и её время; вытесненный sequence не принимается
как новое событие. Receipt key обязан отличаться от producer key.

`monitoring_delivery` реализует реальный loopback HTTP POST `/v1/alerts` и ASGI
sink. Клиент допускает только127.0.0.1, числовой port, signed envelope <=16KiB,
один Content-Length и bounded JSON response. Общий timeout2s включает connect,
headers и весь body; redirects/proxy/chunked/compression не поддерживаются.
Подпись квитанции и binding к событию проверяются независимо от HTTP200.
Сервер проверяет размер каждого фрагмента перед копированием в buffer, ограничивает
чтение/отправку, выдаёт постоянный отказ без отражения входов. Подпись защищает
подлинность, но loopback HTTP не объявляется сетевым TLS-профилем.

Это component transport. Cache sink пока in-memory и не является durable store;
его restart с тем же epoch без восстановления истории запрещён эксплуатационным
контрактом. Новый epoch должен задаваться доверенной конфигурацией. Owned scheduler
и bounded in-memory retention реализованы в `monitoring_runtime`; durable restart
и actual candidate trace остаются следующей обязательной работой.
Реальные loopback tests с controlled clocks не доказывают полный M15 deadline.

Реализован `Accumulator`: принимает immutable ReleaseTrace/QualificationTrace,
сверяет пять bindings reference, проверяет весь batch до изменения состояния,
сохраняет только histogram counts и пары `observation_id -> positive`. ID равен
SHA-256 canonical `[request_id, row_index]`; положительное решение соответствует
score>=0.5, abstention даёт false. Один request ID не считается дважды внутри
окна; максимум20000 наблюдений, закрытое окно неизменно. `serving_http` подключает
компонент к фактически завершённой отправке200; controlled tests проверяют
audit substitution, deadline denial, immutable context и отсутствие raw features
в операторском JSON. Это ещё не native candidate-bound приёмка.

`Labels` проверяет окно, digest ledger и соответствие числа positive decisions
prediction histogram. DSSE/Ed25519 envelope вида `monitor-labels` проверяется
отдельным pinned public key; ключ не извлекается из сообщения. Окно/reference
совпадают точно, issued time не раньше закрытия окна, срок <=24h и действителен
при приёме. Максимум1000 labels/batch; unknown IDs, нецелочисленные labels,
duplicates внутри batch и конфликт с уже принятым label отклоняют весь batch.
Идентичный retry не увеличивает denominator. Подпись подтверждает источник,
но не истинность предоставленного ground truth. Данные feedback не получают
полномочий label authority. Persistence, retention и actual end-to-end путь
этой authority ещё требуют реализации и проверки.

1. Собрать агрегаты только из завершённых actual HTTP predictions, привязанных к
   immutable serving context; сохранить M13 privacy и M14 performance.
2. Подключить проверенный signed label join к сохранённым actual prediction
   IDs/window/model; feedback направлять в quarantine.
3. Реализовать bounded scheduler и authenticated alert sink с receipt. Измерять
   время от admission достаточного окна до фактического acknowledgement <=120s.
4. Показать dashboard/report, telemetry outage, retries и идемпотентную доставку;
   alert не обладает полномочием auto-promotion.
5. Провести свежую candidate-bound native кампанию: 10 clean windows, два shift
   windows, отдельный degraded-label alert, негативные проверки и cleanup;
   сверить primary материалы. Только затем принимать полный M15.

Проверки ядра находятся в `scripts.monitoring_qualification`; [ранбук](../operations/model-monitoring.md)
отделяет их от ещё не выполненной эксплуатационной приёмки.

## Восстановление с новым epoch

Для R1 выбран fail-closed cold restart: сохраняемый private registry запрещает
повтор epoch после потери in-memory состояния. Runtime не сериализует raw
observations и не выдаёт потерянные окна за восстановленные. Новый доверенный
epoch запускает явный telemetry_gap и начинает сбор с insufficient. Это делает
разрыв видимым и предотвращает повтор старого receipt sequence. Полноценный
checkpoint observations/labels не является результатом этого изменения.
Реестр создаётся отдельным provisioning, проверяется по fingerprint и не
инициализируется при missing state. Команды, предел1024 markers, отказ при
повреждении и условия cold recovery приведены в [ранбуке](../operations/monitoring-restart.md).

## Карантин непроверенной обратной связи

Для существующего CLI-контура добавлен `mlsecops.feedback`. Он использует
готовую SQL таблицу quarantine, ingestor для INSERT/readback и curator для
inspect. Дополнительный HTTP service и доступ serving к записи не требуются.
Хранятся только bounded model/bundle/request/row IDs и claimed binary labels;
свободный текст и features запрещены. CAS устраняет идентичный retry, но не
разрешает противоречия между claims. Ни SQL digest, ни форма ID не доказывают
ground truth. Signed label authority и dataset approval остаются отдельными
доверенными действиями. Эксплуатационные команды и ограничения описаны в
[ранбуке карантина](../operations/feedback-quarantine.md).


## Композиция общей M15 acceptance, 2026-11-07

Новый [gate](../../mlsecops/monitoring_gate.py) реализован, [hosted acceptance](../evidence/m15-monitoring-acceptance-2026-11-07.md)
подтверждена на bd90286:167criteria,source bindings,cleanup и offline replay. Exact inventory исполняется заново без skips; свежая actual campaign
связана с source/image/time. До teardown повторно читаются signed proposal,
model и validation из разрешённой SQL. Signed reference связывается с lineage,
approved validation digest/size/rows и сохранёнными artifacts; он не пересчитывается
из эксплуатационных данных, чтобы скрыть drift.

Retained monitoring packet заново сопоставляет 120 HTTP batches с 12 окнами,
10 clean controls, двумя shift windows, подписанными delayed labels и тремя
receipts с deadline. Quarantine proof проверяет submit/retry/curator readback,
15 direct permission denials и отсутствие изменений authority/promotion.
Gate не заменяет эти primary records самозаявленными counters. Private admission
пинит exact bytes и hashes всех packets; после teardown выполняется offline replay.
Сборка M18 на одном candidate остаётся отдельной обязательной границей.

Используются существующие collector, scheduler, sink и workflow. Новый сервис,
система очередей или внешний monitoring backend для synthetic CPU профиля не
требуются. Restart inventory проверяет explicit history loss и запрет reuse epoch;
это не обещание полного восстановления временного ряда или PV durability.
