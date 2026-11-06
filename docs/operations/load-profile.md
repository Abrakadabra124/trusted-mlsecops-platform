# Диагностика нагрузочного профиля M14

Статус 2026-11-06: client/golden/resource contracts проверены; native runner
реализован, первый hosted baseline ещё не проверен. M14 acceptance открыт.
Ответственный: platform operator. Метод: [ADR 0056](../decisions/0056-load-measurement-profile.md).

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
   Наличие этих ограничений проверено в исходниках; их влияние на M14 ещё не измерено.
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
