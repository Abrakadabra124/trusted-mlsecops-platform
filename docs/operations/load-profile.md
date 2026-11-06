# Диагностика нагрузочного профиля M14

Статус 2026-11-06: client/golden contracts реализованы; native benchmark,
CPU/RAM, overload recovery и M14 acceptance ещё не приняты.
Ответственный: platform operator. Метод: [ADR 0056](../decisions/0056-load-measurement-profile.md).

## Проверка без инфраструктуры

В checkout с Python 3.12.15 и зафиксированным окружением выполнить:

```powershell
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.load_golden_qualification scripts.load_measurement_qualification
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
7. Если ресурсы или owned cleanup не подтверждены, оставить gate inconclusive
   либо fail по причине, а не объявлять R1 завершённым.

## Встреченные проблемы и исправления

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
Пока native coordinator не реализован, команды запуска полного M14 и подтверждение
его recovery здесь намеренно не приводятся как готовая процедура.
