# T18: операторская панель и свежие M13/M15

Runtime revision: `6fa4d9690cef2a3a051f31f5a43f708c85b431af`.
Статус: T18 завершён в synthetic CPU lab профиле. Полный R1 не принят.

Панель `/monitoring/ui` подключена к существующему authenticated monitoring API.
Она отображает health, наблюдения, очереди, PSI, качество по меткам, окна,
доставленные сигналы, reference и epoch. Фиксированная оболочка не содержит
данных, все снимки требуют operator bearer. Клиент только читает данные,
не сохраняет ключ, ограничивает размер и время ответа, удаляет устаревшие
значения при ошибке и не разрешает release. [Ранбук](../operations/monitoring-dashboard.md)
описывает работу, восстановление и обнаруженные при разработке ошибки.

## Локальная проверка и чистый checkout

Связанный набор dashboard/privacy/audit: 37 tests, 0 skips, 12.291 s в рабочем
окружении; отдельно 29 tests агрегаторов и native HTTP fixture, 0 skips,
30.549 s. На чистом detached checkout этого revision выполнен `uv sync --locked
--no-build --python 3.12.15` в новую `.venv`, затем те же 37 tests за 12.069 s,
без skips. `git status --porcelain` после проверки пуст. Проверка документации
на чистом checkout: 836 files, 302 Markdown documents, 2273 local links.

21 тест панели включает реальный ASGI routing и исполнение поставляемого
JavaScript в Node VM с контролируемыми DOM/fetch/временем. Проверены успешный
ответ, refresh, частичное окно с `null` PSI, abstentions, valid 503, 401/429,
malformed/oversized response, таймаут заголовков и тела, поздний ответ после
переподключения и очистка на pagehide. Проверка новой серверной оболочки и
wire probe: 55 statements, 26 branches, 100% каждого модуля. Это не заявление
100% покрытия JavaScript или всего приложения.

Отдельно реальный браузер получил 12000 HTTP observations, 12 окон, 200 меток
и 3 подписанные квитанции контролируемого predictor. Проверены desktop,
узкий viewport 390 px (client width и scroll width по 375 px), отсутствие
горизонтального переполнения, неверный ключ, отключение и перезагрузка.
Ошибок console при успешном сценарии не обнаружено. Оба временных loopback
стенда остановлены, их процессы завершились с exit 0 и порты закрыты.
Это визуальная проверка controlled fixture, не actual ONNX acceptance.

## Hosted evidence

Все три запуска относятся к указанному runtime revision и завершились success.

| Проверка | Результат |
| --- | --- |
| [Contracts 42343109982](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42343109982) | 350 Linux test executions с повторами: 21 + 142 + 50 + 8 + 77 + 52; 0 skips; dashboard/probe 100% |
| [M15 42343109962](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42343109962) | 188 criteria: 181 exact controlled methods + 7 aggregate; actual ONNX/HTTP campaign, source/policy/artifact bindings и post-cleanup replay |
| [M13 42343123664](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42343123664) | 512 criteria: 504 exact controlled methods + 8 aggregate; actual serving/feedback privacy, новые статические маршруты, post-cleanup replay |

Node в hosted проверках: v22.23.4; локально v24.19.0. Для приложения Node не
нужен, он исполняет только тесты. Python 3.12.15 и Python-пакеты зафиксированы
lock-файлом. Отсутствующие инструменты и skipped методы не засчитываются.

M15: 12000 actual ONNX/HTTP observations, 10 чистых окон без alarm, 2 shift
окна, 200 подписанных положительных меток, 3 signed receipts. Максимальная
доставка 0.374568635 s. Feedback: 10 claims, 1 quarantine row, идемпотентный
retry и 15 прямых SQL permission denials. Защищённые таблицы и promotion
не изменились; `training_eligible=false`, `verified_labels=false`.

M13: 1014 actual observations, 108 audit events, 18 correlated requests и
35 observed HTTP responses. Monitoring matrix: 1000 новых наблюдений, 4
отказа авторизации, 9 invalid labels/framing, 1 принятая подписанная метка,
retry 0. Квота: 7 accepted и 13 limited из 20 запросов, затем восстановление.
Новые 9 запросов проверяют HTML/CSS/JS без ключа, с header canary и с query
canary. Только точные фиксированные байты или пустой 400 допустимы; проверки
выполняются внутри capture stdout/stderr/logs и audit scan. Метрики остаются
в пределах 69 фиксированных рядов. Feedback CLI: 3 успешные и 8 отвергнутых
команд, 15 SQL denials, состояние защищённых таблиц и promotion сохранено.

## Очистка и проверка первичных данных

Время ниже UTC, 2026-11-07. Успех команды принят только вместе с проверкой
конечного состояния принадлежащего runner ресурса.

| Запуск | Source SQL остановлен и перечитан | Кластер отсутствует | Повторная проверка сохранённого evidence |
| --- | --- | --- | --- |
| M15 | 05:38:02 | 05:38:05 | 05:38:08, success |
| M13 | 05:38:55 | 05:39:00 | 05:39:01, success |

Из `git archive` этого revision восстановлены 175 runtime materials и 493
method materials. Их hashes, policy digest, точные имена методов и их порядок
сверены с первичными M13/M15 envelopes. Hashes и finite metrics приведены
в [машиночитаемой сводке](monitoring-dashboard-summary.md). Raw logs, приватные
пакеты, ключи и browser screenshots в публичный репозиторий не включены.

## Границы результата и следующий этап

M13 и M15 используют один source revision, но разные candidate references и
image IDs. Это две самостоятельные приёмки, а не единая M18 acceptance.
Предыдущий M14 с включённым monitoring принят на `cab2cad`; этот документ
не переносит его измерения на новый image и не заявляет повторный benchmark.

T18 lab scope принят. Далее по плану неделя 11/T29/M23: семь security-event
типов, доверенные producers, duplicate/reorder/gap detection и блокировка
новых promotions при недоступном audit sink. Четыре типа monitoring alerts
не закрывают этот критерий. Также открыты actual M10 assurance/approval,
полный M19 graph, независимые M22 cases (0/2), image findings, M16/M17 и общий
M18. Сохраняется исторический reliability debt R1-B08; один успешный запуск
не доказывает его устранение. Результат не доказывает production utility,
HA, длительную сохранность истории или независимость self-review.
