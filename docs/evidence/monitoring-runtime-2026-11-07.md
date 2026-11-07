# M15: HTTP collection и owned scheduler

Статус: component pass на `6c0b5050ff3799c151a7e0a1436f9d9a1a285404`.
[Linux CI42317454624](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42317454624)
завершён success:76 monitoring tests/0 skips за17.304s,77 смежных HTTP/audit/lifecycle
tests/0 skips за8.007s. Coverage шести modules совпадает с таблицей ниже.
Чистый detached Windows checkout того же commit:76 tests/0 skips за20.749s,
working tree clean; использовалась существующая locked venv, не новая установка.
Это не full M15, M18 или R1. Исторический M14 на `bbff69e` не подтверждает
производительность нового HTTP hook.

## Проверяемое поведение

- Collector принимает только завершённый actual ASGI200 `/v1/predict`, с
  immutable context того же результата. Audit503, late deadline, auth/schema
  refusal, ready и отменённый response не считаются предсказаниями.
- Owned scheduler закрывает достаточные/временные окна, вызывает неизменный
  PSI evaluator и направляет signed alerts в настоящий loopback HTTP sink.
  Ten clean windows не создают alarm; два shifted windows создают data/prediction
  alerts. Отдельный подписанный delayed-label сценарий создаёт quality alert.
- Квитанции проверены отдельным pinned key, доставленные события сохраняют
  original sequence/admission/deadline. Повтор после сбоя идемпотентен;
  поздняя квитанция не обходит120s. Counts/retention и очереди ограничены.
- GET `/monitoring` требует отдельный operator credential. Health, insufficient
  data, delivery faults и pending queues видимы; raw features/labels отсутствуют.
- Shutdown сохраняет частичное окно и ждёт owned task; зависшая отмена не
  объявляется успешной очисткой. Engine/audit закрываются в `finally`.

## Локальное подтверждение

Python3.12.15, Windows, существующее locked окружение; только CPU и loopback,
без локальных Docker/WSL/Kubernetes/SQL. Данные, ключи и traces controlled.

76 monitoring tests,0 skips,22.640s. Coverage с ветвлениями:

| Модуль | Statements | Branches | Покрытие обоих |
| --- | ---: | ---: | ---: |
| monitoring |119|46|100%|
| monitoring_stream |93|36|100%|
| monitoring_labels |64|30|100%|
| monitoring_alerts |77|26|100%|
| monitoring_delivery |118|44|100%|
| monitoring_runtime |215|70|100%|
| Всего |686|252|100%|

Отдельно84 HTTP/metrics/audit/lifecycle/monitoring HTTP tests за15.367s,
3 Linux-only skips: retained fsync concurrency, owned retained lifecycle и
native SIGINT. Они не засчитываются выполненными на Windows; CI должен их
запустить. Coverage всего старого serving_http в этой выборке94%, поэтому
полная старая serving gate не объявляется повторно принятой.

При объединении suites обнаружен дефект тестовой изоляции: глобальная подмена
`asyncio.sleep` затронула owned sink server в другом потоке. Исправлено внедрением
часов только тестируемого Runtime. Повтор всех76 tests завершился успешно;
порог coverage и runtime timeout не ослаблялись.

## Воспроизведение

В чистом checkout этой версии:

```powershell
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.monitoring_qualification scripts.monitoring_stream_qualification scripts.monitoring_labels_qualification scripts.monitoring_alerts_qualification scripts.monitoring_delivery_qualification scripts.monitoring_runtime_qualification scripts.monitoring_http_qualification
uv run --locked python -m unittest scripts.serving_http_qualification scripts.serving_metrics_qualification scripts.serving_http_audit_qualification scripts.serving_lifecycle_qualification
uv run --locked python scripts/check_docs.py
```

CI [monitoring-contracts](../../.github/workflows/monitoring-contracts.yml)
отдельно проверяет >=95% statements и branches каждого из шести modules.
Raw logs и private envelopes не входят в репозиторий.

## Открытые границы

Reference пока задаётся доверенным вызывающим кодом, а fixtures используют
QualificationTrace. Отсутствуют candidate reference builder/configuration CLI,
durable restart, quarantine composition и native candidate-bound M15 acceptance.
Prometheus пока показывает существующие HTTP metrics; ML status доступен в JSON.
Полный M15 потребует сверки primary evidence после cleanup и новой M13/M14
регрессии. Этот компонент не разрешает выпуск и не обучает модель.

Следующий increment добавляет signed configuration и sink CLI; он не входит
в результат `6c0b505`. Его проверка записывается отдельно после своего CI.

Решения: [ADR0057](../decisions/0057-fixed-monitoring-contract.md).
Диагностика и восстановление: [model-monitoring](../operations/model-monitoring.md).
