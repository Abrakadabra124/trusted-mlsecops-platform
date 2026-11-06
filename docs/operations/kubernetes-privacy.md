# M13: диагностика приватного сбора Kubernetes logs

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Статус: collector и worker observer проверены pure/mocked tests; native handoff и общая M13 campaign ещё не реализованы. Это эксплуатационная инструкция разрабатываемого компонента, не подтверждение полного M13.

## Назначение и права

CRI (Container Runtime Interface) связывает Kubernetes с container runtime. Его журналы сохраняют stdout/stderr контейнера; настройка Docker `log-driver=none` другого backend не отключает эти журналы. Worker передаёт в stdout приватный протокол с scores и identifiers, поэтому raw CRI logs нельзя публиковать как обычный CI report.

[Collector](../../scripts/kube_privacy_logs.py) выполняется только внешним оператором разрешённого disposable GitHub-hosted стенда. Caller сначала проверяет ownership Job/StatefulSet и image contract. Collector повторно сверяет Pod UID, owner UID, container ID, image ID, spec, restart count и состояние до/после чтения. Serving-роль сохраняет прежние права на attach без `pods/log`; production config не получает observer или дополнительные credentials.

[Worker observer](../../scripts/kube_privacy_worker.py) предназначен только для qualification probe. Он оборачивает настоящий transport, фиксирует канонические ответы без request features и перед очисткой закрывает attach bridge. Затем оператор должен дождаться успешного завершения контейнера и прочитать его логи до удаления Pod. Base cleanup выполняется и при ошибке/прерывании наблюдателя. Прямой запуск collector на текущей локальной инфраструктуре запрещён ограничениями задачи.

## Проверяемая последовательность

1. Получить verified owned Pod и expected image из текущей campaign, не выбирать произвольный Pod по похожему имени.
2. Для worker сохранить в памяти точный поток фактически полученных ответов. Не конструировать ожидаемый лог из желаемых scores и не добавлять request features.
3. Закрыть attach bridge и проверить завершение процесса. Любой stderr делает наблюдение неуспешным; raw stderr не выводить в диагностику.
4. Оператор проверяет terminal worker и читает не более 1 MiB плюс один контрольный байт. Restart count должен быть строго целым нулём. Совпадение только хвоста, неполный stream, дополнительные строки и canary запрещают pass.
5. Подтвердить неизменность идентичности после чтения. Сохранить raw capture и приватную receipt только в owned private evidence; публичная projection ещё должна быть подключена отдельным runner.
6. Выполнить обычный scoped cleanup, проверить отсутствие собственного Job/Pod. Даже успешное чтение logs без подтверждённой очистки не завершает campaign.

Для PostgreSQL/trust collector допускает снимок работающего контейнера. Такая receipt явно отмечена как window, а не полный lifecycle: она не доказывает отсутствие более поздних записей, проверку всех контейнеров или всего M13.

## Отказы и действия оператора

| Код / симптом | Действие |
| --- | --- |
| `trust_hosted_runner_required` | Проверить тип runner. Не обходить guard и не переносить запуск на локальный Docker/WSL/Kubernetes/SQL |
| `privacy_log_request` | Проверить bounded canary inventory и expected stream. Terminal observation без полного expected output запрещено |
| `privacy_log_identity` / changed | Сверить UID, owner, image, spec и restart count с текущей campaign. Не читать новый контейнер под старой receipt |
| `privacy_log_limit` | Сохранить закрытый диагностический факт overflow. Не увеличивать лимит и не брать tail ради pass; найти producer лишнего вывода |
| `privacy_log_canary` | Оставить M13 fail, не публиковать capture. Установить producer утечки и исправить его; повторить всю затронутую campaign |
| `privacy_log_incomplete_stream` | Проверить EOF, restart/rotation, потерю префикса и наличие неожиданных строк. Отсутствие canary в неполном логе не является успехом |
| `privacy_worker_capture_missing` | Не было полного наблюдаемого exchange. Проверить startup/worker lifecycle; исторический успешный report не заменяет текущий |
| `privacy_worker_bridge_output` | Attach bridge не завершён либо записал stderr. Сохранить приватную диагностику и проверить cleanup; fixed exception code не доказывает исправление причины |
| Ошибка operator callback | Base cleanup остаётся обязательным. Не оставлять Pod ради ручного исследования без отдельного решения об ограниченном retention |

Read-only diagnosis предшествует любым действиям. При неизвестном ownership остановить сбор и передать оператору конкретные IDs в приватном канале. Не выполнять global prune, удаление чужих Pods, изменение RBAC, отключение проверки TLS или перезапись journal. Для повтора нужна новая owned campaign; сборщик не меняет production state, поэтому rollback приложения этим компонентом не требуется.

## Локальная проверка без инфраструктуры

```powershell
$env:PYTHONUTF8='1'
uv run --locked python -m unittest scripts.kube_privacy_logs_qualification scripts.kube_privacy_worker_qualification scripts.kube_serving_runtime_qualification
```

На 2026-11-06: 28 methods pass; collector/observer 79 statements / 22 branches, 100% покрытия. Проверены подмены до/после чтения, overflow, отсутствующие/лишние bytes, canary, restart, неправильный terminal state, исключение и KeyboardInterrupt при observation с сохранением owned cleanup. Это pure/mocked evidence, без настоящего Kubernetes запуска. До M13 остаются actual-candidate HTTP/audit integration, operator handoff, service windows, normal CLI/FD lifecycle, source binding, retained primary packet и публичная projection.
