# M13: диагностика приватного сбора Kubernetes logs

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Статус: collector, worker observer и private operator handoff соединены с actual-candidate HTTP/audit probe. Локальные pure/mocked tests пройдены; первый native запуск ожидается. Общая M13 acceptance ещё не завершена.

## Назначение и права

CRI (Container Runtime Interface) связывает Kubernetes с container runtime. Его журналы сохраняют stdout/stderr контейнера; настройка Docker `log-driver=none` другого backend не отключает эти журналы. Worker передаёт в stdout приватный протокол с scores и identifiers, поэтому raw CRI logs нельзя публиковать как обычный CI report.

[Collector](../../scripts/kube_privacy_logs.py) выполняется только внешним оператором разрешённого disposable GitHub-hosted стенда. Caller сначала проверяет ownership Job/StatefulSet и image contract. Collector повторно сверяет Pod UID, owner UID, container ID, image ID, spec, restart count и состояние до/после чтения. Serving-роль сохраняет прежние права на attach без `pods/log`; production config не получает observer или дополнительные credentials.

[Worker observer](../../scripts/kube_privacy_worker.py) предназначен только для qualification probe. Он оборачивает настоящий transport, фиксирует канонические ответы без request features и перед очисткой закрывает attach bridge. Затем оператор должен дождаться успешного завершения контейнера и прочитать его логи до удаления Pod. Base cleanup выполняется и при ошибке/прерывании наблюдателя. Прямой запуск collector на текущей локальной инфраструктуре запрещён ограничениями задачи.

## Проверяемая последовательность

1. Получить verified owned Pod и expected image из текущей campaign, не выбирать произвольный Pod по похожему имени.
2. Для worker сохранить в памяти точный поток фактически полученных ответов. Не конструировать ожидаемый лог из желаемых scores и не добавлять request features.
3. Закрыть attach bridge и проверить завершение процесса. Любой stderr делает наблюдение неуспешным; raw stderr не выводить в диагностику.
4. Оператор проверяет terminal worker и читает не более 1 MiB плюс один контрольный байт. Restart count должен быть строго целым нулём. Совпадение только хвоста, неполный stream, дополнительные строки и canary запрещают pass.
5. Подтвердить неизменность идентичности после чтения. Сохранить raw capture и приватную receipt только в owned private evidence; [runner](../../scripts/kube_privacy_native.py) публикует ограниченные числовые counters и source revision, без raw logs и private identifiers.
6. Выполнить обычный scoped cleanup, проверить отсутствие собственного Job/Pod. Даже успешное чтение logs без подтверждённой очистки не завершает campaign.

Для PostgreSQL/trust collector допускает снимок работающего контейнера. Такая receipt явно отмечена как window, а не полный lifecycle: она не доказывает отсутствие более поздних записей, проверку всех контейнеров или всего M13.

## Сквозной hosted playbook

[Workflow](../../.github/workflows/kubernetes-privacy.yml) устанавливает locked dependencies, строит pinned image и создаёт отдельный disposable cluster. Обычный preparation формирует новую actual proposal и проверяет production refusal без assurance. Candidate permit разрешает только qualification inference и не подменяет release approval.

[Probe](../../scripts/kube_privacy_probe.py) запускает настоящий HTTP app и отдельный Kubernetes ONNX worker. Он проверяет golden prediction, auth, независимые client quotas, input canaries, metrics, HTTP 429 под давлением и HTTP 503 после fencing. Parent-процесс наблюдает stdout/stderr child до полного завершения; native stderr запрещён.

[Operator](../../scripts/kube_privacy_operator.py) обрабатывает два подтверждаемых шага: terminal worker и закрытый audit packet. [Private exchange](../../scripts/kube_privacy_exchange.py) связывает запрос с campaign и ответ с digest запроса, ограничивает размер и время. Operator повторно проверяет первичный audit packet и соответствие HTTP ledger, затем читает owned PostgreSQL/trust windows. Ошибка даёт отрицательное подтверждение, после которого worker обязан пройти обычный cleanup. Serving RBAC не расширяется.

Весь Pod output должен быть ровно каноническим отчётом с одним переводом строки. Ошибки печатают только fixed phase/code. Private packets сохраняются в `.runtime/evidence/privacy/<campaign>` только на runner; текущий workflow не экспортирует их из ephemeral host. Это ограничение последующей независимой проверки и остающаяся задача полной M13 acceptance.

Запускать через Actions `Kubernetes private output and audit integration` на опубликованной ветке `codex/cp3-m13-privacy`. Проверить exact commit, все test/native steps и оба cleanup steps. Не обновлять ветку во время run: concurrency отменяет предыдущую campaign. При отказе читать только fixed stage в публичном журнале, исправлять подтверждённую причину и повторять affected campaign. Нельзя превращать failed/inconclusive в pass переносом старой receipt.

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

На 2026-11-06: 71 methods основной regression group и 73 methods HTTP/privacy/audit pass на Windows. Collector, worker observer и exchange вместе: 116 statements / 34 branches, 100% покрытия. Новая оркестрация пока покрыта частично; вся группа из шести новых модулей: 409 statements / 98 branches, combined coverage 74%. Это pure/mocked evidence, без настоящего Kubernetes запуска. Проверены подмены до/после чтения, overflow, неполный stream, canary, restart, terminal state, исключение и KeyboardInterrupt с owned cleanup, private packet re-verification, порядок handoff, отрицательный ack, запрет mode conflicts до создания ресурсов.

До полного M13 остаются native validation, все обязательные output channels/normal CLI lifecycle, независимо воспроизводимое сохранение primary evidence и общая source-bound acceptance. Положительный component report всегда содержит `full_M13=inconclusive` и `release_ready=false`.
