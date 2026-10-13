# PB-17 / RB-35: scoped Kubernetes intake

Владелец: MLSecOps lab operator. Область: synthetic local CPU, уже подготовленный **одноразовый** owned cluster с private SQL, controller profile и текущим source/image. Нельзя применять к единственному рабочему ledger, чужому kubeconfig или production. Права, admission, TLS и query limit не меняются. Процедура дополняет [M21](../intake-gate.md) и [RB-34](intake-gate-troubleshooting.md).

## Что проверяется

Scorer - доверенный controller со своим SQL client и evaluator key, но без ONNX parser/runtime. Он создаёт только разрешённые worker Jobs через scoped Kubernetes API. Workers не получают token, signing key, SQL credentials или labels. Отдельный promoter Pod заново читает signed evaluation и denials без evaluator key/API token. Это проверка разных runtime identities, не независимость людей или cluster administrators.

12-case matrix: clean-before, unsafe format, zero-inspected, partial counts, stale response, foreign model, extra output, wrong tool, unsafe status/no-findings confusion, native process failure, scheduling deadline, clean-after. Mutation cases меняют ответ после реально выполненного scanner. No-findings confusion меняет статус, сохраняя противоречащий ему parser rejection; это не доказательство обнаружения произвольного полностью согласованного forged scan при компрометации scanner.

Crash fixture меняет digest запроса перед отправкой штатному worker: процесс действительно завершается nonzero. Deadline fixture оставляет command/image/security прежними, но добавляет уникальный несовпадающий node selector к собственному Job и ждёт реальный DeadlineExceeded. Worker в этом сценарии может не начать работу; report не приписывает ему выполненный scan. Docker process-hang отдельно проверяется PB-14. Эти fault injections не являются production-инцидентом или эксплуатацией ONNX CVE.

## RB-35: deadline, исчезнувший Pod или неверная классификация

**Проблема из source review:** controller_worker обозначал любой terminal Failed как общий process failure. Теперь DeadlineExceeded отдельно передаётся intake как scanner_timeout/inconclusive; crash остаётся scanner_crash/inconclusive. Controlled regression проверяет оба случая, не меняя admission policy или retry budget.

Job deadline ограничивает время всего Job; в Kubernetes 1.31+ terminal condition добавляется после завершения его Pods. Поэтому transient отсутствие Pod при чтении terminal state не равно отсутствию исполнения, но не даёт права выдумать его UID. См. [официальную документацию Kubernetes 1.36](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/#terminal-job-conditions), проверено 2026-10-13.

Probe сохраняет Pod UID/owner и spec, наблюдённые ранее у своего Job. При deadline допускается уже удалённый Pod только с таким observation. Для других terminal outcomes отсутствие Pod блокирует доказательство. Смена Job/Pod UID и другой owner - ошибка; нельзя привязать случайный Pod из namespace. Отдельный controlled fixture воспроизводит удаление Pod перед terminal read.

**Read-only диагностика:**

1. Проверить M21.json и kube-intake-qualification.json, их started/finished, image/source, candidate, case IDs. Если второго файла нет, native replay не доказан.
2. Проверить конкретный очищенный reason в private `evidence/kube-intake-diagnostic.log`. Не публиковать raw logs. `kube_intake_budget_insufficient` требует остановиться, а не сбрасывать ledger.
3. Для ещё существующих ресурсов читать только owned kubeconfig и namespaces. Пример для одноразового `.runtime`:

```bash
kubectl --kubeconfig .runtime/kubeconfig --context kind-trusted-mlsecops get jobs,pods -n ml-eval -o wide
kubectl --kubeconfig .runtime/kubeconfig --context kind-trusted-mlsecops get jobs,pods -n ml-scorer -o wide
```

4. Сопоставить UID с report и ownerReferences. Failed Job не перезапускать автоматически по одному timeout наблюдения. Дождаться terminal condition по тому же UID или классифицировать observation как неполное.
5. При cleanup timeout проверить только созданные этой campaign Jobs/ConfigMaps и их UIDs. Не удалять namespace, все Jobs по prefix или все Docker networks. UID mismatch эскалировать владельцу.

**Исправление и rollback:** исправить установленную причину в reviewed code/profile, затем fresh qualification в disposable state. Не переписывать прошлые receipts, timestamps или reason. При недоступном backend M21 остаётся inconclusive; при mismatch - fail. Откат к совместимой версии reader не восстанавливает потраченные slots и не превращает denial в approval.

## PB-17: воспроизводимый запуск

Prerequisites собираются по [Kubernetes workflow](../../.github/workflows/kubernetes.yml): fresh owned bootstrap, private storage, signed migration, scoped controllers и M20. Не выполнять повторный migration поверх рабочего cluster ради этой проверки. Минимум три свободных slots нужен в cluster ledger; preflight observation не резервирует их и не отменяет конкурентное исчерпание.

**Изменяющая команда** после готовности одноразового стенда:

```bash
uv run --locked python -m mlsecops.acceptance --gate M21 --state .runtime --output .runtime/evidence/M21.json
```

Полный runner создаёт дополнительную host SQL campaign, а в cluster расходует ровно три slots: одна clean evaluation и два отрицательных результата. Matrix inspection сама не читает holdout и не создаёт reservations. Ожидается шесть новых cluster evaluation-table objects: три reservations, одна evaluation, два denial. Existing candidates, datasets и releases не изменяются. Повтор команды - новая qualification с новым расходом budget, не бесплатный retry.

**Критерий результата:** полный report имеет 122 cases/status pass, source_dirty явно указан, подтверждены primary readback и cleanup. Не ограничиваться exit 0 отдельного contract workflow. Отсутствующий backend сохраняет gate inconclusive; любой invalid или incomplete native report блокирует pass. Даже M21 pass не разрешает release без остальных M-gates, image audit и poisoning policy.

**Ограничения:** общий trusted host/API server и локальные keys, синтетические данные, разные CAS identities у Docker/cluster copies, отсутствие M23 tamper-resistant audit. Не проверяются parser exploit, произвольная согласованная ложь скомпрометированного scanner или SQL power-loss recovery. Точные реально выполненные tests/CI и оставшиеся риски хранятся в [STATUS](../../STATUS.md).
