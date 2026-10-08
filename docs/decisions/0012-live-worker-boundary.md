# ADR 0012: живая проверка доступа worker к scorer

Дата: 2026-10-08. Статус: **Implemented component, локально проверен**. Дополнение T26/M20. 137 checks прошли в owned lab; [runbook](../live-worker-boundary.md), [точное evidence/CI](../../STATUS.md). Не меняет права, сети, SQL schema или существующие datasets. Полный M20 пока inconclusive.

## Пробел и основание

Protocol v2 и scoped controllers проверены отдельно. Старые filesystem probes не охватывают актуальные `/client`, `/api`, `/signer`, а отсутствие локального файла ещё не доказывает недоступность соседнего живого процесса. Kubernetes предупреждает, что shared PID namespace раскрывает процессы, environment и filesystem через `/proc/<pid>/root`: [официальная документация](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/) проверена 2026-10-08. Поэтому не включаем shared PID или ptrace для удобства тестирования.

## Ограниченный план

1. Отрицательные unit tests для probe: только ENOENT/EACCES/EPERM означают filesystem deny; connection refused, неверный endpoint и неожиданная ошибка не считаются network pass.
2. Использовать общий production-path Pod builder для scorer и qualification witness. Временно запустить witness с той же ServiceAccount, SQL bundle, projected API token и scorer key, без расширения прав. Он читает проверенный синтетический holdout через TLS и держит labels в памяти и отдельном qualification-only tmpfs file. Не печатать labels, keys, token, их content hashes или raw errors.
3. До и после отрицательных probes подтвердить доступ scorer к настоящим SQL/API endpoints, holdout и signer. Отсутствующий/умерший witness не даёт pass.
4. Read-only CRI inspection связывает node PID с реальным container ID и Pod UID. В каждом `ml-train/trainer` и `ml-eval/evaluator` Job выполнить чтение современных credential paths, `/proc/<observed-node-pid>/{mem,environ,cmdline,root/...}` и TCP к точным ClusterIP SQL/API. Проверить разные PID namespace и одновременно работающий witness, фиксированные security contexts и observed image.
5. Probe Jobs запускает host operator с ограниченным test command, не controller admission path. Они не получают secrets, host mounts, API token или дополнительные capabilities. Production worker command/admission отдельно проверяются existing controller suite. Это детерминированный access probe, не kernel exploit или доказательство отсутствия covert channels.
6. Удалять только созданные временные resources с UID precondition. Проверить прежний SQL ledger и owned resource specifications после suite. Не сбрасывать migration, PVC, keys или историю. Witness deadline 240 s, worker deadline 90 s; выполнение последовательное, без параллельного training.

## Приёмка и границы

Evidence содержит source/image/profile, actual Pod/Job identities, PID namespace, причины отказа и положительные контрольные запросы. Missing prerequisites = inconclusive, unexpected read/connect/identity/cleanup = fail. Сначала component qualification и чистый CI; full M20 требует объединения с текущими protocol/controller checks и subject binding, не автоматического pass по наличию нового документа. Host admin и общий kernel доверены. Scorer не предоставляет отдельный HTTP admin service; проверяется используемый control-plane API, будущие services потребуют расширения matrix.
