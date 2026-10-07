# Подписанный перенос артефактов в private cluster storage

Этот increment переносит snapshot собственного host PostgreSQL в подготовленную закрытую БД Kubernetes. Он не переключает demo, не разрешает serving и не заменяет полные M04/M17/M20. Требования и изменение runtime: [ADR 0009](decisions/0009-storage-migration.md). Актуальное evidence: [STATUS](../STATUS.md).

## Что переносится и почему

В девяти SQL tables хранятся dataset splits, manifests, lineage, candidate bytes и evaluation reports. Content-addressed storage проверяет SHA-256 bytes, а DSSE (Dead Simple Signing Envelope) связывает тип и содержимое документа с доверенным ключом. Подпись backup проверяется по внешним public trust roots, не по ключу внутри самого архива.

PostgreSQL custom archive содержит только data существующих таблиц. CA, пароли, private signing keys, роли и DDL не переносятся. У target собственные TLS certificates, но это тот же owned workspace и те же явно заданные public signing roots. Для отдельного recovery workspace применяется [другой restore path](storage-recovery.md).

Это snapshot import, не online replication. Новые записи исходной БД после backup не появляются в target автоматически. Проверка fresh demo перед backup добавляет candidate/evaluation в source; сама migration их не изменяет. Не запускайте параллельные writers во время qualification.

## Воспроизведение из clean checkout

Нужны prerequisites [Kubernetes lab](kubernetes-lab.md) и [private storage](private-cluster-storage.md), Linux x86_64 Docker Engine, Python 3.12.15, uv, kind, kubectl и Helm. Это отдельный лабораторный cluster, не текущий корпоративный context. CLI всегда передаёт собственный kubeconfig/context.

```bash
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git
cd trusted-mlsecops-platform
uv sync --locked --python 3.12.15
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.cluster bootstrap
uv run --locked python -m mlsecops.storage_bootstrap
uv run --locked python -m mlsecops.kube_storage
uv run --locked python -m mlsecops.kube_storage_migration_qualification
```

Qualification предназначена для **первого переноса в пустой target**, а не для повторного сброса существующей БД. Она создаёт настоящий synthetic dataset, обучает модель, подписывает evaluation, делает backup, проверяет negatives, импортирует archive и выполняет 1 000 predictions. В GitHub это запускает [Kubernetes workflow](../.github/workflows/kubernetes.yml) на disposable runner. Linux CI installer tools описан в prerequisites; он не предназначен для Windows.

Приватные inputs сохраняются в `.runtime/kubernetes-storage/migration-inputs.json`; очищенный итог в `.runtime/evidence/kubernetes-migration-qualification.json`. Отчёт перед запуском становится `inconclusive`, а ожидаемый отказ засчитывается только при точной причине. Не удаляйте уже перенесённые данные ради нового зелёного отчёта. Для повторения всей qualification нужен новый disposable стенд; на существующем проверяется безопасный повтор CLI и текущее конечное состояние.

Проверенный feature commit: `1bd78c98ed1e529f8a82ef4f02e7b314a8751b48`. [Clean-checkout run 37694981606](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37694981606) прошёл 497 уникальных migration checks и 1 000 golden predictions с max error 0.0. Свежий CI обучил модель сам, без локального backup или готового image; полный job занял 7m43s. Это время CI component workflow, не cold-machine production RTO. Для точного воспроизведения данной редакции выполните `git checkout 1bd78c98ed1e529f8a82ef4f02e7b314a8751b48` после clone, до build/bootstrap.

## Обычный перенос и продолжение после сбоя

Создайте backup командой из [storage recovery runbook](storage-recovery.md), сохраните напечатанный backup ID и укажите его вместо `BACKUP_ID`:

```bash
uv run --locked python -m mlsecops.storage_backup
uv run --locked python -m mlsecops.kube_storage_migration --backup .runtime/backups/BACKUP_ID --trust .runtime/trusted-keys.json
```

Проверяются подпись, возраст <=24 h, policy, migration checksum, pinned PostgreSQL image, workspace, archive size/hash и native table-of-contents. Затем живая отдельная SQL session удерживает advisory lock. Это координация migration CLI, не защита от доверенного superuser.

Перед изменением target записывается подписанный `migration-intent.json` с digest backup, namespace UID, volume UID и spec digest. Database connection limit становится 0, существующие обычные client sessions завершаются, ledger проверяется повторно. Superuser и background workers этим лимитом не ограничены. `pg_isready` через admin socket не означает готовность обычных клиентов во время maintenance.

Импорт идёт в одной транзакции. После сравнения всех таблиц записывается подписанный `migration-receipt.json`, и только затем connection limit возвращается к -1. Итоговый статус всегда `storage-migrated-not-release-ready`, `release_ready=false`.

Если процесс прерван после commit, повтор той же команды проверяет прежний intent, archive и фактический ledger, записывает недостающий receipt и открывает клиентов **без повторного импорта**. Ошибка оставляет данные и maintenance для разбора. Не открывайте БД вручную и не удаляйте intent ради обхода проверки. После истечения разрешённых 24 h автоматический resume откажет; требуется отдельное решение оператора, а не подмена timestamp.

Повтор завершённого переноса не прерывает клиентов. Если уже появились новые rows, команда отказывает и не перезаписывает историю. Другие backup/namespace/volume, повреждённая подпись или частично изменённый ledger также запрещены. Rollback до отдельного cutover - продолжать исходный host SQL path; source не удаляется.

## Что доказывает qualification

- Настоящие signature/archive negatives и signed foreign-workspace fixture отказывают до доступа к target. Неверная причина не превращается в pass.
- Вторая migration получает отказ при удерживаемом native advisory lock; закрытие session освобождает lock.
- Fault injection происходит после настоящего native import, перед receipt. Ledger уже совпадает, receipt отсутствует, обычный ingestor действительно не подключается. Повтор завершается без второй копии.
- Signed receipt связывается с backup/intent/namespace/volume и запрещает ложный `release_ready`. Typed validation различает `true` и `1`.
- Publisher Pod читает train/validation; scorer Pod читает holdout и проверяет прежний signed evaluation, но не возвращает holdout labels. В Pods нет signer private keys или host kubeconfig.
- Из target читаются model и 1 000 validation examples. Отдельный offline Docker worker выполняет predictions; scores сравниваются с сохранёнными. Training image и verification image записываются отдельно: это compatibility check, не новый M06 reproducibility experiment.
- На заполненном target повторяются все SQL/TLS/API/network/persistence probes, включая замену PostgreSQL Pod. Итоговые ledger, volume identity, client certificates и исходная БД сверяются снова.

Native archive остаётся доверенным operator input: allowlisted TOC не делает чужой SQL безопасным. `kubectl exec` transport после `pg_restore` дочитывает stdin, сохраняя исходный exit status и строгую проверку stderr. Это предотвращает зависание, когда `pg_restore --list` читает только TOC большого archive и завершает чтение раньше отправителя. Timeout не увеличивается ради скрытия ошибки.

## Границы и следующий этап

Миграцией управляет host administrator. Read-only artifact Jobs не являются готовыми least-privilege controllers; нет automatic cutover, serving readiness, независимого approval или динамического revocation service. Не заявляются HA, daily/offsite RPO, production key custody, безопасность произвольных моделей или завершённый image vulnerability scan.

Следующий этап отделяет publisher/scorer orchestration от host admin, ограничивает создание worker Jobs и связывает реальные SQL identities с workflow. Общие M01-M23 и их пороги не меняются.

## Как объяснить на собеседовании

«Я перенёс ML-артефакты из собственного PostgreSQL в закрытый Kubernetes storage через подписанный snapshot. До импорта проверяются provenance и target identity, во время импорта обычные клиенты закрыты, а receipt выдаётся только после сравнения всех таблиц. Проверил прерывание после commit, безопасное продолжение без второй копии, права реальных Pods и совпадение 1 000 predictions. Это проверенный компонент лаборатории, не production cutover или полный disaster recovery».

Код: [migration](../mlsecops/kube_storage_migration.py), [artifact reader](../mlsecops/kube_artifact_reader.py), [role probe](../mlsecops/kube_artifact_probe.py), [qualification](../mlsecops/kube_storage_migration_qualification.py).
