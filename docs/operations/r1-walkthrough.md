# Сквозной запуск: настоящий candidate и отказ выпуска

Scope: R1-B01, интеграция существующих компонентов. Это воспроизводимый **refusal path**, не завершение R1 и не замена M01-M23. Native результат пока не подтверждён. Разрешённый production release остаётся заблокированным до полной assurance/approval; нельзя подменить её controlled fixtures.

## Что выполняет одна команда

1. Проверяет Linux, чистый checkout, актуальный `data.lock` и новый state внутри `.runtime`. Дважды выполняет bootstrap и сравнивает identity/public-key/policy digests. Собирает pinned worker, поднимает отдельный PostgreSQL с mTLS и разделёнными SQL identities.
2. Создаёт прежние 20 000 synthetic rows, проверяет immutable source, quarantine, подписи, split и SQL publication. Один candidate действительно обучается в isolated worker; отдельный evaluator читает holdout с учётом persistent query budget. Сохраняются candidate/evaluation/model references.
3. Публикует signed proposal, а не approved release. Существующий admission действительно вызывает promotion и отклоняет candidate без assurance. Проверяется отсутствие записи разрешения после отказа. Required gates остаются M01-M23.
4. В отдельном qualification режиме запускает HTTP/ONNX inference **того же candidate**. Проверяет ограничения входа, audit, metrics, export, отзыв permission и HTTP 503. Это временный диагностический допуск, который не может служить production approval. Identity цепочка сравнивает candidate, evaluation, proposal, subject и model SHA-256.
5. Создаёт подписанный SQL backup, останавливает только собственную source БД, восстанавливает в новый workspace/container/volume. Проверяет тот же candidate и bytes модели, ledger, отдельные ключи, 1 000 ONNX predictions до/после и повторный restore без смены container. Это не полный M17: нет заявления о проверенном production RPO/RTO или полном release lifecycle.
6. В конце останавливает только две принадлежащие запуску БД, проверяет фактическое stopped state. Volumes и локальные evidence сохраняются; автоматического удаления или глобального prune нет.

## Prerequisites и запуск

Только отдельный disposable Linux amd64 host с Docker Engine, Python 3.12.15, uv 0.12.23, Git, минимум 2 CPU / 6 GiB Docker memory и 8 GiB свободного диска. Порты loopback 15439, 15440, 15446 должны быть свободны. Профиль не предназначен для рабочего SQL/production host.

По текущему ограничению владельца **не запускать локальные Docker/WSL/Kubernetes/SQL**. Проверять через ручной GitHub workflow [r1-walkthrough.yml](../../.github/workflows/r1-walkthrough.yml), который каждый раз получает новый hosted runner и checkout. Команды ниже предназначены для разрешённого disposable Linux, не для текущего рабочего компьютера:

```bash
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git
cd trusted-mlsecops-platform
git checkout <verified-commit>
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m scripts.r1_walkthrough --confirm-disposable
```

`<verified-commit>` берётся из опубликованного успешного native run, не из предположения о текущем `main`. Повторный запуск использует новый checkout или новый ещё не существующий `--state .runtime/r1-next`. Старое состояние не удалять ради прохождения preflight.

Для GitHub:

```bash
gh workflow run r1-walkthrough.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --workflow r1-walkthrough.yml
gh run view <run-id> --repo Abrakadabra124/trusted-mlsecops-platform
```

## Как читать результат

Основной отчёт: `.runtime/r1-walkthrough/report.json`. Статус `pass` и exit 0 означают, что сквозная **диагностическая ветка с отказом** выполнена. При этом обязательны `r1_status=incomplete`, `release_ready=false`, `release_decision=refused`, `inference_mode=qualification-only-not-production`. Не называть этот exit code приёмкой R1.

Соседние stage JSON содержат evidence и связаны SHA-256 из summary. `source/` и `recovered/` содержат private credentials/keys; не публиковать всю `.runtime`, backup archive, raw logs или приватные audit receipts. Workflow печатает только summary, не архивирует state.

## Отказ и восстановление

- `walkthrough_preflight_rejected`: проверить Linux, чистоту checkout, source lock, отсутствие state и symlinks. Не применять `git reset --hard`, не менять expected digests и не отключать guard. Для source-lock mismatch см. [dependency runbook](tracking-troubleshooting.md#cp2-dependency-audit-остановил-сборку).
- `failed_stage=preparation`: проверить prerequisites, registry access, resource headroom и свободные порты. Не запускать повторно в старый state и не менять чужие resources. Повторять после установленной причины, на новом disposable runner.
- `data-training-evaluation` или `release-decision`: сохранить candidate и evaluation references; проверить pipeline rejection и [holdout budget](holdout-budget.md). Не сбрасывать бюджет, не подписывать фиктивный pass и не выдавать proposal за release.
- `inference-observation`: проверить [output observer](serving-output-troubleshooting.md), актуальность permission и proposal, источник audit evidence. Сохранить отказ, не переключать serving на permissive reader.
- `recovery`: source уже может быть остановлен. Backup сохраняется в `source/backups/`, его ID в `source/evidence/walkthrough-backup.json`. До действий прочитать [restore procedure](../storage-recovery.md); target может быть частичным. Не удалять единственную копию source/backup и не подключать её volume к другому image.
- `cleanup=ownership-or-stop-unconfirmed` либо `no-storage-receipt` после ошибки bootstrap: оператор сначала проверяет workspace/labels/marker/container ID. Отсутствующий receipt не доказывает отсутствие частично созданных ресурсов. Никаких broad Docker cleanup commands; disposable hosted runner уничтожается GitHub по завершении job.

При неуспехе workflow сохраняет fail. Восстановление БД не снимает отзыв и не выдаёт approval. Полные image/controller coverage, robustness/assurance, production release-reader, M13-M19/M22/M23 и clean-checkout R1 acceptance остаются отдельными обязательными блокерами, не future improvements.
