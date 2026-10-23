# Сквозной запуск: настоящий candidate и отказ выпуска

Scope: R1-B01, интеграция существующих компонентов. Это воспроизводимый **refusal path**, не завершение R1 и не замена M01-M23. Первый clean-checkout native запуск подтверждён ниже. Разрешённый production release остаётся заблокированным до полной assurance/approval; нельзя подменить её controlled fixtures.

## Что выполняет одна команда

1. До создания ресурсов проверяет Linux и GitHub-hosted окружение, чистый checkout, актуальный `data.lock` и новый state внутри `.runtime`. Дважды выполняет bootstrap и сравнивает identity/public-key/policy digests. Собирает pinned worker, поднимает отдельный PostgreSQL с mTLS и разделёнными SQL identities.
2. Создаёт прежние 20 000 synthetic rows, проверяет immutable source, quarantine, подписи, split и SQL publication. Один candidate действительно обучается в isolated worker; отдельный evaluator читает holdout с учётом persistent query budget. Сохраняются candidate/evaluation/model references.
3. Публикует signed proposal, а не approved release. Существующий admission действительно вызывает promotion и отклоняет candidate без assurance. Проверяется отсутствие записи разрешения после отказа. Required gates остаются M01-M23.
4. В отдельном qualification режиме запускает HTTP/ONNX inference **того же candidate**. Проверяет ограничения входа, audit, metrics, export, отзыв permission и HTTP 503. Это временный диагностический допуск, который не может служить production approval. Identity цепочка сравнивает candidate, evaluation, proposal, subject и model SHA-256.
5. Создаёт подписанный SQL backup, останавливает только собственную source БД, восстанавливает в новый workspace/container/volume. Проверяет тот же candidate и bytes модели, ledger, отдельные ключи, 1 000 ONNX predictions до/после и повторный restore без смены container. Это не полный M17: нет заявления о проверенном production RPO/RTO или полном release lifecycle.
6. В конце останавливает только две принадлежащие запуску БД, проверяет фактическое stopped state. Volumes и локальные evidence сохраняются; автоматического удаления или глобального prune нет.

## Prerequisites и запуск

Поддерживается только новый GitHub-hosted Ubuntu 24.04 amd64 runner. Нужны Docker Engine, Python 3.12.15, uv 0.12.23, Git, минимум 2 CPU / 6 GiB Docker memory и 8 GiB свободного диска; workflow закрепляет Python/uv и получает чистый checkout. Порты loopback 15439, 15440, 15446 должны быть свободны. Произвольный Linux/self-hosted runner не поддерживается: существующий output observer допускает только disposable hosted CI.

По текущему ограничению владельца **не запускать локальные Docker/WSL/Kubernetes/SQL**. Оператор с доступом Actions запускает ручной [r1-walkthrough.yml](../../.github/workflows/r1-walkthrough.yml), который каждый раз получает новый hosted runner и checkout:

```bash
gh workflow run r1-walkthrough.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --workflow r1-walkthrough.yml --limit 5
gh run view <run-id> --repo Abrakadabra124/trusted-mlsecops-platform --json headSha,status,conclusion,url
```

Выбрать ID именно своего dispatch и проверить `headSha`, а не считать любой последний зелёный run своим. Успех требует `status=completed`, `conclusion=success`, совпадения `headSha` с `source_revision` итогового отчёта и всех пяти stages pass. Первый подтверждённый commit: `af472f3781cfb4dbd5dfa8cb74cb8f2583d4deea`; текущий `main` не объявляется проверенным автоматически.

Сам workflow выполняет одну интеграционную команду после locked install и focused tests:

```bash
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m scripts.r1_walkthrough --confirm-disposable
```

Не копировать эту команду на рабочую машину и не выставлять вручную `GITHUB_ACTIONS`/`RUNNER_ENVIRONMENT`, чтобы обойти guard. Environment marker предотвращает ошибочный запуск, но сам по себе не является криптографическим доказательством доверия к runner. Повторный запуск использует новый hosted checkout; при диагностике внутри согласованного runner допустим новый ещё не существующий `--state .runtime/r1-next`. Старое состояние не удалять ради preflight.

## Подтверждённое исполнение

**Ограничение воспроизведения:** следующий [run 40007993642](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40007993642), commit `72071df3f0311fd65941df9edd823a23a29f8782`, attempt 1, завершился **failure**. Preflight/12 contracts и первые три stages прошли; inference-observation отказал, recovery не запускался, исходная БД остановлена. Причина пока не установлена. Этот отказ нельзя вычеркнуть первым pass или исправлением hosted guard. Новая диагностика читает только существующие private fault traces и печатает фиксированные поля без payload/identifiers; она не ослабляет privacy observer и не разрешает выпуск.

[Run 40006116831](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40006116831), attempt 1, job `120594341314`, commit `af472f3781cfb4dbd5dfa8cb74cb8f2583d4deea`: **success**. Цепочка выполнялась 2026-10-23 18:47:16-18:49:36 UTC. Отчёт подтвердил пять stages pass, 85 actual-candidate serving checks и отказ `release_assurance_required`.

- Candidate: `72654d118d73609c3c7ed60d8c742f9aac2e5e75a53ada4049375da89354bb53`.
- Evaluation: `589d723ea2265d8b4f2342d7803126547da87c965915796fe2348495f405b7de`.
- Model SHA-256: `09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f`.
- Subject SHA-256: `ff2a7ca5b1f527ee3444928e93fb75c289bc32f60bf150fa99d3b98b116f6463`.
- Restore: fresh volume, source offline, тот же candidate/model, 1 000 golden rows, max error **0.0**, restore-to-readback **4.535240 s**. Это один component trace, не полный M17 RTO/RPO.
- Повторный restore сохранил container; обе собственные БД действительно остановлены, volumes не удалены. Безопасный refusal остался после восстановления.

Первый [run 40006074198](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40006074198) на `6f4ea3a` остановился до infrastructure stage из-за Ruff format. Исправление только форматировало contract test; этот failure не скрыт повторным attempt.

После native проверки найден mismatch prerequisites: произвольный Linux проходил начало, но child observer позднее отклонял не-hosted среду. Guard перенесён в ранний preflight; RED подтвердил поздний отказ, затем 12 focused methods pass, 137/138 statements и 29/30 branches (96.67% branches). Проверка этого уточнения на hosted runner относится к финальному воспроизведению, не приписана предыдущему commit.

Во втором failure summary ошибочно оставалось `release_decision=not-evaluated`, хотя stage уже прошёл. RED воспроизвёл это и код теперь сохраняет `refused` сразу после настоящего admission. Эта поправка делает отчёт точным, но сама по себе не исправляет inference. `release_ready` и `r1_status` не меняются при ошибках.

## Как читать результат

Основной отчёт: `.runtime/r1-walkthrough/report.json`. Статус `pass` и exit 0 означают, что сквозная **диагностическая ветка с отказом** выполнена. При этом обязательны `r1_status=incomplete`, `release_ready=false`, `release_decision=refused`, `inference_mode=qualification-only-not-production`. Не называть этот exit code приёмкой R1.

Соседние stage JSON содержат evidence и связаны SHA-256 из summary. `source/` и `recovered/` содержат private credentials/keys; не публиковать всю `.runtime`, backup archive, raw logs или приватные audit receipts. Workflow печатает только summary, не архивирует state.

## Отказ и восстановление

- `walkthrough_preflight_rejected`: проверить, что запуск сделан workflow на GitHub-hosted Linux, затем чистоту checkout, source lock, отсутствие state и symlinks. Не применять `git reset --hard`, не менять expected digests и не отключать guard. Для source-lock mismatch см. [dependency runbook](tracking-troubleshooting.md#cp2-dependency-audit-остановил-сборку).
- `failed_stage=preparation`: проверить prerequisites, registry access, resource headroom и свободные порты. Не запускать повторно в старый state и не менять чужие resources. Повторять после установленной причины, на новом disposable runner.
- `data-training-evaluation` или `release-decision`: сохранить candidate и evaluation references; проверить pipeline rejection и [holdout budget](holdout-budget.md). Не сбрасывать бюджет, не подписывать фиктивный pass и не выдавать proposal за release.
- `inference-observation`: проверить [output observer](serving-output-troubleshooting.md), актуальность permission и proposal, источник audit evidence. Сохранить отказ, не переключать serving на permissive reader.
- `recovery`: source уже может быть остановлен. Backup сохраняется в `source/backups/`, его ID в `source/evidence/walkthrough-backup.json`. До действий прочитать [restore procedure](../storage-recovery.md); target может быть частичным. Не удалять единственную копию source/backup и не подключать её volume к другому image.
- `cleanup=ownership-or-stop-unconfirmed` либо `no-storage-receipt` после ошибки bootstrap: оператор сначала проверяет workspace/labels/marker/container ID. Отсутствующий receipt не доказывает отсутствие частично созданных ресурсов. Никаких broad Docker cleanup commands; disposable hosted runner уничтожается GitHub по завершении job.

При неуспехе workflow сохраняет fail. Восстановление БД не снимает отзыв и не выдаёт approval. Полные image/controller coverage, robustness/assurance, production release-reader, M13-M19/M22/M23 и clean-checkout R1 acceptance остаются отдельными обязательными блокерами, не future improvements.
