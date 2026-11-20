# Проверка четырёх Kubernetes images и supplemental scans

Статус: реализация и controlled qualification. Настоящий hosted результат должен
быть отдельно привязан к commit SHA и terminal job; этот документ не утверждает,
что сканирование уже выполнено. Подпункт R1-B02 не закрывает общие B02/M18/R1.

## Назначение и границы

[Workflow](../../.github/workflows/kubernetes-supplemental.yml) запускает
[native driver](../../scripts/image_kubernetes_native.py) на public GitHub-hosted
Ubuntu 24.04. Он проверяет четыре закреплённых образа из
[независимого inventory](../../scripts/image_kubernetes_inventory.py):
`kube-apiserver`, `kube-controller-manager`, `kube-proxy`, `kube-scheduler`.
Manifest, image config и component name берутся из registry в коде. Произвольных
image references, package coordinates и workflow inputs нет.

SBOM (Software Bill of Materials, перечень компонентов) создаётся исходным Syft
1.54.1. Исходный Grype 0.120.1 проверяет полный SBOM, затем тот же scanner выполняет
28 дополнительных проверок фиксированных Go module coordinates. Версии и digest
обоих scanner images переиспользуются из `image_audit.py`. Дополнительные findings
присоединяются к исходным, включая High, Critical, Unknown и unfixed findings.
Исходные версии, SBOM и reports не переписываются.

Workflow не запускает Kubernetes, SQL, приложение или модель. Он не заменяет
проверку полного runtime/controller inventory из 14 targets. Поле
`validation_coverage` имеет знаменатель **4**, а не 14; `release_ready` всегда
`false`. Корректное срабатывание severity policy может дать
`validation_status=pass` вместе с `vulnerability_status=fail`.

## Предусловия и ответственность

Оператор интеграции отвечает за review, commit, запуск и проверку terminal jobs.
Требуются public repository `Abrakadabra124/trusted-mlsecops-platform`, обычный
GitHub-hosted runner Linux/X64 и чистый checkout точного `GITHUB_SHA`. Driver
проверяет HEAD и `git status --porcelain --untracked-files=all` до и после работы;
это дополняет fingerprint приложения проверкой изменений scripts и registry.
Runtime-файлы остаются в игнорируемой `.runtime`.

Actions закреплены теми же commit SHA, что в
[Go PURL observation](../../.github/workflows/go-purl-observation.yml).
Используются Python 3.12.15, uv 0.12.23 и существующий lock; установка выполняется
с `uv sync --locked --no-build`. Новых зависимостей нет. Preflight проверяет
native driver, alias registry, single-coordinate contract, batch/join, интеграцию
image auditor и image scope. Для каждого из четырёх новых production-модулей
отдельно обязательны не менее 95% statements и 95% branches, без skipped tests.

## Плейбук запуска и проверки

1. Интегрировать reviewed код в чистый commit. Push в
   `qualify/kubernetes-supplemental` автоматически запускает dedicated workflow;
   предусмотрен и `workflow_dispatch` без inputs. Не отправлять повторный запуск
   только из-за timeout наблюдателя. Сначала проверить состояние существующего run.
2. Убедиться, что preflight завершился успешно и каждый module coverage прошёл
   свой порог. Подробный test output остаётся приватным; наружу выходят только
   закрытые счётчики.
3. Native step создаёт эксклюзивную абсолютную директорию
   `.runtime/kubernetes-supplemental`, записывает owner по repository/run/attempt/job/SHA
   и создаёт `run` с закрытыми правами. Существующую директорию не переиспользует.
4. Driver скачивает два закреплённых scanner images и четыре закреплённых
   Kubernetes images. Он сверяет inspect, `docker image save` и identity архива,
   получает полный SBOM и вызывает `aliases.resolve` для каждой исходной inventory
   **до** дополнительного сканирования.
5. Одно обновление базы уязвимостей получает DB (database, база данных). Далее
   применяются неизменяемый snapshot её файлов, ограничение свежести 120 часов,
   проверка hash на старте, read-only cache и `--network none`. Доступ к сети есть
   только для pull и DB update. Перед originals и supplemental scans выполняются
   существующие положительные controls: PyPI urllib3, Go module и Go standard library.
6. Четыре исходных Grype reports проходят обычный `assess(..., diagnostic_only=True)`.
   `run_batch` вызывается один раз для полного набора из 28 coordinates. `join`
   повторяет проверку исходных байтов и добавляет все релевантные результаты.
   `coverage_valid` и `image_scope.coverage` проверяют только четыре exact targets.
7. Driver подтверждает отсутствие всех **40** scanner containers, повторно читает
   reports через `read_batch` внутри `join`, сверяет joined components, DB snapshot
   и исходники. В отдельном `always()` step cleanup повторяется независимо.
8. Принимать компонентную validation только по terminal success всех необходимых
   steps, closed JSON с ожидаемыми счётчиками и подтверждённому cleanup. High/Critical
   findings сохраняют vulnerability decision `fail`. Это не разрешение release.

## Cleanup и приватный replay

Cleanup разрешён только по 40 фиксированным host-created receipt locations:
восемь `<component>-sbom.cid` / `<component>-scan.cid`, `db-update.cid`,
`control-pypi.cid`, `control-module.cid`, `control-stdlib.cid` и 28
`kubernetes-modules/module-NN.cid`, где NN от 00 до 27.
Каждый CID должен быть полным 64-символьным hex ID. Driver сначала проверяет
наличие, при необходимости вызывает `docker rm -f <exact-ID>`, затем снова
подтверждает отсутствие. Ошибка одного receipt не отменяет проверку остальных.
Глобальные prune, удаление по имени, prefix-ID и wildcard не используются.

Каталоги `kubernetes-modules/output-NN` доступны scanner на запись. Любые CID-файлы
в них, а также неизвестные CID-файлы в других местах, **не дают полномочий на
cleanup**. Рекурсивного поиска CID нет. При попытке без CID, malformed ID,
недоступном Docker или неподтверждённом удалении cleanup остаётся `inconclusive`.
Маркер `batch.pending` означает, что batch не вернул полный проверенный набор:
известные CID всё равно очищаются, но отсутствие незаписанной попытки не утверждается.

На том же runner в течение job остаются архивы images, исходные SBOM/reports,
DB, controls, JSON/CycloneDX/trace всех модулей и joined components. Batch является
приватным объектом с путями и не сериализуется. Автоматический replay внутри того
же процесса заново читает сохранённые файлы после cleanup. Cleanup не удаляет эти
байты и повторяем при сохранённом ownership. Это временное хранение в одном job,
не долговременный архив и не транспорт между jobs.

Для повторного cleanup в том же авторизованном hosted job используется ровно:

```bash
.venv/bin/python -B -m scripts.image_kubernetes_native cleanup
```

Не запускать driver на локальной машине: hosted guard откажет до Docker-команд.
Не публиковать raw logs, DB, SBOM, архивы, model artifacts или directory paths.
Workflow не имеет upload-artifact step; он выводит только закрытый JSON.

## Диагностика, восстановление и эскалация

При отказе сначала читать публичные `phase`, `case_index`, `exception_label` и
cleanup counts. Phase имеет фиксированный словарь; index обозначает pull/image/control
или последнюю созданную module invocation directory, а не подтверждённый успешный scan.
Текст исключения и private trace в публичный результат не попадают.

- `source` / `setup`: проверить exact SHA, public hosted environment и чистый checkout.
  Не удалять чужую runtime directory для обхода ownership.
- `pull` / `inventory`: проверить закреплённый manifest/config, identity архива и полный
  inventory. Изменившиеся packages или reference требуют review registry; подстановка
  версии или изменяемого tag не является восстановлением.
- `database` / `controls`: сбой загрузки, stale DB или отрицательный detection control
  оставляют результат `inconclusive`. Не отключать freshness/hash checks и не менять
  DB посередине запуска. Повтор возможен как новая полная попытка после диагностики.
- `original` / `supplemental` / `join`: сохранить исходные findings и приватные байты
  на текущем runner. Не считать пустой report доказательством обработки пакета и не
  разрешать произвольный ERROR log. Изменение формата trace требует проверки pinned
  upstream protocol и reader; неизвестная operational error не является waiver.
- `cleanup` / `replay`: повторить cleanup в том же job, проверить каждый известный CID.
  При `batch.pending` или отсутствии receipt сохранить `inconclusive`, даже если все
  доступные CID уже отсутствуют. Не переписывать evidence, чтобы получить pass.

В controlled review найден и исправлен дефект: рекурсивное чтение CID могло
принять scanner-writable `output-NN/foreign.cid` за host authority. Регрессионный
тест сначала воспроизвёл нарушение, затем подтвердил, что exact allowlist не
передаёт чужой ID ни одной Docker-команде. Это результат controlled теста,
не утверждение о production-инциденте.

Из [предыдущего Go PURL observation](../evidence/go-purl-observation-2026-11-20.md)
сохранено требование абсолютных bind sources. Здесь run/cache/archive paths
абсолютные. Исторический scanner success с `not-a-version` также не принимается
как доказательство: произвольные coordinates отсутствуют в native интерфейсе.

Rollback изменения выполняется новым reviewed commit в коде. Нет развёрнутого
приложения или кластера, которые этот workflow мог бы откатить. Если исправление
требует изменения pin, inventory, правил ERROR, severity policy или coverage
знаменателя, передать вопрос владельцу интеграции и сохранить текущий отказ.

## Проверки и оставшиеся ограничения

[Controlled tests](../../scripts/image_kubernetes_native_qualification.py)
подменяют только внешние Docker/scanner и смежные integration boundaries;
настоящие safe reads, hashing, оригинальный assessor и detection controls выполняются.
Тесты проверяют command binding, полноту 4+28, сохранение original findings,
повторный join, mutation отказ, bounded public output и cleanup при failures.
Statement/branch coverage не заменяет review и настоящий hosted запуск.

Полный 14-target runtime audit, независимый M22, общий candidate-bound M18 и R1
остаются в исходном parent плане. Дата, commit, run ID, действительные counts и
финальный vulnerability decision добавляются только после реального выполнения.
