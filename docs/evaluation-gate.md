# M07: независимая оценка synthetic local-cpu

## Контракт и границы

[Общий runner](../mlsecops/acceptance.py) выполняет [M07 campaign](../mlsecops/evaluation_gate.py), а не читает прежний pass JSON. Полный набор требований M01-M23 не меняется. Этот gate проверяет исходный synthetic-профиль M07, не принимает реальный источник без утверждённых label horizon, temporal/group split и business baseline. T09/T10 и более широкий T08 lifecycle не закрываются автоматически одним gate.

`pass` означает успешную новую лабораторную campaign. `fail` означает нарушенный контракт/качество; `inconclusive` означает недостаточные данные или недоступные prerequisites. Exit codes: 0/1/2 соответственно. Ни один M07 report сам по себе не разрешает promotion: `release_ready=false`, signed evaluation остаётся `unapproved`, M18 не реализован полностью.

## Что запускается

1. До SQL-побочных эффектов проверяются current image/source fingerprint, frozen evaluation policy, data.lock и host test sources. Старый итоговый файл сразу заменяется `inconclusive`.
2. Новый Python-процесс выполняет 48 controlled contracts. Они включают два настоящих fit/export с изменёнными validation features и неизменным train, spy фактического `StandardScaler.fit`, отказ принимать validation labels, sample-size boundaries, paired-bootstrap control с нулевым gain у constant scorer, подписи и holdout reservation. Skipped/expected-failure, неполный список, другое имя теста или другой scope не принимаются. Это controlled host evidence, не трасса из Kubernetes worker.
3. Создаётся новая owned campaign и отдельная PostgreSQL с TLS (Transport Layer Security, шифрование с проверкой идентичности). Native component выполняет настоящее обучение/предсказание, независимую подпись и 24 проверки SQL permissions, leakage, frozen policy, report substitution и read-back. Promoter читает только candidate/evaluation; curator отдельно проверяет все signed splits и отсутствие пересечения IDs. Это доверенный gate administrator, не доступ trainer к labels.
4. Gate заново читает подписанный report и content-addressed candidate. Восстанавливает training request из train и validation, сверяет его digest, source/revision/image, dataset/lineage, manifest, holdout digest/counts, frozen rules и метрики. Проверяет timestamps внутри текущей campaign; хороший старый report не годится для новой приёмки. Проверка подписи не доказывает честность скомпрометированного доверенного scorer.
5. Во второй отдельной БД выполняются 13 native budget checks: четыре процесса, 32 atomic slots, denial до labels/worker/signature, новый candidate и restart PostgreSQL. Бюджет этой БД исчерпывается намеренно. Её holdout bytes, policy, worker image и source должны совпасть с первой campaign. Рабочая БД не очищается и её budget не сбрасывается.
6. Проверяются неизменность source, Git revision, host contracts и data.lock. Сохраняются hashes компонентных reports и материалов. Оба owned SQL-контейнера останавливаются после проверки identity; volumes и evidence остаются. Только после успешного завершения cleanup публикуется итог. Никакого global prune или автоматической замены working state.

Итого при текущем составе: **86 cases = 48 controlled + 24 native evaluation + 13 native budget + 1 reconciliation**. Это группировка проверок, не 86 независимых экспериментов и не число всех subcases. Отдельные 13 unittest methods проверяют сам runner, включая отрицательные мутации и отказ cleanup при чужой identity.

## Почему так

Компонентные проверки уже существовали, но отдельный успешный JSON не связывал их с текущими material inputs. M07 повторяет операции и сверяет первичные артефакты вместо доверия к прошлому summary. SQL budget stress вынесен из рабочей БД, чтобы qualification не превращалась в destructive reset или лишение рабочего scorer всех попыток.

Fit только на training data и применение Pipeline следуют [рекомендациям scikit-learn о leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage). Численная метрика реализована через [average_precision_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html), а не trapezoidal PR area. Исходные lab thresholds сохранены. Paired IID intervals являются диагностикой синтетики, не доказательством business utility или независимости зависимых наблюдений.

## PB-07: воспроизведение

Prerequisites: Python 3.12.15/uv 0.12.23 по lockfile, Docker Linux/amd64, минимум 8 GiB свободного диска и свободные loopback ports 15451/15452. Не запускать две M07 campaigns параллельно на этих портах. Команды выполняются из корня этого репозитория.

Сначала read-only состояние:

```text
git status --short
docker ps --format "{{.Names}} {{.Ports}}"
uv run --locked python -c "from pathlib import Path; from mlsecops.contracts import read_json; path=Path('.runtime/evidence/M07.json'); value=read_json(path) if path.exists() else {}; print({name:value.get(name) for name in ('gate','status','started_at','finished_at','source_revision','residual_risks')})"
```

Следующие команды меняют локальное окружение: синхронизируют зависимости, создают/проверяют workspace и собирают image. Они не выдают release approval.

```text
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops build
uv run --locked python -m unittest scripts.evaluation_gate_qualification
uv run --locked python -m mlsecops.acceptance --gate M07 --state .runtime --output .runtime/evidence/M07.json
```

Последняя команда создаёт две новые disposable SQL-лаборатории и расходует их slots. Это **не read-only диагностика**, не production re-evaluation и не обход лимита рабочего holdout. Ожидание: exit 0, M07 pass, 86 cases, конкретные input digests; завершённые контейнеры остановлены. При ошибке не запускать бесконечный retry и не удалять старые volumes ради pass.

Evidence: `.runtime/evidence/M07.json`, `.runtime/evidence/evaluation-gate.json`, component JSON и локальные материалы в `.runtime/evaluation-gate/<campaign-id>/`. Raw artifacts/keys не публикуются. Storage CI выводит очищенный общий report; контроллерная Kubernetes/M20 регрессия идёт отдельно.

## RB-13: stale image или незавершённая campaign

**Симптом:** exit 2, `image_source_fingerprint_mismatch_rebuild_required`, missing prerequisites или оставшийся running marker. **Ответственный:** platform operator. Stale-image отказ фактически воспроизведён локально при разработке; аварийное отключение host не имитировалось.

1. Прочитать статус, reason, timestamps и source digest указанного output. Старый pass из другого пути не является текущим результатом.
2. Проверить Git diff и image provenance. При ожидаемом изменении исходников пересобрать image штатной командой; не редактировать fingerprint label вручную и не отключать проверку.
3. При занятых портах определить владельца по workspace/container labels. Не останавливать неизвестный процесс. Дождаться своей активной campaign, не запускать второй run поверх неё.
4. Если bootstrap прервался до получения валидного storage marker, ресурсы могут остаться для расследования. Использовать [storage procedure](storage-lab.md); не удалять неизвестный контейнер или volume. При валидном marker сверить `storage_bootstrap.validate(state)` и container_id, затем остановить только принадлежащий этой campaign контейнер. Автоматический unsafe cleanup частичного bootstrap не добавлен.
5. После устранения причины запустить новую campaign. Она получает новый ID, прежнее evidence сохраняется. Конечное состояние: новый текущий report, owned-контейнеры остановлены, оригинальный working state не менялся.

Rollback к прошлому коду не переносит прошлый pass на новые материалы. При изменении identity/source во время проверки результат недействителен, требуется review и повтор. Не применять rollback database snapshot для возврата budget.

В developer regression выявлен `qualification_failed:acceptance-dispatch-M07`: старый тест ожидал inconclusive от ещё не реализованного M07, но теперь запускал настоящую campaign. Исправлен выбор explicit missing-prerequisites state для M07, как для M03/M06/M20. Это проверка безопасного отказа dispatcher, не замена полного M07 на inconclusive: Storage CI по-прежнему обязан отдельно выполнить настоящий gate. Диагностика: сверить имя отказа и выбранный state; после исправления повторить developer suite и полный M07. Не менять ожидаемый статус всех gates на pass и не вырезать native campaign.

## RB-14: компонент зелёный, M07 не принимается

**Симптом:** `M07_component_cases_invalid`, `M07_material_binding_invalid`, `M07_stale_or_future_evidence`, budget/scope mismatch. При разработке negative tests выявили первоначальное принятие старого budget report и подменённого набора contract IDs; проверки ужесточены, отрицательные тесты проходят.

Сохранить candidate/evaluation refs, Git revision и точный reason. Сверить подпись/subject по [RB-12](operations/evaluation-troubleshooting.md), затем полный набор cases и timestamps. Не вручную дописывать отсутствующий case и не менять report на pass. Missing/failed/skipped компонент требует исправления причины и новой полной campaign; ошибку собственно gate воспроизводить controlled тестом до изменения кода. При корректной подписи и неверном subject эскалировать security reviewer.

Критерий восстановления: текущие primary materials согласованы, negative cases отвергаются, полный M07 повторён из clean checkout. CI image-audit failure и другие release blockers не исчезают от успешного M07.

## Проверенные результаты

Локальное evidence и clean-checkout CI публикуются в [STATUS](../STATUS.md). Coverage относится к модулю gate, не ко всей платформе и не является самостоятельным доказательством отсутствия уязвимостей.

На `51ddfef` [Storage CI 38142949998](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38142949998) воспроизвёл 86 M07 cases и 13 runner tests, 120/120 statements и 30/30 branches gate. [Developer CI 38142950002](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38142950002) подтвердил исправление старого dispatcher expectation. Локально после исправления повторены все 74 developer checks и M07, завершённый 2026-10-11T13:22:40Z. Source fingerprint `c133afe44dbb4706cf0b89ba27b0c781226e32635417fe5d5d22f8bfb22a3a86` совпал с CI. Это проверка поведения из clean checkout, не обещание одинаковых image digests или production readiness.
