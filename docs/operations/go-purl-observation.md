# Runbook и playbook: наблюдение Go PURL scanner

## Назначение и границы

[Workflow](../../.github/workflows/go-purl-observation.yml) проверяет реальное
поведение закреплённого Grype для трёх фиксированных публичных packages.
JSON, CycloneDX JSON и trace создаются одним scanner invocation на package.
Это диагностика интерфейса перед [дополнительными Kubernetes scans](../evidence/kubernetes-module-mapping-2026-11-20.md),
а не production verifier и не разрешение выпуска.

Исполнитель - инженер проекта с доступом к Actions публичного репозитория.
Разрешён стандартный disposable `ubuntu-24.04` runner. Локальные Docker/WSL,
Kubernetes и SQL для этой процедуры не нужны. Нужен GitHub CLI с уже настроенным
входом; токен в команды, документы и сообщения не копируется.

## Playbook наблюдения

1. Проверить visibility и выбрать точный source commit, прошедший scoped review.
   Убедиться, что не выполняется предыдущая попытка того же эксперимента.
2. Запустить только dedicated branch `qualify/go-purl-observation`. Push нового
   проверенного commit в эту ветку запускает workflow; force push не нужен.
   Для повторения уже существующего run использовать точный ID после анализа
   причины отказа. Исторический отказ не удалять.
3. Проверить `headSha`, terminal conclusion и каждый step. Потеря соединения
   наблюдателя не означает остановку runner и не разрешает дублирующий запуск.
4. Прочитать закрытые projections основного и отдельного cleanup step. Ожидаемые
   labels: `control`, `streaming`, `malformed-version`; при всех scanner calls
   зарегистрированы четыре попытки с учётом `db-update`.
5. Сопоставить положительный control, DB identity/snapshot, JSON/CycloneDX
   bindings и реальные trace counters. Сохранить фактические findings и
   malformed-version outcome, включая неожиданный exit zero.
6. Убедиться, что cleanup подтвердил отсутствие каждого recorded container ID.
   Завершение Actions job само по себе не заменяет этот результат.

```powershell
gh repo view Abrakadabra124/trusted-mlsecops-platform --json nameWithOwner,visibility
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --branch qualify/go-purl-observation --limit 5 --json databaseId,headSha,status,conclusion,url
gh run view RUN_ID --repo Abrakadabra124/trusted-mlsecops-platform --json headSha,status,conclusion,jobs,url
```

`RUN_ID` заменить наблюдаемым числовым ID. Эти команды только читают состояние.
Повторный запуск через `gh run rerun RUN_ID` - отдельное изменяющее действие,
которое выполняется один раз после разбора и проверки source. Изменение workflow
проверяется новым run на новом commit, а не rerun старого source.

## Runbook отказа

| Наблюдение | Значение и следующий шаг |
|---|---|
| `cases=[]`, единственная attempted запись `db-update` | До регистрации control выполнение не дошло. Проверить `phase`, scanner return/exit и cleanup stage; контейнер мог ещё не быть создан |
| `scanner_failed=true` | Scanner helper выбросил исключение; `failure_code` содержит только фиксированный разрешённый код либо `other` |
| `scanner_returned=true`, ненулевой exit | Процесс вернул код. Не путать с отсутствием scanner invocation или доказательством успешного package matching |
| `cleanup_stage=cid_read`, `cid_present=false` | Нет подтверждённого ID. Не искать ресурс по похожему имени и не объявлять cleanup успешным |
| `cid_present=true`, `cid_valid=false` | Наличие файла не доказывает корректный полный container ID; автоматическое удаление запрещено |
| `cleanup_stage=list/remove/post_absence` | Не подтверждён конечный результат работы с записанным ID. Сохранить отказ и исследовать только собственную попытку |
| `db_same=false` или failed control | Эксперимент недействителен. Не заменять package version и не отключать DB freshness/hash checks |
| `matches=[]`, но нет parsed package или распознанного trace | Утверждать отсутствие findings или полноту обработки нельзя |
| Binding flags false | Реальная форма отчёта не соответствует ожидаемой. Проверить pinned presenter; не менять исходный inventory ради совпадения |

Scanner flags описывают текущий процесс. Отдельный cleanup invocation не
восстанавливает результат прежнего scanner вызова. Повторные cleanup checks
отражают последнюю попытку, а не её историю. Коды ошибок намеренно ограничены:
raw exceptions, IDs, пути и журналы не выводятся в публичный projection.

При отсутствии первичных diagnostics не приписывать отказ конкретной причине.
Добавить минимальный закрытый признак этапа, воспроизвести контролируемый дефект,
провести scoped review и выполнить одну следующую попытку. Нельзя отключать
изоляцию, принимать missing CID за success или использовать global prune.
Исходные raw reports остаются приватными на disposable runner; их постоянное
архивирование за пределами job этой процедурой не реализовано.

## Известная история и проверка исправления

[Run 44670568366](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44670568366)
на `0feb2637c03a2de6df2c1422a8af0cf6b7efb592` завершился failure:
`cases=[]`, cleanup `0/1` в обоих projections. Точная причина исходного
scanner/cleanup отказа не установлена; частичного успеха этому run не присвоено.

В offline regression обнаружено, что cleanup exception мог заменить исходное
исключение scanner. Диагностическое исправление сохраняет первое исключение и
добавляет закрытые stage/return/CID flags. Это исправление наблюдаемости,
не доказательство устранения причины первого native отказа.
Parent: 19 controlled tests pass за 0.916 s; настоящая функция `scanner`
проверена с заменой process boundary. YAML, Python, Ruff, четыре Bash blocks
и docs checks прошли; diagnostic diff получил scoped approval.

[Диагностический run 44672008908](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44672008908)
на `9c7eca66489c6f061e85bebae5978993c0a454c1` также завершился failure.
Зафиксированы `phase=db-update`, `scanner_returned=true`, exit `125`,
`scanner_failed=false`, `cid_present=false`, `cleanup_stage=cid_read`.
Это отказ запуска Docker до подтверждённого container ID; конкретная причина
пока не установлена. Cleanup остаётся `0/1`, scanning results отсутствуют.

Для `stage=observe` статус `observations_captured` подтверждает собранные
наблюдения, valid control, неизменную DB и проверенную очистку. Для
`stage=cleanup` он подтверждает только cleanup зарегистрированных попыток
и не подтверждает результаты сканирования. Полнота 28 дополнительных scans,
runtime coverage и полный B02/M18/R1 требуют отдельной реализации и приёмки.
