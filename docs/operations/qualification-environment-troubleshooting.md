# PB-13 / RB-27 / RB-28: сбой qualification и ресурсы стенда

Сфера: owned synthetic lab и Actions этого репозитория. Ответственный: platform operator; security/ML reviewer, если изменился смысл проверки. Нельзя объявлять неуспешный запуск pass только потому, что следующая попытка прошла.

## PB-13: сохранить и локализовать отказ

Prerequisites: GitHub CLI с доступом к репозиторию, Docker для локальной диагностики, private `.runtime` directory. Команды не меняют remote jobs, SQL или Docker resources; перенаправление создаёт локальный закрытый log.

```powershell
git status --short
git rev-parse HEAD
gh run view 38163839413 --attempt 1 --json status,conclusion,jobs
gh run view 38163839413 --attempt 1 --log > .runtime/ci-36fa443-storage-attempt1.log
docker ps --format '{{.Names}} {{.Status}} {{.Ports}}'
docker network ls
```

Run ID здесь относится к конкретному инциденту 2026-10-11. Для нового инцидента сначала выбрать run **того же commit** через `gh run list`, не читать случайный latest как доказательство текущего кода. Logs могут содержать служебные пути и расширенное evidence, не публиковать весь файл. Сохранить attempt, SHA, failed step, reason code и timestamp.

Если отчёт говорит fail, не переименовывать его в environmental inconclusive без установленной причины. Если неизвестен actual отказ, это диагностический пробел, а не разрешение ослабить assertion. Runtime/SQL/security failures разбираются отдельно от статистического poisoning failure.

## RB-27: concurrent-over-budget-denied в M07

Первый [storage run, attempt 1](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38163839413/attempts/1) на `36fa443` завершился failure в 2026-10-11T18:29:47Z с `holdout_qualification_failed:concurrent-over-budget-denied`. Developer ONNX suite, реальные training/evaluation, SQL roles, material bundle и recovery steps этого run до M07 прошли. Следовательно, нельзя автоматически приписывать отказ проверке ONNX.

Этот assertion требует ровно один отказ с причиной holdout_budget_exhausted после конкурентных claims. Текущий public failure report не сохраняет фактическое содержимое refused receipts, поэтому точная первопричина **не установлена**. Connection/lock/resource contention остаются гипотезами; нельзя называть их исправленным root cause.

1. Сохранить исходный run/attempt и reason code. Не сбрасывать ledger, не увеличивать LIMIT, SQL timeouts или число разрешённых evaluations ради pass.
2. Проверить предшествующие steps и источник кода. При wrong image/source сначала соответствующий runbook, без повторного обучения над рабочим holdout.
3. Для различения устойчивого и единичного отказа допускается **один явно зафиксированный rerun** того же commit в новой ephemeral CI-лаборатории:

```powershell
gh run rerun 38163839413 --failed
```

Это изменяющее действие: выполняет failed job заново, создаёт новую лабораторию, расходует её тестовые slots. Здесь оно выполнено один раз. Не повторять автоматически до зелёного результата. Первая failure остаётся частью истории; outcome второго attempt указан в STATUS.

4. При повторе отказа остановить расширение функциональности и добавить bounded diagnostic evidence фактических отказов с тестом redaction; не выводить credentials/SQL exception body. Этот diagnostic improvement пока не реализован.
5. Даже при successful rerun оставить причину первого отказа unknown и учитывать нестабильность в окончательной приёмке. Совместимость нового ONNX-контракта и надёжность concurrent budget - разные свойства.

**Rollback:** rerun не возвращает потраченные slots и не разрешает новую оценку в рабочей БД. Сохранить failed candidate unapproved; не откатывать stricter model policy ради unrelated failure. Эскалация: повторяемый отказ, несогласованные receipts, дублирование slot или недоказанное состояние commit. [Бюджет и commit uncertainty](holdout-budget.md).

## RB-28: Docker address pool exhausted / неверный порядок bootstrap

Локальная попытка M07 на `36fa443` остановилась с `storage_docker_failed:network`. Адресная диагностика именно нового owned budget state воспроизвела ответ daemon: `all predefined address pools have been fully subnetted`. Это установленная локальная ресурсная причина, **не объяснение remote CI failure**. Quality-stage container после ownership-проверки остановлен штатным finally; данные, network и volume сохранены. На budget-stage volume мог быть создан до отказа network; это partial state, не готовая БД.

Read-only диагностика:

```powershell
docker network ls
docker ps -a --format '{{.ID}} {{.Names}} {{.Status}}'
docker network inspect <exact-network-id>
docker volume inspect <exact-volume-name>
```

Placeholders заменить только после привязки ресурса к workspace/config labels и конкретному private state. Имя `tml-*` само по себе не доказывает ownership. Сверить network Containers, остановленные и работающие контейнеры, IPAM subnet, volume и сохранённые recovery markers. Не печатать client files/keys.

Варианты устранения требуют отдельного scoped maintenance:

- Вывести из эксплуатации конкретные завершённые lab resources после проверки ownership, отсутствия потребителей и сохранения нужных evidence/volumes. Удаление network может сделать прежний storage marker невалидным; это не прозрачный restart.
- Спроектировать новый Docker address pool без пересечения с VPN/LAN/другими clusters, согласовать restart и impact. Не назначать случайный subnet и не менять daemon config во время работающих проектов.
- Выполнить проверку в чистой ephemeral CI-среде, явно сохранив локальное inconclusive. Это не исправление локального pool и не полноценный recovery drill.

В этом increment выбрано сохранить локальные ресурсы и использовать отдельный CI. Ни global prune, ни удаление чужих networks/volumes, ни перезапуск Docker не выполнялись. Прямая повторная create-попытка для конкретного нового budget network также получила отказ, новый network не появился. Автоматический cleanup/recovery не реализован.

Дополнительная встреченная ошибка подготовки: acceptance был вызван до bootstrap и сохранил inconclusive report в новом state. Последующий bootstrap правильно отказал `refusing_nonempty_unowned_workspace`. Не стирать этот каталог и не подделывать workspace.json. Создать отдельный действительно пустой **тестовый** state, сначала выполнить bootstrap, затем acceptance с output внутри него; исходный diagnostic report сохранить. Это не перенос/сброс рабочего holdout budget.

**Критерий восстановления:** свободный непересекающийся subnet, подтверждённые owned network/container/volume, штатный bootstrap с TLS/roles, полный новый M07 report и negative budget checks. Сейчас локальный rerun этого критерия не достиг. Эскалировать при неизвестном владельце resources, пересечении subnet или необходимости трогать рабочие clusters. Не превращать exit 2 в pass.
