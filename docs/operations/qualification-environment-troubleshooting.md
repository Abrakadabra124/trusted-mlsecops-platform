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

4. При повторе отказа остановить расширение функциональности и прочитать `diagnostics.holdout_concurrency`. Diagnostic improvement реализован после этого инцидента: bounded reason codes и claimed slots без credentials/SQL exception body. В старом attempt этого поля не было; новый код не восстанавливает утраченную причину задним числом.
5. Даже при successful rerun оставить причину первого отказа unknown и учитывать нестабильность в окончательной приёмке. Совместимость нового ONNX-контракта и надёжность concurrent budget - разные свойства.

**Rollback:** rerun не возвращает потраченные slots и не разрешает новую оценку в рабочей БД. Сохранить failed candidate unapproved; не откатывать stricter model policy ради unrelated failure. Эскалация: повторяемый отказ, несогласованные receipts, дублирование slot или недоказанное состояние commit. [Бюджет и commit uncertainty](holdout-budget.md).

### Текущий диагностический контракт

[holdout_diagnostics.py](../../mlsecops/holdout_diagnostics.py) принимает максимум 32 наблюдения для обработки; attempts=33 означает превышение лимита, а не точное число произвольного большого массива. В output остаются только номера slots в 1..32, количества фиксированных rejection codes и invalid receipts. `claimed_slots` обозначает заявления receipts, не доказанные reservations: при подмене digest именно проверка exact receipt отвергает результат. `complete=true` означает только получение ровно 32 ответов, **не gate pass**. `diagnostic_only=true` обязателен; release permission здесь не выдаётся.

Причины вне фиксированного allowlist, длинные строки, URL с credentials, newline injection и нестроковые причины становятся `unclassified_rejection`. Причина не включается в exception message, raw receipts не сохраняются в public report. Диагностика не делает новых SQL reads/claims, не читает labels и не возвращает slots. Явные context/digest/slot mismatch теперь отвергаются до принятия двух concurrent cases.

Read-only относительно БД, из корня репозитория:

```powershell
uv run --locked python -m unittest scripts.holdout_budget_qualification.BudgetDiagnosticContracts
uv run --locked python -c "from mlsecops.contracts import read_json,canonical; report=read_json('.runtime/evidence/M07.json'); print(canonical({'status':report['status'],'source_revision':report['source_revision'],'diagnostics':report.get('diagnostics',{})}).decode())"
```

Вторая команда предназначена для report, созданного **доверенным текущим runner**, не для произвольного присланного JSON: read_json сам по себе не санитизирует неизвестный файл. У старого report diagnostics отсутствует; это не отсутствие отказов. Сверить SHA, timestamps и exit code текущего процесса. M07 failure остаётся failure даже при корректной диагностике.

| Наблюдение | Следующее действие |
| --- | --- |
| holdout_budget_exhausted | Сверить 31 distinct slot после initial slot и полный gate; не reset ledger |
| storage_connection_rejected / unavailable | Проверить identity, TLS и доступность owned SQL; underlying SQLSTATE мог быть скрыт transport wrapper |
| storage_claim_rejected:55P03 | Исследовать contention/lock diagnostics; это lock_not_available, не автоматическое доказательство конкретного timeout |
| storage_claim_rejected:57014 | Query canceled; различить configured timeout и другое cancellation по закрытым серверным данным |
| storage_claim_rejected:40001 / 40P01 | Transaction serialization failure / deadlock; сохранить evidence, не refund и не бесконечный retry |
| unclassified_rejection / invalid_receipts | Не угадывать причину; ML/platform review и отдельный тест прежде расширения allowlist |

Названия SQLSTATE сверены с [PostgreSQL 18 error codes](https://www.postgresql.org/docs/18/errcodes-appendix.html) 2026-10-11. Эти значения классифицируют наблюдение, но сами по себе не устанавливают первопричину инцидента.

Проверка: 11 controlled methods, 31 statements/10 branches diagnostic module, 100% coverage. Включены redaction/oversized inputs, mixed known codes, невалидные receipts, exact context, propagation через native qualification/CLI/M07 и ownership-safe stop. Они воспроизводят сохранение наблюдений при инъецированных отказах, **не старый неизвестный CI fault**. Runtime failure до возврата списка, killed child, иной failure после этой стадии или ошибка cleanup могут не содержать эту диагностику; отсутствие поля не означает pass. Текущие native/CI outcomes см. [STATUS](../../STATUS.md).

**Rollback:** при ошибке нового formatter оставить gate fail/inconclusive, сохранить private evidence и исправить formatter отдельным reviewed patch. Не заменять безопасный report печатью raw receipts и не отключать check_claims. Политика budget и роли БД в этом increment не мигрируют.

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
