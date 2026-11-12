# T29: sequence gap и отказ audit при здоровом ML

Статус: [sequence и actual outage на c57d3f6](../evidence/m23-outage-c57d3f6-2026-11-12.md)
прошли компонентную hosted-проверку, включая recovery и post-cleanup replay.
Это компонентные проверки [плана M23](../m23-acceptance-plan.md),
не общий gate M23/M18/R1. Ответственный - оператор disposable CI lab.
Реальные данные и production в этот профиль не входят.

## Зачем две проверки

Sequence campaign теряет событие между двумя полученными событиями либо хвост,
о котором известно только из heartbeat. Heartbeat - подписанный сигнал жизни
producer и его последнего номера события. Настоящий collector должен создать
подписанное `telemetry.gap` за 120 секунд, сохранить исходный таймер после restart
и восстановить health после доставки удержанного события. Delivery receipt -
подписанное подтверждение маршрутизации события, а не только HTTP 200.

Outage campaign продолжает реальные HTTP predictions существующего candidate
и пересчитывает свежие окна мониторинга по 1000 observations. Cilium policy
временно закрывает ingress только принадлежащего кампании audit collector.
Координатор проверяет audit refusal, неизменность SQL/CAS и доставку исходного
durable denial после удаления fault. CAS - хранилище, адресующее содержимое
по digest; неизменность проверяется вместе с SQL, не только по exit code.

Actual candidate пока не имеет полного assurance. Поэтому вызов promotion
только на нём мог бы отказать до проверки audit и дать ложное доказательство.
Отдельный controlled authorization/trust fixture проходит именно до настоящей
audit boundary, используя реальные SQL и collector. Он не выдаёт actual candidate
production approval; оба subject явно разделены в retained packet.

## Предварительные условия и воспроизведение

- Чистый checkout нужного commit и неизменённые `uv.lock`, image/tool pins.
- Только disposable GitHub-hosted Linux runner. Локальные infrastructure
  mutations этим ранбуком не разрешаются.
- Один owned run каждого workflow на выбранном commit; проверить отсутствие
  предыдущих активных запусков перед новым push/dispatch.
- Достаточный лимит CI job: sequence 6 минут, outage 30 минут. Это бюджеты
  runner, не изменение порогов delivery <=60 секунд и detection <=120 секунд.

Из корня чистого checkout доступны локальные pure проверки:

```powershell
uv sync --locked --no-build --python 3.12.15
uv run --locked python -B -W error -m unittest scripts.security_event_sequence_native_qualification scripts.security_outage_exchange_qualification scripts.security_outage_packet_qualification scripts.security_outage_probe_qualification scripts.kube_security_boundary_qualification scripts.kube_security_outage_operator_qualification scripts.kube_security_outage_native_qualification scripts.security_audit_boundary_probe_qualification
```

Hosted workflow
[Security contracts](../../.github/workflows/security-events-contracts.yml)
содержит отдельный job `sequence-gap`. Workflow
[healthy ML audit outage](../../.github/workflows/kubernetes-security-outage.yml)
запускается при изменении своих компонентов в рабочей ветке либо явно через
`workflow_dispatch`. Не запускать вручную второй экземпляр, если push уже создал
owned run. В GitHub CLI следует выбрать точный
ref; `SOURCE_REF` ниже заменяется опубликованной веткой с проверенным commit:

```text
gh workflow run kubernetes-security-outage.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref SOURCE_REF
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --workflow kubernetes-security-outage.yml --limit 5
gh run view RUN_ID --repo Abrakadabra124/trusted-mlsecops-platform
```

Проверить `headSha`, terminal conclusion и отдельные cleanup steps выбранного
run. Public `pass` компонента не разрешает release: `release_ready=false`,
full M23 остаётся `inconclusive` до отдельной общей приёмки.

## Диагностика и безопасное восстановление

На Windows проверочный checkout следует размещать в коротком пути, без вложенных
`.runtime/checkouts` внутри другого worktree. При clean-checkout проверке
`scipy.sparse.linalg` не импортировался: путь к `_arpacklib.cp312-win_amd64.pyd`
имел длину 261 символ. Перенос только owned test worktree в более короткий путь
восстановил импорт с тем же установленным wheel, без смены lockfile или версий.
Это наблюдённое ограничение Windows native-module loading. Сначала проверить
наличие файла и длину пути, затем выбрать короткий checkout и повторить
`python -c "import scipy.sparse.linalg"` и полные тесты. Не исправлять это
понижением SciPy, отключением проверок или изменением чужих окружений.

1. При `sequence_deadline_failed` или `sequence_packet_invalid` проверить
   конечный код и шаг, затем private observations в пределах owned runner.
   Различать heartbeat loss и sequence gap; нельзя обнулять ledger, начинать
   новый episode или увеличивать 120 секунд, чтобы получить pass.
2. При `security_green_probe_rejected` проверить фазу operator, непрерывность
   1000-row windows, независимый golden prediction, привязку bundle/model и
   актуальность `/monitoring`. Старый зелёный dashboard не заменяет свежий
   snapshot. Неполные данные означают отказ проверки.
3. При отказе promoter до audit boundary зафиксировать исходную причину.
   `release_assurance_required` не доказывает отказ из-за audit outage.
   Controlled probe принимает только один `promotion_audit_unavailable` и
   durable `promotion.denied` с reason `audit_unavailable`.
4. При failure или child exit координатор снимает только свою fault policy,
   затем очищает принадлежащие ему Job/ConfigMap и возвращает HTTP ownership.
   Не применять global prune, удаление namespace или чужих policies.
5. После recover сверить прежний event ID, envelope digest и новый receipt
   одновременно в producer outbox и collector. Не генерировать заменяющее
   событие и не удалять outbox, даже если повторная отправка кажется проще.
6. После кампании workflow останавливает только source SQL, чей marker и
   container identity подтверждены, удаляет только validated owned cluster
   и проверяет его отсутствие. Затем offline verifier перечитывает retained
   primary packet. Если cleanup не завершён, run не принят.

При несовпадении ownership, UID, registry, source/method hashes, SQL/CAS или
отсутствии исходных records остановить повторные mutations. Сохранить частные
артефакты и конечный failure code, передать оператору причину и точный run/commit.
Повтор допустим после устранения установленной причины в новом чистом запуске;
предыдущий failure остаётся частью истории, а не заменяется новым summary.

## Доказательства и ограничения

ConfigMap использует AtomicWriter symlinks. При монтировании bundle целиком
qualification fixtures с `Path(__file__).resolve()` искали policy и `uv.lock`
внутри `scripts`. Pure reproduction подтвердил оба отказа. Теперь immutable
ConfigMap содержит `source/<filename>`, а `/app/scripts` монтируется через
`subPath: source`: подкаталог содержит обычные файлы. Отдельный regression test
воспроизводит представление проекции и выполняет fixture setup/cleanup с запретом
SQL, socket connect/bind и дочерних процессов внутри fixture. Pod spec проверяет
точный subPath/items/readOnly; реальный bind mount прошёл CI на `c57d3f6`.
Нельзя подменять ROOT в production, обходить policy или считать этот pure test
доказательством полного native recovery. Ошибки operator и child теперь выводят
только проверенные public code locations до удаления Job.

При внутреннем review воспроизведены три controlled failure: заранее собранные
green windows принимались без временной связи с outage; повторный выход из
generator context терял неочищенную fault policy; replay не сравнивал commit
в lineage с source revision. Три отрицательных теста сначала падали и после
исправления проходят. Оператор теперь сохраняет wall/monotonic границы действий,
сопоставляет полные HTTP windows с подтверждённым outage, а UID inventory остаётся
до успешного повторного удаления. Чистые смежные проверки: 122 tests, 0 skips.
Это история тестового review, не production-инциденты и не независимый M22.

Sequence private packet хранит signed registry/events/receipts и snapshots;
outage private packet содержит HTTP observations, monitoring windows, bindings,
operator phases и hashes. Они остаются в `.runtime/evidence`, не выгружаются
как публичные GitHub artifacts. Console output ограничен конечными кодами,
метриками и digest. Из подписей не следует независимая аттестация часов observer.

Offline replay заново проверяет содержимое и связи. Его успешный результат
не доказывает неизменность инфраструктуры после завершения CI и не превращает
qualification permit в production authorization. Следующий обязательный этап -
общий source-bound inventory всех семи event types и проверка M23 как целого.
