# M11: сквозная проверка trust lifecycle

Предыдущий принятый source: [M11 на5486596 /43132977638](../evidence/m11-observer-callers-2026-11-12.md)
прошёл146cases с двумя observer transitions, сверкой primary hashes/traces и
подтверждённой SQL/cluster cleanup. Controlled backup/recovery step также pass,
но full_M17 остаётся inconclusive. Предыдущий `aa276b2` fail в live-trust-outage
с `kube_serving_probe:trust-fault-response-contract` не повторился; его причина
не установлена. Новый pass не закрывает эту нестабильность.
Историческая [M11 campaign](../evidence/m11-trust-acceptance-2026-11-06.md) pass на
`21317fd`, CI42202109996, не заменяет текущую приёмку. Общий M18/R1 открыт.

## Назначение и границы

[Runner](../../mlsecops/trust_acceptance.py) выполняет свежую кампанию на одном source/image, готовит actual candidate proposal до проверок и фиксирует hashes методов, конфигурации и первичных отчётов. [Reconciler](../../mlsecops/trust_gate.py) проверяет candidate/model/subject bindings, полноту сценариев, типы результатов и сохранение независимых authority states. [Trace validator](../../mlsecops/trust_trace.py) пересчитывает ограничения времени по HTTP observations, а не доверяет заявленному `pass`.

Qualification permit разрешает только изолированную проверку настоящего candidate. Подписанные approval/rollback/signer positive controls используют отдельные явно обозначенные fixture releases. Они проверяют механизм и не подменяют независимые ML reports. Общий M18 по-прежнему требует M01-M17/M19-M23 для одного candidate, включая независимый M22; `release_ready` этого runner всегда false.

## Запуск только в disposable hosted CI

Prerequisites: разрешённый GitHub-hosted Linux runner, чистый checkout, pinned tools/image, собственный cluster и source SQL, подготовленный synthetic candidate. Текущие локальные Docker/WSL/Kubernetes/SQL запускать для этой процедуры запрещено. Использовать [существующий workflow](../../.github/workflows/kubernetes-serving.yml), который проверяет код, готовит стенд и всегда выполняет scoped cleanup.

```bash
uv run --locked python -m mlsecops.acceptance --gate M11 --state .runtime --output .runtime/evidence/M11.json
```

Последовательность: fresh prepare -> controlled contract inventory без skipped/expected-failure -> ordinary CLI expiry/replay/rollback -> actual candidate clock/cache/outage/blackhole/policy/root/model/key -> signed SQL rotation history -> live смена publisher/assessor/approver -> сверка source и первичных traces -> report. Полный backup/restore затем остаётся отдельным workflow step.

Обязательные наблюдения:

- Actual production promotion отказан без assurance; candidate/model/subject остаются привязаны к одной подготовленной proposal.
- При outage/blackhole нет ML responses после 60 s, trace продолжается за границу 60 s. Для всех trust faults требуются минимум два 503 и отсутствие последующего 200.
- При signed approval expiry были успешные ответы до срока, первый отказ в пределах двух секунд до expiry, отказ сохраняется после expiry. Просроченный promotion retry не пишет журнал.
- Действующий старый sequence отвергается именно как sequence conflict. Старый signed trust document ещё valid, но отвергается как version replay.
- Negative clock/cache injection даёт ожидаемые причины, очищает cache/Reader и блокирует прежний экземпляр. Это dependency injection, не изменение OS clocks.
- Отдельные model/key authorities сохраняют независимые CA/storage/history; отзыв одной не меняет другую. Cold Readers возвращают точные причины отзыва до worker startup.
- Разрешённый whole-bundle rollback сохраняет subject/proposal целевого комплекта, не смешивает модели. Неверные history links и revoked target отклоняются.
- После смены release signer старый экземпляр остаётся fenced; новый release без M22 не записывается; новый worker активируется явно.

## Диагностика и восстановление

| Симптом | Проверка и действие |
| --- | --- |
| Exit 2 / inconclusive | Проверить prerequisites и тип runner. Не переносить запуск на запрещённый локальный runtime |
| `M11_contracts_failed` / incomplete | Проверить inventory, import errors, skips и expected failures. Отсутствующий test module не считается выполненным |
| `M11_native_binding` | Сверить source/image/candidate/model/subject и последний stage. Не заменять mismatch редактированием готового report |
| `M11_trace_invalid` | Проверить timestamps/statuses, late 200, повторную activation, границу lease и полноту trace. Не увеличивать grace period ради pass |
| `M11_descriptor_or_time_order` | Proposal должна предшествовать checks, timestamps должны иметь timezone и правильный порядок. Новый proposal требует новой кампании |
| `M11_inputs_changed` | Source или метод изменился во время проверки. Завершить cleanup и запустить новую кампанию из чистого checkout |
| Native runtime failure | Сохранить private evidence, определить failed stage, исправить причину и повторить. Historical green не закрывает текущий отказ |
| `trust-fault-response-*` | Сверить последний `live-trust-*` stage и конечный код. `overloaded` означает HTTP429/overloaded, `client-limited` означает HTTP429/client_limited; `http-200` или `http-503` означает неверный контракт соответствующего ответа; прочие `http-N` означают неожиданный статус. `other` сохраняет неопределённость. Диагностика не выводит body, request ID или неизвестный error code |
| Cleanup failure | Сверить ownership и конкретные IDs. Не выполнять global prune; без подтверждённой очистки campaign не принимается |

До запуска reporter заменяет прежний итог на `inconclusive`. Ошибка не оставляет прежний success текущим результатом. Raw logs, keys и credentials остаются в private state. После failure сохранять первичные материалы и проверять остановку source SQL, удаление собственного cluster и созданных signer targets/workers. При неизвестной причине, чужом ownership или нехватке независимого approval остановить activation и передать диагностику владельцу.

Критерий принятия: terminal success job, M11 `pass`, совпадающие hashes/current source, пройденные negative cases и подтверждённая очистка. Это проверка M11 механизма; готовность R1 требует оставшейся общей приёмки.

Для ошибки response contract: сначала сохранить stage/code и проверить cleanup,
затем воспроизвести соответствующий отказ с ограниченной диагностикой. Не
засчитывать429 как503, не менять60s deadline, не сбрасывать trust history и не
повторять старую кампанию с утверждением об исправлении без установленной причины.
Finite-классификатор проверен отрицательными unit cases с приватным canary.
Hosted5486596 прошёл, но failure branch новой диагностики там не исполнялась;
причина предыдущего неожиданного ответа остаётся неизвестной.

## Общий отказ без точного кода в ad53e3e

[Run43146213251](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43146213251)
дошёл до `actual-candidate-policy-change` и завершился с exit1. M11 report сохранил
только `runtime verification rejected`; SQL/cluster cleanup подтверждён. Срок permit
и другие возможные причины пока не установлены этим отчётом. Подробная временная
линия находится в [evidence](../evidence/serving-handoff-2026-11-12.md).

Следующий increment сохраняет в `diagnostics.runtime_failure` только проверенные
`exception`, `source_file`, `source_line`. Используется существующий ограниченный
валидатор source location: путь только внутри известных scripts/mlsecops, без
абсолютного каталога, текста исключения, locals или payload. Некорректная location
заменяется `other/unknown/0`; исходный fail/inconclusive и exit code сохраняются.
Unit tests воспроизводят настоящий отказ `candidate_trust_window` до инфраструктуры,
а также приватный canary и некорректную location. Это проверка диагностики, а не
доказательство причины старого hosted отказа.

Оператор повторяет существующий hosted workflow на новом source, сверяет location
с файлом именно этого commit и последним stage, затем проверяет owned cleanup.
Если source location неизвестна, требуется дополнительное приватное расследование;
общий отказ не становится pass. Не продлевать permit и не менять180s preflight guard,
HTTP deadlines или пороги M11 на основании одного предположения.

## Progress parser и startup refusal

Наd66b12a [M11 run43155792337](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43155792337)
закончился fail: runtime location scripts/kube_serving_faults.py:31, stage
controlled live-trust-policy-change. Native campaign04:38:41.850045 ->04:51:33.064321
UTC; это не общий timeout. Stop owned SQL и Remove owned cluster success,
следующий backup шаг не принят. Raw private Pod log не опубликован, конкретный
startup cause из этого run не получен.

При проверке source найден воспроизводимый дефект протокола: kube_serving_probe
может вывести уже валидированное `serving-startup-refused` перед terminal fail,
но progress parser ожидал только trust-fault или status pass/fail. Unit test
повторил тот же отказ schema. Это установленный дефект диагностики; без исходного
Pod log он не считается доказательством конкретной причины native startup.

Parser теперь распознаёт только существующий finite startup schema с bounded
phase/worker_phase/cause. Сообщение разрешено один раз до coordination phases и
не считается фазой. После него запрещены ready/denied и pass; unknown fields,
private canary, duplicate и ошибочный порядок по-прежнему отклоняются. Host ждёт
завершения owned Job, существующий finite diagnostic export показывает startup
record и terminal failure code, затем выполняется прежний UID-bound cleanup.
Это не retry, не разрешение inference и не увеличение lease/timeout.

Порядок диагностики для оператора disposable hosted стенда:

1. Подтвердить terminal run и оба cleanup steps через `gh run view`.
2. Сопоставить source_revision/fingerprint и последнюю native stage с M11 report.
3. После публикации correction выполнить существующий kubernetes-serving.yml
   playbook. Найти finite serving-startup-refused и последующий probe_failure.
4. Сверить cause с Reader/worker boundary в том же source. Исправлять подтверждённую
   причину, сохраняя60s fail-closed,600s permit и180s preflight.
5. При unknown cause или незавершённой очистке оставить M11 fail/inconclusive;
   не публиковать raw log, не допускать release и не повторять run без нового
   диагностического или причинного изменения.

Local46tests без skips проверили protocol и native harness. Parser/coordinator
96/97statements,51/52branches в focused suite; skipped assertions не используются.
Поддельный successful report после startup refusal и coordinator acknowledgement
при таком отказе запрещены. Свежий hosted результат correction ещё pending.

## Expiry и передача HTTP владельца

[Run43162491549](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43162491549),
source451c713908e04db50f2ea6e20abb181952ad4906, job130996687187: M11 fail,
05:39:16.955328 ->05:44:14.609934 UTC. SQL stop и owned cluster cleanup success.
Последовательность finite observations: controlled-after-approval05:42:31.061148,
signed-approval-expiry05:43:24.431970, startup refusal05:43:49.081212.
Диагностика Reader: `release_expired_or_future_document`, worker_phase=none.
Это конкретный новый отказ; причина старого d66b12a им не устанавливается.

Контекст: controlled approval задаётся на90s. Общий coordinator вернул постоянный
HTTP после положительного probe, затем снова остановил его перед expiry probe.
Короткое разрешение продолжало стареть во время этих переходов. Отказ Reader
сохранил fail-closed, но не является требуемым наблюдением перехода200->503 в
уже работающем процессе. M11 нельзя принимать по такому cold refusal.

Исправленный playbook `scripts.kube_approval_campaign.qualify` использует один
existing owner transfer для пары отдельных Jobs. После подтверждённого suspend
подписывается прежнее90s approval, выполняется admission, затем первый настоящий
probe с positive inference и worker-loss check, затем отдельный expiry probe.
Каждый Job сохраняет собственный cleanup с подтверждением отсутствия Pods.
Постоянный owner возвращается один раз после обоих probes; fresh heartbeat,
Pod/pin/permissions/receipt проверки общего coordinator сохраняются. Оба отчёта
сохраняются отдельно, одна проверка не копируется вместо другой.

После возврата выполняются прежние cold-start отказ, запрещённый retry без записи,
явный controlled renewal и следующие trust tests.90s approval,60s fail-closed,
120s telemetry/return,600s permit и30min M11 budget не увеличены. Ошибка второго
probe не приводит к автоматическому re-sign/retry; она остаётся ошибкой после
безопасного возврата владельца. Actual candidate не получает controlled approval.

Проверка без инфраструктуры: `python -W error -m unittest
scripts.kube_approval_campaign_qualification scripts.kube_approval_fixture_qualification
scripts.kube_serving_expiry_qualification`. Сверить после нового hosted run обе
отдельные positive/expiry observations, trace до и после настоящего expires_at,
negative cold/retry, ownership return и terminal cleanup. Пока этого нет,
коррекция локально проверена, M11 на новом source не принят.

## Полное время возврата владельца

Симптом: fresh heartbeat получен вовремя, но заключительное чтение Pod UID или
проверка независимых receipts заканчивается после120s. Старое измерение до этих
операций могло сообщить успех и занизить return_seconds/elapsed_seconds.
Это воспроизведено управляемыми часами в unit tests, не объявляется наблюдавшимся
production-инцидентом. Аналогичная граница найдена при change_configuration.

Ответственный оператор hosted qualification выполняет следующую проверку:

1. Запустить отрицательные проверки без инфраструктуры:

   ```bash
   uv run --locked python -W error -m unittest scripts.kube_owned_probe_qualification scripts.kube_serving_handoff_native_qualification scripts.kube_serving_reconfigure_native_qualification
   ```

2. Подтвердить, что heartbeat до deadline не разрешает успех после позднего
   UID/receipt readback. Новый report измеряет время после всех этих проверок;
   завершение ровно на120s принимается, после120s отвергается.
3. При owned_probe_return_binding или kube_serving_configuration_binding
   сопоставить finite stage, source и UID. Не редактировать report и не увеличивать
   срок. Исходная ошибка probe остаётся ошибкой при своевременном возврате owner.
4. Дождаться terminal CI, SQL stop и удаления только owned cluster с readback.
   При неопределённом ownership не повторять bootstrap и не выполнять global prune.
5. После причинного исправления запустить прежние M11/Primary workflows на одном
   новом commit. До source-bound native результата коррекция остаётся локально
   проверенной; предыдущие green runs её не принимают.

Локальный результат:59affected tests/0skips. Общий coordinator имеет55statements
и16branches, все покрыты focused suite. Native проверка исправления pending.

## Отказ Kubernetes при ротации корня

[M11 run43246221504](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43246221504),
sourceff06fa0: fail. Native campaign15:21:29.645891 ->15:34:41.271662 UTC;
planned-authority-root-rotation15:33:07.323734. Диагностика сохранила Rejected,
mlsecops/cluster.py:74, но потеряла уже классифицированные operation/category.
SQL stop и owned cluster cleanup success. Точная причина runtime отказа неизвестна.
Продвижение после signed-approval-expiry не является полной приёмкой expiry/M11:
итоговый gate не сформировал положительные cases/metrics.

Исправлена диагностика: M11 экспортирует kubernetes_request только для точного
конечного множества операций и категорий. Любой посторонний suffix/exception type,
stderr, command arguments и private canary не попадают в это поле. Отдельные
stages preflight/commit/observer/completed показывают продвижение ротации;
stage обозначает начало фазы, кроме completed. Без completed переход не принят.

1. Выполнить `python -W error -m unittest scripts.cluster_command_qualification
   scripts.trust_acceptance_qualification scripts.kube_root_rotation_qualification`.
   Локально22tests pass/0skips; проверены redaction и отсутствие completed после
   неудачного observer transition. Это тест диагностики, не runtime correction.
2. После terminal предыдущего CI и подтверждённой cleanup запустить прежний M11
   workflow на новом source. Сопоставить последнюю root stage, finite operation и
   category с исходным кодом. Не публиковать raw logs, SQL или credential paths.
3. При unknown сохранить неопределённость и исследовать конкретную операцию.
   При timeout не увеличивать120s transition,60s serving lease или общий30min budget.
4. Если commit ротации прошёл, нельзя откатывать retired root ради green.
   Убедиться в остановке принадлежащих запуску ресурсов и сохранении private evidence.
   Не выполнять повторный bootstrap поверх неизвестного ownership.
5. Только после причинного исправления, свежего source-bound M11 pass и cleanup
   создавать milestone prerelease. Пока M11 fail, релиз не публиковать.

### Уточнение create forbidden наf85140e

[Run43250406895](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43250406895),
job131294342513: M11 fail, SQL stop и owned cluster cleanup success. Source
f85140e8bcfb4f556d3ce36c33313c7f5066fc60, native15:44:35.629473 ->16:00:17.458988 UTC.
Root preflight15:58:19.050075, commit phase15:58:41.700633,
observer phase15:58:53.500798 и completed15:59:15.764189 UTC.
После завершения ротации Kubernetes отказал `create:forbidden`.
Это не доказательство ошибки чтения outbox или незавершённой ротации.
M11 cases/metrics пусты, итоговый gate не принят.

Следующая диагностика сохраняет прежний общий отказ и добавляет только finite
категории quota/admission/rbac/pod_security. Перед созданием probe resource
печатаются тип ConfigMap/Job и его индекс. Для распознанной счётной квоты отдельный
record kubernetes-quota-refused содержит только разрешённый вид ресурса и целые
requested/used/limited. Имена ресурсов, namespace, пользователь и raw stderr
не экспортируются; неизвестные форматы остаются без выдуманных значений.

Оператор сопоставляет последний serving-probe-create с category. При quota
сверяет фактический peak с декларацией storage-budget и подтверждённой очисткой
предыдущих ресурсов; нельзя автоматически повышать budget или удалять чужие
объекты. При admission/RBAC сверяет конкретный manifest и разрешённую роль,
сохраняя запреты credential/command/privilege. После исправления необходим тот же
полный M11 с cleanup, а не только успешное создание одного Job.

### Probe bundle в прежнем бюджете ConfigMap

Контролируемый harness воспроизвёл недостаток квоты: при трёх постоянных картах
(namespace CA, HTTP config, rotated observer) прежние две карты probe требуют
пятого объекта, а count/configmaps=4. Privacy/CLI probe добавлял ещё карту кода.
Связь подтверждена [M11 run43255736643](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43255736643)
на source cf019804ae1e0a154bac0ba9e67e0ec26d1c8e72: после root-rotation-completed
создание ConfigMap с index1 получило category quota и count/configmaps
requested1/used4/limited4. Это доказывает превышение квоты, но не полный inventory
постоянных объектов. Native campaign16:14:18.765150 ->16:29:29.914562 UTC,
cases/metrics пусты; SQL stop и owned cluster cleanup success.

Подготовлено объединение временных данных в одну immutable ConfigMap на Job.
config.json и request.json читаются по прежним read-only subPath. Для privacy/CLI
Python-файлы находятся в том же объекте, но projection items в /app/scripts
выбирает только исходные .py. Source annotation сохраняет hash Python bundle;
JSON-конфигурации не проецируются в каталог кода. Суммарный размер ключей/значений
ограничен1MiB до первого create; никаких credentials в ConfigMap не добавлено.

Квота остаётся4: три постоянных объекта плюс один временный bundle. Объект имеет
уникальное имя и прежние ownership labels; cleanup удаляет только зарегистрированные
Job и bundle после проверки UID. Serving ownership, отдельные Secret/mounts,
worker isolation и все deadlines остаются прежними. Если реальный inventory
отличается, это требует отдельной диагностики, а не удаления неизвестных объектов.

Проверка: прежний harness с ограничением реальной quota сначала отказал при втором
create; после объединения прошли обычные, privacy/CLI, failed/foreign-UID scenarios.
Oversized bundle отказан до API writes. Общий local suite38tests/0skips pass.
Native correction и завершение M11 pending.

### Ранний отказ Primary наcf01980

[Run43255745071](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43255745071),
job131313355091: отказ16:13:47 UTC до первого native case/stage. Source SQL stop и
owned cluster cleanup success. Имеющийся report содержит только fail/release_ready=false;
причина не установлена и не отождествляется с M11 create:forbidden.

Failure report Primary теперь использует существующие validated source location
и finite Kubernetes classification. Исключение, абсолютные пути и private payload
не печатаются. При следующем отказе оператор сопоставляет относительный файл/строку
и категорию операции с тем же source; при unknown сохраняет неопределённость.
Report прежнего успеха по-прежнему заменяется до запуска, error/interrupt не
создают ложный pass. Native объяснение этого раннего отказа пока pending.
