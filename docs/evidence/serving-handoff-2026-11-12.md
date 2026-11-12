# Сериализованное владение serving identity

Компонент handoff проверен на реальном hosted Kubernetes. Полные M11/M23/M18
и R1 не приняты. Candidate/load/monitoring/privacy получили identity wiring,
но их новые сквозные проверки ещё не завершены успешно.

## Принятый результат на39e0159

- Source: `39e0159672efc1d14d628e130553d4d853488f97`.
- Runtime fingerprint: `210f14a8bddb4a4e04d280f1ce20d5ee5dc6bc1f5908e221da574c4dc248fa84`.
- [Primary43143770511](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43143770511),
  job130936696110: terminal success, включая SQL stop и owned cluster deletion/readback.
- Report:2026-11-12T02:49:56.923589Z ->03:01:25.056946Z.
-20 aggregate checks; внутри handoff22 обычных HTTP checks и10 checks
  восстановленного Deployment. Эти числа описывают разные вложенные проверки,
  а не новые acceptance gates.

| Проверка | Наблюдение |
|---|---|
| Возврат исходного Deployment и нового heartbeat |53.747003s, bound120s |
| Serving heartbeat после завершения временного HTTP owner |9 ->11 |
| Независимые receipts новых identity.denied |2 |
| Сохранение audit pin/permissions/outbox prefix |pass |
| Реальный ONNX inference после возврата |3предсказания, max golden error7.583384781240099e-08 |
| Подмена модели/bundle |exact binding checks pass |
| Отказы HTTP |401/422/413 проверены |
| Последующий revocation |refusal в том же восстановленном Pod |
| Завершение service |service_pods0, worker_jobs0, audit state retained |
| Допуск actual candidate |не получен; full_M10=inconclusive, release_ready=false |

Старый HTTP Pod `255b70c3-5e2c-4eff-8a1b-16b7c02d6ad7` заменён на
`551b3870-3a35-40e9-aa76-6657e2c396d7`. Между ними работал существующий реальный
qualification HTTP CLI. Это сериализованные владельцы одной serving identity,
не один непрерывно работающий PID и не доказательство multi-node HA.

Переход проверяет отсутствие предыдущего HTTP/worker перед следующим владельцем.
Trust observer находится в том же namespace, но имеет отдельные ключи/outbox.
Он исключается из inventory только после проверки audit state, Deployment/ReplicaSet
ownership, UID, spec/image, containerID/restartCount и повторного readback.
Исключения по одному label/имени нет. Граница - один trusted operator; отдельная
распределённая блокировка нескольких operators не реализована.

## Отказы, которые сохранены в истории

| Source/run | Результат и вывод |
|---|---|
|6d202b5 /[43139537422](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43139537422) |Первый handoff pass:44.281584s, heartbeat9->11,2receipts. Он ещё не проверял все orphaned Pods. |
|6d202b5 /[43139535579](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43139535579) |Observer45s recovery timeout:outbox2events/1receipt, collector1/1,3failed checks. Причина остаётся неизвестной. |
|86a6327 /[43141312875](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43141312875) |Handoff fail. Новое требование пустого namespace также считало legitimate trust observer; исправлена граница inventory. SQL/cluster cleanup pass. |
|86a6327 /[43141310976](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43141310976) |Linux unit выявил ошибку классификации flock conflict через общий path guard. Native job pass. Исправление сохраняет конечный security_store_busy непосредственно у flock. |
|39e0159 /[43143768272](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43143768272) |Store/lock и handoff tests pass; contracts job fail на старой load-fixture с пустым config. Native job130936684671 pass:25/37/15/46checks. Общий workflow остаётся failure. |
|39e0159 /[43143774536](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43143774536) |M11 fail до actual-candidate inference: approval истекло до reader в expiry probe. SQL/cluster cleanup pass, backup не принят. |

M11 дошёл до `controlled-after-approval` в02:54:30.874629Z, затем
`signed-approval-expiry` в02:55:14.818905Z. Reader в02:55:44.970128Z корректно
отказал с `release_expired_or_future_document`. Нет доказательства активного
перехода через expiry в этом запуске, поэтому его нельзя засчитать как M11 pass.
После этого подготовлена оптимизация повторной audit validation внутри одного
preflight; после Job состояние читается заново.90s approval, bounds expiry,
delivery и telemetry не изменены.

Последующий [M1143146213251](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43146213251)
на ad53e3e прошёл прежнюю точку отказа: после signed-approval-expiry03:17:19.421202Z
дошёл до unexpired-previous-sequence03:19:18.526670Z, затем до actual candidate.
Последний stage `actual-candidate-policy-change` в03:37:36.068734Z, общий отказ
в03:38:32.338942Z. M11 report:fail/exit1, cases=[], metrics={}, причина только
`M11 runtime verification rejected`. Он не доказывает конкретную первопричину
последнего отказа. SQL stop и cluster deletion с readback прошли; signer и backup
этапы не приняты. Нужна ограниченная диагностика этого отказа перед следующим
M11 acceptance. Увеличение срока permit или ослабление gates не выполнялось.

## Локальная проверка и границы

Последующий source `ad53e3e658f42fcf432dc586a4f789d801fc85f4`, fingerprint
`35298d26beb5917e3354c52a256315c089433f052eb48316822aad3d44a76a48`, прошёл
[primary43146216798](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43146216798).
Report03:11:47.937712-03:25:21.909515UTC:20aggregate checks; handoff63.797179s,
heartbeat10->12,2independent identity receipts,22legacy HTTP и10restored checks.
Максимальная ONNX/golden ошибка7.583387712228884e-08. Независимое чтение cleanup
подтвердило0service Pods/0worker Jobs и сохранённый audit state; SQL/cluster cleanup
также прошёл. Full M10 остаётся inconclusive, mandatory serving heartbeat=false,
release_ready=false. Это повторное подтверждение scoped handoff, не полный R1.

В том же source
[security43146211890](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43146211890)
contracts job прошёл, а native observer failed с подтверждённым `journal_busy`.
Подробности и ограниченный recovery playbook записаны в
[ранбуке](../operations/periodic-trust-observer.md#подтверждённая-конкуренция-за-journal-и-ограниченное-восстановление).
Общий security workflow не принят; результат handoff не отменяет этот отказ.
Clean checkout ad53e3e:241tests/4Linux-dependent skips с warnings as errors;
координатор89/89statements и30/30branches. Собственное locked Python3.12.15
окружение, импорты из этого checkout и чистое Git tree проверены.

Clean checkout39e0159 с собственным locked Python3.12.15 environment:
229tests,4Linux-dependent skips, warnings as errors, чистое Git tree.
Ruff556files; docs947files/343Markdown/2507links в clean checkout.
Coordinator на39e0159:85/85statements,26/26branches; CI coverage gate pass.
Поздние fixture corrections и оптимизация preflight требуют своего нового CI.

Private logs, raw reports, ключи и snapshots не опубликованы. Публичные числа
извлечены из source-bound CI report; две копии primary report в log совпали.
Диагностические child codes не выводят exception text и не меняют scheduling.
Успешный новый observer run не является причинным исправлением старого45s timeout.
Предыдущий M11 HTTP response-contract failure также остаётся отдельной нестабильностью.

## Воспроизведение и дальнейшая работа

- [Код координатора](../../mlsecops/kube_serving_handoff.py),
  [native proof](../../scripts/kube_serving_service_native.py),
  [primary workflow](../../.github/workflows/kubernetes-promotion.yml).
- [Ранбук handoff/cleanup](../operations/kubernetes-security-state.md),
  [observer diagnostics](../operations/periodic-trust-observer.md),
  [identity wiring](../operations/identity-security-events.md).
- [План интеграции](../../tasks/audited-serving-integration-plan.md).

Следующий результат: свежий M11 с действующим approval при старте, затем общий
handoff всех callers и явные configuration/root transitions постоянного Deployment,
bootstrap до actual admission и mandatory serving heartbeat. После окончательного
профиля обязательны свежие M13/M14 и полная M23 campaign. Actual admission, M19,
независимые M22 challenges и итоговая M18-приёмка одного candidate остаются открытыми.
Локальные Docker/WSL/Kubernetes/SQL в этой задаче не запускались.

## Проверенная смена конфигурации наd66b12a

Source `d66b12ab4ed269dbd587fa5dd35b9af371768d12`, fingerprint
`3715b90accd3298cbea5523fc9338c1383189461baad652fef26ad800bd7afbb`.
[Primary43155788888](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43155788888),
job130975280323: terminal success. Report04:38:03.097080 ->04:48:13.440003 UTC.
21aggregate checks, включая17controlled checks; это вложенные проверки,
не21принятый acceptance gate. Runtime JSON и повторный sanitized readback совпали.

| Переход | Результат |
|---|---|
| Working policy -> несовместимая policy |54.987612s, heartbeat8->9, Ready/predict503, no inference worker, exact Reader refusal |
| Возврат исходной policy |56.628996s, heartbeat9->11, Ready200, один worker,3ONNX predictions |
| Golden parity после возврата |max error7.583384781240099e-08 |
| Config binding |Исходный hash восстановлен; оба ConfigMap UID новые |
| Владение HTTP |Оба Pod UID новые и совпали с final readback, Deployment UID сохранён |
| Journal и permissions |Сохранены; отказ без новых событий, после восстановления1новый identity.denied с независимым receipt |
| Финальная очистка service |service_pods0, worker_jobs0, audit_state_retained=true |
| Cleanup runner |Stop owned SQL и Remove owned cluster success с readback |

Исполнялись реальные suspend/reconfigure/resume, UID/resourceVersion-guarded
удаление immutable ConfigMap и ожидание нового heartbeat после исчезновения
старого владельца. Оба перехода уложились в исходные120s. Это не атомарная
операция нескольких объектов и не непрерывный PID.

[Security43155788165](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43155788165)
на том же source: оба jobs success,993test executions/22batches без skips;
coordinator139/139statements,46/46branches и batch reader41/41statements,
24/24branches. Чистый detached checkout d66b12a с собственным locked Python3.12.15
повторил191tests без skips, Ruff908files, docs954files/345Markdown/2529links,
git tree clean. Runtime ниже обязательных сроков не заменяет эти проверки source.

Границы: full_M10=inconclusive, release_ready=false, mandatory_serving_heartbeat=false.
Actual candidate ещё отказан; M11 оценивается отдельным run. Ускорение всего M11
и последующий audit readback внутри постоянного HTTP owner этим отчётом не доказаны.
Прерванный config transition остаётся suspended; автоматический resume после
такого сбоя пока не реализован и не считается проверенным восстановлением R1.

## Audit внутри существующего HTTP owner наaf12c85

[Primary43158134286](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43158134286)
на `af12c85e99818c429c1f1b643e327aacd62ebaf2`, job130982761025 success;
05:00:03.699636 ->05:10:07.543884 UTC. Runtime fingerprint прежний3715b90accd3298cbea5523fc9338c1383189461baad652fef26ad800bd7afbb:
изменился host harness, а mlsecops runtime/lock/image inputs остались прежними.
Git source_revision и image revision label различают commits.

`controlled.audit.serving_owner.mode=service`. Audit readback и последующий
before-admission HTTP readback наблюдали один Pod UID
`c0a3468c-b0e9-44aa-bba4-1b14f8bd1be5`. Проверка journal выполнилась внутри этого
Pod; два чтения не выдаются за Pod replacement.12audit assertions подтвердили
отдельные serving/trust identity и volumes, private permissions, запреты worker,
отказ настоящего promoter при collector outage, отсутствие изменения model ledger,
сохранение original pending events и их независимые receipts после восстановления,
collector/observer restart и сохранение counter.

Перед admission этот же HTTP отдавал503 без inference worker.21aggregate checks
включают дальнейший controlled admission, настоящий ONNX, handoff и revocation.
Config roundtrip повторён:54.405273s несовместимая policy и55.74917s восстановление,
оба в120s, retained Deployment/outbox; после восстановления новый identity receipt.
Cleanup service0Pods/0Jobs, audit state retained; SQL stop и cluster deletion/readback
success. Две опубликованные JSON-копии результата совпали.

[Security43158134098](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43158134098)
также success:1002test executions/23batches без skips,25/37/17/46native assertions;
max SQL event delivery30.993991066s, forced-lock recovery1.128798347s,
observer gap90.754629227s и HTTP producer gap90.175439186s. Cleanup подтверждён.
Чистый af12c85 checkout с отдельным locked Python3.12.15 environment:
103tests без skips, Ruff909files, docs955files/345Markdown/2531links, git tree clean.

Это не before-first-actual bootstrap, не mandatory serving registry и не полный
M23 outage на healthy ML/dashboard. full_M10=inconclusive и release_ready=false.
Общий coordinator callers из следующего commit и M11 имеют самостоятельную приёмку.

## M11 наaf12c85

[M11 run43158137922](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43158137922)
и job130982781249 завершились success. Gate report:146/146cases pass, exit_code0,
source clean и exact af12c85e99818c429c1f1b643e327aacd62ebaf2. Gate interval
05:03:13.134157 ->05:25:53.878972 UTC; весь шаг с подготовкой начался05:01:22.
Source revision/fingerprint совпали с input_digests; SHA256 обоих primary signer
report files пересчитаны из canonical JSON с завершающим newline и совпали с
artifact_hashes M11. Actual candidate c5f6ba79246a468390d0b6d2f841633a5d6e2d7bfb18e1b2a6bb800a1b617bc8,
model fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46.

Максимальный первый503 при actual outage59.791335739s, controlled outage59.793921363s;
остальные измеренные actual trust faults3.178120563-12.9481417s. Signer revocation
для publisher/assessor/approver0.579493061-0.584212183s. Пороги не расширялись.
Следующий component recovery прошёл36cases: restore-to-golden7.327263s,
1000golden rows, max error0.0; full_M17=inconclusive. SQL stop и owned cluster
deletion/readback завершились success. Полные логи сохранены только приватно.

Этот source предшествует общему coordinator и mandatory serving registry.
release_ready=false; M10/M13/M14/M19/M22/M23 и остальные обязательные gates не
закрываются этим результатом. Причина startup refusal предыдущего d66b12a остаётся
неустановленной: успешный повтор не доказывает причинного исправления.

## Обязательный serving profile на451c713

[Primary43162487334](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43162487334),
job130996675110, source451c713908e04db50f2ea6e20abb181952ad4906: success.
Runtime fingerprint1bf9b48696aa1dd78b85fa78998c95ba24a030ddd35933d3c3d6f46118a8bbeb,
source clean;05:38:56.333834 ->05:52:44.787021 UTC. Две JSON-копии отчёта совпали.

До parent submit и Kubernetes admission actual candidate появился настоящий HTTP
Pod377f2117-3aa0-4be3-b3c3-4be98fea1760: /livez200, /readyz503, predict503,
inference worker отсутствовал. Fresh serving heartbeat0->1 подтверждён за39.897243s,
UID в HTTP observation и final readback совпал. Parent отказал с
release_assurance_required, Kubernetes admission также rejected. Mandatory trust
и serving heartbeat включены, optional serving registry больше не принимается.

Controlled context заменён через прежний suspension/reconfigure/resume за66.003658s,
heartbeat3->4, Deployment и outbox сохранены. Audit readback использовал этот же
HTTP Pod, UID совпал с before-admission observation.12audit checks и21aggregate
checks прошли: admission, настоящий ONNX, outage/refusal, retained events/receipts,
смена Pod, revocation и сохранение отказа. Общий coordinator вернул HTTP за46.584579s
с2новыми independently matched identity receipts. Следующий incompatible config
transition67.69003s и restore68.751609s уложились в120s, receipt после restore есть.

Финальное состояние:0service Pods,0worker Jobs, audit state retained. Source SQL
stop и owned cluster deletion/readback success. full_M10=inconclusive,
release_ready=false; controlled approval не разрешает actual candidate.

[Security43162487960](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43162487960)
на том же source/fingerprint success:1047test executions/24batches/0skips,
25promotion/37trust/17continuous-observer/46HTTP-identity assertions. Max committed
event delivery31.023695234s, forced-lock recovery1.126971016s, observer gap90.766003236s,
HTTP producer gap91.282036754s, heartbeat period30.101s. Owned SQL/collector и
child-process cleanup подтверждены. HTTP component использует controlled unready
engine; он не заменяет healthy ML/dashboard outage или M13/M14/full M23.

M11 на451c713 failed с конкретным startup expiry отказом, см.
[runbook](../operations/trust-acceptance.md#expiry-и-передача-http-владельца).
Следующие readback-capacity и paired-expiry corrections этим Primary не приняты.

## Полная граница времени возврата

Внутренний Codex review воспроизвёл позднее завершение final UID validation при
своевременном heartbeat. Независимый M22 reviewer этим review не заменяется.
Два новых test methods сначала дали3failures: поздний Pod readback, поздний receipt
и заниженное время успешного отчёта. В смежном configuration transition повторены
те же3failures двумя отдельными methods. После исправления59affected tests pass,
0skips; Ruff check/format затронутых5files pass.

Оба координатора повторно измеряют elapsed после binding и receipt validation.
Предел120s не увеличен; exact-boundary120s принят,121s отказан. Старый failure probe
не превращается в success после восстановления. Focused coverage owned-probe:
55/55statements и16/16branches; startup41/41 и14/14, paired-expiry27/27 и2/2.
Native доказательство нового deadline correction pending; см.
[runbook](../operations/trust-acceptance.md#полное-время-возврата-владельца).

[Security43246221510](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43246221510)
на предшествующем sourceff06fa00bcc8f8b2eed7c3781402bf677c284e88 завершился success.
Contracts1057test executions/24batches/0skips. Native25/37/17/46assertions;
fingerprint3d6727838007bb8ce9bc32d0d169a08043d294d4f90f8ee14a8e5d24af4e27e1.
Максимальная delivery31.049631466s, forced-lock recovery1.122129069s,
observer gap90.190401397s, HTTP gap90.995876636s, heartbeat31.141s.
Это component evidence с controlled unready engine, не full M23/M13/M14/R1.

## Primary наff06fa0

[Run43246227657](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43246227657),
job131279502905: success, sourceff06fa00bcc8f8b2eed7c3781402bf677c284e88 clean.
Fingerprint3d6727838007bb8ce9bc32d0d169a08043d294d4f90f8ee14a8e5d24af4e27e1 совпал
с Security выше. Две полные JSON-копии совпали; время native report
15:20:27.588976 ->15:32:25.799719 UTC.21aggregate/17controlled/12audit checks pass.

Actual HTTP до admission: fresh heartbeat0->1 за34.620659s, live process,
ready/predict503 и отсутствие worker. Parent отказал именно по
release_assurance_required. Controlled transition56.269086s сохранил Deployment,
outbox и identity. Последующий ordinary CLI выполнил настоящий ONNX inference,
проверки401/413/422, worker-loss503 и cleanup. Max golden error7.583384781240099e-08.
Возврат owner38.205402s, heartbeat15->17 и2independent identity receipts.
Incompatible configuration56.889707s отказала до worker; restore59.401644s
вернул predictions и новый receipt.

Финальный readback:0service Pods,0worker Jobs, audit state retained. SQL stop и
owned cluster deletion success; job terminal success. Измерения возврата относятся
к старой границе до final reads; корректное измерение нового5d39e71 ещё требует CI.
full_M10=inconclusive,release_ready=false. Этот Primary не заменяет M11 или R1.

## Финальное измерение наf85140e

[Primary43250411996](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43250411996)
и[Security43250403360](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43250403360)
success на sourcef85140e8bcfb4f556d3ce36c33313c7f5066fc60.
Fingerprint9ade76dc47a67eee9bc8cf26a15ee8420c2682edc5f0d294e7399a22fdddaa33 совпал;
Primary clean, обе полные копии отчёта идентичны. Native report
15:43:36.198326 ->15:57:27.853945 UTC,21aggregate/17controlled/12audit checks.

HTTP до admission39.1179s. Возврат owner49.255072s включает final UID и receipt
validation: heartbeat20->22,2independent receipts. Configuration переход68.484214s,
incompatible67.838097s, restore69.510022s с новым receipt. Все ниже120s; limits не
менялись. Max ONNX golden error7.583387712228884e-08. Final0service Pods/0worker Jobs,
audit retained, SQL stop и owned cluster cleanup success. full_M10=inconclusive,
release_ready=false.

Security:1062test executions/24batches/0skips, owned coordinator55/55statements и
16/16branches. Native25/37/17/46assertions. Max committed delivery31.106404561s,
observer stopped notice90.170662227s, HTTP stopped notice90.934879428s.
Это проверка correction и компонентов; отдельный M11 и полный M23/R1 не заменены.
Clean checkout того же source:81affected tests/0skips, Ruff и docs checks pass.
