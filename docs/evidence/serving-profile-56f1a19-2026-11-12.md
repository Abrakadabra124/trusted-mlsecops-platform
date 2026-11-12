# T29: serving profile на 56f1a19

Неделя 11 - Security events и потеря telemetry. Срез на 2026-11-12:
Security, Primary, M11, M13 и M14 проверены на указанном source.
Это синтетический профиль `local-cpu` на центральном процессоре (CPU),
в отдельных disposable hosted окружениях. Полные M23, M18 и R1 не приняты.

Source: [56f1a19ce1e317d3b0642b65cb61664b89451216](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/56f1a19ce1e317d3b0642b65cb61664b89451216).
Он включает [7026997](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/7026997):
audit reader повторяет временный busy при setup в том же общем бюджете 3 s.
Общий проверенный source fingerprint:
`4fd482c46c05addb287c04fddfbc699eef74186afb00963976b821c0b4ab9558`.

| Проверка | Hosted run | Состояние |
| --- | --- | --- |
| Security | [43266470330](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43266470330) | success |
| Primary | [43266480086](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43266480086/job/131351305777) | success |
| M13 privacy | [43266904494](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43266904494) | success, gate pass |
| M14 load | [43266911707](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43266911707) | success, gate pass |
| M11 trust lifecycle | [43266471492](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43266471492) | success, gate pass, primary replay verified |

## Зачем сгруппированы probes

По source все прежние 22 Kubernetes Jobs остаются отдельными. Сокращаются
передачи serving ownership: с 21 до 8, за счёт одной передачи для семи
controlled probes после root rotation и одной для восьми candidate probes.
Это убирает повторный suspend/resume постоянного serving между соседними Jobs.
Root/observer/peer rotation остаётся отдельной границей. Каждый Job заново
проверяет audit/root/profile, привязки и собственный cleanup; общий кеш preflight
не вводится. [Код controlled](../../scripts/kube_controlled_trust_campaign.py),
[код candidate](../../scripts/kube_candidate_campaign.py).

Группы используют существующий [owned coordinator](../../scripts/kube_owned_probe.py).
При отказе дальнейшие Jobs не запускаются; обратимый fault восстанавливается
до возврата owner, необратимый отзыв не отменяется. Возврат требует отсутствия
probe Jobs/Pods, прежнего suspension ticket, проверки UID и свежего heartbeat
после последнего cleanup. Один ownership report относится ко всей группе.
Бюджеты 30 min, permit 600 s, preflight 180 s, fail-closed 60 s и owner return
120 s сохранены. Полный M11 job завершился за 29 min 6 s в прежнем лимите 30 min.
Резерв этого запуска 54 s; одно прохождение не доказывает устойчивый запас на
любом runner. [Runbook](../operations/trust-acceptance.md#m11-не-укладывается-в-общий-бюджет).

## Security и Primary

Security: пересчитаны 1085 выполнений unittest в 24 пакетах, 24 OK, 0 skips.
Это число выполнений с повторами, не число уникальных тестов. Четыре native
reports имеют `pass`, точный source/fingerprint и `release_ready=false`:
promotion audit 25 cases, trust history 37, periodic trust 17, HTTP identity 46.
Итого 125 компонентных cases; сами по себе они не закрывают полный M23.

Primary: две полные копии report идентичны, `source_dirty=false`, `status=pass`.
Native interval 17:12:52.126203-17:24:49.486259 UTC; 21 aggregate, 17 controlled
и 12 audit checks являются вложенными наборами. Actual startup 33.412359 s,
controlled startup 55.60324 s, owner return 39.95328 s с двумя identity receipts.
Несовместимая конфигурация/восстановление: 57.118297/58.86056 s; максимальная
ошибка golden scores 7.583384781240099e-08. Конечное состояние: 0 service Pods,
0 worker Jobs, audit state сохранён; SQL stop и удаление собственного кластера
подтверждены. Actual promotion отказан с `release_assurance_required`;
`full_M10=inconclusive` и `release_ready=false` сохраняются.

## M11: свежая приёмка trust lifecycle

Job 131351279157: 17:09:53-17:38:59 UTC, все шаги success, включая остановку SQL
и удаление собственного кластера с проверкой отсутствия. M11 acceptance:
17:14:58.163802-17:38:37.952436 UTC. Приняты 146 критериев: 125 controlled contracts
и 21 aggregate criteria. Preflight содержит 746 выполнений в 18 пакетах, 0 skips.
Четыре критических модуля gate/trace/runner/inventory покрыты полностью:
346 statements и 74 branches. Отдельная owner/campaign coverage в Security:
165 statements и 40 branches, 100%.

Отдельная offline-проверка восстановила source и method materials из Git blobs
точного commit, пересчитал hashes первичных JSON с завершающим newline, проверил
полноту controlled IDs из AST исходников и повторно выполнил reconcile/traces.
Проверяющий скрипт проверен на историческом успешном fixture и 14 regressions:
подмена source/hash и поздний HTTP 200 отвергаются, даже если хеш изменённого
native report пересчитан. Это внутренняя проверка другим кодом, а не независимый
человеческий review M22. Raw logs и приватные packets не публикуются.

| Actual fault | Первый HTTP503, s |
| --- | ---: |
| Trust outage | 59.814372159 |
| Blackhole | 12.236475398 |
| Policy change | 3.044801854 |
| Root rotation | 3.354656371 |
| Model revocation | 3.257161859 |
| Key revocation | 3.046027652 |

Trace validator проверил границу 60 s, минимум два отказа и отсутствие последующего
ML 200. Outage/blackhole наблюдались и за границей 60 s. Signed approval отказан
за 0.368838 s до expiry в установленном консервативном допуске. Сохранены clock/cache,
valid-version/sequence replay, разрешённый rollback и отказы revoked target.
Первый HTTP 503 при смене publisher/assessor/approver: 0.473272/0.440667/0.420378 s.

Controlled batch вернул owner за 25.418521 s: heartbeat 40->41, 5 independent receipts.
Candidate batch: 25.277704 s, 107->108, 7 receipts. Время включает final UID и receipt
validation. SQL signer history имеет 37 checks, live signer campaign - 68 cases,
последующее восстановление - 36 checks: 1000 golden rows, ошибка 0.0,
5.346648 s до golden.
Это controlled recovery component; full_M17 остаётся inconclusive.

SHA-256 gate M11:
`45009a1fce7e7f8722ec433d93cad69291a170ec973108264c7b0d579a5d0b0c`.
SHA-256 первичного native report:
`af7681dd14ef1813022c537006980e7e237414aeb816c4d420eb6333024b4821`.
Полные hashes signer/recovery сохранены в очищенном verification asset milestone.
M11 pass подтверждает механизм synthetic lab; он не разрешает actual production
release, не заменяет independent M22 и не закрывает общий M18/R1.

## M13: privacy и audit

Gate pass: 514 уникальных criteria с совпадающими expected/actual; preflight
296 выполнений в 8 пакетах, 0 skips. Campaign 17:15:18.713758-17:20:42.384668 UTC.
Проверены 9 input canaries, 35 HTTP responses, 108 audit events, 36 durable
privacy events и 5 закрытых service windows с повторной проверкой сохранённых
пакетов. Monitoring включает 1014 observations, 69 metric series и 9 dashboard
requests; отдельный feedback CLI проверяет quarantine, retry и запрет прямой
записи в защищённые таблицы. Native stderr и controlled CLI output: 0 байт.

Actual candidate проверяется по qualification permit; controlled CLI release
отдельно проверяет approval/context wiring. Его admission не наблюдается
независимо; такая связность проверена на actual shared audit path. Результат
не доказывает защиту от membership inference, привилегированного владельца
хоста или непрерывную историю всех сервисов. Реальные данные требуют отдельной
спецификации целей обработки, сроков хранения и privacy.

## M14: нагрузка и деградация

Gate pass: 153 уникальных criteria с совпадающими expected/actual; preflight
395 выполнений в 4 пакетах, 0 skips. Campaign 17:14:55.025951-17:20:22.668793 UTC.
Профиль: 10 s прогрева, затем 120 s измерения, 10 concurrent clients, одна
строка на запрос; closed-loop, отдельное соединение на запрос, timeout 2 s.

| Измерение | Результат |
| --- | --- |
| Прогрев | 1352 успешных запроса |
| Основное окно | 16153 запроса, все HTTP 200 и правильные predictions |
| Успешная пропускная способность | 134.6083 запросов/s |
| Latency p50 / p95 / p99 | 69.471620 / 98.257359 / 124.527213 ms |
| Максимальная latency | 173.043642 ms |
| Ошибки основного окна | 0 unexpected 5xx, timeout, transport, quota denial и mismatch |
| Отдельный overload | 40 попыток: 10 правильных ответов, 30 ограничений, 0 errors, recovery=true |

Operator получил по 43 resource samples для controller и worker. Максимальный
наблюдавшийся working set: 239968256 и 41779200 байт; максимальный промежуток
между samples: 10 и 11 s. Это выборочные наблюдения, не истинный пик памяти.
Лимиты controller/worker: 2/1 CPU и по 1 GiB RAM. Вложенный native observation
сохраняет `full_M14=inconclusive`; итоговый composed M14 gate имеет `pass`.
Его составная проверка и post-cleanup reverify обязательны для принятия.

## Привязки, очистка и границы

Основной исполнитель независимо пересчитал source fingerprint, method materials
и policy digest по неизменяемым Git blobs. Для обоих gates проверены уникальность
case IDs и все expected/actual; hashes полных gate reports повторно совпали
с verified summaries. У M14 дополнительно сверены embedded summary/diagnostics
hashes и сохранённые bindings после cleanup. SQL stop, cluster deletion и
последующий reverify evidence завершились success у M13 и M14.

M13 и M14 имеют один source, но разные candidate, subject и built image IDs.
Это отдельные кампании, не общая M18-приёмка одного candidate. Qualification
permit не разрешает production release. Raw logs, полные private JSON, runtime
идентификаторы и credentials остаются в `.runtime/evidence` вне публикации.
M11 принят в указанных границах. Milestone prerelease публикуется на проверенном
source; готовность R1 этим документом не заявляется.

## Повтор на точном source

Использовать существующие hosted workflows [M11](../../.github/workflows/kubernetes-serving.yml),
[M13](../../.github/workflows/kubernetes-privacy.yml) и
[M14](../../.github/workflows/kubernetes-load.yml). Их исходные runs завершены;
SQL/cluster cleanup подтверждён, для M13/M14 также подтверждён post-cleanup reverify.
Повтор требует нового disposable hosted runner и заново создаёт только принадлежащие
ему ресурсы. Локальную инфраструктуру эти команды не запускают.

Сначала только диагностика. Выбрать один исходный run и проверить его source,
полный список шагов и отсутствие активной кампании с тем же workflow/ref.
Это обязательно из-за `cancel-in-progress`; при активной кампании дождаться её
завершения и подтверждённой очистки. Для M13 использовать run 43266904494 и
workflow `kubernetes-privacy.yml`, для M14 - 43266911707 и `kubernetes-load.yml`.

```powershell
$repository = 'Abrakadabra124/trusted-mlsecops-platform'
$source = '56f1a19ce1e317d3b0642b65cb61664b89451216'
$runId = 43266471492
$workflow = 'kubernetes-serving.yml'
$run = gh run view $runId --repo $repository --json headSha,headBranch,status,conclusion,jobs | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $run.headSha -ne $source) { throw 'source mismatch' }
if ($run.status -ne 'completed' -or $run.conclusion -ne 'success') { throw 'terminal success required' }
$run.jobs.steps | Format-Table name,status,conclusion
gh run list --repo $repository --workflow $workflow --branch $run.headBranch --limit 100 --json databaseId,headSha,status,conclusion
```

После проверки очистки и отсутствия пересекающихся кампаний выполнить изменяющий
шаг: GitHub повторит исходный commit, даже если branch уже переместилась.
Не запускать следующий повтор или push этой ветки, пока этот attempt не завершён
и его cleanup не проверен.

```powershell
gh run rerun $runId --repo $repository
if ($LASTEXITCODE -ne 0) { throw 'rerun rejected' }
gh run watch $runId --repo $repository --exit-status
if ($LASTEXITCODE -ne 0) { throw 'inspect failure and owned cleanup before retry' }
gh run view $runId --repo $repository --json headSha,status,conclusion,jobs
```

В новом attempt заново проверить source/candidate/image bindings, первичные
отчёты, hashes, все criteria и terminal cleanup/reverify. Исторический успех
не заменяет свежий результат. Команды повторного запуска приведены как инструкция;
дополнительный attempt ради подготовки этого документа не выполнялся.
