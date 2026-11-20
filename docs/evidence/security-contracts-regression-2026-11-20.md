# Регрессия security contracts на 422accf7

20 ноября 2026 года [run 44662205908](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44662205908)
workflow `M23 security event contracts` завершился **success** во всех трёх jobs.
Точный source: `422accf72d5f994b5501bcd83bbf07b7f8374600`.
Результат сверён с сохранёнными metadata, selected summary и private log этого
run; команды и cleanup проверены в source указанного commit. При подготовке
отчёта новые runtime, network или test executions не запускались.

Цель проверки - регрессия аутентифицированных security events, первичных
source records, durable journal, observer/producer lifecycle, обнаружения
потери событий и отказа audit dependency около SQL commit. Контрактные fixtures
дополнены ограниченными реальными Linux process, filesystem, HTTP и SQL
сценариями. Это компонентное evidence, не полная M23 acceptance одного candidate.

## Jobs и время

Все времена UTC; durations рассчитаны по `startedAt` и `completedAt` job.
Jobs выполнялись параллельно, поэтому их длительности нельзя складывать во
время одного сквозного прогона.

| Job | Интервал 20 ноября | Длительность | Результат |
| --- | --- | --- | --- |
| [audit-promotion-sql](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44662205908/job/136042866727) | 02:38:13-02:45:24 | 7 min 11 s | success |
| [contracts](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44662205908/job/136042867008) | 02:38:14-02:41:37 | 3 min 23 s | success |
| [sequence-gap](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44662205908/job/136042867289) | 02:38:14-02:41:38 | 3 min 24 s | success |

В log подтверждены **26 запусков unittest suites, 1248 выполнений test methods
с повторами**. Каждый соответствующий `Ran ...` summary завершается отдельным
`OK`; `OK (skipped=...)` и `FAILED` summaries отсутствуют. Это не 1248 уникальных
тестов: workflow повторяет некоторые qualification modules в разных группах.
Coverage thresholds проверялись существующими командами workflow; общий процент
покрытия всего проекта этим отчётом не заявляется.

## Шесть native component projections

Все шесть проекций имеют `status=pass` и **`release_ready=false`**. Counts ниже
относятся к cases конкретного component, а не к полным критериям M23.

| Component и точный scope | Cases | Что проверялось и где граница |
| --- | --- | --- |
| `security_event_promotion_native`: `controlled-auth-real-audit-and-SQL` | 25 | Реальные collector outage, audit admission и SQL rollback; authorization/trust заданы controlled fixtures. |
| `security_trust_events_native`: `bounded-trust-history-observer-not-continuous-M23` | 37 | Реальная SQL history, отдельный observer CLI и collector recovery; bounded history scenario. |
| `security_trust_service_native`: `continuous-trust-source-not-full-M23-or-R1` | 17 | Реальный continuous observer, periodic delivery, contention recovery и уведомление об остановке source. |
| `security_identity_events_native`: `actual-http-and-identity-child-with-controlled-unready-engine-not-M13-M14-M23` | 46 | Реальные HTTP/identity child и collector outage; engine намеренно unready, inference и native M13/M14 не проверяются. |
| `security_source_campaign`: `intake-controller-source-primary-not-full-M23` | 3 | Actual intake/controller decisions и replay primary после cleanup; executor synthetic/in-process, изоляция worker не заявляется. |
| `security_event_sequence_native`: `hosted-sequence-component-not-full-M23-R1` | 25 | Два isolated collector scenarios: `ingest-hole` и `heartbeat-head-only`, restart, signed recovery; без SQL, Kubernetes и model workload. |

Измерения этого run: bounded trust observation максимум **0.244 s**; continuous
trust commit delivery максимум **31.023 s**, periodic interval **31.168 s**,
forced contention recovery **1.127 s**, stopped-source notice **90.531 s**.
Identity HTTP максимум **0.250 s**, heartbeat interval **30.111 s**,
stopped-producer notice **90.791 s**. Значения округлены до миллисекунд.
Это наблюдения конкретных component scenarios, не общая latency guarantee или
измерение производительности serving модели.

## Что означает cleanup

- Три SQL-компонента используют [owned disposable SQL](../../scripts/release_reader_native.py).
  После проверки прежних ownership fields удаляются конкретные container,
  network и volume; затем проверяется их отсутствие и удаляется owned state.
  Здесь cleanup означает удаление этих SQL-ресурсов, не только остановку SQL.
- Collector fixture ожидает завершения своего процесса, проверяет exit code
  и закрытие owned port; component checks подтверждают удаление private fixture
  directory. Continuous observer дополнительно проверяет отсутствие process
  group/children. Два одинаковых cleanup case в его проекции относятся к двум
  остановкам, не к двум независимым acceptance criteria.
- Identity scenario проверяет штатное завершение owned HTTP child и закрытие
  порта, затем collector/private-files cleanup. Intake/controller и sequence
  projections подтверждают `cleanup_verified=true`; для sequence есть отдельный
  `owned-cleanup` в каждом из двух сценариев. Сохранённые private primary вне
  fixture directory не следует считать удалёнными вместе с runtime fixture.

Cleanup подтверждается component checks и соответствующими readers, а не одним
фактом завершения disposable runner. Неизменность source проверяется отдельно.

## Воспроизведение существующим workflow

[security-events-contracts.yml](../../.github/workflows/security-events-contracts.yml)
на указанном source имеет `workflow_dispatch`, `pull_request` и push triggers
для `main` и `codex/cp4-m23-security-events-20261107`. Используются
`ubuntu-24.04`, uv `0.12.23`, Python `3.12.15` и repository lock;
job timeouts: contracts 5 min, sequence-gap 6 min, audit-promotion-sql 10 min.

Для ручного повтора заменить `REVIEWED_REF` существующим branch/tag, указывающим
на проверенный commit, а `RUN_ID` - идентификатором именно нового выбранного run.
Это инструкции для repository owner; при составлении отчёта dispatch не выполнялся.

```text
gh workflow run security-events-contracts.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref REVIEWED_REF
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --workflow security-events-contracts.yml --limit 10 --json databaseId,headSha,status,conclusion,url
gh run view RUN_ID --repo Abrakadabra124/trusted-mlsecops-platform --json headSha,status,conclusion,jobs,url
gh run watch RUN_ID --repo Abrakadabra124/trusted-mlsecops-platform --exit-status
```

Перед интерпретацией результата сверить `headSha`, terminal state всех трёх jobs,
test summaries и шесть component projections. Workflow сам выполняет
`uv sync --locked --no-build --python 3.12.15`, pinned qualification/coverage
commands и существующие native entrypoints. Полный порядок команд находится в
workflow на exact source; локальный запуск hosted native entrypoints не требуется.
При timeout наблюдателя повторно читать тот же `RUN_ID`, не создавать новый run.
`cancel-in-progress=true` может отменить предыдущую попытку на том же ref;
cancelled/failed/incomplete результат не считается pass.

Этот документ не публикует private pins, packets/model data, raw logs,
signatures или trust keys. Суммирование component counts не создаёт полную
M23 acceptance. Native M13/M14, общий same-candidate M18 и R1 этим run не
закрываются. Успех относится только к указанному source, не к более новым commits.
