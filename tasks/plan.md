# План перехода DevSecOps -> MLSecOps

## Как читать план

Это план **реализации**, не отчёт о завершённых неделях. R0.2 завершён, с 2026-10-07 начат R1: локальный reference с [M01-M23](../docs/acceptance.md) и 29 задачами. Уже есть developer preview, но полная приёмка не пройдена; актуальные результаты в [STATUS](../STATUS.md). Плановый ориентир сохраняется: 14-16 недель активной работы при 15-20 часах в неделю, плюс 25% календарного резерва, примерно 18-20 недель всего. Это оценка, не обещание даты; discovery, реальные данные и production-профиль могут увеличить срок. T25-T29 добавляют ориентировочно 30-50 часов к исходному scope.

Зависимости важнее даты: если gate не принят, следующая неделя не превращает результат в готовый автоматически. Одна рабочая итерация: требование -> отрицательный тест -> реализация -> проверка конечного состояния -> очищенное evidence -> review -> commit. Не менять действующую foundation вслепую.

## Карта зависимостей

```mermaid
flowchart LR
    W1[1: Scope и foundation] --> W2[2: Данные]
    W2 --> W3[3: Изоляция]
    W3 --> W4[4: Воспроизводимость]
    W4 --> W5[5: Независимая оценка]
    W5 --> W6[6: Attack lab]
    W6 --> W7[7: Intake и challenges]
    W7 --> W8[8: Trust и inventory]
    W8 --> W9[9: Serving]
    W9 --> W10[10: Наблюдение]
    W10 --> W11[11: Security events]
    W11 --> W12[12: Rollback и restore]
    W12 --> W13[13: Полная приёмка]
    W13 --> W14[14: Review и release]
```

## Неделя 1: Контекст и foundation

**Задачи:** T01, T02. Уточнить utility target, label horizon, владельца данных и профиль угроз. Инвентаризировать ОС/WSL/Docker/CPU/RAM/disk, прочитать текущие ограничения registry и подписей. Проверить foundation в отдельном окружении, совместимость ML-пакетов, источники и лицензии. Создать общий acceptance runner и inventory без production credentials.

**Результат:** versioned scope, resource/compatibility matrix, pinned foundation reference, P0 backlog с разрешённым путём устранения, bootstrap idempotency evidence. **Приёмка:** M01. **Почему сначала:** несовместимая база и общий signing key обесценят последующие ML-gates.

## Неделя 2: Контракт данных и происхождение

**Задачи:** T03, T04. Создать синтетический generator, data dictionary и dataset card; определить temporal/group split для реального профиля. Реализовать quarantine, schema/range/duplicate checks, versioned source и подписанный SHA-256 manifest. По [ADR 0005](../docs/decisions/0005-data-lineage.md) DVC исключён из активного стека после security spike; для одного source используется fixed-step lock. Пройти tamper/path/permission negative tests, не снижая пороги приёмки.

**Результат:** approved immutable dataset + split, повторяемая подготовка, отчёт отказов. **Приёмка:** M02, M03. **Зависимость:** согласованный формат и storage profile недели 1. Реальные приватные данные не добавляются в Git.

## Неделя 3: Изоляция обучения

**Задачи:** T05, T06, начало T26. Развести identities, prefixes/volumes, namespaces и network policy. Trainer не видит holdout/signing keys; evaluator не меняет candidate. Отделить controller/publisher от недоверенного worker. Запустить настоящий Job с timeout/CPU/RAM, а также неуспешные обращения от каждой роли.

**Результат:** executable access matrix, workload manifests и termination evidence. **Приёмка:** M04, M05. **Ключевая проверка:** отказ в реальном запросе, а не только наличие YAML с `deny`.

## Неделя 4: Обучение и reproducibility

**Задачи:** T07, T08, начало T25, компонент T26. Создать preprocess/train/export шаги, параметризованный DAG и MLflow tracking в закрытом контуре. Credentials остаются у внешнего publisher. Зафиксировать inputs и выполнить три fresh-process прогона. Проверить изменение seed/data/environment. Начать asset schema и dependency graph, выполнить компонентные tests boundary до evaluator.

**Результат:** связанный run lineage, candidate model, численное сравнение повторов. **Приёмка:** M06. **Ограничение:** не обещать bit-for-bit equality на других CPU/GPU или версиях библиотек.

## Неделя 5: Независимая оценка

**Задачи:** T09, T10, T25-компонент, T26-интеграция. До final holdout утвердить evaluation policy; отдельно настроить validation tuning, independent evaluation, baselines, slices и confidence intervals. Prediction worker получает только features, trusted scorer хранит labels отдельно. Реализовать лимит запросов к holdout и report binding. Проверить graph fixtures без serving; заполнить model card.

**Результат:** frozen policy, isolated worker и scorer, clean report, отрицательные проверки доступа и output protocol. **Приёмка:** M07, M20; M19 пока компонентно. **Stop condition:** данных недостаточно или utility не доказана - только лабораторная демонстрация, не настоящий advisory пилот.

## Неделя 6: Манипуляции и формат модели

**Задачи:** T11, T12. Выполнить poison experiment matrix и ограниченные evasion probes, не смешивая исследование атак с fixture enforcement. Протестировать ONNX parity, allowed operators, unsafe formats, external paths и resource limits.

**Результат:** attack report с bypass/false positives, безопасный экспорт, parity report. **Приёмка:** M08, M09. **Почему до подписания:** подписывать нужно candidate с известными результатами, а не скрывать отсутствие оценки подписью.

## Неделя 7: Проверяемое сканирование и независимые challenges

**Задачи:** T27, T28. Проверить реальную format/tool coverage, не допускать false green при нуле проверенных объектов. Добавить абсолютные poisoning budgets на двух размерах train и challenges, не использованные для tuning. Коммерческий scanner и GPU не являются условием завершения.

**Результат:** intake coverage report, 36 poisoned runs + 6 controls и не менее двух reviewer challenges. **Приёмка:** M21, M22. Исследование LLM poisoning мотивирует постановку эксперимента, но не считается воспроизведённым на табличной модели.

## Неделя 8: Bundle, approval и отзыв доверия

Исполняемый порядок T13 от 2026-10-14: (1) полный digest-bound release descriptor поверх существующей candidate capsule, включая feature contract, model card, ML-BOM, dependency lock и runtime profile; (2) отдельно подписанные promotion policy, assurance и approval с внешним trust root, exact subject/environment/policy binding и отказом при любом отсутствующем/непринятом gate; (3) durable promotion state machine и concurrency/replay checks; (4) scoped controller и serving integration. Первые два шага проверяются controlled positive/negative matrix и реальным чтением candidate из disposable SQL. Реальная отсутствующая приёмка не заменяется искусственно зелёными reports. M10 остаётся открыт до проверки переходов состояния и integration; M11/M12 не закрываются offline signature tests.

Следующий increment после cd4c6fd: постоянный promotion ledger в PostgreSQL, отдельная явная миграция без переписывания checksum исходной schema v1 и без изменения working state. Атомарный переход под row lock связывает environment, policy pin, sequence и immutable request/evidence; текущий точный повтор идемпотентен, конфликтующий или старый sequence не переключает head. Только trusted promoter вызывает ограниченную SQL-функцию, прямые UPDATE/DELETE запрещены. SQL не заменяет cryptographic verifier: Python admission проверяет полную signed chain до записи, а будущий serving обязан проверять её повторно. Запись выбора не означает ready или production activation.

Критерии этого increment: реальные SQL concurrent same/conflicting requests, rollback interrupted transaction, stale replay, expiry после ожидания lock, неизвестный environment/policy, restart durability и права ролей; controlled crypto fixtures отдельно от реального candidate, который по-прежнему не проходит отсутствующую assurance. Existing backup экспортирует только исходные CAS tables, поэтому наличие нового ledger должно запрещать прежний неполный backup до явной поддержки согласованного snapshot/restore. Миграция и native проверки выполняются только в owned disposable среде; рабочие БД/cluster не мигрируются автоматически. Runbook должен описывать ambiguous commit, readback, безопасный retry и запрет reset sequence/ledger.

**Задачи:** T13, T14, интеграция T25. Реализовать signed bundle и отдельное approval; закрепить signer/evaluator/policy/environment binding, idempotency, replay prevention и revocation. Связать inventory с verifier и транзитивным отзывом. Изменение alias, model bytes и evaluation report не должно обходить gate.

Recovery increment после a65ee56: opt-in backup manifest v2 включает CAS и promotion authorities/events/heads в одном exported snapshot, фиксирует обе migrations и проверяет структурную связность journal. Legacy v1 сохраняет запрет пропуска ledger. Restore допускает только новый owned target и внешний операторский backup-id pin, не выбираемый автоматически из архива; data-only TOC allowlist и одна транзакция, maintenance для application clients до сверки. Повтор завершённого restore не стирает поздние записи; повреждённый, неподписанный, неполный или чужой backup не даёт ready. Native acceptance: concurrent promotion исключён из snapshot целиком, exact journal/CAS readback в независимом target, stale replay/роль/повтор/неопределённый import. Backup pin выбирает конкретный recovery point, но не доказывает отсутствие более новых решений после него: serving activation и current trust/revocation остаются отдельным обязательным шагом M11/M17. Обновлять PB/RB одновременно с кодом.

**Результат:** проверяемый promotion state machine и revocation tests. **Приёмка:** M10, M11. **Риск:** локальные keys остаются lab-допущением, не заменяют production workload identity/KMS.

## Неделя 9: Serving и privacy

Реализован [API/isolated serving increment](../docs/serving-api.md): persistent session, actual-byte load handshake, before/after trust checks и bounded HTTP contract. [ADR 0031](../docs/decisions/0031-isolated-serving-api.md) и [evidence](../docs/evidence/serving-api-2026-10-14.md) отделяют fixture execution от настоящей acceptance. Далее обязательны candidate-bound full M12, HTTP outage deadline trace и T16 privacy/quotas/audit; thresholds и исходная цель не сокращены.

После verified native `2942255` следующий короткий этап T15 - qualification на неизменённом proposal настоящего synthetic training/evaluation, а не на пересобранной test lineage. Проверять source/model/material digests и точный release subject; сохранить отдельные qualification authority, credentials и scope. Не импортировать искусственные all-pass reports как реальную приёмку остальных gates. M12 evidence должен фиксировать actual candidate, входные материалы и HTTP checks; final promotion остаётся отдельным шагом, запрещённым при любом failed/inconclusive gate. Затем добавить timestamped HTTP trust-outage trace <=60 s; component-only trust timing не заменяет endpoint trace.

Уточнение [ADR 0032](../docs/decisions/0032-candidate-serving-qualification.md): (1) negative tests и signed qualification permit без M-gate assertions; (2) qualification-only Reader immutable proposal и текущий trust; (3) read-only actual-candidate HTTP replay в disposable CI; (4) source snapshot/readback, negative production approval и очищенное evidence/ранбук. Production Reader/config не получают bypass-флаг. Это разрешение испытать, а не фиктивное разрешение выпустить.

На `0a47b7b` этот slice подтверждён: 39 actual-candidate native cases, golden consistency error 0.0, source unchanged. Следующий slice: остановить только owned disposable trust authority, записать UTC/monotonic timestamps последней успешной trust read и HTTP ответов, проверить отсутствие продления lease и отказ не позже 60 s; offline cold start не разрешать. После запуска той же authority требовать fresh signed read, explicit verified load и golden replay, а не cached fallback. Любой поздний/неподтверждённый отказ сохранять fail/inconclusive; не подменять HTTP trace прежним component timing. Добавить failure-first contracts, native evidence и отдельные outage/recovery ветви PB-26. Это следующий component step, не закрытие остальных M11/M12 требований.

Реализован pre-runtime [current reader ADR 0030](../docs/decisions/0030-current-release-reader.md): immutable bytes + repeated authorization/current head/lease checks. Следующая интеграция обязана передать именно эти bytes isolated worker, подтвердить running digest, проверить before/after-inference state и HTTP contract. Native positive contract fixture не заменяет реальную ML acceptance; [evidence](../docs/evidence/release-reader-2026-10-14.md) и [PB-24](../docs/operations/release-reader-troubleshooting.md).

Перед endpoint использовать [online trust ADR 0029](../docs/decisions/0029-online-trust.md): отдельный текущий signed policy service, независимый от model backup, online startup, monotonic lease максимум 60 s, без cache grace после expiry. Подключить проверку до и после inference, сверку реально загруженного bundle и текущий revoked ancestor set. Component/SDK pass не заменяет эту endpoint приёмку; root rotation и разрешённый rollback остаются отдельными проверками T14.

**Задачи:** T15, T16. Реализовать API-контракт, verify-then-load, atomic bundle selection, trusted readiness, ошибки и abstain. Добавить auth/quotas, ограниченный audit, redaction и тестовые PII canaries.

**Результат:** usable reference inference API с известным model digest, negative API/loader suite, reconciliation реально загруженной версии и отзыв ancestor до endpoint. **Приёмка:** M12, M13, M19 целиком. **Безопасный fallback:** отсутствие ML не отменяет deterministic release gates.

HTTP outage slice после `cdea4236` реализуется отдельным diagnostic module поверх того же actual-candidate Reader/Engine. Не менять production lease ради удобного теста. Сначала локальные trace/ownership/recovery negatives, затем clean-checkout native CI с сохранением fail/inconclusive и обновлением PB-26/RB-52; при позднем HTTP отказе исследовать runtime cleanup, не вычитать его из measured latency.

Результат: `2905e70` сохранил late 503 failure; `e9120e0` после lifecycle correction подтвердил 46 actual-candidate cases и 59.995078784 s. Следующий короткий slice: failure-first slow/blackholed trust read при приближении lease expiry, явный response deadline с сохранением bounded in-flight ownership/cleanup и controlled + owned native fault injection. Остановленный контейнер даёт быстрый connection refusal и не проверяет этот класс отказа. Не увеличивать 60 s, не выдавать ~4.9 ms запаса единственного прогона за SLO; сверять no-ML-after-deadline и фактический клиентский отказ отдельно. Затем продолжать T16 privacy/quotas/audit и общую M11/M12 acceptance без фиктивного release approval.

## Неделя 10: Нагрузка и ML monitoring

Checkpoint перед переходом к T16: [ed87e97 evidence](../docs/evidence/serving-deadline-2026-10-15.md) подтвердил 52 candidate cases при свежем lease, но без отдельного ACTIVE timestamp до HTTP completion. Следующий [native increment 960091f](../docs/evidence/serving-expiry-2026-10-15.md) подтвердил **62 cases**, включая подлинную 8 s signed policy без подмены часов: client-completed 503 за 6.694990456 s до expiry, повторный 503 после expiry при pending SQL, timed ACTIVE, no-auto-reactivation, renewal version 3/readback и source preservation. Production code/thresholds не ослаблены. Теперь следующий slice T16: ограниченный список authenticated principals, per-client quotas до body/executor, bounded audit allowlist и canary export tests. Это будущие deliverables, не завершённые функции; полная M11/M12/R1 acceptance остаётся открытой.

**Задачи:** T17, T18. Измерить latency/throughput/resource usage по фиксированному профилю. Добавить data/prediction/label-quality reports, trust alerts и telemetry health. Проверить clean windows, drift injection и delayed labels; feedback отправлять только в quarantine.

### Проверяемые slices T16

Первый slice реализован по [ADR 0035](../docs/decisions/0035-serving-client-quotas.md): bounded local identity/rate/in-flight и retained tickets. [Native 687a7c7](../docs/evidence/serving-clients-2026-10-15.md) подтвердил **67 actual-candidate cases**, quota window 0.002959852 s, statuses 422/429/422/429, refill 200/200, admissions [2,2,4] и прежние trust/recovery boundaries. Failed `f273fd5` сохранён: исправлена частота diagnostic polling, не защитные пороги. Это не завершение T16. [RB-54/PB-28](../docs/operations/serving-client-troubleshooting.md) проверен вместе с реализацией. Следующие пункты сохраняют исходный контракт, audit/privacy ещё не реализованы.

1. **Identity и quota boundary.** Перед кодом зафиксировать ADR о конечном списке локальных principals, случайных credentials и независимых rate/in-flight budgets. Principal определяется только проверенным credential, не IP, forwarded headers или переданным client ID. Квоты проверяются до body/executor; HTTP timeout не освобождает slot ещё работающего SQL thread. Acceptance: один клиент не расходует чужой budget, неизвестные credentials не создают новые buckets, clock anomalies/cancellation не дают дополнительный budget, duplicate authorization отвергается. Проверить совместимость старого single-client lab config без скрытого выключения ограничений. Это не remote identity provider и не distributed quota.
2. **Минимальный audit и корреляция.** Определить bounded event schema и правила retention/sink failure до выбора storage. Только server-generated request ID, конечные event/outcome codes и проверенная release-chain correlation; без request body, features, scores, tokens, raw URLs, exception text и клиентских trace IDs. Audit должен отражать фактически отправляемый статус после финальной проверки deadline, а не предполагавшийся 200 до serialization. Зафиксировать различия attempted/sent/completed: отменённый transport не доказывает доставку клиенту. Приёмка включает переполнение очереди, unavailable sink и отсутствие продления serving deadline из-за telemetry; политика потери audit не должна молча давать pass M13.
   Checkpoint после `1e8bb1f`: [ADR 0036](../docs/decisions/0036-serving-audit-journal.md) реализует core записи с hard caps и durability/lifecycle diagnostics. До обязательного HTTP подключения выполнить owned rotation/retention с общим storage cap и безопасным закрытием segment, затем ASGI producer со снимком verified release и actual response transitions. Публичный export должен сводить private IDs к конечным агрегатам, не хешировать payload. Pure journal pass не разрешает M13 или автоматическое удаление файлов.
3. **Privacy и cardinality qualification.** Canary suite покрывает valid/invalid body, headers/query/path, rejected JSON и exception paths; проверяются application/server logs, metrics, trace/export и absence raw-feature persistence. Metric labels ограничены конечными route/outcome enums, без request/principal/release IDs; private audit correlation не экспортируется автоматически как public evidence. Привязать результат к actual candidate и clean checkout, обновить runbook диагностики quotas/sink failure и безопасного восстановления. Только после этого принимать scoped M13 evidence и переходить к M14; masking не считается differential privacy.

### Проверяемая граница T16: retention перед HTTP audit

Статус этой границы: **реализованный opt-in Linux компонент, native quality qualification pass на 42ce792: 61 audit tests / 0 skips**. [ADR 0037](../docs/decisions/0037-audit-retention.md) фиксирует policy и ownership; [branch evidence](../docs/evidence/audit-branches-2026-10-16.md): core 76/80 branches = 95%, retention 102/102 = 100%, 10 checker tests и 67 serving regression cases pass. Branch criterion подтверждён для двух модулей, не всей security-critical логики и не полного M18. Следующий перечень остаётся контрактом приёмки, а не заявлением о завершении T16:

- Общий budget учитывает активный segment, закрытые retained segments и зарезервированные pending bytes. Новый segment не обходит общий cap; исчерпание места не разрешает незаметную потерю событий. Верхняя граница числа файлов ограничивает и metadata overhead.
- Rotation не удаляет активный writer или segment с неподтверждённой durability. Storage credit освобождается только после подтверждённого удаления owned closed segment; ошибка write/fsync/close/unlink оставляет неуспешную qualification, а не reset counters.
- Retention policy явно разделяет минимальный срок сохранения для расследования и максимальный срок хранения для privacy. Если cap конфликтует с минимальным сроком или удаление невозможно, нет обещания одновременно сохранить доступность, полноту и срок удаления: результат fail/inconclusive, эскалация оператору. Числа lab policy не объявляются юридическим нормативом.
- Ownership определяется не совпадением имени/glob. Unknown files, symlinks, заменённый parent и параллельный writer не должны приводить к чтению, перезаписи или удалению чужих данных. Startup после interruption требует явного reconciliation, а не очистки всего каталога. Windows privacy нельзя принять по Linux mode bits.
- Проверить clock rollback/forward, отсутствие новых requests после наступления expiry, restart и длительный I/O. Retention нельзя привязывать только к следующему emit; blocked worker нельзя объявить завершённым из-за истечения join timeout. Смена часов не даёт дополнительного storage budget или преждевременного удаления.
- После native filesystem проверки подключить actual ASGI send с immutable verified release context. Sink failure не продлевает trust deadline; logging overload не должен останавливать `/livez` или создавать неограниченную очередь для anonymous flood. Политика отказа защищённых endpoints должна быть явной, а не выводиться из одного `healthy=false`.
- При correlation сохранить различие release и qualification: `VerifiedRelease.request_sha256` представляет проверенную promotion selection, но `QualifiedCandidate` сейчас такого selection не имеет. Нельзя подставить proposal/permit hash в `selection_sha256` и назвать это approval. До actual-candidate audit определить отдельный versioned context с qualification scope; получать его из immutable verified reader result, не перечитывать mutable engine после отправки ответа. Обе ветви обязаны сохранить `release_ready=false`, пока настоящая release-приёмка не пройдена.

Приёмка storage slice сохраняет hard limits и воспроизводит negative cases; [RB-56/PB-30](../docs/operations/audit-retention-troubleshooting.md) продолжает RB-55/PB-29. Crash/reboot reconciliation остаётся отдельной незавершённой задачей, не разрешением удалить stale guard. До ASGI/canary/export проверки полный M13 остаётся открытым. Никакой автоматический purge текущих файлов этим планом не выполняется.

Storage quality slice выполнен на `42ce792`: непокрытые failure branches получили negative tests, отдельный >=95% branch gate по каждому audit-модулю прошёл. Нельзя заменять его итоговым Cover или выводить из него покрытие других модулей. Все 10 CI этой revision terminal: 6 success / 4 failure, M20 723/M21 122 pass; [matrix](../docs/evidence/audit-branches-2026-10-16.md) сохраняет image/ML failures. Historical checkpoint `b2b3bf6` оставлен в предыдущем evidence, не подменяет новый прогон.

Context slice реализован по [ADR 0038](../docs/decisions/0038-serving-audit-context.md): immutable release/qualification refs, reader -> Engine snapshot -> private HTTP handoff. Local 169 adjacent methods pass, context module 100%; [native 503b68b attempt 2](../docs/evidence/serving-context-2026-10-16.md) 72 cases pass. Failed attempts сохранены; M07 connection failure не объявлен исправленным. Следующий slice: совместимая версия audit event schema и привязка к фактическим ASGI send transitions. Failure-first cases должны запретить фиктивное response_completed после transport cancellation и успешный protected request при неподтверждённой audit admission. Проверить, что sink failure/overload не продлевает trust deadline, не создаёт anonymous unbounded queue и не останавливает liveness. Политику failure и объём зарезервированных событий на request зафиксировать до HTTP event подключения. После этого all-output canaries/cardinality на actual candidate; storage/context tests не принимают полный M13.

Historical source checkpoint до ADR 0038: `QualifiedCandidate` ещё не содержал permit/proposal, public dictionaries не переносили private context. Теперь verified reader result содержит отдельные qualification refs, Engine возвращает private typed result и HTTP не сериализует его context. Финальная проверка lease по-прежнему может заменить success на 503; это требует будущей корреляции с фактическим send, не только с намерением ответа.

По [ASGI HTTP specification](https://asgi.readthedocs.io/en/latest/specs/www.html), проверенной 2026-10-16, response.start ещё не гарантирует flush; успешный body send означает передачу в send buffer, не подтверждение чтения клиентом. Финальный body с more_body=false завершает response при отсутствии trailers. Поэтому отдельно проверить start/body/disconnect и не называть completed подтверждённой доставкой. Перед кодом выбрать и явно описать различие queue reservation, durable acknowledgement и фактически отправленного ответа: ошибка async sink после send не позволяет «отозвать» уже отправленный 200. Ни telemetry, ни ожидание fsync не должны продлевать trust deadline. Этот вопрос требует отдельного design/negative-test slice, а не замены понятия durability словом accepted.

Источники для проектирования повторно проверены 2026-10-15: [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) рекомендует исключать secrets, проверять log injection и resource exhaustion; [OpenTelemetry sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/) отдаёт приоритет минимизации и отдельно предупреждает об угадываемых hashes; [Prometheus instrumentation](https://prometheus.io/docs/practices/instrumentation/) объясняет стоимость каждого labelset. Конкретные границы выше - проектное применение этих принципов, не утверждение о внедрённых collector/Prometheus services.

**Результат:** benchmark, dashboards, маршрутизируемые alerts, отсутствие auto-promotion по drift. **Приёмка:** M14, M15. **Ограничение:** небольшой lab-run не подтверждает месячный SLO.

## Неделя 11: Security events и потеря telemetry

**Задачи:** T29. Реализовать семь event contracts, доверенных producers, bounded fields и воспроизводимый replay. Проверить forgery, duplicates, reorder, gaps и sink outage. Событие от model worker не получает автоматически статус достоверного security finding.

**Результат:** detection fixtures, измеренные alert/gap deadlines, запрет новой promotion без audit. **Приёмка:** M23. Sigma rules допустимы только после выбора backend и проверки его field mapping.

## Неделя 12: Безопасное изменение и recovery

**Задачи:** T19, T20. Выполнить staged rollout, failure-triggered rollback целого bundle, запрет rollback к отозванной версии. Создать согласованный backup metadata/artifacts и восстановить в независимый namespace/storage.

**Результат:** доказательства RTO/RPO, restore integrity и compatibility, утверждённые runbooks. **Приёмка:** M16, M17. Не ограничиваться `backup command exited 0`.

## Неделя 13: Сквозная приёмка и эксплуатационные долги

**Задачи:** T21, T22. Объединить M01-M17 и M19-M23 на одном candidate, проверить source/container/control-plane inventory, negative suite, coverage и evidence redaction. Добавить retention, expiry, отзыв dataset/model, безопасный teardown и оценку production delta.

**Результат:** воспроизводимый acceptance bundle и явно незакрытые риски. **Приёмка:** техническая часть M18. Если любой обязательный gate fail/inconclusive, не публиковать runtime как принятый.

## Неделя 14: Независимый review и передача

**Задачи:** T23, T24. Провести review угроз/гарантий и три демонстрации: clean release, tamper/poison rejection, recovery/revocation. Подготовить инструкции запуска, архитектурное объяснение, known limitations, release notes и sanitized evidence.

**Результат:** R1 reference release при выполненных gates; отдельный go/no-go документ по реальным данным. **Приёмка:** M18 целиком. Если второго человека нет, self-review помечается именно так; production go-live не разрешается автоматически.

## Недели 15-16 и календарный резерв

При необходимости завершить integration/review fixes и повторить затронутые gates. Не заполнять свободное время добавлением новых платформ. Отдельный резерв 25% покрывает discovery и задержки; при его расходовании пересчитать прогноз, а не сокращать обязательные отрицательные проверки.

## Что происходит после reference

R2 пилот требует отдельного решения владельца: разрешённые реальные данные, privacy/retention requirements, стоимость ошибок, независимые approvals, TLS/identity/KMS и внешнее резервирование. Shadow-оценка должна пройти достаточный полный label horizon; календарный план не может сократить эту физическую задержку.

R3 production не фиксируется произвольной датой без требований по нагрузке, доступности, юрисдикции и бюджету. GPU/LLM/feature store добавляются только через отдельный ADR и новый профиль приёмки.

## Промпт для следующей цели

> Реализуй R1 trusted MLSecOps reference по GOAL.md, tasks/todo.md и docs/acceptance.md. Начни с T01-T02 и read-only inventory; не меняй действующую foundation без отдельного плана миграции. Используй первоисточники для pinned-версий, сначала negative tests и малые проверяемые шаги. Выполняй T25-T29 по зависимостям, а не после T24; сохраняй worker/controller boundary и fail-closed intake. Храни реальные данные/ключи вне Git, не обходи policy и не называй synthetic utility реальной. Для каждой задачи сохраняй sanitized evidence и обновляй статус только после проверки конечного состояния. Production, облачные расходы и настоящий dataset требуют отдельного согласованного контекста. Цель завершена только при M01-M23 pass на одном candidate, M18 как итоговом агрегаторе и опубликованных ограничениях.
