# Backlog реализации

T03, T04 и T26 завершены для synthetic-only профиля; остальные **26 задач открыты**, реализация начата 2026-10-07. Результаты и границы каждой приёмки в [STATUS](../STATUS.md). Каждый раздел - результат одной или нескольких коротких итераций. Номера gates ссылаются на [полную приёмку](../docs/acceptance.md). Runner `mlsecops.acceptance` выполняет M02, M03, M06, M07, M20 и M21, а неподключённые полные проверки возвращают inconclusive. Эти gates не закрывают автоматически более широкий T07-T10/T27 lifecycle. T25-T29 добавлены исследованием R0.2; ID сохраняют историю, порядок задают зависимости и [календарный план](plan.md). Ранняя проверка компонента не заменяет позднюю интеграционную приёмку.

## T01
- [ ] Scope, inventory и acceptance runner. Зависимости: нет. Gate: M01.
- Результат: требования к labels/данным, resources inventory, machine-readable report schema и CLI runner с явным fail для отсутствующих checks.
- Проверка: недоступный tool/несовместимый foundation блокирует bootstrap; повторная инвентаризация не меняет текущий runtime.

## T02
- [ ] Foundation P0 и совместимые зависимости. Зависимость: T01. Gate: M01.
- Новый component 2026-10-11: [candidate storage rehearsal](../docs/storage-candidate.md), 434 native checks, 1 000 golden predictions/error 0.0 и 47 controlled contracts локально и в [CI 3b4aaa0](../docs/evidence/storage-candidate-2026-10-11.md). Source/target свежие, working SQL не меняется. Подтверждена совместимость, не security adoption; отдельный pull failure сохранён как inconclusive. Baseline storage/developer/Kubernetes regression прошла, M20 722 checks; новый security scan fail, candidate storage 3 Critical/88 High, worker 55 High.
- Прогресс: [storage snapshot/restore](../docs/storage-recovery.md) сохраняет ledger; baseline [image audit](../docs/container-audit.md) дал fail: worker 56 High, storage 7 Critical/101 High matches. [69 triage groups](../docs/evidence/container-audit-2026-10-08.md) сохранены. [Candidate experiment локально и в CI](../docs/evidence/image-candidates-2026-10-09.md) повторил 74 worker и 123 audit/candidate checks. Same-DB comparison: worker 55 High, storage 1 Critical/79 High и четыре новых advisory IDs; оба candidates fail. Далее: supported runtime remediation и scoped storage restore-to-new-target, без смены working SQL. Полный inventory, P0 и adoption ещё не приняты.
- Результат: pinned version matrix, отдельное окружение, проверка registry maintenance path, storage decision, идемпотентный bootstrap и rollback migration plan.
- Проверка: два bootstrap, schema migration/restore smoke, отсутствие потери артефактов/ключей; lockfile и runtime соответствуют inventory.

## T03
- [x] Dataset generator, schema и passport. Зависимость: T02. Gate: M02.
- Evidence: 44 source/intake checks, schema/expiry/feedback/signature negatives и dataset card. Только синтетика; unresolved foundation P0 не объявляются закрытыми этим gate.
- Результат: deterministic synthetic generator, data dictionary, ranges, source approval, label/split policy; роли владельцев отмечены.
- Проверка: valid/invalid fixtures, отсутствие PII и train-test leakage, точное повторение generated inputs.

## T04
- [x] Quarantine, versioned source и signed manifests. Зависимость: T03. Gates: M02, M03.
- Evidence: [executable M03](../docs/integrity-gate.md), 36 файловых fixtures, 367 SQL/TLS checks, 26 pipeline checks и 2 сквозные проверки. Доверенные curator/host остаются допущением; M04/M20 не закрыты.
- Решение: DVC не принят после dependency security spike; [ADR 0005](../docs/decisions/0005-data-lineage.md) заменяет его фиксированным source lock без изменения acceptance. M02 и M03 работают, незакрытые foundation P0 не объявляются решёнными этим gate.
- Результат: state machine dataset, artifact hashes, split manifests, rejection report и storage permissions.
- Проверка: single-byte tamper, source expiry, traversal/symlink, duplicate rows, missing object; approved версия не перезаписывается.

## T05
- [ ] Identity и изоляция. Зависимость: T04. Gate: M04.
- Прогресс: отдельные namespaces/ServiceAccounts, реальные API denials, Cilium probes и SQL storage ACL работают. [Private cluster storage](../docs/private-cluster-storage.md) прошёл 436 component checks; полная интеграция identities, включая serving, ещё не завершена.
- [Signed migration](../docs/cluster-storage-migration.md) прошла 497 локальных checks. Следующий [controller component](../docs/scoped-controllers.md) прошёл 133: scoped RBAC/admission, API TLS и реальное обучение/оценка из отдельных Jobs. Это не закрывает полный M04.
- Результат: role/access matrix, namespace/storage/network policies и restricted service accounts.
- Проверка: фактические разрешённые/запрещённые операции trainer/evaluator/serving, не только RBAC simulation.

## T06
- [ ] Sandboxed training Jobs. Зависимость: T05. Gate: M05.
- Прогресс: настоящий Job backend, admission, deadline, PID/OOM/egress probes и cleanup проверены; влияние на будущий настоящий serving service ещё не измерено.
- Результат: Job runner без host privileges, лимиты, deadlines, pinned image и cleanup.
- Проверка: denied egress, timeout, memory exhaustion, отсутствие signing secrets и влияния на serving.

## T07
- [ ] CPU pipeline и export. Зависимость: T06. Gate: M06.
- Интеграция 2026-10-11: [общий M06 dispatcher и CI evidence](../docs/reproducibility-gate.md) заново запускает campaign и сверяет файлы/requests/digests/MLflow. Локально и в clean-checkout run `38136658929` на `c9e672f` прошли 18 cases и 47 controlled contracts. Это численная приёмка, не автоматическое завершение всего T07/T08 lifecycle.
- Новый component 2026-10-11: [native reproducibility campaign](../docs/reproducibility.md), три fresh-process повтора и по одному actual seed/data/environment изменению. Локально 6 training/6 prediction/6 MLflow records, 33 controlled comparator cases; baseline difference 0.0, mutations не приняты как повторы. Полный gate/dispatcher не закрыт. Добавлены [ранбуки и read-only плейбук](../docs/runbooks.md).
- Результат: preprocess/train DAG с seed/hyperparameters и machine-readable outputs; fit только на train.
- Проверка: три fresh-process runs, сравнение входов и predictions; mutation inputs не маскируется cache hit.

## T08
- [ ] MLflow tracking и lineage. Зависимость: T07. Gate: M06.
- Новый local component: [PostgreSQL/TLS service и CI](../docs/tracking-service.md), отдельные DB identities, host publisher, persistence обеих services. Локально и в clean-checkout run `38131527513` на `40d26dc` прошли 54 native + 16 controlled checks и 74 worker checks. T08 остаётся открытой: Kubernetes publisher, metadata-loss/recovery и полный M06 ещё нужны.
- Прогресс: [MLflow 3.17.0 spike и clean-checkout CI](../docs/tracking-spike.md): отдельный hashed lock, 91 package dependency audit без findings/skips локально; audit, три реальные training runs и 53 HTTP access/artifact/restart checks повторены в CI `a48a9dc`, run `38129646455` success. Это offline SQLite probe, не замена PostgreSQL/TLS или завершённая интеграция publisher; последующая native mutation campaign описана в T07.
- Результат: защищённый MLflow, отдельная metadata DB, run-to-material binding и artifact access tests. Только внешний publisher получает право записи; training worker не получает его credentials.
- Проверка: anonymous/чужая identity запрещены, потеря metadata не меняет runtime alias, повторное обучение сохраняет отдельные runs.

## T09
- [ ] Frozen evaluation policy. Зависимость: T08. Gate: M07.
- Increment 2026-10-11: [единый M07](../docs/evaluation-gate.md) заново исполняет controlled/native checks и сверяет source/policy/data/request/evaluation. Локально и в clean-checkout CI `38142949998` на `51ddfef` прошли 86 cases. Более широкая зависимость T08 сохраняется.
- Результат: model card, clean baseline, slice definitions, threshold/CI policy до final holdout, бизнес-dataset stop conditions.
- Проверка: dummy comparison, sample counts, disjoint entities и label maturity; недостаток данных = inconclusive.
- Предыдущий component increment 2026-10-11: [code-bound frozen lab policy](../docs/frozen-evaluation.md), explicit inconclusive, DummyClassifier AP equivalence, paired IID intervals и controlled train-only preprocessing. Позже включён в M07; зависимости T08 остаются открытыми.

## T10
- [ ] Independent evaluator. Зависимости: T09, T26. Gate: M07.
- Follow-up 2026-10-11: [RB-27](../docs/operations/qualification-environment-troubleshooting.md) сохраняет M07 concurrent-denial failure на первом CI attempt и success одного повторного запуска без изменения кода. Bounded receipt diagnostics реализована с 11 redaction/propagation tests и exact receipt binding, без ослабления budget/assertion. Причина старого отказа остаётся unknown, а не исправленной задним числом; новые CI outcomes в STATUS.
- Increment 2026-10-11: M07 dispatcher связывает signed report с первичными SQL materials, проверяет budget во второй owned БД, отвергает stale/partial evidence. 13 runner tests, 100% gate statements/branches локально. Это не завершение всего T10 и не разрешение release.
- Результат: trusted scorer вне prediction worker, holdout access budget, signed subject-bound evaluation reports. Labels и signing keys недоступны worker.
- Проверка: report swap, попытка trainer прочесть holdout, missing metric, signature mismatch; deny self-approval.
- Increment 2026-10-11: [read_evaluation](../mlsecops/storage_pipeline.py) сверяет expected candidate, signed metrics, execution/protocol и существующий reservation; native promoter read-back без labels. 24 native SQL/model checks, не общая M07-приёмка.
- Предыдущий component increment 2026-10-11: [постоянный holdout budget](../docs/operations/holdout-budget.md) в SQL/scoped-controller scorer, atomic reservation до labels/worker, signed receipt, concurrent processes/restart/new-run negatives. Позже включён в M07, но полный T10 остаётся открыт; восстановление старого snapshot не имеет внешнего anti-rollback witness.

## T11
- [ ] Poisoning benchmark. Зависимость: T10. Gate: M08.
- Сверка evidence 2026-10-11: [primary-material verifier](../docs/poisoning-benchmark.md) заново вычисляет все метрики и связывает 35 cases с 251 сохранённым файлом. Локально integrity pass при неизменном robustness fail; 17 verifier tests. Это компонент, не полный M08 и не устранение 10 measured violations.
- Increment 2026-10-11: [native 30+5 matrix](../docs/poisoning-benchmark.md), protocol frozen до запуска. Локально 35 trainings/35 predictions; 10 targeted-ASR violations при 5% poisoning. M08/T11 не закрыты: failure не waived, нужна общая gate/material integration и последующее обоснованное устранение риска. Independent M22 challenges не выполнены.
- Результат: clean controls + label-flip/backdoor matrix, ASR/CIs/utility deltas и полный отчёт failures/bypasses.
- Проверка: known-violation fixtures блокируются, challenge outcomes не скрываются, train-only attacker budget соблюдён.

## T12
- [ ] Safe format и robustness probes. Зависимость: T11. Gate: M09.
- Mitigation 2026-10-13: [paired robust training](../docs/robust-training-protocol.md), [PB-19/RB-37](../docs/operations/robust-training-troubleshooting.md). 14 native workers/47 primary files; candidate сохраняет utility, но recall drop 0.052245/0.062241/0.061433 всё ещё >0.05. Кандидат не adopted, исходные thresholds не менялись. [Evidence](../docs/evidence/robust-training-2026-10-13.md); следующий design review должен учитывать clean/attacked TP и новые независимые проверки, не tuning на опубликованных probes. Полный M09 остаётся открыт.
- Increment 2026-10-13: [frozen evasion/domain support](../docs/robustness-protocol.md), [PB-18/RB-36](../docs/operations/robustness-troubleshooting.md). Исполняемый abstain core и реальные isolated train/intake/prediction probes; 17 controlled methods, два local replays, 12 outside-support abstentions. Измерено падение recall 0.07183673469387755 >0.05; failure не waived. Следом нужны заранее обоснованные mitigations с независимыми probes, release/serving integration и общий M09. Наличие OOD guard не устраняет атак внутри [0,1]^6.
- [Clean-checkout CI 5e3bb21](../docs/evidence/robustness-2026-10-13.md) подтвердил execution complete, primary readback и те же metrics, source_dirty=false; workflow failure не подавлен. M20/M21 и functional regression остались pass. Это evidence выявленного риска, не закрытие T12/M09.
- Компонент 2026-10-11: [linear-onnx-v2](../docs/model-contract.md), точный graph/parameter/output contract, 1000-row real CPU parity и отрицательные fixtures. Evasion, OOD/abstain и полный M09 остаются открытыми.
- Результат: ONNX allowlist, parity report, declared evasion suite, ограниченный OOD/abstain policy.
- Проверка: pickle/external tensor/custom operator/oversized graph отклоняются до load; golden cases соответствуют Python output.

## T13
- [ ] Release bundle и promotion verifier. Зависимости: T12, T25, T27. Gate: M10.
- Проверенный increment 2026-10-14: [durable SQL journal + signed-chain admission](../docs/promotion-ledger.md), [PB-21/RB-40/RB-41](../docs/operations/promotion-ledger-troubleshooting.md). Current retry, sequence/expiry/concurrency и event readback; 108 native SQL checks и 106 local methods pass, [evidence](../docs/evidence/promotion-ledger-2026-10-14.md). Scoped controller/serving, trust lifecycle и полный backup/restore ledger ещё не приняты, T13 остаётся открыт.
- Increment 2026-10-14: [release descriptor, supplemental materials и отдельная авторизация](../docs/release-authorization.md); SQL proposal readback и fail-closed M01-M23 report contract. [PB-20/RB-38/RB-39](../docs/operations/release-authorization-troubleshooting.md), [evidence](../docs/evidence/release-authorization-2026-10-14.md). Durable state transition/concurrency/replay, scoped controller, полный общий evidence bundle и M10 ещё нужны. Не использовать controlled all-pass fixtures для native approval.
- Foundation 2026-10-11: [signed candidate materials](../docs/material-bundle.md), 9-object verification closure, offline signature/binding checks, SQL publication/serving readback, 12 native checks. [PB-11/RB-22/RB-23](../docs/operations/material-bundle-troubleshooting.md). Capsule unapproved; full release schema, ML-BOM/model card, approval, full gates и promotion state machine ещё нужны. Это не M10 pass и не закрытие T13.
- Результат: versioned format, signatures/envelopes, subject/environment/policy binding, approval и idempotent state transition.
- Проверка: весь negative promotion suite; данные, model, report и runtime image проверяются как один release.

## T14
- [ ] Trust lifecycle. Зависимость: T13. Gate: M11.
- Increment 2026-10-14: [ADR 0029](../docs/decisions/0029-online-trust.md), отдельная TLS SQL authority, root-signed policy/version, irreversible revoke и lease максимум 60 s с учётом задержки/expiry/clock rollback. Promotion SDK требует fresh read; [PB-23/RB-44/RB-45](../docs/operations/trust-troubleshooting.md) и [evidence](../docs/evidence/online-trust-2026-10-14.md). Serving endpoint, root rotation, rollback authorization и полный M11 не закрыты этим компонентом.
- Результат: revocation/expiry policy, trust lease, key rotation и контролируемый rollback authorization.
- Проверка: old policy/foreign environment/replay/revoked signer/clock skew; отказ после истечения lease без тихого fallback.

## T15
- [ ] Inference API и loader. Зависимость: T14. Gate: M12.
- Результат: API schema, verified readiness, atomic bundle load и явные ошибки/abstain.
- Проверка: request limit suite, malicious paths/URLs не поддерживаются, TOCTOU и missing signature не дают ready.

## T16
- [ ] Privacy, quotas и audit. Зависимость: T15. Gate: M13.
- Результат: auth, per-client throttling, redaction, bounded-cardinality telemetry и trace-to-release correlation. Public evidence не содержит приватных identifiers/URLs или угадываемых hashes чувствительных значений; masking не объявляется differential privacy.
- Проверка: test canaries не появляются в logs/evidence, чужие identity отвергаются, raw features не сохраняются по умолчанию.

## T17
- [ ] Нагрузочный профиль. Зависимость: T16. Gate: M14.
- Результат: benchmark runner, client-side distribution, resource measurements и overload decision.
- Проверка: воспроизводимый payload/compute profile, отдельные intentional negatives, отсутствие скрытого исключения timeouts.

## T18
- [ ] Model/data/security monitoring. Зависимость: T17. Gate: M15.
- Результат: scheduled reports, dashboards, alert routing, drift versus label-quality distinction и feedback quarantine.
- Проверка: injected shift, degraded labels, clean windows, telemetry outage; ни один alert не повышает candidate автоматически.

## T19
- [ ] Canary и rollback. Зависимость: T18. Gate: M16.
- Результат: staged rollout, совместимость целого bundle и manual-review fallback.
- Проверка: failure injection с измерением времени, запрет отозванного previous release, отсутствие смешанных preprocessing/model.

## T20
- [ ] Backup и независимый restore. Зависимость: T19. Gate: M17.
- Increment 2026-10-14: [signed snapshot v2 CAS + promotion journal](../docs/decisions/0028-promotion-recovery.md), [PB-22/RB-42/RB-43](../docs/operations/promotion-recovery-troubleshooting.md), [evidence](../docs/evidence/promotion-recovery-2026-10-14.md). External backup pin, exact readback, maintenance и неизменяющий retry; 36 source-offline native checks и 1 000 golden predictions/error=0.0 на `8f94e2e`, отдельно 125 local methods pass. Автоматический pre-receipt resume, current trust/serving recovery и расписание ещё не приняты; T20/M17 остаются открытыми.
- Прогресс: native consistent SQL backup, signed manifest, fresh storage restore, 430 component checks и 1 000 golden predictions работают. Нет полного release/serving recovery, актуального trust-service revocation и ежедневного расписания, поэтому задача и M17 остаются открытыми.
- Результат: metadata/artifact backup manifest, recovery runbook и evidence из нового namespace/storage.
- Проверка: RTO/RPO, corrupt/missing blob, denied expired/revoked trust, golden predictions после restore.

## T21
- [ ] Сквозной release acceptance. Зависимости: T20, T25, T26, T27, T28, T29. Gate: M18.
- Результат: M01-M17 и M19-M23 reports на одном candidate, completeness check и source fingerprint. M18 агрегирует все gates и выполняется последним.
- Проверка: любой missing/fail/inconclusive report блокирует final acceptance; сканирование всего заявленного ML runtime scope.

## T22
- [ ] Lifecycle и production delta. Зависимость: T21. Gate: M18.
- Результат: retention/expiry/decommission policy, resource/cost estimate, safety/privacy risks и список внешних предпосылок пилота. Риск-ориентированный scope и пересмотр источников по изменению угроз; LLM/MCP остаются отдельным треком.
- Проверка: delete/retire fixture не ломает действующий referenced bundle, отозванная версия больше не serve; backup retention согласован.

## T23
- [ ] Независимый review и game day. Зависимость: T22. Gate: M18.
- Результат: review log, проверка заявлений, clean/tamper/recovery демонстрации и residual risk sign-off.
- Проверка: повтор runbooks по инструкции другим человеком; при self-review явно указать отсутствие независимости.

## T24
- [ ] Документация и reference release. Зависимость: T23. Gate: M18.
- Результат: инструкции запуска/удаления, model/dataset cards, release notes, sanitized evidence и честные known limitations.
- Проверка: clean checkout walkthrough, ссылки/секреты/CI, повторная проверка опубликованного commit и артефактов; реальный pilot не объявлен автоматически.

## T25
- [ ] Inventory graph и reconciliation. Зависимости: T04, T08. Gate: M19.
- Прогресс: [collector signed candidate](../docs/candidate-lineage.md) строит реальную metadata projection из SQL без holdout reads, проверяет curator/evaluator/build bindings. 18 collector + 8 runner tests, отдельный native SQL replay; [PB-10/RB-20/RB-21](../docs/operations/candidate-lineage-troubleshooting.md). Это один candidate, не persistent deployed inventory; dedicated read-only role, lifecycle и serving integration ещё нужны.
- Прогресс 2026-10-11: [структурный компонент](../docs/asset-graph.md) и [PB-09/RB-19](../docs/operations/asset-graph-troubleshooting.md). Strict schema v1, typed digest-bound edges, completeness/digest сверка observations и exact impact с aliases. 25 local tests, 100% statements/branches. Fixture 2 datasets/3 models/4 deployment records не является live serving; signed ingestion, durable/current revocation, collector и M11 integration остаются открыты.
- Результат: versioned asset schema, owners, dependency graph, точный impacted set и блокировка неизвестных assets. В недели 4-5 готовится компонент; после T14-T15 проверяется интеграция отзыва до serving.
- Проверка: fixture M19, dangling/cyclic reference, unknown owner, alias/digest mismatch; интеграционный отзыв ancestor укладывается в M11 и не затрагивает независимую ветвь.

## T26
- [x] Worker/controller boundary. Зависимости: T05, T06. Gate: M20.
- [Исполняемый M20](../docs/worker-authority-gate.md) прошёл локально и в [clean-checkout CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37835470267) на `2831d6c`: 722 cases, включая 19 native malformed responses без sign/write, два настоящих positive controls, subject binding и cleanup. T26 закрыта для текущего synthetic local scope. Непроверенные serving permissions/stress части T05/T06 этим не закрыты.
- [ADR 0010](../docs/decisions/0010-scoped-controllers.md) реализован как component: cross-namespace RBAC, native admission, projected controller tokens, bounded API transport и отдельные worker Jobs.
- [Prediction protocol v2](../docs/prediction-protocol.md) прошёл 164 contract checks и 136 controller checks: одноразовый consume, row order и request/image binding до подписи. [Live access component](../docs/live-worker-boundary.md) прошёл 137 checks, включая `/proc` живого scorer, актуальные credentials и SQL/API. M20 заново запускает эти suites вместе с native output matrix. Это не persistent holdout budget M07.
- Результат: изолированные training/prediction workers, publisher/scorer с отдельной identity, typed bounded prediction protocol. Контракт и компонентные fixtures готовы до T10; полная проверка с evaluator завершается в T10.
- Проверка: попытки чтения labels/keys/DB/service-account token и /proc соседнего controller запрещены; malformed/replayed/oversized outputs не становятся подписанным результатом.

## T27
- [ ] Artifact intake coverage. Зависимости: T12, T26. Gate: M21.
- Текущий результат: **[M21 122/122 pass на 04b5e78](../docs/evidence/intake-acceptance-2026-10-13.md)**, source_dirty=false. Scoped-controller matrix, Job deadline/process failure, две durable denials и независимый promoter readback выполнены в clean-checkout CI. [PB-17/RB-35](../docs/operations/scoped-intake-troubleshooting.md). T27 не закрыта автоматически: T12 и release/serving integration ещё не завершены; preflight outcome persistence имеет отдельный remaining scope. Следующие пункты сохраняют историю прежних increments, не текущий статус gate.
- Исторический increment: [M21 reconciliation runner](../docs/intake-gate.md) исполняет fresh controlled/Docker/SQL cases и сверяет primary signed materials. [CI 12143a6](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38442903172) подтвердил 85 pass cases, source_dirty=false, но сохранял один обязательный inconclusive для scoped-controller native negative matrix. [PB-16/RB-34](../docs/operations/intake-gate-troubleshooting.md). Workflow failure/exit 2 не подавлялись; недостающий native replay теперь выполнен на 04b5e78, а не удалён из требований.
- Текущий increment: [ADR 0025](../docs/decisions/0025-signed-intake-denial.md), signed SQL denial с привязкой к candidate/reservation, идемпотентным readback и отказом при потере persistence. [CI на 10e5e8e](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38438233449) подтвердил 15 contracts и 25 native SQL checks: три denials, fresh-process signature readback, permissions и неизменность исходной evaluation. [PB-15/RB-32/RB-33](../docs/operations/intake-denial-troubleshooting.md) сохраняют порядок диагностики и границы проверки. Full M21 aggregator, preflight/filesystem outcomes, Kubernetes-specific denial replay и release integration остаются открытыми.
- Компонент 2026-10-13: [независимый intake](../docs/artifact-intake.md) обязателен до prediction, receipt проверяется в signed SQL reader; [PB-14/RB-29/RB-30](../docs/operations/artifact-intake-troubleshooting.md). Controlled protocol/path tests и native Docker faults выполнены; SQL durable failures добавлены следующим increment выше, полный M21 и release/serving integration ещё не завершены.
- Компонент 2026-10-11: scanner требует полностью проверенный двухузловой профиль, rejects unknown protobuf fields, receipt v2/2 nodes. Полный intake/conversion/path/timeout/crash gate не завершён; [PB-12](../docs/operations/model-contract-troubleshooting.md).
- Результат: quarantine report с declared format/tool coverage, scanned count, digest, policy version и явным inconclusive. Выбор scanner после проверки поддержки фактического ONNX-профиля.
- Проверка: unsupported/zero-scanned/crash/timeout/stale report, подмена digest и mutation после conversion блокируются; разрешённый clean ONNX проходит полный intake.

## T28
- [ ] Absolute-budget и независимые attack challenges. Зависимости: T10, T11, T12. Gate: M22.
- Результат: 36 poisoned runs + 6 clean controls, не менее двух отложенных reviewer challenges, заранее заданные attacker capabilities и корректная единица статистического анализа.
- Проверка: абсолютные бюджеты и доли записаны вместе, challenge не использован для tuning, hard-boundary bypass блокирует release, неопределённый результат не превращается в pass.

## T29
- [ ] Security event contracts и replay. Зависимости: T14, T18. Gate: M23.
- Результат: семь типизированных событий, trusted producers, schema validation, idempotent ingestion, gap/heartbeat detection и fail-closed promotion при недоступном audit sink.
- Проверка: positive/negative replay, forgery, duplicates, out-of-order, sequence gaps и sink outage; alert/gap latency измерены. Sigma добавляется только с выбранным и проверенным backend.
