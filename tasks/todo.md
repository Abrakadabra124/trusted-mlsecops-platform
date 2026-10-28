# Backlog реализации

T02 node candidate 2026-10-29: [native build/audit f8a15c4](../docs/operations/node-candidate.md#native-результат-2026-10-29-мск), builder success, audit fail; Critical/High 67/394 -> 61/349. Обновление только Kubernetes недостаточно, candidate не принят. Полный T02 остаётся открытым. Следующая обязательная работа CP2 - T12/M09 actual-candidate binding, формат, parity и frozen evasion без ослабления исходных критериев.

T02 2026-10-29 МСК: [native diagnostic scan](../docs/evidence/cp2-system-images-2026-10-28.md#native-diagnostic-scan-завершён-2026-10-29-мск) завершён: 14/14 scanned, 4/14 application coverage, fail; Go controls и cleanup pass. [Node patch candidate 1.36.6](../docs/operations/node-candidate.md) реализован для отдельного hosted build/audit, без adoption, native ещё требуется. Остальные R1 blockers сохраняются. Предыдущие записи ниже являются историей этапа.

T02 update: Cilium 1.20.4 regression прошла M01/M04/M05/M21; optional-distro fix подтверждён 14/14 native observations при прежнем coverage 4/14. Оба Go controls прошли native на f12476c. Diagnostic scan unapproved system inventories реализован без возможности pass: **197 audit cases + 12 tests pass**, native ожидается. [Evidence](../docs/evidence/cp2-system-images-2026-10-28.md). System application coverage, реальные CVE и model failures остаются обязательными блокерами CP2.

T02 system coverage 2026-10-28: [фактические packages и main checkpoint](../docs/evidence/cp2-system-images-2026-10-28.md), observed 4/14 coverage / 13 package observations, main 7 success / 3 failure. Optional-distro diagnostics исправлена и проверена controlled tests; native verification ожидается. Cilium 1.20.4 закреплён, отдельные Kubernetes/audit runs выполняются. Следом application profiles и remediation реальных system findings, без waivers и без ослабления model gates.

T02 2026-10-28: [новый storage artifact опубликован и принят компонентными проверками](../docs/evidence/cp2-runtime-adoption-2026-10-28.md), immutable/anonymous readback pass, общий pin обновлён для fresh states. filelock/MLflow fixed locks проходят audit с неизменным source output. Developer/Storage/Kubernetes на `1dc1f05`, исправленный Tracking и полный component image audit на `37fe32b` success. Полное observed system/application coverage и model gates остаются обязательными; T02/CP2/R1 не закрыты.

**Активная очередь:** [R1-B01-R1-B08 и CP1-CP5](../docs/r1-delivery.md), следующий checkpoint CP2 после принятых M01/M04/M05. Общий entrypoint R1-B01 остаётся обязательным до финальной приёмки. Исторические Txx/gates ниже не удалены и не ослаблены. [FI backlog](../docs/future-improvements.md) не исполняется до R1 и явной команды владельца; новую работу привязывать к обязательному blocker/criterion.

T16 current: [ADR 0049 private primary audit evidence](../docs/decisions/0049-private-audit-evidence.md), **[native a7a09c8 verified](../docs/evidence/audit-evidence-a7a09c8-native.md)**: 85 cases, Linux 20 packet / 26 parent-output / 56 export-IO tests без skips, 10 terminal CI: 6 success / 4 failure. [Evidence](../docs/evidence/audit-evidence-2026-10-20.md) сохраняет replay/ledger/fsync RED и review; [RB-68/PB-42](../docs/operations/audit-evidence-troubleshooting.md). Не закрывать task по этому компоненту: production lifecycle/429/503 privacy, service logs, subject composition и public gate projection ещё обязательны.

T16 approved metrics: **native 93de1b6 verified**, 35 metrics tests / 0 skips, collector/probe 100%, 78 actual-candidate cases и 69 approved samples. [Evidence](../docs/evidence/serving-metrics-2026-10-19.md): 10 terminal CI, 6 success / 4 failure; source-lock correction подтверждена, исторический fail сохранён. [RB-62/PB-36](../docs/operations/serving-metrics-troubleshooting.md). Остались controller/all-output/export/correlation, полный M13 и image/ML blockers.

T16 worker increment: безопасная диагностика CLI/import и Linux core/dumpability guard реализованы; [native d2c48bf](../docs/evidence/worker-privacy-2026-10-19.md): 13 tests / 0 skips, guard 100%, 77 candidate cases pass. Intake test regression исправлена и проверена Linux CI: 36 Developer tests, Intake 66/66, M21 122 pass. Все 10 CI terminal: 6 success / 4 failure; Windows symlink error и image/ML blockers сохранены. Не закрывает весь worker/controller output scope или M13. [RB-61/PB-35](../docs/operations/worker-privacy-troubleshooting.md).

T16 update 2026-10-19: [existing output privacy](../docs/evidence/serving-privacy-2026-10-19.md) проверена на native 621d355: 17 privacy tests / 0 skips, 77 actual-candidate cases, 12 privacy requests / 36 durable events. Все 10 CI terminal: 6 success / 4 failure, M20 723/M21 122 pass; четыре image/ML failures сохраняются. T16 открыта: worker channels/metrics/cardinality/export/full correlation не закрыты; [RB-60/PB-34](../docs/operations/serving-privacy-troubleshooting.md).

T01, T03-T06 и T26 завершены для synthetic-only профиля; остальные **23 задачи открыты**, реализация начата 2026-10-07. Результаты и границы каждой приёмки в [STATUS](../STATUS.md). Каждый раздел - результат одной или нескольких коротких итераций. Номера gates ссылаются на [полную приёмку](../docs/acceptance.md). Runner `mlsecops.acceptance` выполняет M01-M08, M20 и M21, а неподключённые полные проверки возвращают inconclusive. Исполняемый M08 подтверждён отказом на фактическом candidate, а не passing robustness. Эти gates не закрывают автоматически более широкий T02/T07-T11/T27 lifecycle. T25-T29 добавлены исследованием R0.2; ID сохраняют историю, порядок задают зависимости и [календарный план](plan.md). Ранняя проверка компонента не заменяет позднюю интеграционную приёмку.

## T01
- [x] Scope, inventory и acceptance runner. Зависимости: нет. Gate: M01.
- CP1 `ab00a4e`: M01 pass / 10 cases из clean hosted checkout; [доказательства](../STATUS.md). T02 image/P0 remediation и общий продуктовый walkthrough ещё не приняты.
- Результат: требования к labels/данным, resources inventory, machine-readable report schema и CLI runner с явным fail для отсутствующих checks.
- Проверка: недоступный tool/несовместимый foundation блокирует bootstrap; повторная инвентаризация не меняет текущий runtime.

## T02
- [ ] Foundation P0 и совместимые зависимости. Зависимость: T01. Gate: M01.
- CP2 image scope: [наблюдаемый inventory](../docs/container-audit.md#фактические-образы-среды-cp2) проверен в native [40750705961](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40750705961): 14 images, полное coverage 4/14, before/after reconciliation пройдена, audit fail. Текущий collector: 18 methods / 66 branches pass; 185 audit cases pass. Application profiles и устранение findings ещё требуются; T02/R1-B02 открыты.
- История CP2 2026-10-28 до adoption: [tracking включён в обязательный audit](../docs/container-audit.md#расширение-cp2-на-tracking), native scan выявил 56 High matches. [Brotli remediation](../docs/operations/image-audit-troubleshooting.md#cp2-brotli-в-закреплённых-wolfi-images) на `edc6862` прошла 74 worker / 435 storage checks, 1 000 golden rows/error 0.0; worker и оба candidates имели 0 Critical/High/Unknown, baseline storage оставался уязвим. Последующие publication, immutable readback, fresh-state adoption и five-workflow regression подтверждены [новым evidence](../docs/evidence/cp2-runtime-adoption-2026-10-28.md). Исторический failure сохранён; T02/CP2 не закрыты из-за полного runtime scope и model gates.
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
- [x] Identity и изоляция. Зависимость: T04. Gate: M04.
- CP1 `61c6849`: M04 pass / 764 cases, полные native API/SQL/network matrices связаны с текущими resource/source/image identities. Основной review и проверка трёх fixes завершены; [run и доказательства](../STATUS.md), [runbook](../docs/kubernetes-lab.md#cp1-m04m05-и-отказ-training-при-настоящем-inference). M05 и общая R1-приёмка отдельно открыты.
- Прогресс до CP1: отдельные namespaces/ServiceAccounts, реальные API denials, Cilium probes и SQL storage ACL. [Private cluster storage](../docs/private-cluster-storage.md) прошёл 436 component checks; теперь включён в свежую полную M04 integration вместе с serving identities.
- [Signed migration](../docs/cluster-storage-migration.md) прошла 497 локальных checks. Следующий [controller component](../docs/scoped-controllers.md) прошёл 133: scoped RBAC/admission, API TLS и реальное обучение/оценка из отдельных Jobs. Это не закрывает полный M04.
- Результат: role/access matrix, namespace/storage/network policies и restricted service accounts.
- Проверка: фактические разрешённые/запрещённые операции trainer/evaluator/serving, не только RBAC simulation.

## T06
- [x] Sandboxed training Jobs. Зависимость: T05. Gate: M05.
- CP1 `ab00a4e`: M05 pass / 58 cases, 13 overlapping Running observations при deadline/OOM и неизменный actual-candidate HTTP/ONNX inference до/во время/после. Native `61c6849` fail на отсутствующем proposal report сохранён; исправление принято новым native запуском. [Доказательства и границы](../STATUS.md). Не control HTTP fixture, не release approval и не M14 load acceptance.
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
- CP2 2026-10-28: [fresh candidate-bound M08](../docs/poisoning-benchmark.md#исполняемый-m08-для-существующего-кандидата) проверен в [40747492224](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40747492224), `518ada6`: 68 checks, 35 trainings/predictions, 251 primary files, actual model replay error 0.0. Gate fail: 10 violations при 5% poisoning; release_ready=false. Интеграция завершена, устойчивость и независимые M22 challenges остаются открыты. Подробнее в [STATUS](../STATUS.md).
- Сверка evidence 2026-10-11: [primary-material verifier](../docs/poisoning-benchmark.md) заново вычисляет все метрики и связывает 35 cases с 251 сохранённым файлом. Локально integrity pass при неизменном robustness fail; 17 verifier tests. Это компонент, не полный M08 и не устранение 10 measured violations.
- Increment 2026-10-11: [native 30+5 matrix](../docs/poisoning-benchmark.md), protocol frozen до запуска. Локально 35 trainings/35 predictions; 10 targeted-ASR violations при 5% poisoning. M08/T11 не закрыты: failure не waived, нужна общая gate/material integration и последующее обоснованное устранение риска. Independent M22 challenges не выполнены.
- Результат: clean controls + label-flip/backdoor matrix, ASR/CIs/utility deltas и полный отчёт failures/bypasses.
- Проверка: known-violation fixtures блокируются, challenge outcomes не скрываются, train-only attacker budget соблюдён.

## T12
- [ ] Safe format и robustness probes. Зависимость: T11. Gate: M09.
- 2026-10-29: [M09 actual-candidate integration](../docs/evidence/m09-candidate-2026-10-29.md) проверена native `0150f62`: 42 cases, 18 001 predictions, 3 000 golden rows/error 2.086162567138672e-07, 0 mismatches, 12 abstentions, 28 primary files. Evasion fail 0.07183673469387755 >0.05 сохранён, SQL cleanup pass. 20 gate/regression + 35 controlled methods pass; 146/146 statements, 34/34 branches. Полный T12/M09 и прежние T02/T11 blockers остаются открытыми.
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
- Increment 2026-10-14: [ADR 0029](../docs/decisions/0029-online-trust.md), отдельная TLS SQL authority, root-signed policy/version, irreversible revoke и lease максимум 60 s с учётом задержки/expiry/clock rollback. На `214cc3c` 45 native checks pass, реальный outage denial 59.992019191 s; 156 local adjacent methods pass. Promotion SDK требует fresh read; [PB-23/RB-44/RB-45](../docs/operations/trust-troubleshooting.md) и [evidence](../docs/evidence/online-trust-2026-10-14.md). Serving endpoint, root rotation, rollback authorization и полный M11 не закрыты этим компонентом.
- Результат: revocation/expiry policy, trust lease, key rotation и контролируемый rollback authorization.
- Проверка: old policy/foreign environment/replay/revoked signer/clock skew; отказ после истечения lease без тихого fallback.

## T15
- Slice после `cdea4236`: [HTTP outage trace](../docs/evidence/http-trust-outage-2026-10-15.md) и [RB-52](../docs/operations/candidate-serving-troubleshooting.md). Native `2905e70` выявил late 503 60.082361397 s; [ADR 0033](../docs/decisions/0033-serving-retirement.md) отделяет invalidation от cleanup. **На `e9120e0` 46 cases pass, первый 503 59.995078784 s**. Failure-first tests и оба traces сохранены. Далее bounded response при slow/blackholed trust reads и оставшаяся production Reader/privacy/audit acceptance; один stopped-authority run не закрывает полный M11/M12.
- Новый qualification path после `afdc05c`: [ADR 0032](../docs/decisions/0032-candidate-serving-qualification.md), неизменённый actual proposal, purpose-separated permit, same Engine/HTTP/worker. На `0a47b7b` 39 actual-candidate native cases pass, golden error 0.0; [PB-26/RB-50/RB-51](../docs/operations/candidate-serving-troubleshooting.md), [evidence](../docs/evidence/candidate-serving-2026-10-15.md). Qualification не закрывает M12 и не разрешает release. Следующий slice - timestamped HTTP trust outage <=60 s с online recovery.
- [ ] Inference API и loader. Зависимость: T14. Gate: M12.
- Increment после `a711ffa`: [ADR 0031/API](../docs/serving-api.md), persistent Docker ONNX session, named-input loopback HTTP, before/after trust checks, deadlines/cleanup и cancellation accounting. [PB-25/RB-48/RB-49](../docs/operations/serving-troubleshooting.md), [evidence](../docs/evidence/serving-api-2026-10-14.md). На `d0d4423` и отдельно после resource/startup corrections на `2942255` по 34 native HTTP/ONNX/TLS checks pass; test assurance не превращается в real approval. Исправления имеют 50 serving methods / 94% coverage, adjacent suite 137 pass. Полный candidate-bound M12 и HTTP outage trace остаются обязательными.
- Increment 2026-10-14: [ADR 0030](../docs/decisions/0030-current-release-reader.md), Reader проверяет current head/event, authorization, current trust и неизменяемые bytes. На `37397ce` 18 native TLS SQL checks pass, 86 local adjacent methods pass. [PB-24/RB-46/RB-47](../docs/operations/release-reader-troubleshooting.md), [evidence](../docs/evidence/release-reader-2026-10-14.md). Это pre-runtime component с controlled positive fixture, не verified ONNX load/readiness или HTTP API; задача остаётся открытой.
- Результат: API schema, verified readiness, atomic bundle load и явные ошибки/abstain.
- Проверка: request limit suite, malicious paths/URLs не поддерживаются, TOCTOU и missing signature не дают ready.

## T16
- [ADR 0048](../docs/decisions/0048-privacy-acceptance.md): **[native b0df48e verified](../docs/evidence/privacy-evidence-b0df48e-native.md)**, 83 cases, Linux 14 + 22 tests без skips, checker 100%; CI 6 success / 4 failure, attempt 1. [Local RED/review](../docs/evidence/privacy-evidence-2026-10-20.md), [RB-67/PB-41](../docs/operations/privacy-evidence-troubleshooting.md). До полного M13 обязательны private primary snapshots/HTTP linkage, production lifecycle/429/503, service-log observations, subject composition и strict public projection. M13 dispatch остаётся inconclusive.
- [ADR 0047](../docs/decisions/0047-serving-output-observation.md): **[native 2a70ffc verified](../docs/evidence/serving-output-2a70ffc-native.md)**, 82 cases, 19 output / 38 privacy Linux methods, probes 100%, 6 success / 4 failure CI. [Карта каналов](../docs/privacy-output-map.md), deferred snapshot publication, sealed nested captures, [RB-66/PB-40](../docs/operations/serving-output-troubleshooting.md). Следом full M13 aggregation; shared/local forced-stop recovery не доказан, T16 и release blockers открыты.
- Private correlation [ADR 0046](../docs/decisions/0046-private-audit-correlation.md): **native 54cbe50 verified**, 64 tests / 0 skips / 100%, 81 actual-candidate case; [полный report/CI](../docs/evidence/audit-correlation-54cbe50-native.md), [RB-65/PB-39](../docs/operations/audit-correlation-troubleshooting.md). Source/run/report/authority snapshot проверен против primary materials; controlled release отделён от actual qualification. 10 terminal CI, 6 success / 4 failure. Далее output-channel map, remaining end-to-end canaries и отдельная M13 aggregation; T16 пока открыта.
- Public audit export [ADR 0045](../docs/decisions/0045-public-audit-export.md): **native f0d0542 verified**, 46 tests / 0 skips, 80 candidate cases, 332 events / 83 completed / 0 unresolved; [evidence](../docs/evidence/audit-export-2026-10-19.md), [RB-64/PB-38](../docs/operations/audit-export-troubleshooting.md). 10 terminal CI, latest attempts 6 success / 4 failure; первый M07 failure сохранён, retry не устраняет неизвестную причину. Full all-output и private source-to-request correlation остаются обязательными зависимостями M13.
- Controller/transport privacy: [ADR 0044](../docs/decisions/0044-controller-process-privacy.md), [native fe1437e](../docs/evidence/controller-privacy-2026-10-19.md), [RB-63/PB-37](../docs/operations/controller-privacy-troubleshooting.md). Linux 18 guard + 70 lifecycle tests / 0 skips, actual controller snapshot, M20 725 / M21 122 и 78 candidate cases pass; CI 6 success / 4 failure. Не полная M13-приёмка.
- [ ] Privacy, quotas и audit. Зависимость: T15. Gate: M13.
- HTTP increment, native verified 2026-10-19: [ADR 0040](../docs/decisions/0040-serving-http-audit.md), обязательный audit до body/executor, own durable intent до 200, actual send/cancel и slot lifetime. [281e902 evidence](../docs/evidence/serving-http-audit-2026-10-18.md): 48 HTTP tests / 0 skips, module 100%, 74 candidate cases, audit pair 8/8; CI 6 success / 4 failure. All-output canaries/cardinality/correlation остаются следующими. Windows concurrent real-fsync не квалифицирован. Исторические checkpoints ниже не описывают текущий HTTP code.
- Component 2026-10-18: [audit admission](../docs/decisions/0039-audit-admission.md), четыре reserved events, owned durable ack и event schema 2. [Native 01ec902](../docs/evidence/audit-admission-2026-10-18.md): 77 methods / 0 skips, schema 100%, core 94/98 branches, retention 102/102; 72 serving regression cases pass. CI 6 success / 4 failure. Следом обязательное HTTP подключение, actual send/cancellation, sink/deadline cases и all-output privacy/cardinality. M13 не закрыт.
- [Context handoff / ADR 0038](../docs/decisions/0038-serving-audit-context.md): implemented, local 169 adjacent tests pass / context 100%; [native 503b68b attempt 2](../docs/evidence/serving-context-2026-10-16.md) 72 cases pass. Release и qualification разделены, private refs не добавляются в HTTP JSON. CI 6 success / 4 failure; M07 first-attempt instability остаётся unexplained. ASGI event production/admission/canaries ещё не реализованы.
- [Branch quality slice](../docs/evidence/audit-branches-2026-10-16.md): native 42ce792, core 76/80 branches = 95%, retention 102/102 = 100%; Linux 61 audit + 10 checker tests без skips, serving regression 67 pass. Независимый per-module branch gate обязателен в CI; весь T16/M18 не закрыт.
- [Retention / ADR 0037](../docs/decisions/0037-audit-retention.md): opt-in bounded Linux spool, общий payload budget и clean restart; [native b2b3bf6](../docs/evidence/audit-retention-2026-10-16.md): исторические 51 tests pass / 0 skips, core/retention Cover 97%/93%, serving regression 67 pass. Отдельный branch критерий двух модулей закрыт следующим increment выше; crash/reboot reconciliation и HTTP correlation/canaries остаются открытыми.
- [Audit core / ADR 0036](../docs/decisions/0036-serving-audit-journal.md) добавляет bounded private spool и failure ownership, не HTTP integration. Следом нужны retention/rotation, ASGI correlation и all-output canaries; T16 остаётся открыт.
- Частичный increment 2026-10-15: [ADR 0035](../docs/decisions/0035-serving-client-quotas.md), bounded local client identity/rate/in-flight и [RB-54/PB-28](../docs/operations/serving-client-troubleshooting.md). [Native 687a7c7](../docs/evidence/serving-clients-2026-10-15.md): 67 actual-candidate cases pass, quota/refill/accounting и trust recovery подтверждены после исправления диагностического polling. Audit/retention/cardinality и полный M13 остаются открытыми.
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
