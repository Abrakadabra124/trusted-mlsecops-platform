# Backlog реализации

T03 и T04 завершены для synthetic-only профиля; остальные **27 задач открыты**, реализация начата 2026-10-07. Промежуточные increments закрывают части других задач, но не их полные gates; результаты в [STATUS](../STATUS.md). Каждый раздел - результат одной или нескольких коротких итераций. Номера gates ссылаются на [полную приёмку](../docs/acceptance.md). Runner `mlsecops.acceptance` выполняет M02 и M03, а неподключённые полные проверки возвращают inconclusive. T25-T29 добавлены исследованием R0.2; ID сохраняют историю, порядок задают зависимости и [календарный план](plan.md). Ранняя проверка компонента не заменяет позднюю интеграционную приёмку.

## T01
- [ ] Scope, inventory и acceptance runner. Зависимости: нет. Gate: M01.
- Результат: требования к labels/данным, resources inventory, machine-readable report schema и CLI runner с явным fail для отсутствующих checks.
- Проверка: недоступный tool/несовместимый foundation блокирует bootstrap; повторная инвентаризация не меняет текущий runtime.

## T02
- [ ] Foundation P0 и совместимые зависимости. Зависимость: T01. Gate: M01.
- Прогресс: [storage snapshot/restore](../docs/storage-recovery.md) сохраняет ledger и восстанавливает отдельный экземпляр; image audit и полный P0-отчёт ещё не приняты.
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
- Прогресс: отдельные namespaces/ServiceAccounts, реальные API denials, Cilium probes и SQL storage ACL работают; least-privilege controllers и полная интеграция identities ещё не завершены.
- Результат: role/access matrix, namespace/storage/network policies и restricted service accounts.
- Проверка: фактические разрешённые/запрещённые операции trainer/evaluator/serving, не только RBAC simulation.

## T06
- [ ] Sandboxed training Jobs. Зависимость: T05. Gate: M05.
- Прогресс: настоящий Job backend, admission, deadline, PID/OOM/egress probes и cleanup проверены; влияние на будущий настоящий serving service ещё не измерено.
- Результат: Job runner без host privileges, лимиты, deadlines, pinned image и cleanup.
- Проверка: denied egress, timeout, memory exhaustion, отсутствие signing secrets и влияния на serving.

## T07
- [ ] CPU pipeline и export. Зависимость: T06. Gate: M06.
- Результат: preprocess/train DAG с seed/hyperparameters и machine-readable outputs; fit только на train.
- Проверка: три fresh-process runs, сравнение входов и predictions; mutation inputs не маскируется cache hit.

## T08
- [ ] MLflow tracking и lineage. Зависимость: T07. Gate: M06.
- Результат: защищённый MLflow, отдельная metadata DB, run-to-material binding и artifact access tests. Только внешний publisher получает право записи; training worker не получает его credentials.
- Проверка: anonymous/чужая identity запрещены, потеря metadata не меняет runtime alias, повторное обучение сохраняет отдельные runs.

## T09
- [ ] Frozen evaluation policy. Зависимость: T08. Gate: M07.
- Результат: model card, clean baseline, slice definitions, threshold/CI policy до final holdout, бизнес-dataset stop conditions.
- Проверка: dummy comparison, sample counts, disjoint entities и label maturity; недостаток данных = inconclusive.

## T10
- [ ] Independent evaluator. Зависимости: T09, T26. Gate: M07.
- Результат: trusted scorer вне prediction worker, holdout access budget, signed subject-bound evaluation reports. Labels и signing keys недоступны worker.
- Проверка: report swap, попытка trainer прочесть holdout, missing metric, signature mismatch; deny self-approval.

## T11
- [ ] Poisoning benchmark. Зависимость: T10. Gate: M08.
- Результат: clean controls + label-flip/backdoor matrix, ASR/CIs/utility deltas и полный отчёт failures/bypasses.
- Проверка: known-violation fixtures блокируются, challenge outcomes не скрываются, train-only attacker budget соблюдён.

## T12
- [ ] Safe format и robustness probes. Зависимость: T11. Gate: M09.
- Результат: ONNX allowlist, parity report, declared evasion suite, ограниченный OOD/abstain policy.
- Проверка: pickle/external tensor/custom operator/oversized graph отклоняются до load; golden cases соответствуют Python output.

## T13
- [ ] Release bundle и promotion verifier. Зависимости: T12, T25, T27. Gate: M10.
- Результат: versioned format, signatures/envelopes, subject/environment/policy binding, approval и idempotent state transition.
- Проверка: весь negative promotion suite; данные, model, report и runtime image проверяются как один release.

## T14
- [ ] Trust lifecycle. Зависимость: T13. Gate: M11.
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
- Результат: versioned asset schema, owners, dependency graph, точный impacted set и блокировка неизвестных assets. В недели 4-5 готовится компонент; после T14-T15 проверяется интеграция отзыва до serving.
- Проверка: fixture M19, dangling/cyclic reference, unknown owner, alias/digest mismatch; интеграционный отзыв ancestor укладывается в M11 и не затрагивает независимую ветвь.

## T26
- [ ] Worker/controller boundary. Зависимости: T05, T06. Gate: M20.
- Результат: изолированные training/prediction workers, publisher/scorer с отдельной identity, typed bounded prediction protocol. Контракт и компонентные fixtures готовы до T10; полная проверка с evaluator завершается в T10.
- Проверка: попытки чтения labels/keys/DB/service-account token и /proc соседнего controller запрещены; malformed/replayed/oversized outputs не становятся подписанным результатом.

## T27
- [ ] Artifact intake coverage. Зависимости: T12, T26. Gate: M21.
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
