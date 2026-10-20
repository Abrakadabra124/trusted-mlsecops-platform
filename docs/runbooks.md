# Эксплуатационные процедуры

- [Full-lifecycle serving output observation, RB-66/PB-40](operations/serving-output-troubleshooting.md). Bounded child FDs, sealed captures, deferred publication, strict wire и forced-stop limits; [evidence](evidence/serving-output-2026-10-19.md), [карта M13 channels](privacy-output-map.md).

- [Private source-to-request correlation, RB-65/PB-39](operations/audit-correlation-troubleshooting.md). Exact payload/envelope hashes, legacy/mismatch/unresolved windows, отдельные release/qualification authorities и безопасный rollback; [evidence](evidence/audit-correlation-2026-10-19.md).

- [Public audit export, RB-64/PB-38](operations/audit-export-troubleshooting.md). Closed-spool ownership, bounded projection, incomplete windows и безопасный cleanup; [evidence](evidence/audit-export-2026-10-19.md). Не repair stale lease и не полный M13.

- [Controller privacy, lifecycle и cleanup, RB-63/PB-37](operations/controller-privacy-troubleshooting.md). Constant CLI/lifespan diagnostics, native readback, partial/ambiguous reader startup и cancellation; [native fe1437e evidence](evidence/controller-privacy-2026-10-19.md): 18 + 70 tests / 0 skips, actual controller snapshot и owned CLI SIGINT. Полный M13 не принят.

- [Serving metrics и bounded scrape, RB-62/PB-36](operations/serving-metrics-troubleshooting.md). Operator identity/quotas, final-send/disconnect, schema/canary checks, source-lock correction и safe rollback; [native 93de1b6 evidence](evidence/serving-metrics-2026-10-19.md): 35 metrics tests, 78 candidate cases, 69 approved samples. Полные M13/R1 остаются открытыми.

- [Worker startup diagnostics и core policy, RB-61/PB-35](operations/worker-privacy-troubleshooting.md). Guard до input/runtime imports, constant errors и native wait-status proof; [evidence](evidence/worker-privacy-2026-10-19.md) сохраняет Windows skip и pending Linux qualification.

- [Serving privacy и полнота capture, RB-60/PB-34](operations/serving-privacy-troubleshooting.md). Native telemetry/redirect controls, bounded canaries и fail-closed диагностический probe; [evidence](evidence/serving-privacy-2026-10-19.md) фиксирует native 621d355, 77 candidate cases и ограничения полной CI/M13-приёмки.

- [HTTP audit lifecycle, RB-59/PB-33](operations/serving-http-audit-troubleshooting.md). Fail-closed admission, owned intent, actual send/cancel, pending quota ownership и safe recovery; [evidence](evidence/serving-http-audit-2026-10-18.md) фиксирует native 281e902 pass и отдельное Windows fsync limitation.

- [Audit admission и durability, RB-58/PB-32](operations/audit-admission-troubleshooting.md). Bounded reservations, owned ack, pending writer и mixed event versions; HTTP integration рассматривается отдельно в RB-59.

- [Private context handoff, RB-57/PB-31](operations/serving-context-troubleshooting.md). Release/qualification separation, generation binding и 503 diagnostics без раскрытия private refs; HTTP event sink рассматривается отдельно в RB-59.

- [Retained audit storage, RB-56/PB-30](operations/audit-retention-troubleshooting.md). Rotation/expiry, same-boot restart, guard ownership и неизвестное состояние после interruption. [Evidence](evidence/audit-retention-2026-10-16.md) отделяет локальные contracts от native qualification.

- [Private audit journal core, RB-55/PB-29](operations/serving-audit-troubleshooting.md). Accepted/durable/unconfirmed, bounded queue/disk, retained writer ownership и safe failure handling. [Evidence](evidence/serving-audit-2026-10-15.md) не заменяет будущую HTTP/M13 qualification.

- [Client identity и quotas, RB-54/PB-28](operations/serving-client-troubleshooting.md). 401/429/503, bounded credentials, retained in-flight tickets и safe recovery без reset quotas. [Evidence](evidence/serving-clients-2026-10-15.md) различает unit/loopback и native qualification.

- [HTTP deadline и зависшее доверие, RB-53/PB-27](operations/serving-deadline-troubleshooting.md). Sticky generation fence, retained pending operations, paused established SQL query и unpause-before-drain. [Evidence](evidence/serving-deadline-2026-10-15.md) отделяет controlled от native проверки.

- [Actual candidate qualification, PB-26/RB-50/RB-51/RB-52](operations/candidate-serving-troubleshooting.md). Source/permit binding, expiry, key separation, owned-authority outage, timestamped HTTP trace и online recovery. [Candidate evidence](evidence/candidate-serving-2026-10-15.md) и [outage evidence](evidence/http-trust-outage-2026-10-15.md) отделяют contracts от native результатов. Qualification не разрешает release.

- [Serving API, PB-25/RB-48/RB-49](operations/serving-troubleshooting.md). Liveness versus readiness, auth/schema/overload, worker deadline/cleanup, cancellation accounting, thread-start failure, resource-profile mismatch и verified reload. [Evidence](evidence/serving-api-2026-10-14.md) не смешивает component fixture с полным ML release.

- [Проверенное чтение release, PB-24/RB-46/RB-47](operations/release-reader-troubleshooting.md). Journal не заменяет approval; material integrity, head race, expiry и revoke не обходятся cached model. [Evidence](evidence/release-reader-2026-10-14.md) отдельно отмечает controlled fixture, настоящий SQL и отсутствующий runtime endpoint.

- [Online trust, PB-23/RB-44/RB-45](operations/trust-troubleshooting.md). Отдельная authority, irreversible revoke, outage/clock/expiry, conflicts и запрет переноса устаревшего доверия из backup. [Evidence](evidence/online-trust-2026-10-14.md) различает controlled clocks, actual TLS SQL и оставшуюся endpoint integration.

- [Promotion recovery, PB-22/RB-42/RB-43](operations/promotion-recovery-troubleshooting.md). Общий snapshot CAS/journal, внешний backup-id pin, source-offline qualification, maintenance при неопределённом import и запрет overwrite поздних записей. [Evidence](evidence/promotion-recovery-2026-10-14.md) отделяет controlled tests от native результатов.

- [Promotion ledger, PB-21/RB-40/RB-41](operations/promotion-ledger-troubleshooting.md). Ambiguous commit, concurrent sequence, expiry после lock, безопасный retry и запрет неполного backup/обнуления journal. [Evidence](evidence/promotion-ledger-2026-10-14.md) различает controlled SQL fixtures и полноценное ML approval.

- [Release proposal/authorization, PB-20/RB-38/RB-39](operations/release-authorization-troubleshooting.md). Диагностика отказа, schema/time binding, interrupted publication, idempotent retry и rollback без удаления evidence. Controlled и native результаты раздельно в [evidence](evidence/release-authorization-2026-10-14.md).

## Проверенные локальные процедуры

- [Robust training, PB-19/RB-37](operations/robust-training-troubleshooting.md). Paired baseline/candidate, fixed probes/utility guards, диагностика convergence и source-lock mismatch без ослабления policy. Controlled и native outcomes раздельно в STATUS.
- [Evasion и abstain, PB-18/RB-36](operations/robustness-troubleshooting.md). Frozen inference-time budget, domain-support guard, отличия statistical failure от runtime error, безопасное повторение и запрет tuning по опубликованным probes.
- [Scoped Kubernetes intake, PB-17/RB-35](operations/scoped-intake-troubleshooting.md). Реальные controller identities, scheduling deadline/process failure, Pod UID observations, отдельный promoter readback и запрет reset budget. Controlled/native evidence отдельно в STATUS.
- [Сверка intake evidence, PB-16/RB-34](operations/intake-gate-troubleshooting.md). Fresh Docker/SQL campaign, защита от stale/foreign/partial reports, ownership cleanup и обязательный inconclusive при отсутствующей scoped-controller matrix. Controlled и native evidence разграничены в STATUS.
- [Подписанные отказы intake, PB-15/RB-32/RB-33](operations/intake-denial-troubleshooting.md). Read-only проверка отрицательного документа, потеря SQL persistence, безопасный retry без refund и явно изменяющий disposable-lab replay. Controlled contracts проверены; native CI evidence отражается в STATUS.
- [Приём ML-артефакта, PB-14/RB-29/RB-30/RB-31](operations/artifact-intake-troubleshooting.md). Независимый scan, сохранение fail/inconclusive, native timeout/crash и clean-after-faults, Windows symlink privilege, Docker и порядок ownership bootstrap перед evidence.
- [Qualification и ресурсы стенда, PB-13/RB-27/RB-28](operations/qualification-environment-troubleshooting.md). Сохранение failed CI attempt, один диагностический rerun без reset budget; установленное исчерпание Docker subnet pool. Recovery действий над networks здесь не проводилось.
- [Контракт ONNX, PB-12/RB-25/RB-26](operations/model-contract-troubleshooting.md). Диагностика export/graph/labels, неизвестных protobuf-полей и runtime outputs; безопасная свежая qualification без обхода policy или reset рабочего holdout.
- [Подписанные материалы candidate, PB-11/RB-22/RB-23/RB-24](operations/material-bundle-troubleshooting.md). Сначала read-only lineage, затем явно изменяющая publication в owned lab; отказ на tamper/subject, безопасный повтор interrupted writes, SQL serving readback без approval и исправление сравнения эквивалентных ключей.
- [Candidate lineage, PB-10/RB-20/RB-21](operations/candidate-lineage-troubleshooting.md). Read-only сверка настоящих подписанных SQL материалов, нерасширенные роли, сохранение разных runs при одинаковых model bytes и контролируемая ошибка записи evidence.
- [Asset dependency graph, PB-09/RB-19](operations/asset-graph-troubleshooting.md). Synthetic replay, missing/cyclic/digest-swapped references, неполные observations, контролируемый отказ глубоко вложенного input. Не live revocation и не полный M19.
- [Image audit, RB-18](operations/image-audit-troubleshooting.md). Диагностика отсутствующих длинных CI log lines, полная публикация JSON без переоценки findings, vendor triage и запрет небезопасной замены runtime.

Ранбук объясняет, как распознать проблему и выбрать безопасное действие. Плейбук задаёт конкретную последовательность; исполняемая версия автоматизирует только обозначенные действия. Наличие инструкции само по себе не доказывает успешное восстановление.

- [Tracking: диагностика и встреченные bootstrap-проблемы](operations/tracking-troubleshooting.md). Исполняемый read-only плейбук проверяет configuration, ownership/runtime policy и HTTPS без изменения сервисов. Отдельно описаны chmod/CHOWN, отсутствие опубликованного порта, частичный bootstrap и TLS.
- [Воспроизводимость и наблюдение за CI](operations/reproducibility-troubleshooting.md). Проблемы canonical JSON, неполного pairwise comparison и недоступности API; порядок проверки input digests, повторных запусков и отрицательных сценариев.
- [Шаблон incident record](operations/incident-template.md). Содержит границы воздействия, evidence, действия, rollback, критерии восстановления и следующий шаг.
- [M06 gate и PB-04](reproducibility-gate.md). Свежая campaign, сверка отчёта с сохранёнными материалами, explicit state, stale-image/source checks и fail/inconclusive диагностика.
- [Holdout budget, PB-05 и RB-08/09/10](operations/holdout-budget.md). Read-only ledger, исчерпание попыток, неопределённый commit, restore без ложного refund и проверка отказа до labels/worker.
- [Независимая оценка, PB-06 и RB-11/12](operations/evaluation-troubleshooting.md). Недостаток labels, undefined metrics, противоречивый signed report, подмена subject и безопасная проверка исправления.
- [Единый M07, PB-07 и RB-13/14](evaluation-gate.md). Свежая campaign, stale image/report, неполные contract results, ownership-safe cleanup и повтор без reset рабочего holdout budget.
- [Poisoning campaign, PB-08 и RB-15/16/17](operations/poisoning-troubleshooting.md). Различение statistical violation и runtime failure, сверка первичных материалов, защита input от перезаписи, сохранение отрицательных результатов и повтор без ослабления policy.

Для каждого нового существенного сбоя обновлять этот каталог и соответствующий ранбук одновременно с исправлением. Ошибки разработки и controlled negative tests не называются production-инцидентами.

## Планируемые сценарии продукта

Эти процедуры - **спецификация для T14-T23**, не готовые команды к существующему кластеру. Конкретные CLI, permissions и alert routes появятся при реализации. Любое действие сохраняет audit и не раскрывает raw data/keys. Ответственные роли описаны в [карте продукта](product-map.md).

## 1. Dataset или model tampering

**Сигнал:** digest/signature/subject mismatch. **Ответственный:** security reviewer + platform operator.

1. Остановить promotion и изолировать объект, не удаляя forensic evidence.
2. Записать actual/expected digest, identities, source request и текущий approved release.
3. По inventory graph найти все зависимые runs/models/releases/endpoints, включая общий preprocessing/runtime policy. Отозвать затронутое множество, сверить реально работающие digests; не ограничиваться сменой alias или одной моделью.
4. Проверить audit источника, storage write permissions и возможности скомпрометированного credential.
5. Пересоздать candidate из отдельно проверенных inputs; провести полный gate set.

**Восстановление:** только новый approval или разрешённый совместимый release без компрометации. **Проверка:** M03, M10-M12, M19; runtime digest соответствует принятому решению, независимая ветвь не отозвана ошибочно.

## 2. Poisoning или подозрительная разметка

**Сигнал:** targeted probe anomaly, ухудшение slice, необычный источник labels. **Ответственный:** data owner + ML engineer + security reviewer.

1. Freeze promotion и обратную связь из подозрительного источника.
2. Отделить integrity violation от семантически допустимых, но подозрительных данных.
3. Сравнить clean control, affected sample IDs, label provenance и attacker budget.
4. Не считать высокий confidence или нормальную среднюю accuracy оправданием модели.
5. Проверить исправленную независимую выборку и необходимость полного retrain.

**Восстановление:** утверждённый clean dataset и полный independent evaluation. **Проверка:** M07-M09, M22; пропущенные challenge cases остаются в отчёте, абсолютный бюджет и доля poisoned rows указаны вместе.

## 3. Drift без подтверждённого ухудшения

**Сигнал:** data/prediction shift при достаточном window. **Ответственный:** ML owner.

1. Проверить schema, пропуски, изменения upstream и состояние самой telemetry.
2. Проверить sample size, bins/reference version и сезонность.
3. Дождаться зрелых labels или явно оставить качество неизвестным.
4. При необходимости ограничить использование/включить abstain и отправить данные на review.
5. Не запускать auto-promotion. Новое обучение возвращается через quarantine и все gates.

**Проверка:** M15, отдельные alerts для распределений и подтверждённой model quality.

## 4. Revocation, compromise key или недоступный trust service

**Ответственный:** security operator, с approver для повторного выпуска.

1. Отозвать затронутый key/release/policy и ограничить credential.
2. Проверить распространение revocation до работающих replicas.
3. Истечение trust lease переводит ML-путь в 503; это ожидаемая безопасная деградация, не повод выключать verifier.
4. Проверить, какие прежние releases тоже подписаны скомпрометированным key. Автоматически доверять им нельзя.
5. Перепроверить материалы, обновить trust roots разрешённой процедурой и выдать новые approvals.

**Проверка:** M11; measured reject time, audit reason и отсутствие serving отозванного digest. Root-of-trust recovery требует отдельного защищённого доступа, не секретов из Git.

## 5. Canary failure и rollback

**Ответственный:** platform operator + release approver.

1. Остановить дальнейшее увеличение traffic при превышении error/latency threshold.
2. Выбрать предыдущий whole bundle с действующей policy, совместимой schema и без revocation.
3. Создать новое rollback approval, связанное с source/target digests и причиной.
4. Переключить desired state, дождаться verified readiness и проверить несколько реальных ответов с digest.
5. Если подходящего release нет, выключить ML-advice и оставить ручной путь, не возвращаться к сомнительной модели.

**Проверка:** M16; RTO, отсутствие mixed artifacts, logs и клиентские ответы.

## 6. Disaster recovery

**Ответственный:** platform operator, data owner подтверждает доступность/retention данных.

1. Выбрать согласованный metadata+artifact snapshot и записать момент начала recovery.
2. Восстанавливать в отдельное окружение, не поверх единственной рабочей копии.
3. Восстановить metadata, immutable objects и approvals; ключи через отдельный защищённый процесс.
4. Сверить все referenced digests и текущую trust policy. Старый backup не отменяет последующую revocation.
5. Выполнить golden inference, проверить модель/схему/логи и измерить полный RTO/RPO.

**Проверка:** M17. Успешное чтение backup archive без usable verified inference недостаточно.

## 7. Retention и вывод модели из эксплуатации

**Ответственный:** data owner + release owner.

Найти все model/dataset references, запретить новые approvals, отозвать serving-разрешение, перевести клиентов на согласованную замену. Только затем удалять артефакты по политике хранения; запрещено удалять объект, ещё нужный действующему разрешённому release. Правовые сроки и основания устанавливаются для реального набора отдельно, не придумываются в lab.

Если удаление данных влияет на обученную модель, определить необходимость retrain или retirement. Удаление raw rows само по себе не доказывает machine unlearning. Сохранять минимальный допустимый audit без запрещённых персональных данных.

## 8. Неполный intake, нарушение worker boundary или audit gap

**Ответственный:** security reviewer + platform operator. **Сигнал:** inconclusive scanner, denied worker operation, неизвестный producer, sequence gap или недоступный audit sink.

1. Блокировать новую promotion; сохранить ограниченный технический report без raw payloads. Отсутствие findings при отсутствии покрытия не считать clean.
2. Проверить claimed/actual format и digest, scanner exit status и scanned count. После conversion проверяется новый артефакт; unsafe loader не запускается рядом с credentials.
3. При worker policy violation остановить Job, проверить доступ к labels/keys/controller, отозвать затронутые credentials и releases по фактическому воздействию. Недоверенный stdout не является authoritative evidence.
4. При audit gap проверить trusted producer, sequence и heartbeat, восстановить доставку с idempotent event IDs. Потерянные события не заменять выдуманными записями.
5. Повторить intake, isolation probes и replay; получить отдельное разрешение на возобновление. Уже работающий serving следует своей trust lease/availability policy, а не неявному auto-restart из-за alert.

**Проверка:** M20, M21, M23. Измерить восстановление telemetry и перечислить реально утраченные evidence; при неизвестном воздействии оставить риск открытым.

## Обязательный incident record

Время, тип инцидента, затронутые dataset/model/bundle digest, исполнители и права, выполненные действия, разрешённый следующий state, влияние на пользователей, ссылки на redacted evidence, остаточный риск и owner follow-up. Пароли, signing keys и исходные payloads сюда не включаются.
