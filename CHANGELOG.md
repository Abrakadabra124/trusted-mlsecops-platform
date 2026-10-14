# История исследовательского проекта

## R1 actual-candidate serving qualification - 2026-10-15

Добавлены purpose-separated short-lived permit и qualification-only Reader неизменённого upstream signed proposal. Same Engine/HTTP/isolated worker проверяются без переноса all-pass contract reports на настоящий candidate. Read-only source snapshot/readback, отдельная disposable trust authority, release denial и 14 дополнительных HTTP boundary/overload checks. Исправлены expiry-after-refresh, Base64 key alias и fixture-only import leakage; production Reader/config не меняются. [PB-26/RB-50/RB-51](docs/operations/candidate-serving-troubleshooting.md), [evidence](docs/evidence/candidate-serving-2026-10-15.md). Полные M12/R1 и final approval не объявляются завершёнными.

## R1 serving resource и startup cleanup corrections - 2026-10-14

Native `d0d4423` подтвердил 34 HTTP/ONNX/TLS cases, но review обнаружил расхождение resource profile и ошибки thread-start/cleanup ownership. Исправлены Docker request/readback и signed runtime descriptor на 1 CPU / 1 GiB; старый descriptor отвергается даже с корректной подписью. Heartbeat публикуется после start, Channel завершает child при thread failure, Engine владеет Worker до изменяющего one-shot start. Добавлены negative regressions и диагностические ветви [RB-48/RB-49](docs/operations/serving-troubleshooting.md). [Evidence](docs/evidence/serving-api-2026-10-14.md) разделяет предыдущий native commit и последующие corrections. Full M12/R1 остаются открытыми.

## R1 isolated serving API increment - 2026-10-14

Постоянный digest-pinned Docker worker загружает exact verified ONNX bytes один раз и использует bounded nonce/row-bound JSON protocol без сети, mounts и signing credentials. Engine проверяет current Reader до/после inference и не сохраняет fallback при failure. Добавлен loopback FastAPI/Uvicorn с bearer auth, named features, body/admission limits и 401/413/422/429/503; cancellation сохраняет slot до завершения underlying thread. [ADR 0031](docs/decisions/0031-isolated-serving-api.md), [API](docs/serving-api.md), [PB-25/RB-48/RB-49](docs/operations/serving-troubleshooting.md), [evidence](docs/evidence/serving-api-2026-10-14.md). Полные gates и production readiness не объявляются пройденными.

## R1 current release reader increment - 2026-10-14

Serving-only reader связывает current SQL head/event/authority с полной signed authorization, immutable material bytes и текущим trust. Повторная head/time проверка, external sequence floor и in-process equivocation history; frozen handoff не объявляется runtime readiness. Добавлены controlled negative tests, отдельная disposable native qualification и [PB-24/RB-46/RB-47](docs/operations/release-reader-troubleshooting.md). Настоящие блокирующие ML gates не ослаблены; HTTP/sandbox activation и full M12 остаются открытыми. [Evidence](docs/evidence/release-reader-2026-10-14.md).

## R1 online trust increment - 2026-10-14

Добавлены отдельная TLS SQL authority, root-signed monotonic policy versions и необратимые revocation sets. Lease учитывает время запроса, wall/server expiry и clock rollback; SDK promotion требует свежий trust read, сверяет model/dataset/runtime/signers и не возвращает activation при неопределённом commit. Model backup не архивирует authority. [PB-23/RB-44/RB-45](docs/operations/trust-troubleshooting.md), [evidence](docs/evidence/online-trust-2026-10-14.md). Endpoint, root rotation, rollback authorization и full M11 остаются открытыми.

## R1 promotion recovery increment - 2026-10-14

Добавлен opt-in signed backup v2 для CAS и promotion journal в одном snapshot, exact migration/TOC/chain checks, внешний restore pin и maintenance до readback. V1 не теряет guard, новый target не становится release-ready. [PB-22/RB-42/RB-43](docs/operations/promotion-recovery-troubleshooting.md), [evidence](docs/evidence/promotion-recovery-2026-10-14.md). Completed retry не стирает новые данные; автоматический pre-receipt resume и полный M17 ещё нужны.

## R1 promotion ledger / admission increment - 2026-10-14

Добавлены отдельная PostgreSQL schema и restricted transition, policy/sequence/current-idempotency проверки, full signed-chain SDK admission до writes и immutable event readback. Legacy backup запрещён при наличии неподдерживаемого ledger, проверка scope связана с экспортируемым snapshot. [PB-21/RB-40/RB-41](docs/operations/promotion-ledger-troubleshooting.md) описывают retry/time/commit/recovery failures. [Evidence](docs/evidence/promotion-ledger-2026-10-14.md); не полный M10 или activation.

## R1 release proposal / authorization increment - 2026-10-14

Добавлены complete signed descriptor, девять supplemental документов, отдельные policy/assurance/approval с decoded-key separation, subject/environment/time binding и обязательными M01-M23. SQL proposal publication идемпотентна и выполняет full readback; activation отсутствует, release_ready=false. 29 controlled methods, отдельный native SQL workflow step, [PB-20/RB-38/RB-39](docs/operations/release-authorization-troubleshooting.md), [ADR 0026](docs/decisions/0026-release-authorization.md). Исправлены contract mismatch, policy-validity time gap, CAS closure и прямой SQL write-denial probe. Проверенные результаты: [evidence](docs/evidence/release-authorization-2026-10-14.md).

## R1 paired robust training research - 2026-10-13

Добавлен research-only вариант обучения с clipped-box worst-case logistic loss, frozen paired experiment на baseline и candidate, independent model intake, strict parity и primary response readback. SciPy 1.18.1 объявлена прямой зависимостью без изменения package versions; data.lock обновлён только после подтверждения прежних generated bytes. PB-19/RB-37 документирует source-lock failure, convergence/utility/material diagnostics и безопасное воспроизведение.

Local candidate улучшил измеренное падение recall, но не прошёл прежний лимит 0.05 на всех трёх probes. Failure сохранён, автоматической adoption нет. 18 controlled methods, 100% math-core statements/branches; полный M09 и R1 не приняты. Подробности и последующий CI: [evidence](docs/evidence/robust-training-2026-10-13.md).

Review исправил четыре gaps доказательств/отказов; итоговые 22 controlled methods и 125 Linux tests pass. Второй 14-worker native replay дал идентичные model bytes/metrics, statistical fail сохранён. Thresholds и training objective не менялись.

[Clean-checkout CI a252f6f](docs/evidence/robust-training-2026-10-13.md) повторил модель и все summaries с source_dirty=false. Все 10 workflows terminal: шесть functional/documentation success, четыре research/security failure. M20 723/M21 122 pass; image, poisoning и обе evasion campaigns не waived. Опубликованы aggregate evidence и digests без raw materials.

## R1 bounded evasion and domain-support abstain - 2026-10-13

Добавлены ограниченный advisory core, frozen feature-space attack protocol, native Docker replay с independent intake, private primary materials и отдельный CI workflow без подавления failure. 17 negative/positive contracts, два local eight-worker replays и PB-18/RB-36. Domain-support guard подтвердил abstain, но recall drop 0.07183673469387755 превышает прежний 0.05: результат сохранён как fail, thresholds не менялись. Это T12 component, не full M09, production или release approval.

[CI 5e3bb21](docs/evidence/robustness-2026-10-13.md) повторил metrics с source_dirty=false. M20 723/M21 122 pass и functional regressions success; image audit, poisoning и новая evasion campaign failure. Очищенные evidence и все девять terminal CI outcomes опубликованы без raw materials.

## R1 scoped Kubernetes intake qualification - 2026-10-13

Добавлен scoped scorer probe с real Jobs, отдельным promoter readback signed evaluation/denials и binding к exact model bytes/materials свежей Docker campaign. DeadlineExceeded больше не классифицируется как обычный process crash; missing Pod принимается только по ранее сохранённому owner/UID observation. Permissions/admission не расширены, рабочий budget не сбрасывается. Полный M21 исполняется в Kubernetes workflow, contracts workflow не выдаёт gate approval. PB-17/RB-35 описывают fault mechanisms, расход трёх cluster slots, cleanup и ограничения; native outcomes в STATUS.

[Clean-checkout CI 04b5e78](docs/evidence/intake-acceptance-2026-10-13.md): M21 122/122 pass, M20 regression 723 pass, source_dirty=false. Проверены real deadline с исчезнувшим Pod, slots 24/25/26, independent signed readback и очистка. Functional workflows success, image audit и poisoning failure сохранены как blockers. RB-35 дополнен проверенной диагностикой неполного CI log export без повторного расхода holdout.

## R1 fresh intake evidence reconciliation - 2026-10-13

Добавлен M21 dispatcher с новой controlled/Docker/SQL campaign, actual signed-object reconciliation, source/image/policy/time binding, rejection stale/partial/foreign evidence и cleanup ownership guard. Native Docker scanner может проверять exact bytes SQL candidate вместо другой модели. 15 negative runner contracts и PB-16/RB-34 покрывают диагностику неполной приёмки. Missing scoped-controller matrix остаётся обязательным inconclusive, CI не скрывает exit 2; полный M21 и R1 не объявляются завершёнными.

## R1 signed intake denials - 2026-10-13

SQL scorer сохраняет validated fail/inconclusive как отдельный DSSE `intake-denial` с exact subject и spent reservation. Идемпотентная публикация, проверка readback, read-only CLI, nonzero controller outcome и остановка при потере persistence. Ни отрицательная подпись, ни exit 0 audit reader не разрешают release. Добавлены negative contracts, disposable SQL replay и PB-15/RB-32/RB-33; full M21 остаётся открытым, native результаты фиксируются отдельно в STATUS.

## R1 independent artifact intake - 2026-10-13

Отдельный inspect worker до prediction, bounded digest/nonce/image-bound receipt, mandatory signed evaluation schema 2 и повторная offline/SQL проверка. Старые reports не переписываются, holdout budget не сбрасывается. Добавлены 20 controlled contracts, 5 native Docker scenarios и обязательная CI coverage. PB-14/RB-29/RB-30 описывают fail/inconclusive, crash/deadline recovery и Windows/Docker ограничения. Full M21/release остаётся открытым.

## R1 bounded holdout failure diagnostics - 2026-10-11

После реального CI failure добавлены безопасные diagnostic reason codes, claimed-slot summary и propagation через native runner/CLI/M07. Exact receipts связываются с holdout, slot и policy; foreign digest/duplicate slot отвергаются. 11 новых controlled tests проверяют bounds, redaction и сохранение fail. SQL grants, timeouts, LIMIT и thresholds не меняются. RB-27 обновлён; причина первого исторического failure остаётся неизвестной.

## R1 explicit ONNX model contract - 2026-10-11

CI подтвердил model/developer checks. Встреченные qualification-проблемы вынесены в PB-13/RB-27/RB-28: первоначальный M07 concurrency failure с неизвестной причиной, успешный одиночный rerun и отдельное установленное исчерпание локальных Docker subnets. Причина первого CI failure не объявляется исправленной; unsafe cleanup и waiver не применялись.

Вместо operator-name allowlist добавлен versioned two-node baseline contract: topology, shapes/types, finite bounded parameters, binary labels/transform и запрет неизвестных protobuf-полей. Проверяются оба runtime outputs, normalization и label/score consistency; ошибки runtime возвращают fixed reason. 18 methods включают настоящий sklearn export и 1000-row CPU parity; model.py имеет 100% statement/branch coverage. Fixtures и scan receipt обновлены до v2 без редактирования исторических reports. PB-12/RB-25/RB-26 описывают диагностику и безопасную повторную проверку. Полные M09/M21 и release approval не заявляются.

## R1 signer identity encoding fix - 2026-10-11

Final review воспроизвёл принятие одного ключа под разными Base64-представлениями за разные curator/evaluator/approver identities. Guards теперь сравнивают decoded bytes. Два regression methods воспроизвели три bypass cases до исправления и отказ после него. RB-24 содержит preconditions, fingerprint diagnosis и безопасную эскалацию без ручной подмены trust roots. Это не обход криптографии и не зарегистрированный production-инцидент.

## R1 signed candidate material bundle - 2026-10-11

Добавлено замыкание проверяемых candidate materials: отдельный DSSE index, 9 immutable objects, offline semantic verification, idempotent SQL publication и serving-role readback. SQL и capsule используют одинаковые existing signature readers через explicit callback. Полный ModelReleaseBundle/approval не подменяются: capsule остаётся unapproved, M10 inconclusive. Controlled suites и fresh native SQL проверяют tamper, scope, nested signatures, partial writes и отсутствие новых holdout queries. PB-11/RB-22/RB-23 описывают диагностику, последствия publication и безопасный повтор.

## R1 verified candidate lineage - 2026-10-11

Добавлен read-only collector signed dataset/candidate/evaluation metadata в asset graph. Проверяет independent expected build pins, material/holdout bindings, timestamps и SQL client identities. Одинаковые model bytes сохраняют разные provenance nodes; quality failure остаётся failure, approval не выдаётся. 18 collector и 8 runner tests с полным coverage, native SQL qualification и RB-20/21 для metadata collisions и ошибок diagnostic output. Изменений grants или ledger reset нет; full M19 пока inconclusive.

## R1 asset dependency graph component - 2026-10-11

Добавлены bounded schema v1, typed digest-bound references, owner/environment checks, cycle detection, complete deployment observation reconciliation и transitive revocation impact. Content aliases и previous rollback candidate не обходят impact calculation. Synthetic fixture и 25 tests выполняются также в developer CI. PB-09/RB-19 включает фактически воспроизведённый nested-input defect и проверку контролируемого отказа. Компонент не выдаёт approval, full M19 остаётся inconclusive; live collectors, persistence и serving integration ещё нужны.

## R1 observable image audit evidence - 2026-10-11

Исправлена публикация image-audit JSON одной длинной строкой, которую обычный CI log viewer не показал. Bounded pretty JSON сохраняет все fields/findings/status, экранирует control characters и отклоняет oversized publication без усечения. Canonical report, scanner inputs и High/Critical gate не меняются. RB-18 содержит read-only диагностику, vendor triage и безопасный дальнейший remediation path; уязвимости не объявлены исправленными этим изменением.

## R1 poisoning primary evidence reconciliation - 2026-10-11

Добавлена отдельная сверка 35 research cases с source-locked данными, mutation receipts, ONNX bytes, training/prediction requests, scores и повторным вычислением AP/ASR/CI. Выявленный output-overwrites-input defect закрыт отрицательными tests; output ограничен evidence directory. CI проверяет материалы даже после statistical failure и сохраняет этот failure. Worker/model protocol и thresholds не меняются. RB-17 описывает расследование расхождений; это trusted-host component, не подписанный approval и не полный M08.

## R1 native poisoning matrix - 2026-10-11

До запуска заморожен train-only protocol: 30 poisoned runs + 5 controls, отдельные security probes, paired bootstrap/Wilson bounds и unchanged M08 thresholds. Native offline workers выполнили всю матрицу; локально выявлены 10 targeted-ASR violations при 5% poisoning, результаты не исключены. Добавлены strict matrix contracts, CI с сохранением failure, отдельное evidence и PB-08/RB-15/16. Полный M08 не принят, M22/challenges и defence remediation остаются открытыми.

## R1 executable M07 acceptance - 2026-10-11

Общий runner теперь запускает fresh evaluation campaign, сверяет первичные подписанные материалы и training inputs, выполняет 48 controlled contracts и native evaluation/budget suites. Добавлены source/time/scope/case binding, отдельные owned SQL states и безопасная остановка. Старый pass не переиспользуется, условия M01-M23 не ослаблены. Ранбуки PB-07/RB-13/14 описывают диагностику и восстановление после встреченных отказов. Проверенные результаты и CI фиксируются в STATUS.

## R1 frozen evaluation и subject-bound read-back - 2026-10-11

Добавлены code-bound evaluation policy, pass/fail/inconclusive, null для undefined metrics, TP/ratio consistency, paired IID 95% intervals и проверка report против expected candidate и persisted reservation. Scorer применяет правила до доступа к holdout; promoter читает только candidate/evaluation. 31 contracts и 24 native SQL/model checks; ранбуки PB-06/RB-11/12. Полный M07/T09/T10 пока не закрыт, production utility не заявляется.

## R1 persistent holdout budget - 2026-10-11

В SQL/scoped-controller scorer добавлена atomic reservation до holdout read, append-only ledger с frozen synthetic cap 32 и binding receipt в подписанном report. Новый run/candidate и restart не сбрасывают бюджет; worker failure не даёт refund. Добавлены 16 controlled tests, native multi-process/restart qualification, read-only CLI и PB-05/RB-08/09/10. M20 history assertions различают reservation и signed evaluation; storage recovery проверяет сохранённый слот. Полный M07, защита от административного snapshot rollback и production readiness не объявляются завершёнными.

## R1 executable M06 acceptance - 2026-10-11

[M06](docs/reproducibility-gate.md) теперь запускается общим CLI: свежая native campaign, восстановление input bindings из signed datasets, сверка модели и векторов, повторный MLflow read-back. Поддержан explicit state без fallback, захвачен host scripts digest и dirty flag, старые evidence не принимаются. Локально 18 integration cases, 47 controlled contracts, 100% statements/branches gate module; stale worker даёт inconclusive до rebuild. Полные T07/T08, остальные gates и release blockers сохранены. Добавлен ранбук PB-04.

[CI 38136658929](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38136658929) на `c9e672f` завершился success: M06 18 cases, 47 contracts, source_dirty=false, шесть trainings/predictions/tracking records, baseline differences 0.0. M06 принят в заданном synthetic local scope, не весь T07/T08 или R1. Документационный follow-up не меняет исполняемый код, проверен локально и не запрашивает повторный CI.

## R1 native reproducibility and operational playbooks - 2026-10-11

Добавлены три baseline обучения и настоящие seed/data/environment mutations с шестью MLflow публикациями/read-back. Локально comparator прошёл 33 cases, baseline difference 0.0; полный M06 ещё не принят. При review исправлен pairwise tolerance bypass с negative regression. [Описание и evidence](docs/reproducibility.md).

По запросу владельца AGENTS.md требует писать ранбуки вместе с исправлениями. Добавлены [каталог процедур](docs/runbooks.md), incident template, разбор chmod/CHOWN, actual port binding, partial bootstrap, TLS, NumPy/JSON и CI observation failures. Новый read-only tracking doctor проверяет ownership/configuration и HTTPS, не меняет сервисы и не даёт release approval. Изменяющие qualification/restart действия явно отделены.

[Clean-checkout CI на 44deac9](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38134212049) подтвердил 33 comparator/26 doctor tests, native campaign с шестью runs и live doctor; success. Отдельный image audit по-прежнему failure. Документационный follow-up записывает evidence без изменения кода и без повторного CI; локальный docs checker обязателен.

## R1 persistent private tracking - 2026-10-11

Реализован [постоянный local MLflow и проверен clean-checkout CI](docs/tracking-service.md): separate metadata/auth PostgreSQL databases, certificate identities, HTTPS/mTLS, private backend network, loopback endpoint и внешний host publisher. Локально и в run `38131527513` на `40d26dc` прошли 54 native + 16 controlled boundary checks, 74 worker checks, 13 configuration и 19 client contracts. Три настоящих обучения и artifacts сохранились после остановки/старта PostgreSQL и MLflow. Полные M06/T08, recovery, Kubernetes integration и image OS security не приняты.

## R1 MLflow compatibility and authorization spike - 2026-10-11

Добавлен [отдельный MLflow 3.17.0 image и offline probe](docs/tracking-spike.md): hashed dependencies, проверка model-run projections, реальные grants/denials и restart с тремя fresh training runs. Локальный audit 91 dependency без известных vulnerabilities/skips; audit, 53 native HTTP checks, 27 projection и 12 orchestration contracts повторены в clean-checkout CI `38129646455` на `a48a9dc`, success. Worker dependencies, SQL и release authority не изменены. PostgreSQL/TLS deployment, image OS audit и полные T08/M06 не приняты.

## R1 isolated candidate storage restore - 2026-10-11

Добавлен explicit immutable image binding для внутреннего экспериментального restore, без изменения default image/receipt policy. Новый runner проверяет подписанный backup в свежем candidate target, TLS/SQL роли, ledger, collation sample и golden predictions. Локально и в CI 434 native checks и 47 controlled contracts прошли; отдельный локальный image pull отказал с inconclusive. [Runbook](docs/storage-candidate.md), [CI evidence и новая scan DB](docs/evidence/storage-candidate-2026-10-11.md): 100% branches малого runner, candidate storage 3 Critical/88 High, worker 55 High. Security gate fail, рабочая история и deployment не переключались.

## R1 isolated image candidates - 2026-10-09

Добавлены multi-stage worker с исправленным PCRE2 и без uv в runtime, PostgreSQL 18.6-trixie candidate без unused gosu и old layers, source/recipe binding и four-image same-DB comparison. 123 controlled checks и 74 worker developer checks прошли локально и в clean-checkout CI. [Native evidence](docs/evidence/image-candidates-2026-10-09.md): worker High 56 -> 55, storage Critical 7 -> 1 и High 101 -> 79; четыре новых storage advisory IDs не скрыты. Оба candidates fail, working SQL не меняется. [Runbook и границы](docs/image-candidates.md).

## R1 native audit findings - 2026-10-09

Проверен clean-checkout run `37842817452` на `19c618c`: native SBOM, свежая DB, positive detection control и оба image scans завершены. Исправлены реальные форматы Grype `db.status`/`v6.1.10`. 99 controlled checks прошли, branch coverage трёх audit modules 98,78%. Severity gate правильно вернул fail: 56 High matches worker, 7 Critical и 101 High matches storage. [Evidence и 69 triage groups](docs/evidence/container-audit-2026-10-08.md). Порог не ослаблен, working SQL и runtime не переключались, M01/R1 остаются открытыми.

## R1 worker/storage image audit - 2026-10-08

Добавлены pinned Syft/Grype runner и CI, привязка SBOM к config digest свежего Docker archive, отрицательные проверки reports/archive/CLI и fail-closed policy. Native SBOM локально работает; Grype DB недоступна из-за TLS timeout, поэтому audit не объявляется пройденным. [Runbook](docs/container-audit.md). Runtime worker и private SQL этим host-only increment не меняются; M01/R1 остаются открытыми.

## R1 executable worker authority gate - 2026-10-08

Добавлен исполняемый M20: свежий запуск isolation/protocol/controller/live-access suites и 21 реальный prediction Job в qualification scorer с действительными signer/SQL credentials. Девятнадцать повреждённых responses должны отказать до sign/write; два положительных контроля подписываются, сохраняются и перечитываются. Report связывает source/image/policy/dataset/candidate/model и hashes компонентов. CLI не оставляет старый pass при missing prerequisites или crash. [Воспроизведение и точное покрытие](docs/worker-authority-gate.md); результаты текущего source и CI фиксируются в STATUS. Полный R1 остаётся незавершённым.

## R1 live worker boundary - 2026-10-08

Добавлены scorer witness, worker access probes и UID-bound cleanup. Общий controller Pod builder сохраняет настоящие mounts/identities, witness подтверждает доступ к holdout/signer и SQL/API до/после двух worker Jobs. Локально прошли 137 checks: 43 unit/controlled checks и 94 live/orchestration checks. На каждую worker identity проверены 29 filesystem/proc paths и две network boundaries. [Runbook](docs/live-worker-boundary.md). Воркер не получает credentials или host privileges; полный M20 ещё не объявляется принятым.

## R1 prediction protocol v2 - 2026-10-08

Исправлен приём неизвестной schema version и произвольного scan report. Добавлены одноразовый pending batch, точные row IDs/order, request/model binding и ограничения response до signer/SQL publication. Старый prediction v1 больше не исполняется, исторические signed evaluations не переписываются. Все callers, включая golden recovery/migration, используют общий helper. Локально прошли 164 protocol и 136 controller checks; [runbook и границы](docs/prediction-protocol.md). Полные M20/M21/M18 не объявляются закрытыми.

## R1 scoped controllers - 2026-10-08

Publisher/scorer теперь выполняются в отдельных Kubernetes Jobs без host kubeconfig или Docker socket. Добавлены bounded HTTPS client, собственные Role/RoleBinding, fail-closed native admission, отдельный evaluator Secret и image-bound provenance. Настоящее обучение и оценка записывают новую историю в private SQL; исходная host БД не меняется этим demo. Локально прошли 133 checks, включая 60 API/admission/RBAC проверок. [Инструкции и ограничения](docs/scoped-controllers.md). Это проверенный компонент, не полный M04/M20 или trusted release.

## R1 signed cluster migration - 2026-10-08

Добавлен opt-in перенос проверенного SQL snapshot в private Kubernetes storage: external trust roots, target identity binding, native advisory lock, maintenance, atomic import и signed receipt. Resume после сбоя не копирует committed данные повторно; source и последующие target rows не перезаписываются. Publisher/scorer Pods проверяют реальные migrated artifacts, отдельный offline worker выполняет 1 000 golden predictions. Локально 497 checks прошли, max error 0.0. [Runbook](docs/cluster-storage-migration.md); полные M04/M17/M20 и R1 остаются открытыми.

## R1 private storage increment - 2026-10-08

Добавлен opt-in Kubernetes PostgreSQL profile: отдельные role identities, DNS-bound mTLS, default-deny network, retained PVC и проверяемый по UID bootstrap. 436 локальных checks включают SQL/TLS/API/network denials и persistence при замене Pod. Host storage не переключён и не удалён. Исправлен Linux libpq password-file warning без ослабления TLS или JSON protocol. [Runbook](docs/private-cluster-storage.md); full M04/M20 и R1 остаются открытыми.

## R1 developer preview - 2026-10-07

Реализован подписанный native PostgreSQL backup с общим snapshot для dump/ledger и restore только в новый owned workspace. Локально прошли 430 recovery component checks, 1 000 golden predictions совпали, источник не перезаписан. Full M17 и R1 остаются открытыми. [Воспроизведение и ограничения](docs/storage-recovery.md).

Добавлен executable M03: Linux tamper/symlink/signature fixtures, реальные storage/pipeline checks и hashes SQL-dataset до/после отказов. Локально прошёл 431 case; T04 закрыта в synthetic-only профиле. Windows symlink privilege не включается, fixtures выполняются в offline Linux container. Full R1 и M04/M20 остаются открытыми. [Runbook и точное покрытие](docs/integrity-gate.md).

Третий increment добавляет source lock, signed snapshot authorization, bounded quarantine, explicit curator approval, signed data lineage и M02 acceptance с 44 проверками. После security spike DVC исключён из active dependency set, вместо CVE waiver принят ADR 0005. 74 developer и 52 Kubernetes checks на предыдущем transport increment прошли в GitHub CI. Полный R1 не принят.

Второй increment добавляет isolated Kubernetes backend, pinned Cilium/Helm/kind, native admission и quotas, actual role/network/resource qualification и отдельный clean-checkout CI workflow. Локально прошли 52 Kubernetes component checks. ONNX telemetry выключена до запуска runtime. Подробнее: [Kubernetes lab](docs/kubernetes-lab.md).

Начата реализация по запросу владельца. Добавлены frozen policy, pinned environment/image, bootstrap, DSSE signing, synthetic datasets, изолированные Docker workers, Logistic Regression -> ONNX, независимый scorer и исполняемая developer qualification. Детали и ограничения: [STATUS](STATUS.md), [журнал](docs/implementation.md). Полный R1 не принят, trusted promotion не разрешён.

## R0.2 - 2026-10-06

- Проверены новый пользовательский текст, CyberOrda и дополнительные первоисточники; реестр вырос с 24 до 44 записей. Добавлены датированный международный обзор, критический разбор и восемь traceable design decisions.
- Архитектура расширена inventory graph, worker/controller boundary и отдельным ADR, fail-closed artifact intake, absolute-budget challenges и security event contracts.
- Приёмка расширена с 18 до 23 gates, угрозы с 14 до 19, backlog с 24 до 29 задач. Старые ID сохранены; M18 остаётся финальным агрегатором.
- План пересчитан на 14-16 недель активной работы плюс 25% календарного резерва. Установка LLM/GPU/облачных платформ не добавлена.
- Документационный validator проверяет source-to-decision JSON и его связи. Это не evidence выполнения ML-контролей.

Статус всех ML implementation tasks остаётся PLANNED. Нет обучения моделей, ML runtime, новых production credentials или изменений DevSecOps foundation. R0.2 обозначает редакцию документов, не выпущенный runtime или Git tag.

## R0.1 - 2026-10-06

Первоначальный research/design snapshot: [commit 6b5e981](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/6b5e981cfa599de1530de0a0cfe9727748dcdbd2). Содержит разбор исходных PDF/схемы/PT, read-only baseline audit, архитектуру CPU reference, threat model, приёмку и первый roadmap. Обучение и эксплуатация ML не выполнялись.
