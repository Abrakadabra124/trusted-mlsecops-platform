# Измеримая приёмка будущей платформы

**M02 реализован и проверяется executable runner; M01 и M03-M23 пока не приняты полностью.** Числа ниже - пороги лабораторного профиля, не автоматически достигнутые результаты и не отраслевые нормативы. Policy зафиксирована до исходного эксперимента; нельзя ослаблять её после просмотра final holdout без нового review и новой оценки. R0.2 сохраняет номера старых gates, добавляет M19-M23 и расширяет итоговый M18. Фактическое evidence: [STATUS](../STATUS.md).

## Единый формат проверки

CLI-контракт: `uv run --locked python -m mlsecops.acceptance --gate M01 --profile local-cpu --output .runtime/evidence/M01.json`. Runner создан в первом increment R1; пока полный gate не подключён, он сохраняет `inconclusive` и возвращает exit code 2. Это не ошибка, которую следует обходить, и не пройденная приёмка. [Документационный валидатор](../scripts/check_docs.py) остаётся отдельной проверкой.

Каждый report: gate ID, status=`pass|fail|inconclusive`, timestamps, git SHA, input digests, policy digest, compute profile, test cases с expected/actual, метрики, exit codes, artifact hashes, redaction version и residual risks. Любая незавершённая обязательная проверка запрещает promotion. Evidence хранится отдельно от ключей и сырых чувствительных данных; публично публикуется только очищенная копия.

## Профиль измерения

- `local-cpu`: Linux x86_64 container, pinned Python/dependencies/image, CPU provider, 1 вычислительный поток, без GPU. Точная модель CPU/ОС и доступные ресурсы записываются в T01.
- Training job: до 2 vCPU, 4 GiB RAM, 10 минут; serving replica: до 1 vCPU, 1 GiB RAM; модель до 50 MiB. Проверить resource headroom до запуска параллельных сервисов, эти limits не являются замером текущего ПК.
- Данные lab: 20 000 синтетических строк, frozen split 70/15/15, seed генератора, без персональных данных. Синтетическая временная структура не доказывает корректность реального temporal split.
- Нельзя сравнивать ML p95 с прежним Release Ledger p95 как один workload. Для GPU/ARM/реальных данных требуется отдельный профиль.

## M01
**Foundation и повторяемый bootstrap.** В чистом отдельном окружении bootstrap проходит дважды без потери данных/смены ключей, baseline reference pin сохранён. Версии и digest всех используемых images/lockfiles доступны. Negative: отсутствующий обязательный tool или несовместимая версия дают отказ с причиной, а не downgrade защиты. Evidence: inventory, первый/второй state diff, P0-отчёт. Задачи T01, T02.

## M02
**Контракт и карантин данных.** Все fixtures с неверным типом, пропущенным обязательным полем, duplicate ID, неконечным числом, неизвестным source approval, просроченным разрешением и поддельным feedback отклоняются до approved storage. Clean fixture принимается. Для schema/duplicate нарушений допускается 0 строк в approved; доменные range-пороги фиксируются отдельно. Evidence: fixture matrix, row counts, dataset card. T03, T04.

## M03
**Целостность dataset и split.** 100% перечисленных fixtures подмены bytes/manifest/split/signature дают reject; approved dataset читается с теми же digest. Неавторизованная перезапись невозможна для ingestor/trainer. Negative: single-byte tamper, traversal, symlink escape, missing object и stale source version. Evidence: hashes до/после, access-denied и verifier output. Не обещает обнаружение semantic poisoning. T04.

## M04
**Изоляция прав.** Trainer не читает holdout/keys, не пишет releases и не создаёт privileged Job; serving не читает train/candidates. Evaluator не изменяет candidate. Проверить реальными API/storage/network-запросами под каждой identity, а не только YAML или `can-i`. Все запрещённые операции отклонены, все минимально необходимые разрешены. Evidence: identity/access matrix и network probes. T05.

## M05
**Ограниченное обучение.** Job без root/capabilities/hostPath/Docker socket, readonly root, egress allowlist, ресурсы и active deadline. Negative: попытка произвольного egress, чтения host, infinite training и исчерпания памяти завершаются отказом/лимитом без влияния на serving. Evidence: pod spec плюс фактические probes/termination. T06.

## M06
**Воспроизводимость.** Три fresh-process обучения на одинаковом local-cpu профиле без reuse готовой модели. Все input digest совпадают; максимум абсолютной разницы вероятностей на golden set <= `1e-6`, разница AUPRC <= `1e-4`. Отдельно сохраняются artifact hashes, различие metadata не скрывается. Negative: seed/data/env mutation должна выявляться как изменение inputs, не считаться повторением. Evidence: runs, vectors digest и comparison report. T07, T08.

## M07
**Независимая оценка и отсутствие leakage.** Preprocessing fit только на train, нет пересечений entity IDs, real profile использует temporal/group split. Для lab: AUPRC >= 0.80 и прирост >= 0.10 к DummyClassifier на frozen holdout; >= 200 positive labels в общей оценке, >= 100 размеченных примеров на заявленный slice. Недостаточный объём = inconclusive. Для пилота эти synthetic thresholds не переносятся: нужен предварительно утверждённый cost/precision/recall target и 95% CI выигрыша против бизнес-правила. Negative: test leakage, незрелые labels, подмена evaluator report. T09, T10.

## M08
**Poisoning benchmark и честные пределы защиты.** Выполнены 30 poisoned runs + 5 clean controls по [протоколу](threat-model.md). Для release candidate относительно matched clean control: падение clean AUPRC <= 0.03; верхняя граница 95% CI прироста targeted ASR <= 0.10 на заранее выбранных probes, denominator >= 500. Эти пределы только для оговорённых атак. Known-violation fixtures с нарушением порога блокируются все; challenge bypass и false positives публикуются независимо от результата. Нельзя требовать «любая атака должна обнаруживаться» и подбирать fixtures под желаемый ответ. T11.

## M09
**Безопасный формат, parity, ограниченная устойчивость.** Python/ONNX probability max absolute error <= `1e-5` на >= 1 000 golden cases, совпадение label для случаев вне epsilon-зоны decision threshold. Forbidden pickle/custom operator/external path/oversized graph fixtures отвергаются до load. Evasion suite: только разрешённые признаки и заданный бюджет; падение recall <= 0.05 на заранее утверждённых probes, OOD fixtures приводят к abstain. Отчёт перечисляет непокрытые атаки. T12.

## M10
**Комплект и promotion policy.** Все обязательные digests связаны, signature/identity/issuer policy проверяются до promotion; approval связан с environment и policy. Negative: чужой signer, отсутствующий report, mismatched subject, alias swap, self-approval trainer, неизвестная schema и повтор в другом environment отклоняются. Повтор разрешённого promotion идемпотентен. Evidence: positive/negative matrix и state transitions. T13.

## M11
**Отзыв доверия и replay protection.** Отозванные key/model, истёкший approval, старая policy и неразрешённый rollback отклоняются. При недоступном trust service serving прекращает ML-ответы не позднее 60 s после последней успешной проверки актуальной policy; дополнительные 60 s после истечения lease не добавляются. Точные clock/lease semantics зафиксированы, negative clock skew тоже проверяется. Необработанная revocation не маскируется cached alias. Evidence: timestamped trace и причина отказа. T14.

## M12
**Inference contract и fail-closed.** Проверяются 413/422/429/503, NaN/Inf, неизвестные поля/версии, >100 строк, body >64 KiB, malformed model и отсутствующая подпись. Ready=true только после verified load. Output содержит правильный bundle digest, score в `[0,1]` или abstain. Negative: изменение bytes после проверки не должно попасть в runtime. Evidence: API tests, loader probes и running digest. T15.

## M13
**Privacy и audit.** Искусственные PII/secret canaries из input не встречаются в logs/metrics/traces и публичном evidence; raw features по умолчанию не сохраняются. Проверены auth, per-client quotas и ограниченная cardinality. Audit связывает source/run/report/approval/release/request без raw payload. Public export не содержит private storage URLs, identifiers и легко перебираемых hashes чувствительных значений. Membership inference не объявляется устранённым; masking не называется DP. Реальный пилот требует purpose/retention/privacy specification, а DP при выборе - отдельного review privacy unit, adjacency, epsilon/delta, composition и реализации. T16.

## M14
**Нагрузка и деградация.** 10 s прогрева, затем 120 s, 10 concurrent clients, одна строка/запрос, pinned golden payload, >= 1 000 измеренных запросов. Предлагаемые lab targets: p95 <= 200 ms, p99 <= 500 ms, неожиданные 5xx < 0.1%; намеренные invalid-input тесты отдельно. Результат включает RPS, CPU/RAM, errors, latency distribution и отсутствие неверного digest. Overload приводит к ограниченному отказу, не OOM loop. T17.

## M15
**Мониторинг качества и обратной связи.** Synthetic shift fixture даёт alert <= 120 s после попадания достаточного окна в scheduled evaluator. Initial profile: >=1 000 observations/window, фиксированные bins/reference, PSI >=0.2 как lab warning, минимум два окна; реальные пороги калибруются отдельно. Delayed-label fixture ухудшения recall на >0.05 после >=200 positives даёт другой alert. Clean control не создаёт alarm в 10 контрольных окнах; это не оценка production false-positive rate. Alert не запускает auto-promotion. T18.

## M16
**Canary и rollback целого bundle.** В lab провести staged traffic 10% -> 50% -> 100% с минимум 100 валидными наблюдениями на стадии, без увеличения ошибок >1 процентного пункта и нарушения latency gate. При fixture отказа возврат к разрешённому compatible bundle <= 120 s; model/preprocessing/config не смешиваются. Отозванная previous model не используется; manual-review fallback остаётся доступен без ML. T19.

## M17
**Независимый restore.** В новом namespace/storage восстановить metadata, artifacts и approvals из согласованной резервной копии; провести digest verification и golden predictions. Target lab RTO <=15 min, RPO <=24 h при ежедневной копии. Negative: corrupt/missing artifact и revoked key выявляются до ready. Измерять от начала recovery, не только SQL import. Offsite/HA lab не доказывает. T20.

## M18
**Итоговый evidence и governance.** M01-M17 и M19-M23 выполнены на одном зафиксированном release candidate; каждый report имеет полные inputs и отсутствуют скрытые skipped gates. Новая security-critical логика имеет >=95% branch coverage и все перечисленные negative cases, coverage не заменяет review. Проверены inventory runtime+controllers in scope, severity policy без молчаливых scanner exceptions, документация, model/dataset cards, expiry/retention и teardown. Независимый reviewer для пилота обязателен. Evidence содержит limitations и не содержит secrets. T21-T24. M18 остаётся последним по исполнению независимо от номера.

## M19
**Инвентаризация и transitive impact.** Для fixture graph из 2 datasets, 3 models, 4 deployments и shared runtime/policy получить точный ожидаемый набор зависимостей. Неизвестный owner, dangling edge, запрещённый cycle или actual digest mismatch блокируют promotion. Отзыв dataset запрещает все его descendants, включая previous rollback candidate, но не независимую ветвь; serving следует lease M11. Evidence: versioned graph, observed deployment snapshot, expected/actual impacted sets. T25.

## M20
**Изоляция model worker от evaluator authority.** Под worker identity попытки чтения holdout labels, signer material, metadata DB, `/proc` процесса controller, service tokens и controller admin API отвергнуты. С разрешённым batch predictions проходят schema/order/size/finiteness проверки; arbitrary text, extra fields, missing rows, oversized output и повтор batch ID не превращаются в signed report. Доказательство: manifests плюс реальные access/output probes. Host-admin и все covert channels вне гарантии. T26.

## M21
**Покрытие intake и fail-closed scanner.** Scan report связывает все входные hashes, tool/policy version, inspected/unsupported/skipped/error counts. Набор approved outputs состоит только из реально проверенных разрешённых объектов. Empty scan, renamed unsupported payload, timeout/crash, stale report, report для другого digest, traversal/symlink и modified conversion output дают reject/inconclusive, не pass. Clean allowed ONNX fixture проходит полный путь до оценки, unsafe format не допускается даже при «no findings». Evidence: support matrix и negative reports. T27.

## M22
**Дополнительная assurance campaign.** Выполнены 36 absolute-budget poisoned runs + 6 clean controls по [расширенному протоколу](threat-model.md) и минимум 2 независимых challenge cases. Для сопоставимых probes сохраняются M08-пороги, нельзя выбрать только выгодные seeds. Отчёт отделяет deterministic enforcement от statistical robustness, фиксирует независимую единицу CI и запрещает объявлять per-scenario CI общей гарантией. Любой подтверждённый обход hard boundary блокирует release; недостаточные данные/неразобранный challenge = inconclusive. Для challenge с новым воздействием метрика и severity утверждаются до запуска, не подгоняются под результат. T28.

## M23
**Security events и доставка реакции.** Минимум по одному fixture для каждого из 7 event types архитектуры; authentic denied/revoked/mismatch events доходят до ожидаемого alert route <=60 s в lab после ingest, без raw payload. Подделанный producer отклонён, duplicate event id не создаёт повторный incident, out-of-order доставлен с признаком задержки, missing sequence/heartbeat обнаружен <=120 s. При audit sink outage новые promotions блокируются, даже если drift dashboard зелёный. Если выбран Sigma backend, дополнительно проверяются field mapping и replay результата после конвертации; без backend не заявляется Sigma deployment. T29.

## Измерение качества: определения

- AUPRC - площадь под precision-recall кривой; положительный класс и prevalence записываются, иначе число трудно интерпретировать.
- ASR (attack success rate) - доля успешных целевых ошибок среди заранее определённых eligible probes. Для доли независимых Bernoulli observations использовать Wilson 95% CI, для разницы matched controls - заранее выбранный paired bootstrap с фиксированным seed и 2 000 повторений. Для зависимых release/entity observations выбирать cluster/block resampling до эксперимента; не считать повторные seeds или дубликаты строк независимыми новыми примерами.
- p95/p99 считаются по клиентской end-to-end latency без прогрева; timeout/error не удаляются из отчёта.
- PSI - Population Stability Index, сигнал различия распределений по зафиксированным bins; не доказательство concept drift, атаки или бесполезности модели.
- RTO/RPO - время восстановления и максимально допустимая потеря данных по времени. Их lab-измерение не создаёт production SLA.

## Правила исключений

Hard security gates не обходятся ради демо. Невыполнимый порог означает расследование, пересмотр scope или новую версию policy с объяснением и повторной проверкой. Если недостаточно данных для CI/slice, статус inconclusive. Не подменять это снижением sample-size требования после просмотра результата.
