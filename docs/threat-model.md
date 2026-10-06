# Модель угроз v0.2

Статус: проектная модель, без выполненного red-team тестирования. Объект - Release Risk Advisor и его ML delivery chain. Основания: [NIST AML](sources.md#s05), [MITRE ATLAS](sources.md#s07), [OWASP AI Exchange](sources.md#s08). Internal IDs `THxx` не являются идентификаторами стандартов.

## Активы и противники

Активы: исходные данные/labels, holdout, training code/image, model/preprocessing, evaluation report, release policy, keys, approvals, inference API, telemetry и backups.

Противники: внешний API-клиент с ограниченной квотой; недобросовестный поставщик части train-данных; скомпрометированный trainer; атакующий candidate storage; contributor с недоверенным PR; похититель ограниченного machine credential. Основной профиль не предполагает одновременно полный контроль evaluator, signer и host administrator.

**Доверяем, но учитываем риск:** host/cluster administrator, bootstrapped trust roots, утверждённым владельцам holdout и release policy. Компрометация этих ролей может обойти lab-контроли; для production нужны дополнительные организационные и аппаратные меры. Никакая подпись не защищает от сознательно вредоносного доверенного approver в одиночку.

## Реестр угроз

| ID | Угроза / доступ атакующего | Превентивная и детектирующая мера | Негативный тест | Остаточный риск / gates |
| --- | --- | --- | --- | --- |
| TH01 | Подмена dataset после approval | SHA-256 manifest, immutable version, проверка bytes при чтении | Изменить один byte и подменить manifest отдельно | Curator может одобрить плохой источник; M02, M03 |
| TH02 | Label flipping до подписания, до 5% train | Source/label provenance, quality checks, independent holdout | Poison budgets 0.5%, 1%, 5%, 5 seeds | Статистический detector не универсален; M08 |
| TH03 | Backdoor с редким триггером в train | Targeted probes, reviewer, запрет self-approval | Known trigger и отдельный unseen-trigger challenge | Неизвестный trigger может пройти; M08, M09 |
| TH04 | Подмена model/preprocessing или report в storage | Bound bundle, subject digest, verify then load | Модель B с report A; preprocessing другой версии | Компрометация доверенного signer; M10, M12 |
| TH05 | Вредоносный сериализованный объект | No pickle/pyfunc autoload, ONNX allowlist, sandbox | Forbidden format, external path, oversized graph | Уязвимость ONNX parser остаётся; M09, M12 |
| TH06 | Trainer читает holdout/keys или изменяет releases | RBAC, storage credentials, egress policy | Реальные обращения от trainer identity получают deny | Host-admin и kernel escape вне lab-гарантии; M04, M05 |
| TH07 | Poisoned PR или dependency получает secrets | Read-only PR CI, pinned deps/images, изолированные jobs | PR-job не получает signing/prod credentials | Compromised trusted runner; M01, M05, M18 |
| TH08 | Leakage через API, logs, model extraction | Data minimization, auth, quotas, ограниченный output | PII canary в test input не попадает в logs; квота | Membership inference не исключён; M13 |
| TH09 | Evasion допустимыми feature changes | Domain constraints, ограниченный perturbation budget, abstain | Изменить разрешённые признаки в диапазоне | Без формального доказательства остаются обходы; M09 |
| TH10 | Exhaustion на inference/training | Body/row/CPU/RAM/time quotas, rate limits | Большой body, NaN, concurrent requests, runaway job | Распределённая нагрузка выше capacity; M05, M12, M14 |
| TH11 | Replay старой подписи, alias swap, revoke bypass | Environment-bound approval, policy digest, expiry, trust lease | Старое approval, чужой environment, revoked key | Доверенное время/доступность policy service; M10, M11 |
| TH12 | Слепое переобучение из feedback | Feedback quarantine и независимая разметка | Прислать поддельные labels/дубликаты | Colluding source/label owners; M02, M15 |
| TH13 | Drift/label delay скрывает ухудшение | Раздельные metrics, sample-size gates, matured labels | Drift, затем labels с ухудшением; метрики не смешиваются | Несвоевременная/смещённая разметка; M07, M15 |
| TH14 | Restore/rollback возвращает отозванную модель | Current trust check, compatibility group, coherent backup | Corrupt artifact, missing data, revoked previous release | Общий failure domain lab; M16, M17 |
| TH15 | Неучтённый endpoint или потомок отозванного dataset | Asset graph, owner, reconciliation, transitive revoke | Dangling edge, unknown owner, running alias mismatch, revoked ancestor | Inventory/control-plane compromise; M19, M11 |
| TH16 | Candidate компрометирует evaluator parser и получает authority | Отдельные controller/scorer и prediction worker без keys/labels | Worker читает token, labels, signing key или controller socket | Kernel escape/covert channels не исключены; M20 |
| TH17 | Пустой/неподдерживаемый scan даёт ложный green | Coverage-aware intake report, quarantine, no auto-load | Unsupported format, zero objects, scanner crash, stale policy | Неизвестные parser defects и backdoor; M21 |
| TH18 | Overfit к известной suite или малый абсолютный poison count | Hidden challenge и absolute-count budgets | Новая стратегия/trigger после freeze policy, fixture gaming | Ограниченность конечных probes; M22 |
| TH19 | Потеря/подделка security telemetry скрывает атаку | Authenticated events, sequence/gap, ingest health, replay | Duplicate/out-of-order/forged event, collector outage | Trusted producer compromise; M23 |

ATLAS mapping на проверенном snapshot: TH02/TH03 относятся к `AML.T0020` Poison Training Data; TH04/TH05/TH07 к `AML.T0010` AI Supply Chain Compromise; TH09 к `AML.T0015` Evade AI Model; privacy часть TH08 связана с `AML.T0024.000` Infer Training Data Membership. Это сопоставление сценариев, не доказательство полного покрытия ATLAS.

## Протокол исследования манипуляций

1. Работать только на синтетических/разрешённых данных в отдельном lab, не атаковать сторонние сервисы.
2. До запуска фиксировать capabilities: attacker изменяет только train, не holdout, не signer; список изменяемых features/labels, бюджет, seed, цель и знания.
3. Сохранить clean control для каждого seed; не выбирать только удачные попытки.
4. Для label flipping и backdoor провести 3 бюджета x 5 seeds = 15 опытов на семейство; всего 30 poisoned runs плюс 5 clean controls. Это будущий ограниченный benchmark, не выполненный результат.
5. Отдельно измерить clean AUPRC, slice recall, долю targeted ошибок (ASR), разницу к matched clean control, время и причину gate decision.
6. Обязательно иметь known-violation fixtures для проверки enforcement и challenge cases для исследования неизвестного поведения. Успех первого не выдавать за успех второго.
7. В отчёте публиковать и пропущенные challenge-атаки, и false alarms на clean controls. Никакого удаления неудачных результатов ради «100 из 100».

Для первых двух poison families бюджет относится к числу изменённых train-строк, а не размеру файла. ASR считается на заранее определённом наборе подходящих примеров, который clean model классифицировала корректно. Размер набора и доверительный интервал обязательны; малый denominator даёт inconclusive.

### Дополнение R0.2: absolute и adaptive challenges

Исходные 30 poisoned runs + 5 controls сохраняются. Отдельный M22-профиль: два размера train (2 000 и 14 000 строк), budgets 1/5/25 изменённых строк, три seeds, два семейства (label flipping и backdoor) = 36 poisoned runs + 6 matched clean controls. Во всех reports указывать и count, и fraction, источник/позицию poison rows, возможности атакующего и фактический размер train. Holdout остаётся независимым и одинаково определённым для сравниваемой пары.

Это наша ограниченная tabular-матрица, мотивированная вопросом из [S31](sources.md#s31), а не воспроизведение эксперимента с LLM или перенос его «250 документов». Дополнительно reviewer задаёт минимум по одному не использованному при настройке защиты challenge на семейство. Policy и тестовые методы фиксируются до reveal; после обнаруженного bypass нельзя подправить detector и повторно назвать тот же holdout независимым.

Адаптивность означает, что reviewer знает документированные защитные правила и подбирает challenge с учётом этих правил в заранее ограниченном train-only/query/time budget. Доступ к final labels, signer или внешним сервисам это не разрешает. Budget, knowledge и tuning queries записываются до запуска; defender не получает challenge cases для настройки. Если reviewer и автор защиты один человек, человеческая независимость не заявляется.

Учитывать вероятную зависимость samples внутри release/entity и reuse одних и тех же примеров между seeds. Bootstrap выполняется по объявленной независимой единице (entity/time block при необходимости), а не по искусственно размноженным копиям строк. При трёх seeds не заявлять статистически надёжную оценку всей популяции моделей. Per-scenario CIs не являются одновременной 95% гарантией для всей матрицы; pooling и multiple-testing policy объявляются заранее.

Challenge bypass сохраняется в evidence и классифицируется по воздействию. Неустранённый bypass hard authorization/integrity boundary блокирует reference release. Остальные отклонения требуют явно принятого ограниченного риска; нет владельца/достаточных данных - inconclusive, не pass.

## Политика остаточного риска

Высокий риск без проверенного контроля не закрывается словом «принят» самим trainer. Для lab можно продолжать исследование с явным запретом production promotion; для пилота нужен независимый reviewer/владелец риска. Любое исключение ограничено сроком, областью, конкретным release digest и compensating controls. Exceptions не отменяют проверку подписи или запрет загрузки отозванного артефакта.
