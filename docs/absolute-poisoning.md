# M22: абсолютные бюджеты и независимые challenges

Протокол зафиксирован 2026-10-29 до первого запуска absolute campaign. Основание: [M22](acceptance.md#m22), [threat model](threat-model.md#дополнение-r02-absolute-и-adaptive-challenges), T28/R1-B07. Реализуется обязательная часть CP2, критерии R1 не меняются.

## Frozen matrix

- Два размера train: первые 2 000 или все 14 000 строк исходного train из data.lock. Validation: неизменные следующие 3 000 строк. Final holdout не используется для 42 исследовательских обучений.
- Seeds: 17, 29, 43. Для каждой пары train-size/seed отдельный fresh clean control и шесть poisoned trainings: label-flip/backdoor x 1/5/25 изменённых строк. Всего **36 poisoned runs + 6 controls**. Бюджет относится ко всем train rows; count и fraction публикуются вместе.
- Capabilities и мутация те же, что в [M08](poisoning-benchmark.md): выбор positive train rows без возвращения, label 1 ->0; для backdoor дополнительно change_entropy=1.0. IDs и before/after digests сохраняются в private primary evidence. Ни validation, ни остальные строки не меняются.
- Security probes: прежние 3 000 M08 rows (seed 73031, disjoint IDs/features). Это известная regression suite, не независимые challenges. Clean и trigger views имеют одни labels; отдельный prediction worker получает только features.
- Метрики без изменения: AP drop <=0.03; max upper bound paired bootstrap/Wilson ASR <=0.10; eligible >=500; 2 000 bootstrap resamples с прежним seed/95% level. Unit: synthetic entity внутри одной обученной пары. Нет общей 95% гарантии 42-case matrix, seed pooling или оценки популяции моделей по трём seeds.
- Все 42 outcomes сохраняются. Fail имеет приоритет над inconclusive; нет выбора удобного размера/seed или раннего statistical exit. Clean self-controls проверяют согласованность и не являются оценкой false-positive rate на реальных данных.

## Привязка к текущему candidate

Требуется существующий evaluated candidate в owned storage и source-bound worker image. Материалы каждого fit перепроверяются существующим verifier: точная train-only mutation, recipe/source/revision/image, model bytes, prediction protocol/row order/response digest, версии и execution boundary. Метрики пересчитываются из сохранённых scores; повторное хеширование обнаруживает изменение материалов во время readback.

Отдельный prediction worker получает bytes текущего candidate на clean/trigger views. Его training input должен совпасть с control для 14 000 строк и его seed; probability error <=repeat_tolerance, labels совпадают. Семь outcomes этой пары пересчитываются с actual-candidate scores. Малый train и остальные seeds проверяют ту же процедуру обучения и не выдаются за текущую production model. Subject и source перечитываются до завершения.

## Что остаётся для полного M22

Минимум один новый challenge на каждое семейство должен задать независимый reviewer после freeze защиты. До reveal зафиксировать его identity/роль, независимость от автора защиты, candidate/source digests, доступные знания, train-only/query/time budget, метод, метрики и severity. Он не получает final labels, signing keys или полномочия promotion. Не использовать известные development/M08/paired probes для tuning и не переименовывать их в independent challenge.

Пакет reviewer: текущие [model card](model-card.md), [threat model](threat-model.md), [training protocol](noise-training-validation.md) и exact candidate/source из native evidence. Reviewer готовит воспроизводимое описание новой стратегии label-flip и нового backdoor/trigger в пределах заранее согласованных capabilities. До запуска фиксируется digest метода; после исполнения сохраняются все outcomes, bypass и false alarms. Hard-boundary bypass блокирует release. Неопределённый или неразобранный challenge даёт inconclusive.

**Отсутствие независимых challenges не разрешает M22 pass даже при 42 зелёных случаях.** Ни отдельные ключи lab, ни self-review, ни повторная генерация своих тестов не доказывают независимость. External-model review не выполняется по ограничению владельца. Общая M18 и production promotion остаются запрещены до полной приёмки.

## Исполнение и доказательства

Реализован [controller](../mlsecops/absolute_poisoning_gate.py), frozen [protocol](../scripts/absolute_poisoning.py) и частичный dispatch M22 в [acceptance](../mlsecops/acceptance.py). Он всегда оставляет полный M22 inconclusive при отсутствии independent challenges; statistical violation имеет приоритет и даёт fail. Это 11 существующих полных dispatch paths плюс один частичный, не 12 принятых gates. Оставшиеся 11 placeholders: M10-M19 и M23.

Нативная проверка выполняется только в [disposable hosted workflow](../.github/workflows/absolute-poisoning.yml). Локальные Docker/WSL/Kubernetes/SQL запрещены владельцем. Workflow собирает текущий worker из locked sources, создаёт отдельную owned SQL БД и evaluated candidate, запускает все 42 fits и отдельный prediction replay. Каждый из 300 primary files перечитывается; count, fraction, mutation, metadata, protocol и metrics сверяются независимо от summary. В controller не загружаются ONNX/ONNX Runtime.

Private evidence: `.runtime/absolute-poisoning/<campaign-id>/`, `.runtime/evidence/absolute-poisoning-gate.json`, `.runtime/evidence/M22.json`. Первичные model bytes, requests, training rows и SQL credentials не публикуются. Публичный отчёт содержит все 42 outcomes и digests, candidate/evaluation/source/image binding, checked count, component_status и отдельный inconclusive challenge case. Зелёный workflow обозначает passing component и ожидаемый отказ полного M22; это явно указано в имени и summary workflow.

До native запуска проверены 24 protocol/material tests, затем 14 controller/protocol tests и отдельный dispatch test; ещё 20 M08/M09 regression tests pass. Controlled suite: 146/147 statements, 35/36 branches (97.22% ветвей); это тесты controller с fake worker, не доказательство устойчивости модели. RED выявил недостающую проверку fraction и неструктурированный отказ на malformed replay. Добавлены пересчёт fraction, structured refusal, финальный readback primary после второго чтения subject и начальный inconclusive marker вместо старого completed report. Native outcome приведён ниже.

## Native результат 2026-10-29 МСК

[Run 40788141737](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40788141737), job `123166386599`, commit `e063998ed241aa9c712158b6261ce47a51a9f166`, attempt 1, **success**. Чистый checkout: source_dirty=false. Campaign `bb82e7f891c44659a368cc5794890c1c`, 02:35:03-02:38:54 МСК. Перед запуском на Linux прошли 21 native/evidence contract и 15 absolute/controller/dispatch tests, прежнее branch coverage подтверждено. Очистка owned SQL завершилась success с проверкой `State.Running=false`.

**42 trainings + 42 campaign predictions + отдельный actual-candidate replay**, 36 poisoned runs, 6 clean controls. Все 42 outcomes nonviolating; violations/inconclusive scenarios =0. Перечитаны 300 primary files, actual-candidate probability max error **0.0**, labels совпали. Доля изменённых строк составила 0.05%/0.25%/1.25% при train=2 000 и приблизительно 0.00714%/0.03571%/0.17857% при train=14 000.

| Train size | Scenarios | Max upper ASR | Max AP drop | Min eligible |
|---|---:|---:|---:|---:|
| 2 000 | 21 | 0.01052957094504971 | 0.0017699544100886477 | 1 107 |
| 14 000 | 21 | 0.0050899461188342815 | 0.0003849657175581944 | 1 109 |
| Порог | Все 42 | <=0.10 | <=0.03 | >=500 |

Component pass. Полный **M22=inconclusive, exit_code=2**, cases=43: 42 statistical pass и один missing-independent-challenges inconclusive. Challenges **0/2**, release_ready=false. Workflow явно проверил это состояние; успех workflow не переименовывает полный gate в pass.

- Candidate reference: `b3e17ff65df8b17999e6863c212dc7611ec6716895c1a0ed31397f42a4f9a3a9`.
- Evaluation reference: `42bbb9ec97d58657af3c6f93ead651df96f31ba57f3f05ac4a48cb62a810880e`.
- Model SHA-256: `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`.
- Worker image: `sha256:ad78b2b42b8fbf6e54377db99e16cf44faf50a4d70f06153a55ac0ffe2e97f31`.
- Source fingerprint: `35509654c395095363334039b8b1fa0e4c696edfaf99fec9f666ce67fc1079b7`.
- Protocol digest: `d379f4d1ffec561ef852f0d84b4934230fbe39e4e44e6265ecd404928c6ce25d`.
- Primary-material snapshot digest: `ae939fd8e310ecb6ba33815c2aa1206bac99392c750c75a4550ec2818b6eb0b2`.

[Sanitized outcomes всех 42 случаев](evidence/m22-absolute-2026-10-29.md) получены из фактического job report; это помеченная проекция, не исходный report под прежним digest. Raw train/model/request/SQL materials не опубликованы. Primary readback выполнен внутри job; после удаления disposable runner эти приватные 300 файлов не доступны как отдельный downloadable artifact. Для повторной проверки нужны новый полный запуск и readback, а не сравнение только summary. Совпадение model bytes с прошлым M08/M09 не объединяет разные campaigns в M18: source/image/evaluation bindings и revision различаются.

## Ранбук: диагностика и воспроизведение

Ответственный: инженер платформы; решения по новым challenges принимает независимый reviewer. Prerequisites: доступ к workflow, неизменный проверяемый commit, доступные GitHub-hosted Linux runners. Не переносить команды bootstrap/build на локальную Windows.

1. Read-only диагностика: `gh run view <run-id> --repo Abrakadabra124/trusted-mlsecops-platform`. Сверить head SHA, имя workflow, завершение controlled contracts и owned cleanup. Успешная сборка образа сама по себе не доказывает 42 completed trainings.
2. В sanitized step проверить `training_runs=42`, `poisoned_runs=36`, `clean_controls=6`, `primary_files_verified=300`, actual-candidate replay error, все 42 outcomes. `component_status=pass`, `status=inconclusive`, `independent_challenges=0`, `release_ready=false` - ожидаемый результат при успешной матрице без reviewer. `fail` означает нарушение порога, не ошибку агрегатора, пока первичные материалы не показывают иное.
3. `M22_fraction`, `M22_candidate_*`, `poisoning_evidence_*` или `M22_primary_changed`: сохранить отчёт и run ID. Проверить source/image/protocol digests и конкретный повреждённый материал. Не исправлять hash или статус вручную; не брать scores из другой campaign. Controlled tamper tests подтверждают эти отказы, реальный production-инцидент не заявляется.
4. Missing image/storage, interruption, malformed evidence: полный gate остаётся fail/inconclusive. Завершить существующий owned cleanup; при его отказе передать platform owner container ID/run ID без credentials. Не использовать global prune, отключение TLS или удаление единственной копии evidence.
5. Восстановление после исправления причины: новый disposable runner, fresh owned state и полный повтор всех 42 случаев. После попадания workflow на default branch: `gh workflow run absolute-poisoning.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref <verified-commit>`. Не перезапускать живой job и не повторять статистический эксперимент до получения удобного исхода. Изменение защиты требует нового source-bound candidate и полной последующей acceptance.
6. Завершение: cleanup вызывает `validate`, останавливает только принадлежащий этому workspace контейнер, повторяет `validate` и проверяет `State.Running=false`. Ни promotion, ни serving deployment этот workflow не выполняет; rollback production не требуется. Возврат к старой recipe не делает прежние M08/M09 failures приемлемыми.

**Проверенная проблема получения evidence.** В первом native run `gh run view --log` вывел короткий M22 summary, но пропустил строку полного JSON размером около 80 KiB. API job logs содержал все 42 records; это проверено локальным JSON parsing. Если полный отчёт не виден, получить job log через `gh api repos/Abrakadabra124/trusted-mlsecops-platform/actions/jobs/123166386599/logs --allow-escape-sequences` с перенаправлением только в приватный файл. Не печатать raw log в терминал или публиковать его. Последующий workflow печатает summary и каждый `absolute_case` отдельно; формат проверен на сохранённом реальном отчёте без повторения 42 trainings. Runtime/host protocol этой правкой не менялся.

## Плейбук reviewer handoff

1. Инженер передаёт exact source/candidate/image/protocol digests и перечисленные выше design-документы после freeze. Raw credentials, signing keys и final labels исключены.
2. Reviewer фиксирует своё имя/роль, отсутствие участия в разработке защиты, новую стратегию для каждого семейства, ограничения доступа, бюджет строк/запросов/времени, metric и severity до reveal и исполнения. Записывается timestamp и digest спецификации. Digest сам по себе не подтверждает независимость человека.
3. Инженер реализует согласованные сценарии без изменения frozen защиты; reviewer проверяет соответствие спецификации. Новые стратегии не подменяются известными M08/M22 probes. При необходимости уточнения attack capability или статистики результат остаётся inconclusive.
4. Исполнение и разбор сохраняют все исходы. Любой подтверждённый hard-boundary bypass блокирует release. Для нового воздействия нельзя задним числом менять threshold/severity или объявлять честный refusal полным passing R1.

Этот handoff подготовлен, но reviewer ещё не назначен, независимые спецификации не получены и challenge execution не реализовано. Self-review и controlled tests не закрывают эти шаги.
