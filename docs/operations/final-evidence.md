# Финальная проверка evidence M18

M18 читает результаты M01-M17 и M19-M23 одного frozen candidate.
Входом служат оригинальные acceptance JSON, исходные материалы и внешние
pins SHA-256. Диспетчер находится в [acceptance.py](../../mlsecops/acceptance.py),
проверка в [final_evidence.py](../../mlsecops/final_evidence.py).
Она работает офлайн после сбора evidence и teardown.

Успешный результат имеет `scope=frozen-candidate-synthetic-lab`,
`release_ready=false` и `production_authorized=false`.
[Условия M18](../acceptance.md#m18) требуют независимый review, полный
inventory, image policy, coverage и governance. Все эти материалы обязательны
для `pass`. Утверждения о реальных испытаниях следует брать из конкретного
проверенного пакета. Unit fixtures подтверждают работу проверяющего кода.

## Порядок и существующие контракты

Для промежуточной карты достаточно существующей сводки
`scripts.delivery_candidate` в `state/evidence/delivery-candidate.json`,
её независимо полученного hash в `M18_DELIVERY_SHA256` и оригинальных
отчётов или строк JSON из workflow, сохранённых в `evidence/Mxx.json`.
При запуске без `M18_INDEX_SHA256` M18 сверяет receipt, source, доступные
candidate bindings и исходные bytes. Для опубликованной строки он убирает
только `report_sha256`, восстанавливает canonical JSON плюс LF и сверяет
оба hashes с внешним receipt. В `diagnostics` перечислены `receipt_matched`,
`missing_receipts` и `unavailable`. Даже 22 совпавших receipt дают только
`inconclusive/2`, подмена даёт `fail/1`. Полная проверка всегда имеет
приоритет, если передан `M18_INDEX_SHA256`.

1. Зафиксировать clean Git commit, source fingerprint, worker image, data.lock
   и отдельно проверенный план критериев. Внешний владелец сохраняет hash плана.
2. Выполнить существующие gates в workflow на одном candidate. Сохранить
   исходные bytes каждого отчёта и его hash при завершении producer.
3. Сохранить исходный `storage-demo.json`, `storage-trust.json`,
   `trusted-keys.json` и `evidence/release-native.json`. Сохранить policy
   envelope и полный package, который возвращает действующий
   `release_bundle.load`. Каждый материал сохраняется с его исходным
   представлением.
4. Завершить M22 через существующий independent-review intake, исполнение
   двух challenge и reviewer decision. Собрать governance и подписанный review.
5. После teardown выполнить M18. Отсутствующие gates и материалы дают
   `inconclusive/2`. Подмена, чужой candidate, противоречие или failed gate
   дают `fail/1`. Отчёт содержит отдельные диагностические причины по gates.
6. Сохранить M18 вместе с внешними receipts producer. Только отдельный
   release процесс проверяет актуальные authority windows, выпускает
   release assurance и получает явный approval.

M10 проверяется в существующем режиме
`T13-pre-promotion-mechanism-actual-refusal-separate-controlled-authorization`.
Его actual candidate должен получить `release_assurance_required` при
sequence 0. Controlled promotion имеет отдельный subject и sequence 1.
M18 читает этот предшествующий M10, проверяет его привязку к original
proposal и состояние. Вызовов M10 или release authorization из M18 нет.
Это устраняет зависимость M10 от ещё отсутствующего M18.

## Доверие к pins

`M18_INDEX_SHA256` и `M18_PLAN_SHA256` передаются через независимо
контролируемую среду job. Их нельзя вычислять из присланного архива прямо
перед проверкой и считать доказательством происхождения. Владелец producer
должен подтвердить job/run, commit, чистоту checkout и точные hashes при
сборе. Сохранённый receipt должен связывать эти факты с ожидаемым workflow.
Самостоятельно созданные ключи и hash файла подтверждают только внутреннюю
согласованность такого файла.

План утверждается отдельно до запуска. Он фиксирует полный перечень gate
IDs, case IDs, artifact names, ожидаемые причины отрицательных M02/M03,
reviewer public key, список security-critical модулей и разрешённый
package coverage. Индекс связывает окончательные reports и governance.
Проверяющий доверяет происхождению этих внешних pins и хранению reviewer
key. Личную независимость reviewer подтверждает владелец процесса.

Ключ reviewer должен отличаться от всех lab keys и от publisher, assessor,
approver из promotion policy. Используется существующий DSSE
(Dead Simple Signing Envelope, подписанный конверт) с Ed25519.
В реализации применены `signing.verify` и `release_policy.checked`.

## Формат входов

В `storage-recovery.yml` шаг `m18_freeze` выполняется сразу после формирования предложения. Он получает от предыдущего шага SHA-256 четырёх файлов, читает исходные объекты через роль `serving`, проверяет подписи, происхождение данных, модель и оценку. Пакет остаётся в приватном временном хранилище runner. Хеш файла `M18-frozen-inputs.json` передаётся следующему шагу средствами GitHub Actions.

После подтверждённой остановки SQL и удаления Kubernetes команда `python -m scripts.m18_delivery_freeze replay` повторяет проверку по сохранённым байтам. Для воспроизведения ей нужны исходный чистый checkout, тот же каталог состояния и `M18_FREEZE_SHA256` от шага захвата. При отказе проверьте принадлежность хеша той же попытке, исходный `data.lock` и наличие объектов по их хешам. Успешный повтор подтверждает сохранность подписанных материалов. Для решения M18 по-прежнему нужны отчёты 22 дочерних проверок и независимый review.

Все пути ниже относительны к явно указанному state. JSON хранится в UTF-8.
Хеш исходного файла включает завершающий перевод строки. Для объектов,
чей действующий producer считает `digest(canonical(value))`, сохраняются
именно bytes `canonical(value)`.

`evidence/M18-plan.json` содержит следующие поля.

| Поле | Содержание |
|---|---|
| schema_version | 1 |
| source_revision, source_fingerprint | Полный Git SHA и fingerprint зафиксированного source |
| cases | Все 22 gate ID, каждому соответствует hash canonical(sorted(case IDs)) |
| artifacts | Для каждого gate hash canonical(sorted(artifact_hashes keys)) |
| rejections | M02 и M03, mapping case ID к точному ожидаемому actual для expected=reject |
| modules | Относительные Python paths security-critical scope, включая mlsecops/final_evidence.py |
| reviewer_key | Внешне аутентифицированный base64 Ed25519 public key |
| image_packages | Mapping distro/coverage_profile к заранее проверенному непустому списку package names |

`evidence/M18-index.json` содержит следующие поля.

| Поле | Содержание |
|---|---|
| schema_version | 1 |
| source_revision, source_fingerprint, image_id | Точный source и image исходного proposal |
| plan | Hash исходных bytes M18-plan.json, совпадает с внешним M18_PLAN_SHA256 |
| policy_reference | Hash canonical подписанного promotion-policy envelope |
| freeze | Hashes четырёх исходных файлов из шага 3 |
| reports | Mapping M01-M17, M19-M23 к hashes evidence/Mxx.json |
| retained | M13 и M15, hashes существующих privacy-gate-private.json и monitoring-gate-private.json |
| governance | Hashes материалов из следующего раздела |

M18 намеренно исключён из `reports`. Частичный mapping разрешён для
диагностики, но успешная приёмка требует все 22 отчёта.

Материалы по содержимому хранятся в `evidence/M18-objects/<sha256>`.
Функция `retain(state, raw_bytes)` сохраняет точные bytes и возвращает hash.
`retain_package(state, package)` сохраняет исходный release envelope,
capsule envelope, documents и capsule objects. Эти функции помогают
упаковать материалы, а происхождение pins устанавливает внешний producer.

Сохраняются все preimages `artifact_hashes`, включая canonical snapshots,
public key bytes и отдельные model bytes. Для `primary_materials` и
`review_primary` сохраняются также файлы, перечисленные в mapping.
M13/M15 требуют private admissions, исходные private observations и
`retained_packets`. Отсутствующий preimage диагностируется как отсутствующее
evidence, даже если сам hash выглядит корректно.

## Native schemas и привязки

| Gates | Проверяемая связь |
|---|---|
| M01 | Source, worker image, primary inventory/materials, runtime inventory |
| M02 | Source digest и data.lock, совпадающие с подписанной lineage candidate |
| M03 | Source/data.lock, dataset/candidate/evaluation, worker, storage configuration |
| M04, M20 | Dataset/authority primary, общие component hashes и cluster identity |
| M05 | Candidate/model и serving-under-fault bundle subject, ссылки на M04/M20 |
| M06 | Frozen candidate replay, signed evaluator protocol, одинаковые split bytes и request, три отдельных training runs, численные tolerances |
| M07 | Candidate/evaluation, dataset, source, model, holdout, training request и evaluation policy |
| M08, M09 | Candidate/evaluation и actual model, training input, source/image и действующие statistical schemas |
| M10 | Original proposal, policy, actual refusal и отдельная controlled authorization |
| M11-M15 | Candidate/proposal/model/subject, исходные artifacts, для M13/M15 отдельные private admissions |
| M16, M17 | Original proposal packet и qualified candidate, отдельные controlled rollback/recovery fields |
| M19 | Candidate/model/subject и dataset ID, actual fleet primary schema 2 |
| M21 | SQL candidate/evaluation/model/trust, отдельный Kubernetes candidate |
| M22 | Матрица и две независимые challenge, signed intake/freeze/observations/decision |
| M23 | Source/candidate/model/subject, три capture stages и original outage proposal |

Для M06 локальные повторения имеют собственный manifest ID вследствие
отдельно подписанного source approval. Проверяются candidate replay,
split materials, evaluation protocol и tolerances. Равенство reference
dataset ID и exact model bytes между обучениями не требуется.

M08/M09/M22 допускают native cases с полями `id,status`.
Численные M06 cases используют inequality thresholds. M02/M03 сохраняют
собственные отрицательные причины отказа. Остальные cases проверяются
с canonical equality expected/actual. Полноту case IDs и artifacts
определяет внешний план.

M17 public_keys использует hash canonical JSON. M19 public_keys и
M10 input_files используют hash исходного файла. M18 сохраняет эту разницу.

## Governance

`governance` должен содержать ровно следующие ключи.

- `docs/model-card.md`, `docs/dataset-card.md` со hashes текущих файлов.
- `coverage` с исходным coverage.py JSON, branch_coverage=true. Проверяются
  executed/missing arcs, их уникальность, counts и >=95% на каждом модуле
  из независимого scope.
- `image_audit` с действующим observed-runtime image audit.
- `runtime_before` и `runtime_after` с исходными snapshots image_scope.collect.
  Они должны совпадать и связываться с M01/M04, source и controller profile.
- `documentation`, `expiry`, `retention`, `teardown`, `redaction`,
  `limitations` с JSON записи review для каждого направления.
- `review` с DSSE типа `final-evidence-review`, подписанным независимым
  ключом из плана.

Каждая запись направления имеет `kind`, `subject_sha256`,
`decision=pass`, непустое `observation` и непустой список hashes
`evidence`. Это наблюдение reviewer с конкретными приложениями.
`expiry` также содержит `proposal_expires_at`, совпадающее с подписанным
proposal. Историческое окно проверяется на время исходного capture.
Действующая source approval проверяется библиотекой и при offline replay.

`retention.inventory` указывает на JSON с `subject_sha256`, `backup_id`
из M17, `observed_at` и `retain_until`, покрывающим время review.
`teardown.before` и `teardown.after` указывают на наблюдения с
`workspace_id`, `observed_at` и списком `owned`. До cleanup список
непустой, после cleanup пустой. Ответственность за полноту обнаружения
ресурсов отражается в подписанном review и внешнем producer receipt.

Payload итогового review содержит `scope=local-cpu`, `decision=pass`,
`plan`, `reports`, `retained`, `source_revision`, `subject_sha256`,
`model_sha256`, `reviewed_at` и `governance` без самого ключа review.
Все mappings должны в точности совпасть с индексом.
Reviewer завершает review после всех дочерних reports.

Image replay использует действующий `image_audit_contract.assess`, реальные
SBOM (software bill of materials, состав образа) и scanner JSON, фиксированные
Syft/Grype images, общую свежую vulnerability database и positive detection
controls Python/Wolfi/Go. High/Critical, unknown coverage, diagnostic-only,
неполный inventory и scanner exceptions блокируют M18.

Original private evidence хранится в закрытом state. Публичный M18 содержит
hashes и фиксированные диагностические метки. Он не выводит exception text
из недоверенного содержимого. Existing secret patterns проверяются в
публичных child reports, cards и review notes. Полноту redaction отдельно
оценивает подписанный reviewer. Windows path checks имеют ограничения,
описанные в `contracts.bounded_read`, state должен иметь доверенного владельца.

## Запуск и локальная проверка

После установки двух внешних pins и подготовки state запуск выполняется
через обычную точку входа.

```sh
python -m mlsecops.acceptance --gate M18 --profile local-cpu --state .runtime --output .runtime/evidence/M18.json
```

Локальные unit-тесты не запускают дочерние native gates.

```sh
python -m unittest scripts.final_evidence_qualification
python -m coverage run --branch --source=mlsecops.final_evidence -m unittest scripts.final_evidence_qualification
python -m coverage report -m
ruff check mlsecops/final_evidence.py scripts/final_evidence_qualification.py mlsecops/acceptance.py
python scripts/check_docs.py
```

## Карта пробелов на связке 94609c3

Состояния runtime ниже сообщены владельцем общей работы 2026-11-14.
В commit 94609c3 также проверена проектная запись
`docs/evidence/training-to-recovery-5494118.md` с восемью hashes и
идентификаторами candidate/evaluation/model. Сырые журналы запуска
в этой подзадаче не воспроизводились.

| Материал | Текущее подтверждение | Что требуется для M18 |
|---|---|---|
| M02/M03/M06/M07/M08/M09/M16/M17 | Владелец подтвердил общий candidate на 5494118 | Исходные отчёты, external pins и retained preimages, итоговый согласованный source |
| M10 | Владелец подтвердил isolated pass e158930 | Тот же original proposal в общем workflow, корректные raw/canonical key pins |
| M12 | На d119 отказ до HTTP | Диагностика причины и успешная actual-candidate qualification |
| M22 | Intake 7276adc интегрирован в 94609c3, actual 0/2 | Два independently frozen challenge, retained execution и signed reviewer findings |
| M01/M04/M05/M11/M13/M14/M15/M19/M20/M21/M23 | В этом пакете common-candidate приёмка не представлена | Полные acceptance outputs и перечисленные native materials |
| Images | Отдельная параллельная работа | Полный owned-runtime inventory, покрытые scans без исключений |
| Governance | Реализация проверяющего контракта | Внешний план, actual coverage, cards, expiry/retention/teardown observations и independent review |

Отчёты с другого source revision не получают автоматического переноса на
94609c3 или последующие commits. Historical результаты полезны для
диагностики и подтверждения отдельных стадий. Финальный пакет должен иметь
согласованные revision, fingerprint и frozen candidate.

Положительные unit fixtures проверяют криптографический reader, native schema
adapters и диагностические отказы. Полный hosted M18, production assurance,
явный promotion approval и pilot governance остаются отдельными результатами.
