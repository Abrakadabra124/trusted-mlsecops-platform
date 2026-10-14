# Release proposal и отдельное разрешение

Дата: 2026-10-14. Increment T13, **не полный M10 и не разрешённый runtime**. [ADR 0026](decisions/0026-release-authorization.md), [PB-20/RB-38/RB-39](operations/release-authorization-troubleshooting.md), [evidence](evidence/release-authorization-2026-10-14.md).

## Что реализовано и зачем

Проверенный candidate ещё не является разрешённым release. `mlsecops.release_bundle` формирует подписанное предложение с фиксированными материалами; `release_policy` проверяет внешнюю политику полномочий; `release_authorization` отдельно проверяет evidence и approval. Ни одна функция не меняет активную модель. Это предотвращает смешение трёх разных событий: сохранение модели, проверка её качества и разрешение эксплуатации.

CAS (content-addressed storage) хранит байты под SHA-256, а не изменяемым именем. DSSE (Dead Simple Signing Envelope) связывает подпись с байтами и типом документа. Ed25519 проверяет авторство относительно внешнего доверенного ключа; правильная подпись сама по себе не означает хорошие данные, качество или разрешение выпуска.

## Материалы

Комплект включает существующую [9-object capsule](material-bundle.md), её envelope, девять дополнительных документов и внешний release envelope: **20 уникальных SQL objects** в проверенном профиле. Нет training/holdout rows, raw scores или private keys. Это набор для проверки, не backup полного обучения.

| Документ | Ответственность |
| --- | --- |
| dependency-lock | Точные байты uv.lock; SHA-256 и длина должны совпасть с curator-signed lineage |
| feature-contract | Шесть признаков в исходном порядке, конечные числа, synthetic [0,1], abstain за границей, batch <=100 |
| model-card | Назначение, synthetic-only classification, digest модели, оценка и явные ограничения |
| ml-bom | Связи ONNX, embedded preprocessing, dataset/lineage, lock, packages и training/serving images |
| parameters | Source-bound baseline recipe, C=1, max_iter=300, seed, request digest и CPU profile |
| runtime-profile | Локальный isolated worker: UID 65532, read-only, network-none, 2 CPU/4 GiB |
| split_manifest | Canonical payload исходного curator-signed dataset manifest с digest/rows split |
| evaluation_policy | Canonical policy bytes, сравниваемые с независимым context |
| asset_projection | Canonical пересчитанная projection связей candidate и материалов |

ML-BOM (Machine Learning Bill of Materials) здесь - минимальный внутренний JSON-контракт, не заявленная совместимость с CycloneDX. Parameters описывает baseline recipe из закреплённого source; это не восстановление hyperparameters по весам и не независимая аттестация trainer. Research robust-training candidate этим increment не принимается. Runtime profile описывает существующий worker, **не будущий HTTP serving** и не измеренный SLO.

Release manifest связывает source commit, training/serving image, feature/preprocessing/model, dataset/split, evaluation/policy, provenance, owner, environment, release ID, sequence и время действия. Материалы не просто сверяются с входным manifest: verifier заново строит ожидаемые документы из проверенной capsule и независимого context. Даже корректно подписанное изменение model card или runtime contract отвергается.

## Trust и порядок проверки

1. Policy подписывает внешний trust root. Verifier получает root, ожидаемый SHA-256 policy, environment, serving image и часы **не из недоверенного комплекта**. Допустимы только точные M01-M23, без исключения неудобных gates.
2. Policy назначает разных publisher, assessor и approver по decoded public key bytes и issuer. Root также отдельный. Release approver не может быть curator/evaluator. В лаборатории эти ключи всё ещё доступны одному администратору; это не организационная независимость.
3. Publisher подписывает `model-release`. Проверяются capsule, источники, версии, schema, материал и срок. `read` возвращает те же проверенные model bytes, не открывает ONNX parser. `load` только собирает package: его результат обязательно передавать `verify`, он не является разрешением.
4. Assessor подписывает `release-assurance`: subject hash и SHA-256 каждого из 23 reports. Каждый report обязан содержать точные source/model/release bindings, clean source, pass/exit_code=0, непустые cases и artifact hashes. Cases имеют id/status/expected/actual; expected и actual совпадают с учётом JSON-типа. Пропуск, duplicate case, fail, inconclusive, skipped, stale report запрещены.
5. Approver отдельно подписывает `release-approval`, связанный с subject, assurance, policy, environment, sequence и action=promote. Подписи разных типов не взаимозаменяемы. Approval не предшествует assurance, assurance не предшествует policy/release, потомки не переживают родителей. Policy/release <=24 часов, assurance/approval <=1 часа.
6. Успех возвращает `authorized-not-activated`, `authorization_valid=true`, **release_ready=false**. Это проверенное решение в памяти, не durable transition. Даже положительный controlled fixture ничего не запускает.

`subject_sha256` - hash canonical manifest; `proposal_reference` - hash serialized envelope в CAS. Это разные значения. Отчёты связываются с первым, SQL reader получает второе. Во избежание циклических hashes сначала создаётся descriptor, потом reports/assurance, затем approval. Descriptor не содержит hash будущего approval.

Reports <=1 MiB каждый и <=8 MiB суммарно, 1-5000 cases, 1-2048 artifact references; новые signed documents <=1 MiB, supplemental files <=1 MiB каждый. Вложенная capsule сохраняет собственные более строгие bounds. SQL loader проверяет фактическую длину после каждого get, прежде чем накапливать весь комплект; транспорт одного get также имеет SQL size limit, но не streaming API. Неизвестные поля signed contracts и неизвестная schema отклоняются.

## Публикация и отрицательная демонстрация

`publish` допускает только ml_promoter, сначала полностью проверяет package, записывает immutable objects, затем внешний envelope и выполняет readback. Повтор **того же package** не создаёт новую версию. При обрыве остаются уже записанные blobs, но нет успешного результата; автоматического удаления orphaned objects нет. Serving имеет только SELECT releases, не получает новые SQL grants.

`scripts.release_native` использует свежий owned SQL state из storage workflow. Он публикует proposal, сравнивает serving readback, проверяет точный object set и неизменность metadata/holdout budget. Создаёт отдельный lab release-approver key только в приватном campaign directory; существующие trusted-keys не меняет. Проверяет отказ реальному candidate без assurance и с подписанным пустым набором evidence. **Ни один native report не подделывается как M01-M23 pass.**

Assessor остаётся доверенной стороной: verifier проверяет hashes reports и формат evidence, но не повторяет за него все 23 эксперимента и не читает каждый первичный artifact. Наличие artifact hash не доказывает содержание файла. Требуется будущий M18 reconciler с реальными материалами и единым subject; существующие исторические pass reports автоматически не переиспользуются.

## Что ещё нужно до продукта

T13 остаётся открыт: durable promotion state machine, атомарное сравнение sequence, concurrency/replay, integration с scoped controller и всеми gates. T14/M11 требует живой проверки revocation/lease; T15/M12 - verify-then-load и работающий API. Текущие image/M08/M09 failures не waived. Source-bound recipe не устраняет semantic poisoning. Модель остаётся лабораторным советником, не системой принятия production-решений.
