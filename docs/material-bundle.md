# Подписанный комплект материалов candidate

Статус: foundation для T13. **Не полный ModelReleaseBundle, не approval, не M10 pass.** [Контракт полной приёмки](acceptance.md), [ADR 0022](decisions/0022-candidate-material-bundle.md), [PB-11/RB-22/RB-23](operations/material-bundle-troubleshooting.md).

## Зачем нужен

Serving не должен получать доступ к training/holdout или полномочиям metadata controller только ради проверки происхождения модели. `mlsecops.material_bundle` переносит минимальный набор уже проверенных immutable objects в существующее хранилище `releases`, доступное serving для чтения. Верификатор повторно проверяет все вложенные подписи и связи без SQL, signing keys и model execution.

CAS (content-addressed storage) адресует объект по SHA-256 его байтов. DSSE (Dead Simple Signing Envelope) связывает подпись с точными байтами и назначением сообщения. Ed25519 - используемый алгоритм цифровой подписи; открытый ключ проверяющий получает из внешней доверенной конфигурации, не из самого комплекта.

## Что входит

| Namespace | Объекты | Проверка |
| --- | --- | --- |
| manifests | Stored dataset index, manifest, source approval | Три curator signatures, source expiry, policy/source/split binding |
| lineage | Data lineage envelope | Curator signature, dataset/lineage IDs |
| candidates | Candidate index, training metadata, model bytes | SHA-256, schema, external expected build pins |
| evaluations | Signed evaluation, budget receipt | Evaluator identity, model/run/holdout subject, policy, summary и protocol |

Текущий профиль содержит 9 объектов. Dataset rows, raw quarantine, validation scores, приватные ключи не копируются. Split row counts/digests и aggregate evaluation остаются metadata; это не публичные данные по умолчанию. Вся capsule хранится приватно. Это **замыкание verification reads**, а не архив для повторного обучения и не экспорт всех транзитивно упомянутых объектов: например, quarantine payload и scores не нужны этим readers. Их references не означают, что bytes включены или заново проверены.

## Порядок проверки

1. `create(metadata_client, review_client, context=..., signing_key=..., signer_public=...)` использует publisher для manifest/lineage и promoter для candidate/evaluation. Права SQL не расширяются. `candidate_lineage.collect` передаёт фактически прочитанные объекты в `material_sink`, а общий `reconcile` проверяет их семантику.
2. Index содержит schema v1, kind `candidate-materials`, environment, policy digest, candidate/evaluation references, digest полной projection и отсортированные descriptors `{namespace, sha256, bytes}`. State всегда `unapproved`.
3. Approver lab key, отличный от curator/evaluator, подписывает index с типом `application/vnd.trusted-mlsecops.candidate-materials.v1+json`. Это отдельное назначение подписи, не `release-approval`.
4. `verify_bundle(bundle, context=..., signer_public=...)` проверяет внешний доверенный signer, тип, schema, limits, точный набор объектов, длины и digests. Затем запускает те же semantic readers через закрытый callback. Callback не может читать SQL или labels; отсутствующие, лишние и неиспользованные материалы отвергаются.
5. Полученная projection и index пересчитываются по **независимому context**. Он содержит candidate/evaluation refs, policy, curator/evaluator/source-approval trust, expected image ID/source fingerprint/revision, owners и known owners. Взять expected или trusted key из входного bundle означало бы убрать границу доверия; так делать нельзя.
6. `publish(promoter_client, bundle, ...)` проверяет всё до записи, кладёт immutable bytes, затем envelope, сверяет каждый SQL receipt и читает полный результат обратно. `read(serving_client, reference, ...)` читает только `releases` и повторяет полную проверку. Ни одна функция не исполняет ONNX и не меняет active alias.

Результат verifier: проверенные `manifest`, `projection`, `model` bytes, `release_ready=false`, `full_M10=inconclusive`. Quality fail сохраняется и может быть архивирован внутри unapproved capsule, но не становится разрешением на эксплуатацию.

## Ограничения и повтор

- Envelope <=64 KiB, 1-16 descriptors, каждый object 1-50 MiB, суммарно <=64 MiB. SQL reader также проверяет свой размер и hash. Нет extraction в произвольные filesystem paths.
- Одинаковые inputs/context/key дают тот же envelope reference. Повторная SQL запись идемпотентна, existing object проверяется по bytes. Это не воспроизводимость обучения bit-for-bit.
- Межобъектной SQL-транзакции нет. При сбое могут остаться неиспользуемые immutable objects; они не разрешают serving. Index записывается последним, функция возвращает успех только после readback. Повтор безопасен только с теми же проверенными inputs и действующей source approval.
- Host administrator по-прежнему имеет lab keys. Различие ключей не доказывает организационную независимость или защиту KMS. Dedicated bundle signer, key lifecycle и authenticated control-plane request ещё нужны.
- Source approval проверяется по текущему времени, поэтому offline verification не обещает бессрочное принятие старого комплекта.
- Нет model card/ML-BOM, полного feature/API contract, release sequence, expiry/approval, revocation service, trust lease или M18 decision. Полные M09/M10/M11/M21 и promotion остаются обязательными. Signature validity не заменяет image audit/robustness acceptance.

## Проверка

```powershell
uv run --locked python -m scripts.material_bundle_qualification
uv run --locked python -m scripts.material_bundle_native_qualification
```

Первый suite проверяет реальные вложенные Ed25519 signatures с in-memory SQL boundary и deliberately non-executable model bytes. Второй проверяет orchestration/failure paths native runner на контролируемом transport. Они не заменяют настоящий SQL. В [storage CI](../.github/workflows/storage.yml) native runner запускается после actual training/evaluation M03:

```powershell
uv run --locked python -m scripts.material_bundle_native --state .runtime
```

**Эта команда пишет в `releases` выбранного owned lab state.** 12 native cases: signed closure, deterministic envelope, idempotent publication, serving readback, wrong build/tamper rejection, три SQL SELECT denials, SQL INSERT denial, unchanged metadata/budget и exact release object set. CLI не запускает SQL или обучение автоматически. Полный отчёт остаётся `evidence/material-bundle-native.json`, stdout содержит только ограниченный summary. При ошибке exit 1 и fail/inconclusive, не pass из старого файла.

Проверенные local/CI результаты и digests: [STATUS](../STATUS.md). Никакого production-инцидента, полноценного inference deployment или успешной полной приёмки этим increment не заявляется.
