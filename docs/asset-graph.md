# Asset graph: компонент T25

Статус: executable structural component, **не полный M19**. [ADR 0021](decisions/0021-asset-graph.md), [приёмка M19](acceptance.md#m19), [эксплуатация](operations/asset-graph-troubleshooting.md).

## Что реализовано

`mlsecops.asset_graph.assess(document, trusted_owners, environment, snapshot, revoked)` проверяет полную структуру до вычисления impact. Он не загружает модели, не читает SQL, не получает credentials, не вызывает Docker и не изменяет serving. Отдельный runtime/tools inventory остаётся в `mlsecops.inventory`.

Канонический JSON использует существующий `contracts.canonical`. Идентификаторы - ASCII `[a-z][a-z0-9._-]{0,95}`, digest - 64 lowercase hex SHA-256 без prefix. `schema_version` - строго integer 1, не bool/float/string. Неизвестные fields отвергаются. Максимум 2 MiB canonical bytes для graph и snapshot, 1 000 assets/observations/revocations, 32 dependencies/asset, 128 externally supplied owners. Будущий файловый/API adapter обязан ограничивать bytes до parsing; эта функция принимает уже декодированные объекты.

## Схема v1

Graph имеет ровно `schema_version`, `assets`. Каждый asset:

| Поле | Значение |
| --- | --- |
| `asset_id` | Уникальный ID; не registry alias для разрешения загрузки |
| `kind` | dataset, runtime, policy, run, model, release, deployment |
| `sha256` | Digest представленного содержимого, не доказательство его подлинности |
| `owner` | Член отдельного trusted owner allowlist |
| `environment` | Точное совпадение с environment вызывающего controller |
| `dependencies` | Массив `{asset_id, sha256}`, без дубликатов или неизвестных targets |

Обязательные edges:

| Kind | Непосредственные зависимости |
| --- | --- |
| dataset, runtime, policy | Нет |
| run | >=1 dataset, ровно 1 runtime и 1 policy |
| model | Ровно 1 run |
| release | Ровно 1 model, 1 runtime и 1 policy, последние совпадают с run модели |
| deployment | Ровно 1 release |

Удаление обязательных edges не превращает model или deployment в независимый root. Все cycles запрещены. Алгоритм Кана проверяет граф без рекурсивного обхода. Влияние отзыва вычисляется по reverse dependencies и content-equivalent aliases `(kind, sha256)`; каждую группу aliases раскрываем один раз.

Snapshot имеет ровно `schema_version`, `environment`, `graph_sha256`, `deployments`. Каждый deployment observation содержит `asset_id`, `sha256`, `release_sha256`, `model_sha256`, `runtime_sha256`, `policy_sha256`. Должны присутствовать все и только deployments графа, ровно один раз. Каждый digest сверяется с соответствующим node, graph digest - с canonical graph. Перестановка массива меняет graph digest, поэтому snapshot нужно связать заново; impacted set от порядка не зависит.

Revocation input - список точных `{asset_id, sha256}`. Unknown ID, другая версия bytes и duplicate reference отвергаются. Это входное утверждение вызывающего controller, **не реализованный authenticated revocation API**.

## Воспроизводимый synthetic fixture

Из корня checkout после `uv sync --locked --python 3.12.15`:

```powershell
uv run --locked python -m scripts.asset_graph_qualification
uv run --locked coverage run --source=mlsecops.asset_graph --data-file=.coverage-asset-graph -m scripts.asset_graph_qualification
uv run --locked coverage report --data-file=.coverage-asset-graph --fail-under=100
uv run --locked python -m scripts.asset_graph_fixture
```

Эти команды не требуют Docker/SQL/keys и не читают working state. Coverage пишет только игнорируемый локальный файл. Fixture содержит 17 nodes: 2 datasets, shared runtime и policy, 3 runs, 3 models, 3 releases, 4 deployment records. Все bytes/digests и observations синтетические; это не четыре реально поднятых сервиса.

Отзыв `dataset-a` даёт точный набор из 10 nodes:

```text
dataset-a
deployment-a-canary
deployment-a-primary
deployment-a-rollback
model-a-current
model-a-previous
release-a-current
release-a-previous
run-a-current
run-a-previous
```

`deployment-b` остаётся незатронутым. Shared runtime/policy затрагивает все 4 deployments. Отзыв одного deployment не отзывает его ancestors или peers. Если `model-b` получает тот же content digest, что затронутая модель, его alias тоже попадает в impacted set, даже при другом dataset lineage.

Локально 2026-10-11: 25 unittest methods pass; 135/135 statements и 68/68 branches, 100%. Assertion expected set задан явно, не вычисляется проверяемым traversal. RED/GREEN: сначала отсутствие implementation; при review дополнительно воспроизведён raw `RecursionError` на 12 000 nested lists и исправлен на `inventory_document_nesting`. CI добавляет те же checks и replay перед native developer qualification. Фактический clean-checkout результат фиксируется в [STATUS](../STATUS.md), coverage не заменяет независимый review.

Fixture graph SHA-256: `678124fabd2ea8249ab462f807aa706dd091e800f761e0885888850c6d70ec69`. Snapshot SHA-256: `60a549ddd241580262638f2eec43c461e07eaf1a4275972025786d772dd8a4d2`. [Clean-checkout CI 38155172493](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38155172493) на commit `88b168f` повторил 25 tests/100% coverage, fixture digests и 74 existing developer checks; terminal success. Coverage графа проверяется отдельной session, не общей developer session.

## Граница доверия и незавершённое

Переданные graph и observation должны поступать от доверенного, отдельно проверенного collector. Согласованная подделка обоих документов, удаление настоящей зависимости с заменой на другую structurally valid dependency, ложный owner и replay старой snapshot не выявляются одной структурной проверкой. Authenticity, exact material completeness и freshness обеспечиваются будущим интеграционным контуром, а не сравнением двух одинаковых hashes.

`unaffected_deployments` означает только отсутствие связи с переданным revoked set. Нельзя использовать это поле вместо approval. Пока нет persistent graph storage, signed provenance ingestion, independent actual-runtime collector, freshness/monotonic revision, retention/expiry, policy revocation service или реакции endpoint по M11. Lifecycle, purpose/classification и дополнительные asset kinds из архитектуры тоже остаются T25 integration work. Полный acceptance dispatcher M19 сохраняет inconclusive. Старые image security/poisoning failures не устранены этим компонентом.

Result с ID не является универсально очищенным публичным экспортом: для настоящих assets хранить его приватно. В CI публикуется только фиксированный synthetic fixture. Не передавать в owner/asset IDs credentials или персональные данные.
