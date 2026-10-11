# PB-09 / RB-19: asset graph и неполное наблюдение

Сфера: [компонент T25](../asset-graph.md), не production incident response и не исполнение live revocation. Ответственный: platform operator; owner materials подтверждает data/ML owner, доверие пересматривает security reviewer. Нужны checkout, Python 3.12.15 и pinned uv environment. Нет доступа к БД/ключам или прав на изменение deployment.

## PB-09: read-only воспроизведение

Из корня нужного репозитория:

```powershell
git status --short
git rev-parse HEAD
uv run --locked python -m scripts.asset_graph_qualification
uv run --locked python -m scripts.asset_graph_fixture
```

Ожидание: 25 tests OK; fixture `synthetic_fixture=true`, 17 assets, 10 impacted assets, 3 blocked deployments и только `deployment-b` unaffected. Обязательно `full_M19=inconclusive`, `release_ready=false`. Exit 0 означает, что компонент прошёл свои проверки, не что release разрешён. Команды проверены локально; новый CI и его commit указаны в STATUS после завершения.

Сверить результат с явно заданным набором в [контракте](../asset-graph.md). Не заменять сравнение множеств проверкой только count=10. Не использовать fixture digests как hashes настоящих bytes и не выдавать synthetic snapshot за состояние кластера.

## RB-19: дерево диагностики

| Симптом / reason code | Безопасная диагностика | Действие после подтверждения причины |
| --- | --- | --- |
| `inventory_unknown_owner` | Проверить независимый allowlist и владельца источника | Подтвердить owner отдельно; не добавлять имя из сомнительного графа автоматически |
| `inventory_unknown_or_mismatched_reference` | Сравнить ID и digest с исходным проверенным материалом | Пересобрать lineage из verified materials; не переписывать expected digest под найденный файл |
| `inventory_cycle` / `inventory_invalid_dependency_kinds` | Проверить направленность edges и обязательные parents | Исправить producer graph, сохранить rejected input приватно; не удалить dependency ради pass |
| `inventory_release_material_mismatch` | Сравнить runtime/policy run и release | Для другого runtime нужен отдельный совместимый контракт и validation, не alias swap |
| `inventory_snapshot_binding_mismatch` | Сверить environment и версию graph | Получить новый независимый snapshot нужного graph; старый не становится достоверным после ручного rehash |
| `inventory_observed_digest_mismatch` | Сверить deployment/model/runtime/policy из фактического trusted collector | Не разрешать promotion; проверить tampering или некорректный collector |
| `inventory_incomplete_observations` | Найти недостающий deployment, включая rollback/canary | Восстановить сбор наблюдений; неизвестное состояние не считать здоровым |
| `inventory_document_nesting` / bounds / unknown schema | Зафиксировать только reason и безопасные sizes, не raw payload | Исправить producer/adapter; не повышать лимиты или recursion limit как обход |

API сейчас отдаёт `Rejected` с bounded reason code. Integration caller обязан преобразовать его в запрет/ошибку компонента, не default allow. Готового promotion endpoint или collector в этом increment нет, поэтому команды чтения live-state/отзыва не выдумываются.

## Встреченная проблема разработки

При review новой реализации direct call с `assets`, вложенным на 12 000 уровней, дал необработанный `RecursionError` в JSON canonicalization. Воспроизведён отдельным negative test до исправления. Обычная bounded list/schema validation не успевала выполниться, потому что serialization шла первой. Исправление локально перехватывает этот случай как `Rejected("inventory_document_nesting")`; не меняет общий serializer и не повышает лимиты Python.

Проверка исправления:

```powershell
uv run --locked python -m unittest scripts.asset_graph_qualification.AssetGraphContracts.test_excessively_nested_input_is_a_controlled_rejection
uv run --locked coverage run --source=mlsecops.asset_graph --data-file=.coverage-asset-graph -m scripts.asset_graph_qualification
uv run --locked coverage report --data-file=.coverage-asset-graph --fail-under=100
```

Конечное состояние: исключение контролируемое, suite проходит, результат не содержит approval. Это controlled input robustness defect разработки, не обнаруженная эксплуатационная атака. Будущий adapter всё равно должен применять byte limit до parsing.

## Восстановление, rollback, эскалация

Эти команды ничего не отзывают и не меняют workloads, поэтому откат deployment после диагностики не требуется. Не удалять datasets, модели, единственный snapshot или SQL volumes. Если повреждён настоящий inventory, сохранить evidence в закрытой области, заблокировать продвижение и пересобрать его из проверенных immutable материалов. Нельзя восстанавливать доверие только возвратом старого JSON: revocations могли измениться.

Повторный запуск допустим после исправления producer; одинаковый fixture даёт одинаковый результат. Для настоящего serving восстановление требует T14/T15 integration, authenticated актуального trust state и действующего approval. Предыдущий release, зависящий от отозванного ancestor, не является безопасным rollback. Самовольное снятие revocation запрещено.

Эскалировать security reviewer при unexpected model/runtime digest, неизвестном owner, изменившихся edges или расхождении actual/expected impacted set. Если collector недоступен, не подставлять пустой список deployments и не объявлять M19 pass. Существующие security failures остаются blockers; этот плейбук не даёт waiver.
