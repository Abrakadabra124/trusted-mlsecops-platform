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

Ожидание: 25 tests OK; fixture `synthetic_fixture=true`, 17 assets, 10 impacted assets, 3 blocked deployments и только `deployment-b` unaffected. Обязательно `full_M19=inconclusive`, `release_ready=false`. Exit 0 означает, что компонент прошёл свои проверки, не что release разрешён. Команды проверены локально и в [clean-checkout CI 38155172493](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38155172493) на `88b168f`; результат developer workflow - success.

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

## Hosted replay T25

Владелец квалификации выбирает фиксированный commit. Для первого запуска в GitHub Actions предусмотрена ветка `qualify/t25-inventory`. Push владельца в эту ветку запускает [inventory-deployment.yml](../../.github/workflows/inventory-deployment.yml). Когда workflow зарегистрирован в основной ветке, доступен ручной запуск на подготовленном ref:

```bash
gh workflow run inventory-deployment.yml --ref qualify/t25-inventory
```

Runner Ubuntu создаёт disposable lab, обучает и оценивает локальную synthetic-модель, получает подписанный proposal и сохраняет отдельно три SHA-256 по полным байтам файлов. `scripts.inventory_deployment_native` запускает HTTP-трафик, считывает identity загруженного worker, отзывает точный digest dataset и сохраняет приватный пакет. Хеш пакета фиксируется отдельным шагом workflow. В графе семь узлов, включая release и одно наблюдение deployment. Четыре изменения этого графа проходят через существующий `asset_graph.assess`. Контролируемый assessor связывает каждый отказ с подписанным assurance. Штатный promoter должен отвергнуть все четыре запроса, записать подписанные события и сохранить прежний SQL head.

В отдельном disposable drill две подписанные fixture-версии обучаются на разных synthetic train splits. Они используют одну trust authority. После отзыва dataset второй версии проверяются HTTP 503 в пределах 60 секунд, успешный ответ первой версии и отказ promoter вернуть вторую версию. Время отсчитывается до изменения trust. В отчёте отдельно приведён точный impact для исходного fixture из 17 узлов.

После закрытия временных endpoints и хранилищ workflow останавливает принадлежащий ему source SQL и проверяет состояние контейнера. В том же job он выполняет:

```bash
uv run --locked python -B -W error -m mlsecops.acceptance --gate M19 --output .runtime/evidence/M19.json
```

Для повторного чтения в этом job нужны исходная `.runtime`, тот же checkout и значения `M19_PROPOSAL_SHA256`, `M19_KEYS_SHA256`, `M19_DEMO_SHA256`, `M19_PRIMARY_SHA256` из шагов владельца. Файловый digest включает завершающий перевод строки. Поля `graph_sha256` и `snapshot_sha256` считаются по canonical JSON. Приватный packet, ключи и журналы остаются на runner. В лог поступает публичный отчёт с digest, версионированным графом, наблюдаемым snapshot и точными expected/actual sets. После удаления runner для нового прогона нужен новый захват.

Успешный replay данного среза выдаёт 9 пройденных компонентных случаев, `inconclusive`, exit 2 и `release_ready=false`. Workflow проверяет inventory случаев, источник и внешний pin. Пустой отчёт, несовпадение digest, действующий source SQL или попытка подставить другой run требуют нового захвата после выяснения причины. Полный M19 остаётся открытым до наблюдения всех четырёх deployments и проверки общей цепочки от реальных materials до работающих descendants, включая предыдущую версию. Исторические SQL и inventory-event прогоны описаны в [evidence](../evidence/inventory-security-events-2026-11-11.md).
