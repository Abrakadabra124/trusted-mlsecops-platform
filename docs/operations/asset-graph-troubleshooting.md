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

Runner Ubuntu готовит три подписанных release proposal в принадлежащем job SQL-хранилище. Для предыдущей версии trainer читает каждую вторую строку проверенного train split A и сохраняет digest этой выборки в provenance. Текущая версия использует исходный полный train split A. Для независимой версии генератор создаёт отдельный synthetic dataset B с собственным потоком случайных чисел и непересекающимся диапазоном entity ID. Обычные intake, curator, trainer, evaluator и publisher проверяют соответствующие материалы. Шаг подготовки фиксирует digest трёх proposal reports и публичного ключа кампании.

Сначала предыдущая версия обслуживает запрос. Затем запускаются primary и canary текущей версии и независимая версия. При одновременной работе четырёх endpoints capture считывает идентификаторы контейнеров, проверяет worker sessions и образ, подписывает наблюдения и сохраняет четыре отдельных HTTP-журнала. Каждая версия должна вернуть свой эталонный результат. У всех readers общая версия trust policy. После отзыва только split manifest A предыдущая версия, primary и canary должны вернуть HTTP 503 за 60 секунд от начала записи отзыва. Повторная загрузка каждого из трёх кандидатов должна завершиться с `trust_artifact_revoked`. После всех трёх отказов независимый worker должен вернуть корректный HTTP 200 на той же session под обновлённой trust policy.

Replay объединяет подписанные пути по identity и проверяет 17 узлов, 10 затронутых объектов, три заблокированных deployment и один доступный. Четыре семантических повреждения этого же графа проходят через `asset_graph.assess` с пересчитанными digest. Контролируемый assessor связывает каждый отказ с подписанным assurance. Штатный promoter должен отвергнуть все четыре запроса, записать подписанные события и сохранить прежний SQL head.

В отдельном disposable drill две подписанные fixture-версии обучаются на разных synthetic train splits. Они используют одну trust authority. После отзыва dataset второй версии проверяются HTTP 503 в пределах 60 секунд, успешный ответ первой версии и отказ promoter вернуть вторую версию. Время отсчитывается до изменения trust. В отчёте отдельно приведён точный impact для исходного fixture из 17 узлов.

После закрытия временных endpoints и хранилищ workflow останавливает принадлежащий ему source SQL и проверяет состояние контейнера. В том же job он выполняет:

```bash
uv run --locked python -B -W error -m mlsecops.acceptance --gate M19 --output .runtime/evidence/M19.json
```

Для повторного чтения в этом job нужны исходная `.runtime`, тот же checkout и значения `M19_PROPOSAL_SHA256`, `M19_KEYS_SHA256`, `M19_DEMO_SHA256`, `M19_FLEET_INPUTS_SHA256`, `M19_PRIMARY_SHA256` из шагов владельца. Файловый digest включает завершающий перевод строки. Поля `graph_sha256` и `snapshot_sha256` считаются по canonical JSON. Приватный пакет, ключи и журналы остаются на runner. В лог поступает публичный отчёт с digest, версионированным графом, наблюдаемым snapshot, временем отказа каждого deployment и точными expected/actual sets. После удаления runner для нового прогона нужен новый захват.

Для полного профиля workflow требует 14 успешных случаев, `pass`, exit 0 и `release_ready=false`. Все три кандидата работают под временными qualification permits. Тесты durable rollback и promotion используют отдельно одобренные контролируемые releases. На `06f28fd8d0d3f856690e716627ea1fa3240814c9` полный observed профиль получил `pass` в [GitHub run 43547590994, job 132302404422](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43547590994/job/132302404422). SHA-256 публичного отчёта `77ad82826f6d3300754c0e00807782d754648b87141674c5cf7719ff4636eb85`. Общий delivery требует отдельного replay на своём исходном кандидате.

На `1d582c6` владелец проверил срез с одним deployment. Все девять компонентных случаев прошли, обычный M19 вернул `inconclusive`, SHA-256 публичного отчёта `657bf6f8cecea0b23135bcc07832ec869df6fbf2e5603a2c10d5a1ee408f1b30`, GitHub run `43543502530`, job `132289237698`. Исторические SQL и inventory-event прогоны описаны в [evidence](../evidence/inventory-security-events-2026-11-11.md).

## Что показал запуск на оценённой модели

На коммите `1d582c6fc459cc70654ec03c1cabb474d274b3c4` подписанный отзыв обучающего набора распространился до обслуживающего HTTP-процесса за 0,340273719 с. Процесс вернул 503. Вычисленный и ожидаемый наборы затронутых объектов совпали по пяти элементам: набор данных, обучение, модель, выпуск и обслуживающий экземпляр. Кампания включала 800 запросов. Четыре попытки продвижения с дефектами графа получили подписанные отказы. [Журнал T25 и очистка](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43543502530/job/132289237698).

Обычная команда M19 записала девять пройденных случаев, `inconclusive`, код 2 и SHA-256 отчёта `657bf6f8cecea0b23135bcc07832ec869df6fbf2e5603a2c10d5a1ee408f1b30`. С этого кандидата наблюдался один экземпляр. Для полной приёмки нужны наблюдения основной версии, canary, предыдущей версии для отката и независимого сервиса в одном графе. Сравнение с тестовым графом и результаты отдельно подписанных контрольных выпусков доступны в полях `fixture` и `controlled_promotion_denials`.

## M19 на исходном кандидате общего delivery

Адаптер `scripts.inventory_fleet_materials --existing` читает уже выпущенный proposal из source SQL и проверяет его подпись, runtime, source commit, dataset, training metadata и evaluation reference по исходным файлам владельца. Он создаёт два дополнительных сценария previous и independent через обычные trainer, evaluator и publisher. Данные дописываются в content-addressed SQL. Публикация исходного кандидата сохраняет свой подписанный sequence, включая обычное значение 1. Порядок previous/current в этой квалификации подтверждается последовательностью реальных активаций и HTTP-запросов.

До подготовки, при завершении и последующем replay проверяются исходные pins. На всех этапах нужны следующие переменные из шага владельца.

| Переменная | Значение |
| --- | --- |
| `M19_PROPOSAL_SHA256` | SHA-256 полных байтов `evidence/release-native.json` |
| `M19_DEMO_SHA256` | SHA-256 полных байтов `storage-demo.json` |
| `M19_KEYS_SHA256` | SHA-256 canonical JSON `trusted-keys.json`, как `source.outputs.keys` общего delivery |
| `M19_TRUST_SHA256` | SHA-256 полных байтов `storage-trust.json` |
| `M19_WORKSPACE_ID` | `sql.outputs.workspace`, проверенный при создании source SQL |

GitHub задаёт `GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT` и hosted runner identity. Путь state фиксирован как `root/.runtime`. Валидатор проверяет workspace, labels, container/network/volume identity и конфигурацию source SQL. Перед дополнительной публикацией все шесть SQL clients сверяются с его loopback-портом и исходными сертификатами и ключами. Чистый checkout и методы кампании входят в owner binding. Публичный ключ qualification берётся из отдельно закреплённого результата подготовки.

Последовательность общего workflow выполняется в одном job.

1. Пока исходный SQL работает, выполнить `uv run --locked python -B -W error -m scripts.inventory_fleet_materials --existing`. Шаг возвращает `outputs.sha256` для `evidence/M19-fleet-inputs.json`. Python-вход `existing(root, state)` возвращает этот JSON-объект, публикацию выполняет CLI.
2. Передать этот digest как `M19_FLEET_INPUTS_SHA256` и выполнить `uv run --locked python -B -W error -m scripts.inventory_deployment_native`. Шаг возвращает `outputs.sha256` приватного capture.
3. Последовательно провести M17 и принадлежащий orchestration cleanup source SQL.
4. Передать digest capture как `M19_PRIMARY_SHA256`, сохранить `M19_FLEET_INPUTS_SHA256` и пять входных переменных, затем вызвать `uv run --locked python -B -W error -m mlsecops.acceptance --gate M19 --output .runtime/evidence/M19.json`.

Дополнительные сценарии используют отдельные файлы `evidence/M19-previous-demo.json` и `evidence/M19-independent-demo.json`. Подготовка сравнивает байты исходных demo, release report, source trust и публичных ключей, а также исходный promotion-policy envelope. Эта проверка выполняется и при исключении. Дополнительная оценка занимает обычные holdout-budget reservations. Срок действия исходного proposal проверяется штатным verifier. При прерывании подготовки повторять кампанию в свежем job с новым захватом владельца.

Для общего сборщика отчёт содержит `artifact_hashes.proposal_packet`, `source_trust` и `delivery_source`. В `input_digests` входят `candidate_reference`, `evaluation_reference`, `proposal_reference`, `image_id`, `source_revision`, `source_fingerprint`, `qualified_candidate_subject` и `qualified_candidate_model`. Поля `release_subject` и `model` также связаны с исходным proposal. SHA-256 готового публичного отчёта считается по полным байтам файла с завершающим переводом строки.
