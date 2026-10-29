# Проверка неизменности promotion journal

Реализована совместная read-only сверка CAS inventory и promotion journal. Native проверка этой расширенной сверки ещё требуется. Исторические reports, использовавшие только `kube_storage_migration.ledger`, не следует переименовывать в доказательство отдельного snapshot таблиц активации.

[Snapshot helper](../scripts/kube_promotion_snapshot.py) выполняет один SQL SELECT через owned Kubernetes storage adapter. Он повторно использует существующие `storage_snapshot.ledger_sql` и `promotion_recovery.ledger_sql`: в одном statement snapshot читает content-addressed таблицы `ml.*` и `ml_promotion.authorities/events/heads`, затем проверяет migration digest, структуру, объём, hashes и связность журнала. SELECT не изменяет схему, роли, данные или выбранный release.

Configured-serving harness сравнивает этот полный snapshot до и после expired retry и fault probes. Actual-candidate key-revocation дополнительно сравнивает snapshot перед отзывом и после проверки live/cold refusal. Hash снимка включается в отчёт; сами данные и raw logs не публикуются. Trust policy хранится в отдельной authority и закономерно меняется при отзыве, поэтому она не входит в неизменяемый model-storage snapshot.

## Ранбук

1. Убедиться, что это owned disposable hosted environment, migration promotion journal установлена, concurrent writes вне сценария отсутствуют. На текущей Windows native SQL не запускать.
2. В workflow использовать текущий `python -m scripts.kube_serving_native --state .runtime`. Локальные contract tests: `python -m unittest scripts.kube_promotion_snapshot_qualification scripts.promotion_recovery_qualification`.
3. Missing journal, неизвестная migration, invalid linkage или изменённый hash дают отказ проверки. Не заменять полный snapshot прежним CAS-only результатом и не исправлять journal вручную.
4. Для нового теста rollback отдельно сравнивать heads/events и учитывать, что `promotion.promote` может сохранить immutable CAS материалы отклонённого запроса до отказа SQL selection. Отсутствие активации не означает отсутствие любых записей артефактов.
5. После fault/refusal проверить exact selected request/sequence через Reader и cleanup. Сам по себе snapshot не доказывает работоспособный inference, своевременный HTTP отказ или разрешённую ротацию ключей.

Новый helper проверен локальными negative cases; итоговый hosted result и общий M11 остаются обязательными.
