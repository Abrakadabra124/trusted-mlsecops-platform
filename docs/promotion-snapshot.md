# Проверка неизменности promotion journal

Совместная read-only сверка CAS inventory и promotion journal подтверждена в [native run 40898945667](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40898945667), source `b191555633b8a0ca155a1c4fe7efeac1f6fcc38d`. Исторические reports, использовавшие только `kube_storage_migration.ledger`, не следует переименовывать в доказательство отдельного snapshot таблиц активации. Полный M11/CP3/R1 остаётся открыт.

[Snapshot helper](../scripts/kube_promotion_snapshot.py) выполняет один SQL SELECT через owned Kubernetes storage adapter. Он повторно использует существующие `storage_snapshot.ledger_sql` и `promotion_recovery.ledger_sql`: в одном statement snapshot читает content-addressed таблицы `ml.*` и `ml_promotion.authorities/events/heads`, затем проверяет migration digest, структуру, объём, hashes и связность журнала. SELECT не изменяет схему, роли, данные или выбранный release.

Configured-serving harness сравнивает этот полный snapshot до и после expired retry и fault probes. Actual-candidate key-revocation дополнительно сравнивает snapshot перед отзывом и после проверки live/cold refusal. Hash снимка включается в отчёт; сами данные и raw logs не публикуются. Trust policy хранится в отдельной authority и закономерно меняется при отзыве, поэтому она не входит в неизменяемый model-storage snapshot.

## Ранбук

1. Убедиться, что это owned disposable hosted environment, migration promotion journal установлена, concurrent writes вне сценария отсутствуют. На текущей Windows native SQL не запускать.
2. В workflow использовать текущий `python -m scripts.kube_serving_native --state .runtime`. Локальные contract tests: `python -m unittest scripts.kube_promotion_snapshot_qualification scripts.promotion_recovery_qualification`.
3. Missing journal, неизвестная migration, invalid linkage или изменённый hash дают отказ проверки. Не заменять полный snapshot прежним CAS-only результатом и не исправлять journal вручную.
4. Для нового теста rollback отдельно сравнивать heads/events и учитывать, что `promotion.promote` может сохранить immutable CAS материалы отклонённого запроса до отказа SQL selection. Отсутствие активации не означает отсутствие любых записей артефактов.
5. После fault/refusal проверить exact selected request/sequence через Reader и cleanup. Сам по себе snapshot не доказывает работоспособный inference, своевременный HTTP отказ или разрешённую ротацию ключей.

## Проверенный hosted result 2026-10-29

Job `123535634905`, success. 200 Linux methods (142 + 31 + 22 + 5), без skips. Snapshot/fault scope: 232/232 statements, 92/92 branches; attach/runtime: 257/258 и 91/92; expiry: 50/50 и 12/12. После настройки глобального ORT logger весь configured-serving сценарий завершён; [диагностика и границы исправления](trust-blackhole.md).

- Source fingerprint `129af4020ab928d0abe28f2faa8d17da85e9ffe3e1a4ed234326427f74a43110` независимо пересчитан из 133 Git blobs этого commit.
- Image `sha256:ef91035611020b0a5c88841382ba9675c3cf4d1b5be9a32aa7ea4ef66f0e9bb4`.
- UTC interval `2026-10-29T15:13:41.291361+00:00` - `2026-10-29T15:21:13.198594+00:00`.
- Canonical native report + LF SHA256 `b23c7b7a7469015094117b8d3b90801a963aaa5ec4bfa5e5751014bd901b9040`. Две workflow copies идентичны; первичные reports и logs приватные.
- Полный неизменный snapshot при expired retry: `375164e6efa0206820703c884442e07c1bbb98a4fef90d9d99d844ad5e1b8da3`.
- Полный неизменный snapshot при actual-candidate key revocation: `76df618095cc71a14bece04014516c3eab97f2d7d50fca7df8f14f11690c6944`.
- Actual candidate `ea34c8e89f7dfeac0851d1448f1d09de072de3f8c4b96bee2f9acba3b887687f`, proposal `cb27ee02e3100dfdd76eeca2e7a3f3870eb90800ffd70a3e011e35f6cd7c8f78`, model `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`, subject `e60ea9bf0d5c5cc24581b9d00c5ea3d9d9acbbfae02fa2e84366976bd207b8e5`.

Signed expiry: первый полный HTTP 503 за 0.958736181 s до expiry, затем cold refusal и expired retry без изменения полного snapshot. Явное renewal sequence 2 подтвердило обычный CLI и golden error `7.583384781240099e-08`. На этом выпуске также прошли outage (первый 503 за 59.796600935 s), blackhole (13.358871412 s), policy change (4.271063522 s), model revocation (3.877579072 s), cold revoked refusal. Сверка полного snapshot до/после fault probes прошла.

Actual candidate отдельно прошёл 60 HTTP cases и 70 key-revocation cases с проверенными types/actual/expected/status. Golden error 0.0, первый полный 503 за 3.366093184 s, затем повторный 503; exact cold Reader `trust_key_revoked`, no-auto-reactivation и worker absence. Canonical key report + LF hash `1cf75251111155b06bb72893e60e39e2381c127a3b793c69b42dd9d72cb425e0` совпал с artifact hash. Actual production promotion сохранил отказ `release_assurance_required`, `release_ready=false`. Controlled model отличается от actual.

Owned source SQL stop и удаление disposable cluster подтверждены. Snapshot не заменяет проверку действующего старого sequence, разрешённую ротацию ключей/rollback, negative clock, независимые M22 challenges или общую приёмку одного candidate.
