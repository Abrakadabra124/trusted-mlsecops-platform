# ADR 0013: полная проверка worker/evaluator boundary M20

Дата: 2026-10-08. Статус: **Implemented, verification in progress**. Первый полный локальный M20 прошёл; финальный source и clean-checkout CI проверяются отдельно в [STATUS](../../STATUS.md). Полная цель R1 и остальные gates не изменяются.

## Что осталось доказать

На `9963248` clean CI подтвердил native controllers, одноразовый protocol и live access matrix. Protocol negatives используют controlled integration со spies вместо SQL publication. Для M20 добавляем настоящую scorer identity с действительным signer/SQL и deliberate output corruption, а затем единый заново исполняемый gate на одном source/image/dataset/candidate. Предыдущие green JSON files не используются как кэш разрешения.

## Ограниченный runtime plan

1. Создать постоянные отрицательные fixtures и проверить точные причины отказа protocol, затем реализовать native scorer qualification.
2. Host operator запускает отдельный qualification scorer с общим `controller_spec`, без новых permissions или изменённого admission. Scorer использует штатный `controller_worker.run`: настоящий offline prediction Job по существующему fixed-command admission на каждом case. После возврата реального response qualification executor намеренно портит одно поле/форму. Это fault injection на receive boundary, не заявленный exploit ONNX parser или скомпрометированная worker image.
3. Вызвать настоящий `storage_pipeline.evaluate` с реальными candidate/holdout/signing-key/SQL credentials. Покрыть arbitrary text, unknown fields/version, missing/extra/reordered/duplicate rows, bool/NaN/out-of-range scores, oversized response, invalid scan, чужие digests и response от предыдущего batch. Exact rejection reason обязателен. Spies оборачивают реальные signer/SQL functions и подтверждают отсутствие вызовов на negative; snapshot существующих evaluation IDs подтверждает отсутствие публикации. До/после suite провести положительные signed evaluations и прочитать/проверить сохранённые envelopes. Неизвестная ошибка не считается ожидаемым отказом.
4. Не добавлять опасный test mode в production worker/controller request. Qualification использует отдельный module/command, выбранный host operator. Cleanup временных Job/ConfigMap - с UID preconditions. Не удалять SQL rows, keys, migration receipts или PVC; unexpected write сохраняется как failure evidence и запрещает gate pass. Только synthetic lab.
5. M20 runner заново выполняет isolation, protocol, controller, native output и live access suites. Проверяет status/nonempty/unique case IDs, source/image и dataset/candidate/model binding; связывает очищенные reports по hashes. Missing prerequisites = inconclusive, skipped/stale/failed component = fail. `release_ready` остаётся false: один M20 не подменяет остальные 22 gates.

## Критерии результата

- Native positive path возвращает signed evaluation для текущего candidate; negative matrix не вызывает sign/write и не меняет evaluation history.
- Worker запросы содержат только разрешённый model/features protocol, не labels/credentials; scorer не импортирует model parser.
- Live access tests и worker API denials работают на том же образе и текущих identities, witness положительно подтверждён.
- Gate report содержит input digests, cases, metrics, artifact hashes, времена и residual risks; clean-checkout CI повторяет его без ручного копирования private state.

## Границы

Не утверждаем семантическую корректность произвольных scores, отсутствие всех covert channels, безопасность host/kernel администратора или независимый human review. In-memory one-use не заменяет durable query budget M07 и release replay M11. Существующие mutable operator evidence files не становятся tamper-proof audit sink M23. Admission не ослабляется ради fault injection; повторные synthetic holdout queries в qualification не разрешают будущий business holdout reuse.
