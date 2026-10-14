# ADR 0030: Проверенное чтение текущего release перед runtime

Дата: 2026-10-14. Статус: реализован component, native qualification ожидает CI. T15/M12 остаются открытыми.

## Проблема

Promotion journal хранит выбранный request, но SQL function проверяет структуру и порядок, а не все подписи. `release_bundle.read` проверяет proposal и возвращает bytes, но не разрешение независимого approver, полную gate assurance и текущий revoke. Ни одно из этих действий отдельно не разрешает inference. Нельзя читать model по изменяемому alias после проверки другого объекта.

## Решение

`mlsecops.release_reader.Reader` получает serving-only SQL identity, внешний promotion root, policy digest, serving image digest, minimum sequence, проверяемый context и отдельный online trust lease. Context копируется; root/pins не извлекаются из самого candidate. Caller и локальная конфигурация доверены; Python object не является sandbox.

1. Одним fresh SQL SELECT читает head, authority, соответствующий event и DB clock. Проверяет environment, external policy, head/event binding, sequence floor и clock skew <=2 s. Использует более позднее из DB time и округлённого вверх local wall time, не продлевая срок за счёт отрицательного skew.
2. Требует успешный online trust refresh для каждой новой загрузки. Старый lease не разрешает offline startup/reload.
3. Читает canonical selection и authorization по SHA-256 из content-addressed storage (CAS, хранилище по хешу содержимого). Ограничивает размеры и полный набор M01-M23 report refs до загрузки bundle.
4. Повторяет полную cryptographic/semantic проверку root policy, proposal, capsule, material graph, assurance, reports и отдельного approval. Сохранённый `decision` сравнивает с заново вычисленным, но не принимает как доказательство.
5. Связывает selection с environment/policy/sequence/subject/issued/expires из проверенной цепочки. Revocation scope включает все материалы/предков/ключи из promotion и дополнительно selection/authorization CAS references.
6. Обновляет trust, заново читает текущий head и время. При смене head, expiry или откате времени ничего не возвращает. После trust check сохраняет in-process sequence/reference high-water mark.
7. Возвращает frozen handoff с точными `bytes` модели, без нового чтения пути/URL, без parsing/execution ONNX и всегда `release_ready=false`. Bytes не включаются в repr. Это ещё не готовый runtime.

`check(handoff)` принимает только тот же объект, который последний раз успешно вернул этот Reader. Проверяет свежий SQL head, release expiry и lease. Только транспортный отказ trust service допускает остаток прежнего lease, не более исходного deadline. Неверный документ/revoke не маскируются outage. Любой провал текущей проверки или нового load убирает current handoff, но не стирает sequence history. RLock сериализует операции одного Reader.

## Гарантии и границы

Две независимые fresh SQL reads намеренно не находятся внутри длинной repeatable-read transaction: иначе вторая могла бы видеть старый snapshot. Проверка обнаруживает изменение во время material read, но **не является распределённой атомарной транзакцией** с trust service или будущим HTTP response. Serving обязан проверять состояние до и после inference и связывать worker reply с действительно загруженным digest.

Reader не объявляет модель готовой, не запускает ONNX Runtime рядом с credentials, не принимает arbitrary model URL и не создаёт HTTP API. Worker load/nonce/digest protocol, malformed ONNX checks в sandbox, readiness и HTTP 413/422/429/503 остаются следующим обязательным этапом. Передача bytes сама по себе не подтверждает, что runtime использовал именно их.

После рестарта нужен внешний minimum sequence и online trust; in-memory high-water mark не защищает новый процесс от злонамеренного rollback доверенного DB admin. Легитимный rollback также нельзя выполнить понижением floor или ручным UPDATE head. Он требует отдельного проверенного authorization protocol. Чтение SQL head при каждом check консервативно отказывает при model DB outage; его latency ещё не измерена по M14.

## Qualification и независимость от acceptance

Negative-first controlled tests используют настоящие Ed25519 подписи и SHA-256, но memory storage/controlled SQL и часы. Отдельный native runner использует два новых owned PostgreSQL workspace с независимыми CA, настоящими mTLS connections и случайными test keys. Только там создаётся signed positive **contract fixture** с синтетическими all-pass report documents, чтобы пройти реальный SDK -> SQL -> reader happy path. Это проверка enforcement механизма, не доказательство прохождения M01-M23 и не разрешение настоящего candidate.

Fixture не публикуется в source storage, не использует реальные release roots и удаляется вместе с собственными owned resources после проверки. Report явно содержит `full_M12=inconclusive`, `release_ready=false` и controlled-fixture scope. Нет переноса фиктивных reports в acceptance. Реальные image/poisoning/evasion/robustness failures продолжают блокировать release. Эта детализация уточняет границу qualification из ADR 0029, не ослабляет gate policy.

## Источники и сопровождение

- [PostgreSQL 18: transaction isolation](https://www.postgresql.org/docs/18/transaction-iso.html): snapshot одного SELECT и видимость новых commits следующему SELECT в Read Committed. Проверено 2026-10-14; выбор двух fresh reads является проектным решением, не гарантией атомарности.
- [ADR 0027](0027-promotion-ledger.md), [ADR 0029](0029-online-trust.md).
- [PB-24/RB-46/RB-47](../operations/release-reader-troubleshooting.md), [evidence](../evidence/release-reader-2026-10-14.md).
