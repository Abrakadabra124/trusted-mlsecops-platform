# Постоянный promotion ledger

Дата: 2026-10-14. Increment T13 после [release authorization](release-authorization.md). **Не full M10, не serving activation, не production release.** [ADR 0027](decisions/0027-promotion-ledger.md), [PB-21/RB-40/RB-41](operations/promotion-ledger-troubleshooting.md), [evidence](evidence/promotion-ledger-2026-10-14.md).

## Задача и компоненты

Подпись подтверждает документ, но сама не предотвращает два одновременных переключения или повтор старого решения. `mlsecops.promotion` связывает проверку signed chain с постоянным выбором, а `promotion_state` хранит последовательность в PostgreSQL. SQL (Structured Query Language) здесь управляет транзакцией; криптографические проверки остаются в Python verifier.

В отдельной схеме `ml_promotion` находятся:

- `authorities`: явно настроенный environment и policy digest, без автоматической rotation.
- `heads`: текущий sequence и reference на immutable selection request.
- `events`: неизменяемая для application roles история, включая предыдущий request и время записи.
- `migrations`: отдельный checksum migration v1. Исходная `ml.schema_migrations` не переписывается.

SELECT FOR UPDATE блокирует строку environment до конца транзакции. SECURITY DEFINER выполняет ограниченную функцию с правами её владельца, не выдавая клиенту общие UPDATE/DELETE. Function owner - ml_owner, фиксированный search_path pg_catalog/pg_temp, обращения к таблицам квалифицированы, PUBLIC execute отозван. Только ml_promoter может вызвать `record_selection`, serving только читает.

## Admission -> запись -> readback

1. `promotion.promote(client, **arguments)` допускает SQL identity ml_promoter и берёт время из PostgreSQL. Передача caller-controlled clock запрещена.
2. `release_authorization.verify` проверяет весь package, внешнюю policy/root, все M01-M23 reports и approval. Отказ происходит **до первого INSERT**. Реальное отсутствие assurance не заполняется test fixtures.
3. Проверенные bundle, reports и proof сохраняются в существующий immutable CAS releases. Proof содержит signed envelopes, references на reports и verified decision. CAS (content-addressed storage) адресует точные байты по SHA-256.
4. Selection request связывает environment/policy/sequence/subject, proposal и proof, а также исходное время approval и expiry. Время текущей попытки не входит в digest: иначе retry через секунду стал бы другим запросом.
5. SQL-функция загружает request, проверяет типы/bounds/material existence, блокирует head и **после ожидания lock** проверяет server clock и policy. Допустим только следующий sequence. Точный повтор текущего reference возвращает тот же результат, конфликтующий либо более старый request отклоняется.
6. INSERT события и UPDATE head входят в одну транзакцию. Rollback не оставляет половинного перехода. Неопределённый outcome при обрыве соединения не считается успехом и не запускает автоматический retry.
7. SDK перечитывает immutable event и request после commit. Допустимо, что другой уже одобренный transition успел продвинуть head дальше: readback проверяет собственное событие, не обещает вечную актуальность head. Результат `recorded-not-activated`, `release_ready=false`.

Это не превращает SQL в root of trust. Обладатель trusted promoter credential может вызвать SQL-функцию напрямую; database function не умеет проверять Ed25519. Поэтому будущий serving обязан заново проверять signed proof и актуальное доверие, а не доверять одной строке heads. Host/DB administrator остаётся доверенным. Scoped promoter controller, loader и trust lease ещё не интегрированы.

## Установка и backup

`install(state)` и `configure(state, environment, policy_sha256)` - явные privileged операции над проверенным owned state. Повтор не сбрасывает head, policy conflict и неизвестный migration checksum требуют разбора. Рабочая лаборатория не мигрируется автоматически; CI квалификация требует `--confirm-disposable`.

Старый backup экспортирует только исходные CAS tables. После появления ledger он намеренно запрещён: иначе можно потерять sequence и допустить replay после restore. Есть ранняя диагностика и обязательная проверка отсутствия ledger **в том же REPEATABLE READ snapshot**, который экспортируется для pg_dump. Предварительная проверка сама по себе была недостаточна из-за гонки с migration.

Добавлен [явный backup/restore v2](decisions/0028-promotion-recovery.md), [PB-22/RB-42/RB-43](operations/promotion-recovery-troubleshooting.md); фактический verification scope в [evidence](evidence/promotion-recovery-2026-10-14.md). Старый архив не восстанавливает promotion state; отсутствие heads/events после restore означает неполное восстановление, не новый sequence=0. Полный M17 и текущая revocation/serving readiness остаются открытыми.

## Что доказывают проверки

Controlled admission tests используют настоящие подписи, но заменяют transport. Native SQL campaign использует явно **controlled transport payloads**, а не фиктивные одобренные ML-модели. Она проверяет database concurrency, current retry, stale replay, rollback, expiry после наблюдаемого lock wait, запреты прямого DML (data manipulation language) и service restart. Это не все M-gates и не power-loss/disaster recovery.

Отдельный `release_native` вызывает новый admission для настоящего candidate без assurance и проверяет отказ без добавления CAS objects. Положительного native ML promotion по-прежнему нет: текущие security/research gates не приняты. Фактические результаты и ограничения среды фиксируются в evidence, не выводятся из одного наличия кода.
