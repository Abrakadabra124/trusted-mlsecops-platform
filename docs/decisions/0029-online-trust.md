# ADR 0029: отдельная текущая trust authority и ограниченный lease

Дата: 2026-10-14. Статус: implementation in progress, не M11 acceptance.

## Контекст

Signed release и восстановленный promotion journal не доказывают актуальность доверия. T14/M11 требуют отзыв ключа/артефакта, запрет старой policy и остановку ML-пути не позже 60 секунд после последней успешной проверки. Исторический backup не должен возвращать отозванное доверие.

## Решение

Отдельный owned PostgreSQL workspace использует существующие pinned image, mutual TLS 1.3 и verify-full. Это отдельный container/volume/CA от model storage, не новая платформа. Schema ml_trust содержит закреплённые environment/root, checksum migration и append-only версии подписанного документа. Владелец authority устанавливает/обновляет состояние через local administrative CLI; promoter/serving имеют только SELECT. Trainer/curator/evaluator не получают доступ к schema. Host/DB admin остаётся доверенным, не заявляется защита от его компрометации.

Root подписывает canonical DSSE trust-policy: schema_version, environment, version, promotion_policy_sha256, issued_at/expires_at, revoked_artifacts, revoked_keys. Максимальный срок документа 24 h; bounded sorted unique revocation sets. Отзыв необратим в текущей root authority: новая версия сохраняет прежние запреты. Version увеличивается ровно на один; byte-identical текущий документ допускает retry, конфликт/старый документ запрещены. Root rotation и аварийное восстановление самой authority требуют отдельного протокола, не копирования старой policy из model backup.

Consumer получает весь текущий документ и DB time одним fresh SELECT через mTLS, проверяет внешние root/environment/minimum-version pins, подпись и срок. SQL/TLS service является online authority, не недоверенным зеркалом; transport freshness не выводится только из подписи. Повторное использование long-lived repeatable-read transaction запрещено. In-process high-water mark отвергает уменьшение версии и другую подпись/bytes той же версии. Новый процесс не использует сохранённый lease и требует online read и внешний minimum version. Это не защита нового клиента от злонамеренного rollback доверенного DB admin.

Lease отсчитывается консервативно от monotonic времени **начала** запроса, максимум 60 s и не позже expiry. Задержка SQL/readback включена в срок. Для expiry дополнительно проверяются wall clock и server clock; движение wall clock назад, нечисловое время или значимое расхождение с monotonic отменяет lease. Refresh failure не продлевает срок. Неверный подписанный ответ, старая policy, rollback версии или обнаруженный revoke отменяют cached authorization сразу. Нет дополнительных 60 s grace после истечения.

Promotion SDK требует fresh trust read после полной криптографической проверки release и до публикации, затем повторную проверку перед/после journal transition. Нельзя обещать распределённую атомарность между authority и model DB: при отказе после commit запись может существовать, но response остаётся unconfirmed и serving не активируется. Каждому будущему ML response нужен повторный локальный lease check; endpoint integration остаётся обязательной частью M11/M12, не заменяется SDK tests.

## Границы и recovery

Authority размещается только в отдельном свежем owned workspace. Model backup v1/v2 не сохраняет её и должен отказать при попытке архивировать authority state, а не создать частичную копию. Восстановленный model storage обращается к текущей authority отдельно. Не создавать подписанные all-pass ML approvals для qualification: controlled subject fixtures не означают разрешённый release.

## Проверка и источники

План: signature/schema/bounds/clock/outage/replay unit negatives; actual TLS SQL read, concurrent updates, роли, restart, missing service и deadline trace в disposable CI. До выполнения это план, не доказательство M11. Отдельный runbook должен описывать outage, stale pin, revoked material, конфликт обновления и запрет ручного продления lease.

Проверены официальные документы 2026-10-14: [PostgreSQL transaction isolation](https://www.postgresql.org/docs/18/transaction-iso.html), [libpq TLS verification](https://www.postgresql.org/docs/18/libpq-ssl.html), [Python monotonic clock](https://docs.python.org/3/library/time.html#time.monotonic). Выбор отдельной authority и двух clocks является проектным решением, не готовой гарантией этих библиотек.
