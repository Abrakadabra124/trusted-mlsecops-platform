# ADR 0016: явный experimental target для storage restore

Дата решения: 2026-10-09. Реализация: 2026-10-11. Статус: implemented for isolated compatibility rehearsal; adoption not accepted. Scope: T02, compatibility component, не смена работающей SQL-БД и не security waiver.

## Требование

После image comparison требуется проверить настоящее восстановление signed history на candidate PostgreSQL. Нельзя менять глобальный IMAGE, принимать mutable tag из backup, монтировать существующий volume в новый image или выдавать один SELECT 1 за проверенную миграцию.

## Решение

- Default bootstrap/validate/restore сохраняют прежний pinned bookworm image и прежний marker/receipt contract.
- Внутренние Python interfaces получают keyword-only `experimental_image_id=None`. Единственный разрешённый override - полный локальный SHA-256 image ID, переданный доверенным host operator. HTTP/API/environment override не вводится; обычный restore CLI его не предлагает.
- Candidate runner сначала проверяет source fingerprint, recipe digest, role и platform через существующий image binding. Затем передаёт immutable ID в bootstrap, validate, повторный restore и native ACL qualification. Marker/config digest связывают выбранный image, container ID связывает receipt; target не выбирает image из собственного изменяемого marker.
- Source backup policy остаётся baseline-only: подпись, external trust roots, возраст, точные таблицы и hashes проверяются до target bootstrap. Разрешение candidate target не расширяет доверие к входным backups.
- Использовать fresh synthetic source и fresh target в собственном UUID state. Проверить source-to-target ledger, model/evaluation signatures, 1 000 golden predictions, mTLS, все SQL roles, повтор без замены keys/container и отказ перезаписывать последующие данные. Проверить collation/encoding отдельно, не объявлять совпадение sample order доказательством всех Unicode cases.
- Сохранять `release_ready=false`; High/Critical findings из ADR 0015 остаются блокирующими. Bootstrap source/target не меняет shared working SQL. Cleanup удаляет только ресурсы с совпадающими ownership/identity и только явно созданные test directories.

## Проверки до реализации

Неверный digest/tag и foreign candidate binding отклоняются до создания target; default path не принимает candidate marker; эксперимент не меняет baseline IMAGE; receipt нельзя повторно использовать с другим image; image mismatch проверяется по фактическому container. Неполный запуск инвалидирует старый pass. Структурные fixtures отделяются от native restore/SQL/ONNX evidence.

## Альтернативы и ограничения

Native rehearsal прошёл 434 проверки, включая настоящий SQL restore и 1 000 golden predictions с error 0.0. Это fresh synthetic source, не история рабочего кластера. Контрактные проверки отдельно подтверждают запрет mutable/foreign image и отказ default restore принимать candidate target. [Воспроизведение и evidence](../storage-candidate.md).

Monkeypatch IMAGE или копия bootstrap отвергнуты: они скрывают policy change либо расходятся с настоящим recovery path. Публичный произвольный image selector не нужен. Новая production image policy/подписанное migration approval - отдельный gate, не эта возможность оператора лаборатории. Администраторы source/host и backup signer доверены: PostgreSQL предупреждает, что импорт backup из недоверенного административного источника опасен даже при частичном restore.

Основания: [PostgreSQL pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html), [pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html), [collation](https://www.postgresql.org/docs/18/collation.html), [текущий recovery](../storage-recovery.md), [candidate comparison](../evidence/image-candidates-2026-10-09.md).
