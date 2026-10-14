# ADR 0028: единый snapshot CAS и promotion journal

Дата: 2026-10-14. Статус: реализован лабораторный recovery increment; [36 native checks](../evidence/promotion-recovery-2026-10-14.md) проверены в clean-checkout CI. Полные M11/M17 не приняты.

## Контекст

Legacy backup v1 копирует девять CAS tables и намеренно отказывает при наличии promotion schema. Отдельный экспорт heads/events создавал бы несогласованную копию: журнал мог сослаться на request, которого ещё нет в snapshot CAS. Обнуление heads после восстановления разрешало бы старые sequences повторно.

## Решение

Явный `--include-promotion` создаёт signed manifest v2: девять CAS tables и authorities/events/heads читаются из одного exported PostgreSQL snapshot. Подпись связывает обе migrations, archive bytes и оба набора table fingerprints. Проверяются последовательность событий, previous links, head/latest event и request/environment/policy binding. Это структурная целостность, не повторная ML-assurance или криптографическая авторизация каждого promotion.

Restore требует внешний operator backup-id pin, доверенные public keys и новый owned target. Восстанавливаются только данные в установленные из кода схемы; TOC (table of contents) допускает ровно согласованный набор TABLE DATA. Private keys, роли, SQL functions и grants из архива не исполняются. Application connections закрываются на время import/readback, receipt появляется после сверки; затем SQL clients открываются, но `release_ready=false` и serving не запускается.

Завершённый retry только перечитывает состояние. Поздние записи не стираются. Если import мог завершиться, но receipt ещё не записан, target остаётся в maintenance и не перезаписывается автоматическим retry. Автоматическое восстановление такого pre-receipt target требует отдельного resume protocol; до него сохраняется для расследования или явно заменяется новым target без удаления единственной копии.

После проверки archive/pin и до проверки содержимого target захватывается эксклюзивная OS file lock на canonical target path. Она удерживается до receipt и выхода из maintenance. Используются Windows byte-range locking и POSIX flock; sibling lockfile не удаляется, чтобы процессы не получили разные inode. Завершение процесса освобождает lock, наличие файла не означает работающий restore. Это локальная filesystem-синхронизация, не distributed lock для сетевых файловых систем.

## Граница доверия и RPO

Backup pin выбирает конкретную recovery point и защищает от незаметной подмены другим подписанным архивом. Он **не доказывает**, что snapshot содержит самое новое решение: concurrent post-snapshot promotion намеренно не попадает в backup. Оператор должен получить pin из доверенного recovery inventory вне архива, а будущий serving - перепроверить актуальное доверие/отзыв и разрешённое состояние. Повтор старой копии не является безопасным автоматическим rollback продукта. Расписание, offsite/encryption и online revocation не заявляются реализованными.

## Альтернативы и основания

Раздельные backups без общего snapshot отвергнуты из-за гонок; полный schema restore из архива расширил бы доверие до SQL-кода автора backup. Переписывание legacy manifest без новой версии скрыло бы изменение охвата. Оставляем explicit v2 и запрет v1 на journal.

Проверены 2026-10-14: [PostgreSQL pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html) поддерживает заданный synchronized snapshot и strict table names; [pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html) поддерживает TOC inspection и single-transaction import. Эти свойства проверяются отдельно реальным CI, не выводятся только из документации. [PB-22/RB-42/RB-43](../operations/promotion-recovery-troubleshooting.md), [evidence](../evidence/promotion-recovery-2026-10-14.md).
