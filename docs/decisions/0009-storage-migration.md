# ADR 0009: Подписанная миграция storage snapshot в Kubernetes

Дата: 2026-10-08. Статус: implemented, local qualification passed; clean-checkout evidence фиксируется отдельно в STATUS. Связь: T05/T26 и storage component T20; полные M04/M17/M20 остаются обязательными.

## Scope и причина

Private PostgreSQL profile уже проверен, но пустой. Следующий шаг переносит настоящий dataset/candidate/evaluation history из собственного Docker SQL instance в этот instance внутри **того же workspace**. Это opt-in snapshot import, не автоматическое переключение SQL demo и не continuous replication. Исходная foundation, host БД, ключи и существующий operator restore не изменяются.

## Порядок изменения runtime

1. Проверить DSSE backup manifest, текущие внешние trust roots, policy/schema/image, возраст <=24 h и точные archive bytes. До этого target не изменяется.
2. Проверить ownership/config и PVC UID закрытого target. Native archive TOC допускает только девять существующих data tables. Source superuser и backup signer остаются доверенными: native restore не является sandbox для чужого SQL.
3. Удерживать PostgreSQL advisory lock отдельной живой сессией. Второй migration process получает явный отказ, а завершение сессии снимает lock. Файл intent не считается доказательством работающего процесса.
4. Зафиксировать подписанный intent с backup digest, namespace/PVC/spec binding. Временно установить target database connection limit 0 и завершить только его non-superuser sessions. Проверить пустоту уже после ограничения доступа. Superuser Unix admin остаётся доступен для restore; source instance не затрагивается.
5. Импортировать уже проверенные bytes через `pg_restore --single-transaction --exit-on-error`. Сравнить полный ledger под maintenance barrier. Только после совпадения записать signed receipt и вернуть обычный connection limit.
6. При прерывании оставить target в maintenance, не стирать rows. Повтор с тем же валидным intent и archive может продолжить пустой target либо завершить receipt, если все bytes уже совпадают. Другой backup, изменённая identity, посторонние rows или invalid receipt дают отказ. Повтор после появления новых данных не перезаписывает их.
7. Проверить dataset/candidate/evaluation через реальные mTLS role Pods и 1 000 predictions в отдельном offline worker. Это проверка переносимости артефактов, не новая независимая оценка модели и не promotion.

## Откат и ограничения

До будущего явного cutover rollback - продолжить прежний host SQL path. Нет удаления source, переименования cluster resources, сброса schema, копирования private signing keys или автоматического включения serving. Ошибка не разрешает доверенный выпуск. Daily RPO, HA, TLS rotation и полный ML trust recovery этим increment не закрываются.

Основание: [PostgreSQL 18 pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html), [advisory locks](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-ADVISORY-LOCKS), [database connection limits](https://www.postgresql.org/docs/18/sql-createdatabase.html), [session termination](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-ADMIN-SIGNAL). Connection limit не ограничивает superusers/background workers; изоляция от operator admin здесь не заявляется. Выбор maintenance barrier - решение этого локального single-owner профиля, не универсальная online migration процедура.
