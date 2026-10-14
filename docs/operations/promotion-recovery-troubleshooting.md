# PB-22 / RB-42 / RB-43: backup и recovery promotion journal

Ответственный: platform-owner; выбор recovery point и разрешение дальнейшего serving требуют trust/approval owner. Scope: synthetic local CPU. [ADR 0028](../decisions/0028-promotion-recovery.md), [evidence](../evidence/promotion-recovery-2026-10-14.md). Не production DR и не автоматический failover.

## PB-22: создать и проверить полную копию

Начать с read-only: проверить Git revision, ownership state, доступность нужной БД и выбранный environment. Не запускать qualification на рабочем state. Локальный Docker Engine в этой сессии недоступен через dockerDesktopLinuxEngine pipe; это не признак повреждения данных. Working Docker/WSL не перезапускались, reset/prune не применялись.

Для уже установленного journal:

```powershell
uv run --locked python -m mlsecops.storage_backup --state .runtime --include-promotion
```

Команда читает SQL snapshot и создаёт новые локальные backup files. Она не мигрирует schema, не переключает модель и не меняет source journal. Сохранить полученный backup_id в отдельном доверенном recovery inventory вместе с source revision, временем и разрешённой потерей изменений после snapshot. Архив содержит данные, хранить приватно; не коммитить `.runtime` или signing keys. Возраст принимаемой копии ограничен 24 часами, но ежедневное расписание пока отсутствует.

Восстановление меняет **новый** target: создаёт container/volume/network, новые credentials/CA, imports data и сохраняет receipt. `BACKUP_ID` брать из доверенной записи владельца backup, не вычислять автоматически из полученного неизвестного архива. Public trust bundle получать по независимому доверенному каналу.

```powershell
uv run --locked python -m mlsecops.storage_restore --backup .runtime/backups/BACKUP_ID --target .runtime/recovery/journal-01 --trust .runtime/trusted-keys.json --expected-backup-id BACKUP_ID --port 15440
```

Требуется новый свободный target и свободный loopback port. Ожидаются `storage-restored-not-release-ready`, `release_ready=false`, manifest/receipt schema_version=2, совпадение всех CAS и promotion fingerprints. Повтор завершённого restore возвращает reused=true только при неизменном состоянии. Наличие receipt не отменяет live readback. После восстановления не назначать alias и не включать serving вручную: текущие revocations/новые решения после snapshot ещё должны быть сверены.

Controlled tests и **отдельная изменяющая** квалификация:

```powershell
uv run --locked python -m unittest scripts.promotion_recovery_qualification scripts.promotion_recovery_native_qualification
uv run --locked python -m scripts.promotion_recovery_native --state .runtime --confirm-disposable
```

Native runner предназначен только для свежего owned CI state после promotion qualification. Он создаёт controlled SQL selections, делает concurrent promotion после snapshot, останавливает **исходную disposable БД**, восстанавливает новый target, проверяет 1 000 predictions через sandbox worker, возвращает source и удаляет только созданные им verified targets. Отдельный target получает намеренную потерю ответа после commit. Это не read-only doctor и не ML approval. Результат/ограничения в `.runtime/evidence/promotion-recovery.json`; прошлый pass-файл не доказывает текущий запуск.

Проверено на `8f94e2e`: 36 native checks pass, source-offline restore до golden checks 6.870389 s, 1 000 predictions/error=0.0. Отдельно 125 local methods pass; Windows и Linux subprocess locking проверены. Точный campaign/source/backup binding в evidence. Это прогретый CI runner, не cold-machine RTO, power-loss тест или полный M17.

V2 поддержан здесь для независимого Docker target. Прежний Kubernetes migration принимает только v1 table scope и отвергнет дополнительные journal tables до maintenance/import. Не удалять их из архива и не обходить TOC check; перенос v2 в Kubernetes требует отдельной реализации и приёмки.

## RB-42: backup запрещён или manifest не принят

1. `backup_promotion_ledger_not_supported` в обычной команде - ожидаемая защита v1. Если нужен journal, использовать проверенный explicit v2 path, а не удалять schema или guard.
2. `promotion_backup_migration_mismatch` - неизвестная история migration. Сверить установленный checksum с текущим code revision; не переписывать checksum вручную. Backup с другого schema contract требует отдельного migration plan.
3. `backup_ledger_content_invalid` - structural corruption либо превышенный/некорректный ledger. Проверить heads/events/previous links и immutable request binding; остановить promotion до расследования. Не подписывать вручную «исправленный» manifest поверх неизвестных данных.
4. `restore_backup_pin_mismatch_or_missing`, `untrusted_key`, archive integrity или time-window error - отказ до target bootstrap. Проверить выбранный trusted backup ID, внешний public-key bundle, время/версию и наличие всех bytes. Не доверять ключу, вложенному в архив, не продлевать manifest и не отключать digest validation.
5. Если проверка не укладывается в лимиты, сохранить evidence и подобрать согласованный capacity profile. Не обходить ограничения input/process и не переносить импорт в рабочую БД ради теста.

## RB-43: прерванный import или изменившийся target

`restore_target_busy` означает занятый OS lock этого target. Не удалять sibling `.TARGET.recovery.lock` и не запускать второй restore в обход CLI. Наличие lockfile само по себе не доказывает живой процесс: эксклюзивная OS-блокировка автоматически освобождается при завершении процесса. На сетевой файловой системе эту локальную гарантию не заявлять.

1. Не повторять import поверх непустого target и не удалять исходную/единственную копию. Сохранить backup_id, target ownership, timestamp, наличие receipt и очищенный outcome. Не выводить credentials.
2. `restore_requires_new_target` без receipt означает незавершённое восстановление. SQL commit мог произойти, даже если caller получил ошибку. Этот target остаётся в maintenance; отсутствие ответа не доказывает rollback.
3. Только после проверки target ownership администратор читает `datconnlimit` и fingerprints. `datconnlimit=0` намеренно запрещает application connections. Не выполнять `ALTER DATABASE ... CONNECTION LIMIT -1` вручную ради зелёной health check.
4. Автоматический resume до receipt ещё не реализован. Безопасный путь сейчас: сохранить failed target для расследования, заново проверить исходный backup/pin и восстановить в **другой новый target**. Удаление failed target отдельно, только после независимой успешной проверки и ownership; qualification очищает исключительно собственные disposable targets.
5. `restore_existing_promotion_changed` или `restore_existing_target_changed` при повторе завершённого restore означает поздние записи/несовпадение. Повтор не должен стирать их. Сверить legitimate later promotions и выбрать recovery strategy с владельцем; это не повод сбрасывать sequence.
6. Успех восстановления - совпавшие live ledgers, разрешённые/запрещённые SQL операции и golden predictions. Это ещё не ready: необходимо подтвердить актуальный trust/revocation и разрешение запуска модели. Snapshot может законно отставать от source из-за RPO; old backup не доказывает latest head.

Rollback этого кода не удаляет journal. V1 tooling по-прежнему отказывает при его наличии. При неожиданном разрешении клиента во время maintenance, неизвестном migration checksum, повреждённой цепочке или расхождении readback остановить recovery и эскалировать platform-owner. Проверенные controlled/native сценарии и ещё не реализованные recovery steps явно разделены в evidence.

Ревью воспроизвело гонку разработки: два restore проходили раннюю проверку пустого target; поздний процесс мог закрыть connections уже завершённого restore. Исправление сериализует весь участок от проверки target до receipt/thaw. Regression проверяет реальное исключение второго процесса, освобождение lock после os._exit и controlled API race до initialize. Это не production-инцидент и не доказательство network-filesystem locking.

Первый native CI завершился generic failure, не pass. Найденный дефект negative probe: storage.connect оборачивает startup denial в Rejected; ловить только psycopg.Error было неверно. Новый probe проверяет непосредственный отказ PostgreSQL по database connection limit; TLS/auth/другая ошибка не засчитывается. Runner теперь выдаёт фиксированные case labels и allowlisted error codes. Не публиковать raw driver message ради диагностики. Служебные sibling lockfiles исключены из Git, а source_dirty проверяется до/после native campaign; не игнорировать реальные изменения исходников.
