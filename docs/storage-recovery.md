# Резервная копия и восстановление SQL storage

## Что реализовано

Работают CLI создания подписанной согласованной копии и восстановления в отдельную БД. Локальная квалификация 2026-10-07: **430 cases pass**, 31 восстановленный объект в девяти таблицах, 3 926 350 исходных bytes, archive 7 858 806 bytes. Из этих checks 367 повторно проверяют SQL/TLS boundaries уже восстановленного экземпляра, а не являются новыми независимыми экспериментами.

Storage restore занял 11.109 s; путь от начала восстановления до проверки 1 000 golden predictions и подписи evaluation занял 14.562 s. Maximum prediction difference = 0.0. Замер сделан на текущем локальном host с уже доступными images; это не cold-machine disaster recovery benchmark. Исходная БД не остановлена, её ledger и container identity сохранились.

Это storage component T02/T20, **не полный M17**: ещё нет работающего release/serving recovery, online revocation service, проверенного ежедневного расписания и offsite copy. Результат CLI всегда `storage-restored-not-release-ready`, `release_ready=false`.

Код: [snapshot и bounded process transport](../mlsecops/storage_snapshot.py), [backup и manifest verification](../mlsecops/storage_backup.py), [restore](../mlsecops/storage_restore.py), [qualification](../mlsecops/storage_recovery_qualification.py). В [clean-checkout CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37686666806) на commit `6722a03` все 430 checks повторились успешно; полный R1 не принят.

## Технологии и цепочка

PostgreSQL `pg_dump` создаёт native custom-format archive, `pg_restore` импортирует его. REPEATABLE READ snapshot задаёт одну согласованную картину таблиц: все участвующие чтения видят одно состояние, даже если другой клиент добавляет строки. Используется [поддержка exported snapshot](https://www.postgresql.org/docs/18/app-pgdump.html), не попытка скопировать живой PGDATA как обычную папку.

1. Controller проверяет ownership source storage, pinned image, configuration, migration и public trust bundle.
2. В открытой read-only transaction строится ledger: count, sum(bytes), SHA-256 упорядоченных object IDs/размеров/timestamps. Для каждого payload повторно считается SHA-256; повреждённая строка запрещает backup.
3. `pg_dump` читает тот же exported snapshot. В archive входят только девять artifact tables; schema, roles и private keys не копируются. Используется uncompressed custom format и ограничение 256 MiB archive / 10 000 rows / 256 MiB source bytes, без silent truncation.
4. Роль `trust` подписывает manifest через DSSE/Ed25519. Manifest связывает archive digest, размер, ledger, workspace, policy, migration, image, public-key bundle digest и время snapshot. Directory публикуется только после проверки записи.
5. Restore проверяет подпись по **внешнему текущему** public trust bundle, timestamps и возраст <=24 h, context и точные archive bytes. Неверный backup не получает доступ к bootstrap.
6. Только затем создаются новый workspace, CA, SQL credentials, container, volume и network. Schema и ACL устанавливаются из текущей зафиксированной migration. Проверяется точный TABLE DATA scope native archive.
7. Import выполняется `--single-transaction --exit-on-error`, без `--clean` и без перезаписи существующего storage. Ledger всех девяти таблиц должен совпасть.
8. Receipt фиксирует восстановленную identity. Повтор с тем же backup проверяет реальную БД и сохраняет container/keys; если после восстановления появились новые данные, повтор отказывает, а не стирает их.

Согласованность snapshot отдельно проверена настоящей конкурентной вставкой: ingestor добавляет запись после открытия snapshot, source её видит, но backup и восстановленная БД правильно её не содержат. Это проверка native database semantics, не mocked SQL result.

## Команды

Сначала поднимите [SQL lab](storage-lab.md), соберите текущий worker и создайте candidate через `python -m mlsecops.storage_pipeline`. Затем:

```bash
uv run --locked python -m mlsecops.storage_backup
uv run --locked python -m mlsecops.storage_restore --backup .runtime/backups/BACKUP_ID --target .runtime/recovery/storage-01 --trust .runtime/trusted-keys.json --port 15440
```

Замените `BACKUP_ID` на ID из вывода первой команды. Target должен быть новым; повтор успешного restore допускается только с совпадающим receipt и неизменным ledger. Restore **не** назначает новую runtime alias и **не** запускает serving. Public keys исходных артефактов сохраняются отдельно в `recovered-public-keys.json`; приватные signing keys исходного workspace не клонируются.

Public trust bundle для настоящего recovery храните и проверяйте отдельно от backup. Не используйте «доверенный ключ», предложенный вместе с неизвестным архивом. Изменившийся trust bundle отвергает старую копию; полноценная динамическая revocation policy ещё не реализована.

Полная component qualification:

```bash
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.storage_recovery_qualification
```

Она использует свободный loopback port 15441, создаёт собственный временный recovery workspace и удаляет только его контейнер/network/volume после проверки ownership. Операторский target `storage-01` остаётся. Не запускать qualification одновременно с пользовательскими операциями: в suite входят rollback-only SQL permission probes. Неудавшийся частичный restore без успешного receipt не очищается автоматически и требует проверки оператором.

## Проверки и evidence

Negative suite проверяет corrupt/missing/truncated archive, signature/payload/signer tamper, wrong policy/image/schema/trust, boolean-as-version, stale/future/inverted timestamps, path traversal, invalid ledger, неполный/повторный/чужой TABLE DATA scope, пределы output и timeout, исходный/непустой target и позднюю запись в восстановленную БД. Найденный negative fixture выявил принятие `true` вместо migration version `1`; добавлена строгая integer-проверка, fixture теперь отклоняется.

Положительные проверки подтверждают native snapshot consistency, новую identity/storage, полный ledger, сохранение candidate bytes, подписанного evaluation и dataset bindings, 1 000 предсказаний с тем же image, реальные ACL/TLS и идемпотентный repeat. После локальной проверки открытых idle transactions в source БД не осталось.

- `.runtime/backups/BACKUP_ID/data.dump` и `manifest.json`: приватный локальный backup, не файлы для Git.
- `.runtime/evidence/storage-backup.json`: ID, размеры и ledger последнего отдельного backup CLI.
- `.runtime/recovery/storage-01/recovery.json`: receipt операторского restore.
- `.runtime/evidence/storage-recovery-qualification.json`: sanitized cases, timings, archive ID, golden error и ограничения.
- [Storage CI](../.github/workflows/storage.yml): M03, затем fresh backup/restore qualification из clean checkout; проверенные commits перечислены в [STATUS](../STATUS.md).

## Что не обещается

Подписанный dump не становится безопасным, если скомпрометирован доверенный source administrator или signer. [PostgreSQL предупреждает](https://www.postgresql.org/docs/18/app-pgrestore.html), что восстановление недоверенного dump может выполнять код; эта команда не предназначена для сторонних архивов. Host-admin, Docker administrator и локальная custody ключей остаются доверенными.

Сейчас поддерживается только текущая schema/image/policy; автоматического downgrade или migration чужой версии нет. Копия локальная и не зашифрована, расписание не настроено, ежедневный RPO не заявляется. Windows mode 0600 не доказывает корректные NTFS ACL. Для реальных данных нужны согласованные encryption/retention/offsite/key-recovery policies и отдельная приёмка. Полный M17 обязан дополнительно проверить revoked trust до serving readiness и восстановление всего release, а не только БД. [ADR 0007](decisions/0007-storage-recovery.md) фиксирует этот scope.
