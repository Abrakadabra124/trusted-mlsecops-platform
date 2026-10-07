# ADR 0007: согласованная копия и отдельный restore PostgreSQL

Дата: 2026-10-07. Статус: компонент реализован, 430 локальных checks прошли. Scope: T02 migration/restore smoke и storage component будущего T20/M17, не полная приёмка M17. [Runbook и измерения](../storage-recovery.md).

## Решение и границы

Использовать штатные `pg_dump` / `pg_restore` из того же pinned PostgreSQL image. Один exported REPEATABLE READ snapshot связывает dump и ledger девяти artifact tables: число строк, суммарные bytes и hash упорядоченных object IDs, размеров и timestamps. SHA-256 каждого payload дополнительно проверяется при построении ledger. Exporter держит snapshot открытым до завершения dump, не блокирует обычные INSERT и не останавливает рабочую БД.

Копия содержит только data-only custom archive и подписанный DSSE manifest. В неё не входят приватные ключи, клиентские сертификаты, произвольные SQL roles, схемы или Docker volumes. Schema/ACL создаются из зафиксированной migration текущего репозитория. Внешний public trust bundle задаётся оператором, не берётся на веру из самой копии; manifest подписывает отдельная уже существующая роль `trust`.

Restore сначала проверяет signature, формат, версии, policy, возраст <=24 h, размеры и digest, затем создаёт отдельный workspace, CA, volume, network и loopback endpoint. Нельзя импортировать поверх исходной или произвольной непустой БД. Import выполняется атомарно, ошибка не разрешает частичный ready. Повтор того же успешного restore проверяет ledger и не заменяет identities. Чужая/повреждённая цель сохраняется для расследования, не удаляется автоматически.

Ресурсы дополнительной БД: 1 CPU / 512 MiB / 64 PID. Перед созданием проверяется disk headroom. Source containers, kubeconfig и исходная enterprise-devsecops-platform не меняются. Cleanup qualification проверяет ownership и удаляет только созданные ею recovery resources; операторский restore сохраняется.

## Почему так

Собственный сериализатор всех database rows дублировал бы проверенный механизм PostgreSQL. Несогласованные `pg_dump` и отдельный подсчёт таблиц могли бы дать ложный mismatch при параллельной записи. Копирование работающего PGDATA без native backup protocol не выбирается. Restore SQL может выполнять код исходного администратора: поэтому допускаются только подписанные копии доверенного собственного источника, не произвольные сторонние dumps, даже если их SHA-256 известен.

Локальная копия не является offsite backup или шифрованием. Host-admin и signer доверенные; подпись не защищает от их компрометации. Ротация/отзыв через будущий trust service, восстановление online serving и golden prediction readiness остаются обязательной частью полного M17. Snapshot не сохраняет приватные signing keys: их custody/recovery решается отдельно, не путём копирования всех secrets в общий archive. Нельзя заявлять ежедневный RPO без реально настроенного и проверенного расписания.

## Проверки перед принятием компонента

Missing/tampered dump, unsigned/foreign manifest, expired/future snapshot, wrong schema/policy/trust, непустая или исходная цель должны быть отвергнуты. Новый экземпляр должен совпасть с ledger по всем девяти таблицам, сохранить реальные ACL и восстановить candidate/dataset/evaluation references. Qualification измеряет полный component recovery time и проверяет повтор без смены container/CA; это не автоматическое закрытие M17.

## Первоисточники

[pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html) описывает consistent export, custom format и использование внешнего snapshot. [Snapshot synchronization](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-SNAPSHOT-SYNCHRONIZATION) требует сохранять экспортирующую transaction живой. [pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html) описывает single-transaction / exit-on-error и предупреждает об исполнении кода из недоверенного dump. Эти свойства используются в ограниченном lab profile, не как доказательство всей disaster recovery процедуры.
