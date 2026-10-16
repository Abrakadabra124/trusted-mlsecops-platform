# ADR 0037: bounded audit segments and retention

Дата: 2026-10-16. Статус: implemented, corrected native component qualification pass на b2b3bf6; [evidence](../evidence/audit-retention-2026-10-16.md). Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Продолжает [ADR 0036](0036-serving-audit-journal.md), не принимает полный M13 или M18 branch coverage.

## Контракт

Вместо неограниченного создания новых journal sessions использовать один явно выделенный private spool directory. POSIX/Linux профиль: owner-only directory, операции относительно одного проверенного directory FD, конечное число segments и общий byte budget, включающий retained и pending bytes. Legacy single-file Journal сохраняет прежний контракт; retained mode включается явно. Windows native retained mode отклоняется до изменения файлов: Windows ACL enforcement пока не реализован. Рабочий стенд пользователя не меняется.

Один writer владеет spool через exclusive `.lease` file. Порядок startup: проверенный directory FD -> exclusive создание lease -> чтение manifest/inventory -> проверка -> восстановление counters -> admission. Снимки, прочитанные до ownership, не используются. Unknown files, symlinks, hardlinks, изменённые identity/size/hash или несовместимая policy не дают права на очистку. На clean close записывается bounded canonical manifest: exact policy и byte budget, Linux boot ID, clock anchor, global sequence и closed segment identities/sizes/hashes/timestamps. Atomic replace/fsync manifest предшествует удалению lease. Clean restart на том же boot проверяет весь bounded inventory, не обнуляет retained budget/sequence/age. Existing lease означает concurrent writer или interruption: сохранить файлы и отказать, не угадывать по PID и не делать blind unlink. Автоматический recovery после crash/reboot отдельно не заявляется.

Defaults: segment <=1 MiB, <=16 segments, общий payload budget <=16 MiB; event <=2 KiB и pending <=64 сохраняются. Metadata отдельно bounded: manifest <=64 KiB, temporary manifest <=64 KiB, lease фиксированного размера. Это bounds содержимого файлов, не точный расход блоков filesystem; filesystem quota и физическое secure erase не реализованы.

Writer закрывает segment по размеру или возрасту 60 s. Закрытый segment хранится минимум 300 s после последнего подтверждённого write, затем удаляется при maintenance независимо от новых requests. Плановое окно от durable write до удаления старейшего события складывается из rotation age, retention и maintenance interval, плюс фактические задержки I/O и scheduling. Это не доказанный максимальный срок от admission и не hard deadline для filesystem. Lab policy не является юридическим сроком. При clock anomaly, зависшем I/O, отказе удаления или неизвестном состоянии срок удаления не подтверждён: sticky failure для обнаруженных ошибок, сохранение ownership/evidence и эскалация. Зависший syscall может ещё не вернуть ошибку; timeout ожидания не означает завершения writer. Не удалять раньше minimum retention ради освобождения места. Значения policy уменьшаются для контролируемых tests, но не меняются без явного нового профиля при reopen.

Clock: mono и wall samples ограничены integer nanoseconds; backward readings или расхождение elapsed wall/mono >1 s дают failure без purge. Boot ID привязывает persisted monotonic timestamps к одному host boot. Другой boot требует отдельного recovery/reconciliation; wall-clock jump не считается доказательством возраста данных.

Persisted clock не может быть null: новый anchor допустим только для нового пустого spool. При reopen canonical bounded records проверяются потоково по отдельным строкам, без неограниченного списка lines; sequence непрерывен внутри и между retained segments, последний совпадает с manifest head. При полностью истёкших segments head остаётся доверенным локальным checkpoint в unsigned manifest, не криптографическим доказательством против host-admin modification. До fstat regular-file validation применяется O_NONBLOCK, чтобы FIFO вместо manifest не блокировал startup.

`emit` не выполняет filesystem I/O. Writer делает rotation/maintenance; accepted, durable, pending и unconfirmed остаются разными состояниями. Global sequence продолжается после clean restart, session counters остаются локальными. Storage credit освобождается только после unlink и directory fsync owned closed segment. Неудачный sync не становится повторной выдачей budget. При shutdown timeout нельзя закрывать живой writer, удалять его segment или очищать lease.

Handoff point - успешный unlink собственного lease после закрытия segments и durable manifest. До него failed close оставляет guard для reconciliation. После него другой writer уже может владеть каталогом: старый объект не восстанавливает и не удаляет lease, даже если завершающий directory fsync/close вернул ошибку. Такой close остаётся failed, но ownership уже передан; это не повод трогать нового владельца. Constructor cleanup также не экспортирует исходное исключение. Эти два порядка уточнены same-model design review; внешняя модель не использовалась.

## Проверка перед принятием

Failure-first tests: cap без eviction молодых записей; rotation byte/age; expiry на idle writer; clean restart без reset age/sequence/budget; unknown file/symlink/hardlink/parent replacement; concurrent open и stale lease; crash до clean manifest; clock rollback/forward и boot mismatch; short write/fsync/unlink/manifest/close failures; retained pending shutdown. Native POSIX tests выполняются в disposable Linux CI, не подменяются Windows mocks. Проверить существующие 21 audit contracts и serving regression, не ослабляя прежние gates.

## Альтернативы

SQLite рассмотрен как готовый transactional backend. Но `max_page_count` ограничивает database file, а `journal_size_limit` не даёт общего hard cap во время transaction. Добавлять другой persistent engine только для этой очереди сейчас не требуется. По [SQLite PRAGMA](https://www.sqlite.org/pragma.html#pragma_max_page_count) и [atomic commit](https://www.sqlite.org/atomiccommit.html) нужны отдельные границы для sidecar files и crash protocol. Это инженерный выбор данного lab, не утверждение, что SQLite непригоден для audit.

Blind glob cleanup и обычный rotating logging handler не дают проверенной принадлежности файлов и accepted/durable/unconfirmed. Удаление старейшего файла независимо от minimum retention отвергнуто. Источники проверены 2026-10-16; [Python os](https://docs.python.org/3.12/library/os.html) задаёт fd-relative filesystem primitives.

## Остаточный scope

Verification update `42ce792`: [native branch gate](../evidence/audit-branches-2026-10-16.md) подтвердил core 76/80 branches = 95% и retention 102/102 = 100%, 61 audit + 10 checker tests без skips. Backend code не менялся; добавлены fault tests и отдельный per-module measurement. Это закрытие критериев покрытия двух модулей, не полного M18.

ASGI actual-send correlation, versioned candidate/release contexts, all-output canaries, cardinality и полный M13 ещё обязательны. Audit storage не является signed non-repudiation ledger; malicious host administrator/same-UID writer, storage firmware и physical erasure вне доказанного контроля. Failed/interrupted spool требует отдельного восстановления, не тихого обхода сменой path.
