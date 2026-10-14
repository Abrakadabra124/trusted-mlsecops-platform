# Promotion recovery evidence: 2026-10-14

Scope: signed backup v2 и независимый restore CAS + promotion journal. [ADR 0028](../decisions/0028-promotion-recovery.md), [PB-22/RB-42/RB-43](../operations/promotion-recovery-troubleshooting.md). Не full M17/M11 или production DR.

## Локальные controlled результаты

После review correction объединённые **124 adjacent unittest methods pass** на Windows: прежние 106, новые 12 recovery contracts, 3 CLI и 3 OS-lock methods. Проверены реальный второй процесс и освобождение lock после os._exit. Python helpers `promotion_recovery`: 32 statements/6 branches, `recovery_lock`: 29 statements/4 branches, оба 100% coverage. Это не покрытие SQL ветвей или всего native orchestrator; validators/transport substitutes не заменяют реальную БД. Ruff check/format и diff whitespace check прошли.

TDD сначала выявил отсутствие нового module/API, затем snapshot/manifest v2 contract; после реализации все targeted tests прошли. Проверяются exact migration/scope, неизвестная schema, aggregate limits, TOC, maintenance, отсутствие pin до создания target, interrupted import без reopen, post-import mismatch, retry без reimport и CLI redaction/ownership. Настоящие подписи используются для manifest fixtures, SQL transport подменён.

Fresh-context reviewer обнаружил конкурентную гонку restore: поздний процесс мог закрыть уже восстановленный target. Добавлена OS lock до target check, удерживаемая до receipt/thaw; API regression и реальные subprocess tests проверены. Это same-model agent review, не независимая human acceptance M22. Cross-model review пропущен в автономном режиме, внешние CLI не запускались.

Docker Engine локально недоступен через dockerDesktopLinuxEngine named pipe. Working Docker/WSL/SQL/cluster не менялись. Native command включён в fresh CI после прежних storage/release/ledger checks; результат pending до завершённого run. Не объявлять source-offline restore и golden predictions проверенными по одному наличию кода.

## Ограничения

## Первый CI и correction

[Storage run 38610935513](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38610935513) на `75dbf56` завершился failure на новом recovery step; прежние CAS recovery, M03/M07 и 108 promotion checks прошли. Полный native recovery этого commit не принят. Исходный runner сохранил только generic failure, поэтому точный последний успешный шаг по тому log не устанавливается.

Code inspection выявил ошибочную границу negative probe: `storage.connect` преобразует psycopg startup failure в `Rejected`, а runner ожидал psycopg.Error. Controlled regression воспроизводит это преобразование; теперь используется прежний maintenance probe с непосредственным psycopg connection и точным распознаванием database-limit denial, посторонняя TLS/auth error не считается pass. Добавлены безопасные case progress и allowlisted failure codes без вывода SQL/credentials. Полный native outcome проверяется новым run, не выводится только из исправления.

Intake evidence первого run показывал source_dirty=true: legacy negative restore исходного `.runtime` теперь создаёт sibling `..runtime.recovery.lock` у корня checkout. Добавлен узкий ignore для `*.recovery.lock`, не для исходников; `git check-ignore` подтвердил этот путь. Новый runner требует чистый checkout до и после campaign. Presence lockfile не доказывает живой процесс. После correction 19 focused recovery/CLI/lock methods pass.

## Оставшиеся ограничения

Recovery pin выбирает конкретный snapshot, но не доказывает latest state и не восстанавливает post-snapshot promotions. Controlled SQL selections не являются одобренными моделями. Target без завершённого receipt остаётся fenced; автоматический pre-receipt resume ещё не реализован. Online revocation, serving activation, расписание/offsite/encryption и полный M17 остаются открытыми. Security/research failures не обходятся.
