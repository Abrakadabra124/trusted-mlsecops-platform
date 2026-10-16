# RB-56 / PB-30: retained audit storage

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Ответственный: platform operator; срок хранения утверждает security/data owner. [ADR 0037](../decisions/0037-audit-retention.md), [evidence](../evidence/audit-retention-2026-10-16.md). Это opt-in journal backend, ещё не HTTP audit/M13.

## RB-56: безопасная диагностика

1. Зафиксировать code revision, режим Journal, policy и только bounded status: accepted/durable/pending/unconfirmed/reserved_bytes/closed/failure. `reserved_bytes` включает retained bytes предыдущих clean sessions и pending новых событий. `durable_bytes` - исторические успешные writes текущей session, не размер существующих файлов. Нулевой reserved после expiry не отменяет факта прежней durability.
2. Проверить профиль. Retained mode поддерживает Linux/POSIX с `/proc/sys/kernel/random/boot_id`; Windows native отвергается до изменения файлов. Windows успешные unit tests со skips не подтверждают native permissions, deletion или restart. Старый single-file mode не получает автоматическую retention по умолчанию.
3. `audit_spool_open`: сначала выяснить, действительно ли это выделенный private каталог, неизменённая policy и тот же boot. Existing `.lease` может означать работающего владельца, failed startup или interruption. Его возраст/PID не доказывают отсутствие живого writer. Не удалять guard, `.next`, manifest или segments и не менять permissions ради запуска.
4. `audit_capacity_exhausted` / `sink_failed`: закончить admission, сохранить объект writer. Проверить, не исчерпаны ли byte/file caps до minimum retention. Не увеличивать caps и не создавать бесконечные новые spool paths. Отказ filesystem или clock не превращать в eviction молодых записей.
5. `audit_shutdown_pending`: старый thread всё ещё owned. Не менять каталог и не запускать замену writer. Дождаться завершения I/O и повторить close того же объекта. При зависшем filesystem срок удаления не гарантирован; отметить failure/inconclusive и эскалировать.
6. `audit_failed` при закрытом writer не означает, что lease остался у этого объекта. До handoff guard сохраняется; после успешного unlink собственного lease новый процесс уже может владеть каталогом, даже если последний directory fsync/close старого процесса завершился ошибкой. Старый объект не имеет права восстанавливать или удалять новый guard. Не писать скрипт «если close failed, удалить .lease».
7. Retention относится к времени durable writes, а не к дате в имени файла. Clock rollback/forward >1 s относительно monotonic clock и другой boot запрещают автоматический purge. Без исправного worker/I/O нет обещания максимального срока удаления. Logical unlink не доказывает физическое стирание SSD, snapshots или backups.

## PB-30: воспроизводимая qualification

Prerequisites: clean checkout проверяемого code commit, pinned Python/uv; для native cases нужен Linux disposable runner. Команды не запускают Docker, WSL или Kubernetes и создают только собственные временные каталоги/потоки:

```text
git status --short
git rev-parse HEAD
uv run --locked python -m unittest scripts.serving_audit_qualification scripts.audit_retention_qualification
uv run --locked coverage run --data-file=.coverage-serving-audit --source=mlsecops.serving_audit,mlsecops.audit_retention -m unittest scripts.serving_audit_qualification scripts.audit_retention_qualification
uv run --locked coverage report --data-file=.coverage-serving-audit
```

На Windows POSIX cases явно skipped; результат не принимается за native qualification. CI отдельно проверяет serving_audit coverage >=95% и audit_retention >=90%; локальный процент покрытия другого OS не переносится по аналогии. Это component thresholds итогового Cover, не завершённая M18 приёмка >=95% branch coverage. На `b2b3bf6` native suite прошла 51 test без skips, Cover 97%/93%; непокрытые branches остаются обязательной работой до финальной приёмки.

Матрица: byte/age rotation; idle expiry; cap без eviction молодых данных; продолжение sequence/age/budget после clean restart; unknown files, изменённый hash, symlink/hardlink и parent rename; конкурентные writers; failure fsync/unlink/manifest; interleaved startup и handoff cleanup. Проверить конечные bytes и отсутствие изменения чужих sentinel files, не только exit code команды.

## Восстановление и rollback

Поддержанный restart: подтверждённый clean close, тот же host boot, тот же private directory и exact policy/budget, immutable manifest/inventory. Новый writer захватывает собственный exclusive guard до чтения manifest. Сохранённые файлы продолжают расходовать общий budget; нумерация и возраст не обнуляются.

Crash/reboot recovery пока не автоматизирован. При оставшемся guard или boot mismatch не обходить защиту. Сначала остановить/подтвердить завершение всех owned writers, сохранить приватную копию evidence по решению владельца и выполнить отдельный reviewed reconciliation. Этот runbook не даёт команд удаления единственной копии audit или очистки каталога. Неподтверждённые записи нельзя автоматически replay-ить как отсутствующие.

Rollback experimental backend выполняется только в disposable qualification после подтверждённого закрытия. Старые retained files не перезаписываются single-file journal. M13 остаётся inconclusive до HTTP correlation/canary проверки; переключение режима не является разрешением release.

## Ошибки разработки, не production incidents

- Constructor cleanup первоначально мог экспортировать исходный текст ошибки cleanup; failure-first test воспроизвёл утечку canary. Теперь constructor возвращает только bounded `audit_spool_open`.
- Закрытый backend обязан явно отклонять операции: `dir_fd=None` недопустимо использовать как продолжение прежнего owned directory. Добавлен отдельный closed guard.
- Design review уточнил startup ordering и handoff point. Exclusive ownership берётся до snapshot; после handoff старый writer не изменяет новые owner files, даже при cleanup error.
- Shared directory cursor при повторном `scandir(fd)` давал пустой второй inventory в controlled regression. Каждый scan теперь получает независимый fd-relative directory descriptor; Linux suite отдельно проверяет повторный native inventory.
- Второй review обнаружил принятие null clock и рассогласованного sequence head в manifest. Controlled tests воспроизвели оба обхода. Reopen теперь требует сохранённый clock и сверяет непрерывные record sequences с head до admission. Это validation, не подпись manifest.
- Специальный файл FIFO вместо manifest нельзя сначала открыть блокирующим способом, а потом проверять тип. O_NONBLOCK позволяет отказать до ожидания постороннего writer; native test проверяет ограниченное завершение и сохранность FIFO.

Подтверждённые платформы, количество tests и native CI status находятся в evidence. Не считать этот документ доказательством уже выполненных native сценариев.
