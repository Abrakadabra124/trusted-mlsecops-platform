# RB-55 / PB-29: private audit journal core

Ответственный: platform operator; disclosure/retention решает security/data owner. Scope: [ADR 0036](../decisions/0036-serving-audit-journal.md). Компонент ещё не включён в serving HTTP; [evidence](../evidence/serving-audit-2026-10-15.md) не является полной M13-приёмкой.

Этот runbook относится к legacy single-file Journal без параметра retention. Отдельный opt-in retained mode и границы его проверки описаны в [RB-56/PB-30](audit-retention-troubleshooting.md); его нельзя автоматически включать для прежнего файла.

## RB-55: диагностика без изменения рабочего runtime

1. Зафиксировать revision, UTC и bounded status: healthy/closed/failure/accepted/durable/pending/unconfirmed/durable_bytes. Не публиковать файл, path, request/principal IDs, release refs или исходное исключение. Наличие завершённой JSON-строки не доказывает успешный fsync.
2. Различать `emit` acknowledgment и durability. Успешный emit даёт только sequence в очереди. Pending writer требует ожидания или явного inconclusive, не утверждения о сохранённом аудите. После sink failure accepted может быть больше durable даже при полной строке на диске.
3. `audit_queue_full` и `audit_capacity_exhausted` требуют прекратить новый admission в вызывающем компоненте и сохранить ownership writer. Увеличение cap, reset counters или второй writer в тот же файл не являются исправлением. Не трактовать `healthy=false` этого core как уже реализованный HTTP 503.
4. `audit_shutdown_pending` означает, что join deadline истёк, но writer не подтверждён закрытым. Не unlink/rename/truncate файл и не удалять его parent. Объект и thread handle должны остаться доступны владельцу; дождаться завершения I/O и повторить close того же объекта. При продолжающемся зависании оставить квалификацию inconclusive и эскалировать.
5. `audit_failed` после close сохраняет первоначальный failure. Даже accepted==durable не устраняет факт отказа нового event. Файл оставить приватным для диагностики; считать проверку неуспешной. Копировать его в GitHub запрещено.
6. Startup rejection: проверить absolute path, отсутствие existing target, POSIX owner-only parent либо Windows owner-only ACL. Не лечить ошибку широким chmod/ACL. POSIX final parent symlink отвергается; создание связано с проверенным directory FD, не с поздним повторным разрешением path.

## PB-29: воспроизводимая проверка компонента

Prerequisites: checkout проекта, pinned Python/uv dependencies. Команды создают только собственные временные файлы/потоки. Docker, WSL, рабочая БД и Kubernetes не запускаются:

```powershell
git status --short
git rev-parse HEAD
uv run --locked python -m unittest scripts.serving_audit_qualification
uv run --locked coverage run --data-file=.coverage-serving-audit --source=mlsecops.serving_audit -m unittest scripts.serving_audit_qualification
uv run --locked coverage report --data-file=.coverage-serving-audit --fail-under=95
```

Проверяются real file readback/fsync path, short writes, byte budget, active-write queue bound, failed sync, ordered concurrent producers, start/close races и canary exclusion в разрешённой schema. На Windows native POSIX parent-replacement test пропускается явно; он должен выполниться без skip в Linux CI. Mocked syscall test не заменяет этот native filesystem test. Общий test pass с skipped case не объявляется полной платформенной проверкой.

Особо воспроизведённые дефекты разработки: Windows text mode добавлял CR к LF и расходился с byte accounting; поздняя мутация dict добавляла неразрешённое поле; stale Queue.Empty при close терял принятую запись с ложным success; ошибка создания Thread обходила очистку. Исправления: binary FD, fixed-field snapshots, повторная pending-проверка под admission lock, accepted==durable при close и защищённое thread construction. Это контролируемые regression cases, не production-инциденты.

## Recovery, rollback и retention

Восстановление выполняется только после остановки producer и подтверждённого завершения owned writer. Сначала private readback и reconciliation accepted/durable/unconfirmed; полный trace не экспортировать. Новый qualified session обязан использовать новый явно выбранный path, не дописывать прежний файл. При неопределённом fsync нельзя доказать отсутствие или автоматическую безопасную повторную запись события; нужен отдельный recovery protocol.

Автоматической rotation, возрастного удаления и restart resume сейчас нет. Hard 16 MiB cap ограничивает один journal, но не сумму файлов, которые оператор создаёт вручную. Не запускать бесконечные новые сессии для обхода лимита. До проверки общего storage budget и retention не подключать этот core как безотказный круглосуточный HTTP audit.

Rollback: отключать экспериментальное подключение только в disposable qualification, оставляя M13 inconclusive и final promotion denied. Не откатывать release gates ради доступности модели. Для удаления приватного evidence нужны подтверждённое закрытие writer, точный owned path, согласованная retention policy и разрешение владельца; blind glob/prune здесь не предусмотрены. Физическое secure erase и production storage encryption этим модулем не доказаны.
