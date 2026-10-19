# ADR 0044: privacy на входе controller/transport/serving CLI

Дата: 2026-10-19. Статус: implemented, native qualification pending. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Продолжает [ADR 0042](0042-worker-process-privacy.md) и [ADR 0043](0043-serving-metrics.md). Не принимает полный M13.

## Проверенный пробел

Publisher/scorer controller читает private request, SQL/API identities и signer. Его main перехватывает только RecordedDenial; прочие ошибки дают traceback, argparse может отражать аргументы. Диагностические controller_probe/intake_probe также выполняются с identities. Serving CLI читает private config, но сам процесс до этого не применяет worker core policy. Worker transport хранит private result/diagnostic bytes; reader threads создаются/запускаются до try/finally, поэтому отказ их запуска может оставить child без очистки.

## Решение и границы

1. Применять существующую Linux dumpability/core policy в production entrypoints controller, worker_transport и serving_http, а также controller_probe/intake_probe до разбора аргументов и приватного I/O. Library entrypoints/fixtures не изменяют kernel state родительского test runner. На неподдерживаемой платформе CLI fail closed; mock tests не выдаются за native proof.
2. Неверные аргументы не отражаются через argparse. Unexpected errors дают постоянную диагностику и nonzero exit. Structured RecordedDenial сохраняет уже проверенный bounded reference в private controller protocol, не делает его public export. Intake probe использует постоянный incomplete reason вместо широкого regex-пропуска произвольного текста исключения.
3. Read-only readback privacy state отдельно от enforcement, чтобы native publisher/scorer evidence проверяло состояние реальных процессов. Проверка не должна переустанавливать настройки и скрывать их изменение. Не добавлять host sysctl, root privileges или дополнительные сервисы.
4. Child/stream/thread lifecycle transport защищается с момента успешного Popen. Partial thread startup и read failure не печатают private exception из background thread; процесс завершается и reap выполняется, ожидание остаётся bounded. Preserve bounded output protocol, diagnostics counts, overflow/deadline checks и cancellation semantics. Protocol stdout предназначен для scoped parent, не public logging.
5. Scope - перечисленные runtime entrypoints и их private IPC. Остальные administrative tools, interpreter failure до входа в main, privileged host, memory swap, произвольный native code и public export остаются отдельными границами. Audit связывает private release refs, но complete source/run/report/approval/request export всё ещё требует отдельной реализации и проверки.

## Уточнения после review

- Одного try/except вокруг uvicorn.run недостаточно: Starlette передаёт traceback через lifespan failed message, а Uvicorn может вернуть управление после failed shutdown без исключения. Внешний lifecycle adapter заменяет message константой, фиксирует failure и не пропускает исходное исключение в logger; CLI проверяет этот флаг. Это отдельный lifecycle path, HTTP middleware и метрики не перепроектируются.
- process_state требует privacy только при explicit require_privacy=True в production controller. Authority/boundary probes не приобретают скрытую зависимость от enforcement. M20 проверяет и сохраняет snapshot реальных publisher/scorer, а не повторно применяет настройки ради pass.
- Cancellation в kill/wait/join/close откладывается до независимых попыток cleanup; CLI возвращает 130 без private exception context. Обычный cleanup failure даёт постоянный worker_cleanup_incomplete внутри private protocol и общий worker_transport_rejected на CLI.
- Reader связан со своим stream и completion event. Только завершённый target и подтверждённый join разрешают закрытие этого pipe; проблема одного reader не блокирует закрытие независимого безопасного stream.
- Thread.start может создать системный поток до подтверждения Python bootstrap. ident=None и is_alive=False не доказывают отсутствие потока. Если bounded ожидание не подтверждает завершение, затронутый pipe намеренно не закрывается из другого потока: close buffered pipe может зависнуть. Cleanup не объявляется успешным, владелец завершает CLI/process boundary, автоматический retry внутри того же процесса запрещён. Это явно ограниченная recovery policy, не обещание принудительно уничтожить Python thread или устранить отказ ОС.
- Terminal CleanupIncomplete отделён от ожидаемого negative Rejected в developer qualification: он прерывает проверку, не записывает pass и не запускает следующий child. Uvicorn запускается через single-process Config/Server, поскольку convenience run поглощает KeyboardInterrupt; прямой owner проверяет started, lifecycle_failed и cancellation.

## Основания

- [ASGI lifespan specification](https://asgi.readthedocs.io/en/latest/specs/lifespan.html): failed startup/shutdown передают сообщение серверу; graceful возвращение функции само по себе не доказывает успешный shutdown.
- [Python 3.12 threading](https://docs.python.org/3.12/library/threading.html): thread lifecycle и bounded join; возвращение join требует отдельной проверки состояния.
- [Linux PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html): per-process dumpability, а не системный sysctl или защита от привилегированного host.
- Код закреплённых Uvicorn 0.54.0 / Python 3.12.15 просмотрен локально; использованы настоящие LifespanOn/Starlette в controlled tests. Источники проверены 2026-10-19. Не копируется чужая реализация.

## Приёмка

- Failure-first argv/file/config/execute/capture faults с синтетическими private canaries: постоянная stderr/JSON, nonzero exit, отсутствие raw input/traceback.
- Guard failure не допускает reads, worker spawn, SQL/Kubernetes или server startup. Guard не вызывается в процессе Codex и общего unittest runner.
- Partial reader construction/start и background read errors: проверяется child termination/reap, отсутствие живых readers и закрытие принадлежащих capture streams. Не скрывать cleanup failure за успешным envelope.
- Существующие RecordedDenial и success paths сохраняют проверенный protocol; unit tests явно mock guard, native subprocess проверяет настоящий readback.
- Disposable Linux CI: реальный publisher/scorer readback и M20/M21, прежние serving/privacy/metrics cases. Полная matrix, failed attempts и новые runbook/playbook рядом с кодом. Локальную инфраструктуру не запускать/не менять, AGENTS.md/GOAL.md владельца не редактировать.
