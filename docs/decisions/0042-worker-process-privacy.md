# ADR 0042: безопасная диагностика и запрет core dump в ML-worker

Дата: 2026-10-19. Статус: implemented, native verified d2c48bf; intake test regression исправлена и подтверждена повторной compatibility CI. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Продолжает [ADR 0041](0041-serving-output-privacy.md); не принимает полный M13/R1.

## Требование и фактическая граница

Модель и признаки передаются в изолированный Linux worker. Собственный stderr не должен раскрывать пути/текст ошибок, а аварийный снимок памяти не должен становиться дополнительным хранилищем raw features. До изменения worker CLI печатал текст исключения, argparse мог отражать неизвестные аргументы; runtime imports выполнялись до защищённого main. Это воспроизведено synthetic fault tests, не является установленной утечкой production-данных.

Существующий serving использует bounded stdin/stdout protocol, `stderr=DEVNULL` у docker attach и `--log-driver none`. Training Docker path также не сохраняет Docker logs; Kubernetes transport отдельно ограничивает и редактирует диагностический stderr. Они не доказывают отсутствие kernel core dumps. Core dump содержит память аварийного процесса; `RLIMIT_CORE=0` недостаточен, когда host направляет dump через pipe в collector. Основание: [Linux core(5)](https://man7.org/linux/man-pages/man5/core.5.html), проверено 2026-10-19.

## Решение

1. Оба CLI entrypoint (`mlsecops.worker`, `mlsecops.serving_worker`) вызывают `process_privacy.enforce()` до чтения stdin/request-file и до загрузки ML-библиотек. Direct `train/execute/serve` остаются внутренними функциями для unit tests, не заменой защищённого entrypoint.
2. Linux guard через libc задаёт `PR_SET_DUMPABLE=0`, устанавливает soft/hard `RLIMIT_CORE=(0, 0)` и читает оба значения обратно. Ошибка platform/import/syscall/limit или несоответствие readback дают только `worker_privacy_unavailable`, без исходного текста исключения. Успешный syscall без readback не принимается.
3. `ctypes` явно задаёт `c_int` для operation/result и `c_ulong` для четырёх variadic arguments. Это учитывает требование ширины параметров в [prctl(2)](https://man7.org/linux/man-pages/man2/prctl.2.html). [PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html) управляет dumpability конкретного процесса; host sysctl/core_pattern не изменяется.
4. Импорты `ctypes` и `resource` отложены внутрь protected Linux guard: `resource` [доступен на Unix](https://docs.python.org/3.12/library/resource.html), а загрузка `_ctypes` также может завершиться ошибкой native dependency. Импорт Python workers и unit tests на Windows сохраняется, но production CLI не делает небезопасный fallback без Linux-защиты. Fresh CLI fault test не подменяет весь guard и проверяет реальный путь отказа импорта ctypes.
5. Docker training и serving дополнительно получают `--ulimit core=0:0`. Serving readback требует единственный core limit с integer zero soft/hard; missing, nonzero, boolean и duplicate entries отклоняются до attach/input. Другие daemon resource limits разрешены, если core contract соблюдён.
6. Worker CLI использует безопасный argparse error handler и постоянный `worker_rejected` для обычных исключений, включая runtime ImportError. Serving сохраняет `serving_worker_rejected`. Lazy imports помещают загрузку ML runtime в защищённую границу; протоколы успешных ответов и численные результаты не меняются.

## Trade-offs и альтернативы

Один ulimit не закрывает piped core collector. Только read-only rootfs не контролирует host collector. Глобальное изменение core_pattern затронуло бы чужие процессы. Поэтому выбраны собственные process attributes и bounded entrypoint diagnostics, без новых сервисов/пакетов и без изменения host policy.

Цена: post-mortem core debugging worker недоступен; оператор использует очищенные reason/status, версии и воспроизводимую синтетику. Нельзя временно включать dumpable или печатать исходное исключение с реальными данными ради диагностики. Прямой worker CLI на Windows возвращает контролируемый отказ; Windows development tests не являются Linux native proof.

## Проверка и ограничения

Failure-first CLI/argv/file/import tests, negative Docker readback и отдельный 100% gate для guard описаны в [evidence](../evidence/worker-privacy-2026-10-19.md). [RB-61/PB-35](../operations/worker-privacy-troubleshooting.md) фиксирует diagnosis/recovery.

Native CI af7253e и повторный d2c48bf в отдельном disposable Linux subprocess подтвердили dumpable 1 -> 0 и limits [0,0], затем fork/SIGABRT и `WCOREDUMP=false`, signal 6, отсутствие файлов в owned temporary directory. Один returncode или пустой каталог недостаточен для вывода о pipe collector. Baseline dump не создаётся; `core_pattern`, privileged services и чужие данные не читаются/не меняются. [Полный receipt и candidate regression d2c48bf](../evidence/worker-privacy-d2c48bf-native.md) не отменяют failed image/ML gates. Историческая intake regression и её исправление сохранены в evidence.

Не заявляются защита от privileged host, намеренного переустановления dumpability скомпрометированным native code, контроллерных core dumps, всех сторонних diagnostic streams, encrypted memory или полная M13-приёмка. Privacy report/export, approved metrics/cardinality и полная audit correlation остаются отдельной работой. Без accepted image/ML gates release запрещён.
