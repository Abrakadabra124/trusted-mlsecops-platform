# T16: worker diagnostics и process core privacy

Дата: 2026-10-19. Статус: implemented, local contracts verified, native pending. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Основа `daf42074bb45aeaa438a3ee32bb9a4c221662685`. [ADR 0042](../decisions/0042-worker-process-privacy.md), [RB-61/PB-35](../operations/worker-privacy-troubleshooting.md).

## Failure-first

- CLI/argv/error/guard и Docker policy: 7 methods, 7 failures + 5 errors до исправления. Это synthetic tests с mock Docker calls, не запуск локального контейнера.
- Новый process guard отсутствовал: import regression failed до реализации.
- Fresh CLI runtime import failure: 1 method, 2 failures, traceback вместо постоянной диагностики для worker и serving worker. Lazy runtime imports закрывают этот путь; kernel guard вызывается раньше.
- Guard ctypes import failure: 1 method, 2 failures до переноса импорта внутрь protected enforce. Fresh process test не подменяет guard; проверяет, что injected import failure действительно произошёл, до любых kernel mutations.

## Локальный результат

После двух review findings: **39 methods, 38 pass / 1 native Linux skip, 4.543 s**. Guard: **19 statements / 6 branch exits, 100%**. Mock syscalls проверяют недоступную platform/resource/libc, failed set/get dumpability, failed set/get limits; CLI tests проверяют stdin/file denial, constant errors и порядок guard -> execution. Docker inspect rejects missing/nonzero/boolean/duplicate core limit до attach.

Ранние adjacent suites: **51 methods / 0 skips, 6.581 s**, session/model/privacy/candidate contracts. После lazy import fix отдельно model/privacy/candidate suites: **43 methods / 0 skips, 6.516 s**. Попытка добавить несуществующее имя worker_transport_qualification дала loader error; после проверки inventory исправлена команда, не отключён существующий тест. Ruff и formatter проходят. Windows не исполнял prctl/resource/core tests; его skip не выдаётся за native pass. Локальные Docker/WSL/Kubernetes/SQL, исходная enterprise platform и пользовательские AGENTS.md/GOAL.md не менялись.

## Review и ожидаемая native проверка

Design cycle1 нашёл actionable import-before-main boundary; implementation cycle2 выявил аналогичный путь при загрузке ctypes до enforce. Оба замечания воспроизведены и исправлены; final cycle3 завершён без новых actionable findings по read-only inspection. Это не независимое повторение тестов и не native proof. Внешняя модель не использовалась по выбору владельца. Новый artifact не переоткрывает завершённый HTTP privacy review.

Storage CI должен подтвердить реальный Linux guard/readback и fork/SIGABRT wait status без core flag/owned files, затем unchanged actual candidate и прежние M-gates. Native syscall test не меняет host core_pattern и не создаёт baseline core dump. До native результата этот документ не принимает worker kernel privacy. После native проверки остаются controller memory/core policy, arbitrary third-party streams, all-output/public export/cardinality и полный M13/R1.
