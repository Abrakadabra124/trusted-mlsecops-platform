# RB-61 / PB-35: worker startup, приватная диагностика и core policy

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Оператор qualification отвечает за диагностику; security/platform owner согласует изменение policy. [ADR 0042](../decisions/0042-worker-process-privacy.md), [evidence](../evidence/worker-privacy-2026-10-19.md). Это controlled qualification, не отчёт о production-инциденте.

## RB-61: границы и read-only начало

Работать в trusted-mlsecops-platform с закреплённым Python 3.12/uv.lock. Локальные Docker, WSL, Kubernetes и SQL не запускать/не менять. Linux kernel test выполняется только на disposable CI. Unit tests используют mocked syscalls и отдельные subprocess, не понижают hard limits текущего процесса Codex/тестового runner.

```powershell
git status --short
git rev-parse HEAD
uv run --locked python -c "import sys; print(sys.version); print(sys.platform)"
```

Не выводить environment, raw stderr, private input paths, model bytes, core files или память процессов. Не менять core_pattern, daemon logging, seccomp или host sysctl. `enforce()` необратимо понижает hard core limit своего процесса; не вызывать его для диагностики в общем long-lived Python/REPL процессе.

## Симптомы и действия

| Симптом | Проверка | Действие |
| --- | --- | --- |
| `worker_rejected` / `serving_worker_rejected` до ML | Platform, image/source version, предыдущие qualification steps | Не включать raw exceptions; воспроизвести на синтетическом fixture |
| Guard unit failures | Error injection/readback expected constants | Исправить policy integration; не пропускать guard |
| `privacy_native_child_failed` | Native subprocess не завершил контролируемый сценарий | Сохранить fail/inconclusive, проверить Linux ABI/seccomp в разрешённом CI |
| `privacy_baseline_inconclusive` | Baseline dumpability не 1, переход не доказан | Не называть тест pass; определить условия runner без ослабления production policy |
| Core flag true, неверный signal или появились файлы | Не выполнен native negative contract | Остановить acceptance; не удалять evidence ради зелёного запуска |
| `serving_load_failed` до attach | Docker inspect core limit отсутствует/изменён/дублирован | Проверить owned container configuration; не передавать payload до исправления |
| Runtime import failure | Проверить pinned image/dependencies без публикации traceback | Пересобрать из проверенного checkout в disposable CI; не ставить случайную версию пакета |

Constant diagnostics намеренно не позволяют отличить приватные причины по публичному stderr. Уточнять причину через отдельные controlled tests, revision и finite stage results, а не возвращая raw error в API/log.

## PB-35: воспроизводимая проверка

1. Зафиксировать revision/dirty state и scope. Проверить источник image, не менять исходную foundation platform.
2. Запустить локальные contracts:

```powershell
uv run --locked coverage run --data-file=.coverage-process-privacy --source=mlsecops.process_privacy -m unittest scripts.process_privacy_qualification scripts.worker_privacy_qualification scripts.serving_runtime_qualification scripts.serving_session_qualification
uv run --locked coverage report --data-file=.coverage-process-privacy --fail-under=100
uv run --locked python scripts/check_docs.py
```

Expected на Windows: один явно обозначенный native Linux skip, остальные tests проходят; guard coverage 100% не заменяет этот skip. Native CI обязан подтвердить Linux и выполнить test без skip. Библиотеки не должны импортироваться на командном пути до guard; blocked guard запрещает чтение stdin и gzip request-file, stdout остаётся пустым.

3. После разрешённого push дождаться всех 10 CI terminal. В Storage проверить native finite report `worker-kernel-privacy-component-not-full-M13`: dumpable 0, limits [0,0], SIGABRT 6, core_dumped=false, owned_files=0, release_ready=false.
4. Проверить actual candidate, training и Kubernetes regressions на той же revision. Unit guard pass не доказывает compatibility seccomp контейнера; успешный native ML path должен использовать неизменённый защищённый entrypoint.
5. Сохранить sanitized report/CI links и failures. Не переносить pass предыдущего commit на новый; не rerun/cancel вслепую. Public report не содержит канареек или исходной диагностики.

## Встреченные дефекты, recovery и rollback

CLI tests воспроизвели раскрытие unknown arguments, file-path OSError и exception text, отсутствие guard до input и незапрещённые Docker core limits. Review выявил дополнительный путь: ImportError до main печатал traceback; fresh subprocess regression сначала failed для обоих entrypoints, затем runtime imports перенесены под защищённый вызов.

Второй review выявил ранний import ctypes: его native loader тоже мог выдавать traceback до enforce. Импорт перенесён внутрь protected guard. Отдельный fresh-process negative test без подмены всего guard подтвердил red -> green; kernel policy при этом не менялась.

При несовместимости platform/ABI остановить qualification, сохранить revision и error category, исследовать на собственном disposable Linux fixture. При отсутствии guard защищённый startup не разрешается. Не менять kernel policy чужих процессов, не давать worker CAP_SYS_RESOURCE/SYS_PTRACE и не отключать проверки ради запуска.

Rollback к прежнему image восстанавливает также прежние privacy ограничения: для реальных данных он не считается безопасным recovery автоматически. Использовать существующие immutable release/rollback процедуры только с принятым artifact; production rollback этим slice не проверен. Эскалировать при необходимости core debugging, private dataset, изменении syscall/seccomp policy или неизвестном владельце ресурсов. Все core/fault эксперименты остаются synthetic-only и per-process.
