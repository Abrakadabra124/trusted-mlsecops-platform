# T16: controller/transport process privacy, 2026-10-19

Статус: implemented, native qualification pending. Base commit `350ee91544af7500a384bbe476fa8ef30d8c63c6`. [ADR 0044](../decisions/0044-controller-process-privacy.md), [RB-63/PB-37](../operations/controller-privacy-troubleshooting.md).

## Что меняется

Пять CLI применяют Linux guard до parsing/private work, используют приватный argparse и постоянные ошибки. Structured RecordedDenial сохраняет fail/inconclusive, точный bounded reference и release_ready=false. Реальные publisher/scorer добавляют read-only kernel snapshot, без неявного изменения legacy authority/boundary probes. Uvicorn lifecycle failures санитизируются отдельно от HTTP logging; failed shutdown даёт nonzero CLI.

Transport защищает acquisition child, partial reader startup, background read, deadline и cleanup. Cancellation в cleanup не прерывает независимые попытки остальных ресурсов. Completion event и per-stream ownership не позволяют принять ident=None за отсутствие потока или закрыть pipe, который поздно запущенный reader ещё может использовать. Неподтверждённый cleanup остаётся fail, требует завершения owning process и не разрешает retry в нём.

## Failure-first история и ограничения

- Исходные CLI negatives: 3 methods, 8 failures / 12 errors; transport negatives: 3 methods, 6 failures / 1 error. Подтверждены отражение аргументов/ошибок и потеря child cleanup при ошибке запуска reader.
- Review cycle 1: lifetime Uvicorn, прекращение cleanup на собственном отказе, окно после Popen, необработанные старые tests и скрытые process_state callers. Дополнительный red run: 7 tests, 3 failures / 4 errors. Readback до реализации: 5 tests, 3 errors / 2 native skips.
- Первичный red harness ошибочно не подменил uvicorn.run и запустил принадлежащий тесту loopback server; он остановлен, отсутствие тестовых процессов проверено, harness исправлен. Этот запуск не считается validation.
- Review cycle 2: cancellation внутри cleanup, неоднозначный Thread.start bootstrap, блокирование закрытия независимого stream. Controlled regressions проверяют deferred cancellation, mixed completion и реальный delayed Python bootstrap с mocked child. Test harness освобождает только собственный delayed reader.
- Промежуточный local regression до cycle-2 correction: 211 tests, 0 failures/errors, 5 skips, 32.133 s. Это историческая проверка, не доказательство окончательного diff. Последующие результаты и CI должны быть добавлены после исполнения.
- External/cross-model review не использовался по выбору владельца. Same-model review ограничен тремя циклами; findings проверяются по коду и тестам.
- Review cycle 3 нашёл два дополнительных дефекта: developer qualification принимал terminal cleanup за успешный negative, а convenience uvicorn.run поглощал cancellation. Red run: 2 tests, 1 failure / 1 error. Исправлены explicit CleanupIncomplete propagation и прямой Config/Server owner; добавлены проверки четырёх negative positions, настоящего wrapper behavior и native owned CLI SIGINT. Четвёртый review не запускался; окончательный diff проверяется regression/native CI, а не объявляется безусловно одобренным reviewer.

## Локальный checkpoint

- Финальная adjacent regression: **220 tests, 0 failures/errors, 6 native/POSIX skips, 38.094 s**. Включает controller/readback/transport/lifecycle/owner, прежние worker/privacy/HTTP/audit/metrics/candidate/session/runtime/core/access suites. Linux evidence и full M13 этим не заменяются.

- Финальный focused gate: **70 tests, 0 failures/errors, 1 native SIGINT skip, 14.282 s**. private_cli: 5 statements / 100%; serving_lifecycle: 26 statements / 8 branches / 100%; worker_transport: 132 statements / 44 branches / 99% combined. Непокрыт module __main__ dispatch, не cleanup branch.
- Guard/readback suite: **18 tests, 0 failures/errors, 3 native skips, 0.819 s**; process_privacy 34 statements / 10 branches / 100%. Это controlled coverage, не native kernel evidence.
- Locked pip-audit: no known vulnerabilities found. Это Python dependency result, не решение прежних container image findings. Source lock валиден; dependency/data файлы не изменены.

## Воспроизведение

```powershell
uv run --locked python -m unittest scripts.controller_privacy_qualification scripts.controller_readback_qualification scripts.worker_transport_privacy_qualification scripts.serving_lifecycle_qualification scripts.process_privacy_qualification scripts.worker_privacy_qualification scripts.intake_denial_qualification scripts.serving_http_qualification
uv run --locked coverage run --data-file=.coverage-controller-privacy --source=mlsecops.private_cli,mlsecops.serving_lifecycle,mlsecops.worker_transport -m unittest scripts.controller_privacy_qualification scripts.worker_transport_privacy_qualification scripts.serving_lifecycle_qualification scripts.serving_http_qualification scripts.intake_denial_qualification
uv run --locked coverage report --data-file=.coverage-controller-privacy
```

Общий runner не применяет native guard. На Windows Linux-specific children skipped; это не native pass. GitHub CI должен дополнительно подтвердить actual controller snapshot, M20/M21, unchanged actual-candidate serving и все terminal workflows. До этого нет нового native acceptance. Source lock валиден, dependency/data files не менялись. Локальные Docker, WSL, Kubernetes, SQL и исходный enterprise project не затронуты; AGENTS.md/GOAL.md владельца не включаются в commit.

## Что не закрыто

Полные M13/T16/R1 не приняты. Ещё нужны all-output/public-export/correlation verification; административные CLI, pre-main interpreter/import failures, privileged host, swap и arbitrary native code не объявляются защищёнными этим increment. Нельзя принудительно завершить зависший Python thread безопасным универсальным вызовом. Kernel policy не является differential privacy и не устраняет membership inference. Image/ML blockers предыдущего native commit сохраняются до новой проверки, а не маскируются компонентным pass.
