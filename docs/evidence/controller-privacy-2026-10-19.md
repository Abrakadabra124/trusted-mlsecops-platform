# T16: controller/transport process privacy, 2026-10-19

Статус: **native verified fe1437e**, не полная M13/T16/R1-приёмка. Code commit `fe1437e887e15053a3b03a72e892b517da166e76`, base `350ee91544af7500a384bbe476fa8ef30d8c63c6`. [ADR 0044](../decisions/0044-controller-process-privacy.md), [RB-63/PB-37](../operations/controller-privacy-troubleshooting.md), [native receipts и полный candidate report](controller-privacy-fe1437e-native.md).

## Native результат

- Linux guard/readback suite: **18 tests / 0 skips, 5.145 s**, process_privacy 34 statements / 10 branches / 100%. Пять CLI проверены в собственных Linux children; отдельный readback замечает повторное включение dumpability и не исправляет его. Abort receipt: dumpable=0, core limits 0:0, SIGABRT без core flag и owned files.
- CLI/lifecycle/owner suite: **70 tests / 0 skips, 14.259 s**. private_cli 100%, serving_lifecycle 100%, worker_transport **98%** combined (132 statements / 44 branches; не исполнены Windows-only direct kill и module dispatch). Установленный coverage threshold 95% не ослаблялся.
- Native serving child действительно принял SIGINT после startup, закрыл engine, вернул **130** и только постоянную diagnostic, без traceback. Это loopback controlled engine, не production endpoint или реальный model release.
- Реальные publisher/scorer с scoped identities: **dumpable=0, core_limits=[0,0] у обоих**, observer не вызывает setters. Scoped-controller report **139 cases pass**, M20 **725 cases pass**, M21 **122 cases pass**. M20 finished 18:35:50.753416 UTC, M21 finished 18:38:05.495618 UTC.
- Actual-candidate serving: **78 unique cases pass**, source_dirty=false, release_ready=false. Metrics 69 samples; 12 privacy requests / 36 confirmed audit events / 3 owned files, ambient_signals_used=false. Golden 3 rows, maximum error 0; stopped worker denial 2.018293245 s.
- Независимо пересчитан outage: 43 observations, first 503 через 59.749565176 s. Paused SQL denial 10.002861141 s, expiry denial 5.677943162 s; query ACTIVE/pending и generation fenced на момент отказа, renewal version 3. Это controlled measurements, не общий production SLO.
- Canonical SHA-256 полного candidate report: `f8d3b5ef3eb82b664bb0024ea876afce437207cec8a82a0eb94b63b4f82c64ea`. Source fingerprint `5bec6983e846be6b993ae5ac430deb5e32af142c90b67792c96ea1c82bfaf530`. Serving image `sha256:11dda816c7297be4fa28886ae1cabdaf0e1beefc9457f96096c9f96f6e0c6b8b`; controller CI image другой: `sha256:c72f4a36ba22e272e2edb951bf9656fe2a15a5837548d2b364d33bd55a3ecf68`. Оба report привязаны к одному source fingerprint; bit-for-bit image rebuild не заявляется.
- Regression в Linux: metrics **35 / 0 skips / 100%**, privacy+candidate **25 / 0 skips / 100%**, HTTP audit **48 / 0 skips / 100%**, serving **81 / 0 skips**, access **32 / 0 skips**, private audit **77 / 0 skips**. M03 **431**, M07 **97**, M06 **18** pass. Developer profile **74 cases**, intake **66 cases** pass.

## Все 10 CI завершены

Observer зафиксировал terminal matrix **2026-10-19 18:38:27 UTC** для exact code commit. **6 success / 4 failure**. Нет новых rerun/cancellation; документационная публикация evidence не выдаётся за повторный native run.

| Workflow | Run | Conclusion |
| --- | --- | --- |
| Developer runtime qualification | [39301863834](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863834) | success |
| Documentation integrity | [39301863845](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863845) | success |
| Frozen evasion and domain guard | [39301863892](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863892) | failure |
| Frozen poisoning research matrix | [39301863852](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863852) | failure |
| Intake evidence contracts | [39301863872](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863872) | success |
| Kubernetes isolation qualification | [39301863911](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863911) | success |
| MLflow tracking compatibility and private service | [39301863866](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863866) | success |
| Paired robust training research | [39301863835](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863835) | failure |
| Storage role and TLS qualification | [39301863940](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863940) | success |
| Worker and storage image audit | [39301863970](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863970) | failure |

Failures сохранены как blockers, не skipped и не случайные успехи:

- Image audit проверил все четыре exact images, SBOM validated и scan_executed=true, scanner exit 2. Critical/High: worker **0/56**, storage **9/132**, worker-candidate **0/55**, storage-candidate **1/85**. Это package findings, не доказанная эксплуатация каждого CVE.
- Poisoning execution complete: **10 violating / 0 inconclusive / 25 nonviolating** scenarios. Полный M08 не принят.
- Evasion execution complete: recall drop **0.07183673469387755 > 0.05**.
- Paired training execution complete: candidate drops **0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05**. Пороги не менялись ради зелёной CI.

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

Общий runner не применяет native guard. На Windows Linux-specific children skipped; это не native pass. Native GitHub CI fe1437e отдельно подтвердил actual controller snapshot, M20/M21, unchanged actual-candidate serving и terminal matrix. Source lock валиден, dependency/data files не менялись. Локальные Docker, WSL, Kubernetes, SQL и исходный enterprise project не затронуты; AGENTS.md/GOAL.md владельца не включаются в commit.

## Что не закрыто

Полные M13/T16/R1 не приняты. Ещё нужны all-output/public-export/correlation verification; административные CLI, pre-main interpreter/import failures, privileged host, swap и arbitrary native code не объявляются защищёнными этим increment. Нельзя принудительно завершить зависший Python thread безопасным универсальным вызовом. Kernel policy не является differential privacy и не устраняет membership inference. Image/ML blockers предыдущего native commit сохраняются до новой проверки, а не маскируются компонентным pass.
