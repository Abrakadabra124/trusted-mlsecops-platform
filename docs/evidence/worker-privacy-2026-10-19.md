# T16: worker diagnostics и process core privacy

Дата: 2026-10-19. Статус: native kernel/serving verified; intake test regression исправлена и повторно проверена на **d2c48bf**. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Основа `daf42074bb45aeaa438a3ee32bb9a4c221662685`. [ADR 0042](../decisions/0042-worker-process-privacy.md), [RB-61/PB-35](../operations/worker-privacy-troubleshooting.md). Полные M13/R1 не приняты.

## Актуальный результат после исправления: d2c48bf

Code commit `d2c48bf03ce6f669fd990538f01d47b82380f06c` меняет только fault-injection target в существующем test и публикует af7253e evidence. Worker runtime, security thresholds и assertions не изменены. На **2026-10-19 16:56:27 UTC** все 10 workflows завершены, attempt 1: **6 success / 4 failure**. Rerun/cancel не выполнялись. Историческая failed matrix af7253e сохранена ниже.

| Workflow | Run / job | Terminal conclusion |
| --- | --- | --- |
| Storage | [39287256202](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256202) / 118177665632 | success; kernel, serving, M03/M07 |
| Kubernetes | [39287256197](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256197) / 118177666124 | success; M20 723 / M21 122 |
| Developer | [39287256347](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256347) / 118177665375 | success; scanner regression и fresh training |
| Tracking | [39287256362](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256362) / 118177665487 | success; M06 18 |
| Intake | [39287256205](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256205) / 118177671872 | success; 66/66 contract cases |
| Documentation | [39287256287](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256287) / 118177664285 | success |
| Image audit | [39287256239](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256239) / 118177664397 | failure; package scan executed, security findings |
| Poisoning | [39287256258](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256258) / 118177664886 | failure; 10 violating / 0 inconclusive |
| Evasion | [39287256196](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256196) / 118177664901 | failure; recall drop > 0.05 |
| Paired training | [39287256242](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256242) / 118177665819 | failure; candidate recall drops > 0.05 |

### Что проверено на новой revision

- Developer: **36 tests / 0 skips, 2.665 s**, artifact_intake 121 statements / 46 branches, **100%**. Intake aggregate **66/66 pass**; missing scanner test восстановлен. Три fresh training runs дают max probability difference **0.0**, sklearn/ONNX parity max error **2.086162567138672e-7**. Windows symlink limitation не переносится на Linux, где полная suite реально прошла.
- Storage: **13 worker privacy tests / 0 skips, 0.283 s**, guard 100%, native kernel receipt pass. Existing privacy **17 / 0 skips, 1.235 s**, probe 100%; HTTP audit **48 / 0 skips, 4.475 s**, module 100%; journal **77 / 0 skips, 4.030 s**; serving **81 / 0 skips, 14.411 s**; client access **32 / 0 skips, 1.935 s**.
- Actual candidate: **77 unique cases pass**, finished `2026-10-19T16:46:45.912175+00:00`, source_dirty=false, release_ready=false. [Полный report и kernel receipt](worker-privacy-d2c48bf-native.md), canonical candidate SHA-256 **`c1bd83c2c84552cb2034f9a7f284f91cc4548c7871b54126a39d5f7416c1bf19`**. Golden 3 rows / error 0; stopped worker denial **2.011746403 s**. Audit 8 accepted / 8 durable; privacy 12 requests / 36 confirmed events / 3 owned files; ambient_signals_used=false.
- Quotas: statuses 422/429/422/429, refill 200/200, admitted [2,2,4]. Trust outage: **46 observations**, first completed 503 **59.763940434 s**. Paused SQL denial **10.001976876 s** при ACTIVE и незавершённом SQL; near-expiry denial **5.694757575 s** до signed expiry, затем post-expiry denial и renewal/readback version 3. Это один controlled campaign, не статистическое доказательство SLO. Сохранённые traces повторно проверены локальным assessor без запуска инфраструктуры.
- Worker image **`sha256:13cfa0ab458cc21c334c1d673aaa2b3c0863489d4e1e687780edd281b68ed7f3`**, source fingerprint **`aa9ffa0a6216e7f870370cf1e552bd626fc1971e7670726436f307da504d3916`**. Fingerprint совпадает с af7253e, image ID отличается: bit-for-bit reproducibility image не заявляется.
- M03 **431 pass**, M07 **97 pass**, M06 **18 pass**. M20 **723 pass**, finished `2026-10-19T16:53:39.024028+00:00`; M21 **122 pass**, finished `2026-10-19T16:55:57.553295+00:00`. Это исправляет текущую intake regression, но не объясняет исторический M07 connection failure на 503b68b.

### Сохранившиеся blockers и границы

Image candidate compatibility восстановлена: worker 74 checks pass, independent storage restore 435 checks pass. Теперь SBOM validated и scan executed для всех четырёх образов, каждый scanner exit code **2**. Critical/High findings: worker **0/56**, storage **9/132**, worker-candidate **0/55**, storage-candidate **1/85**. Отказ security gate не переименован в success и candidate image не adopted.

Poisoning: 10 violating / 0 inconclusive. Evasion recall drop `0.07183673469387755` при максимуме `0.05`; paired candidate drops `0.052244897959183675`, `0.06224066390041494`, `0.06143344709897611`. Эти ML failures сохраняют запрет release. Все результаты synthetic-only; core protection не защищает от privileged host/скомпрометированного native code, не квалифицирует controller memory, все сторонние outputs, approved metrics/cardinality или полный export/correlation M13. Следующий slice продолжает эти границы, не ослабляя gates.

Дальнейшая публикация этого отчёта docs-only не является новым runtime прогоном. Code acceptance привязана к d2c48bf, а не автоматически к любому будущему main.

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

Storage CI подтвердил реальный Linux guard/readback и fork/SIGABRT wait status без core flag/owned files, unchanged actual candidate и M03/M07. Native syscall test не меняет host core_pattern и не создаёт baseline core dump. Controller memory/core policy, arbitrary third-party streams, all-output/public export/cardinality и полный M13/R1 остаются открытыми. Отдельная intake regression ниже не скрывается успешным Storage job.

## Native evidence af7253e

Code commit `af7253e91a6709800b9d9e1e7febf0f34cd2e427` опубликован в main. [Полный sanitized report и kernel receipt](worker-privacy-af7253e-native.md) сохранены из Storage job **118163593269**, run **39283688533**, attempt 1. Candidate canonical SHA-256: `d3544f54f36b5bb85af11f1b0cb32513af589a1dae05354b0c74cab115daa3fd`.

- Native worker privacy: **13 tests / 0 skips, 0.362 s**, guard 19 statements / 6 branches, 100%. Dumpability 1 -> 0, core limits [0,0], SIGABRT 6, core_dumped=false, owned_files=0. Receipt сохраняет release_ready=false.
- Existing serving privacy: **17 tests / 0 skips, 1.265 s**; HTTP audit **48 / 0 skips, 4.598 s**; journal **77 / 0 skips, 3.750 s**; serving **81 / 0 skips, 15.763 s**; client access **32 / 0 skips, 2.031 s**. Core audit branch counts 94/98, retention 102/102.
- Actual candidate: **77 unique cases pass**, finished `2026-10-19T16:21:12.184010+00:00`, source_dirty=false, release_ready=false. Golden 3 rows, max error 0; stopped worker denial 2.013813627 s. Audit pair 8 accepted / 8 durable; privacy 12 requests / 36 confirmed events / 3 owned files, ambient_signals_used=false.
- Quotas: boundary 422/429/422/429, refill 200/200, admitted deltas [2,2,4]. Outage: 44 observations, first completed 503 after **59.747452988 s**. Paused SQL: **10.002498574 s** with ACTIVE before denial and unfinished query; near-expiry signed policy: **6.689870448 s**, before signed expiry, renewal/readback version 3. Сохранённые traces повторно проверены локальным assessor, без сетевых или SQL вызовов.
- Worker image: `sha256:4ee6e46110f48213a77e7c9c32fc44f1c6051576789f60990a06041b446687c5`; source fingerprint: `aa9ffa0a6216e7f870370cf1e552bd626fc1971e7670726436f307da504d3916`. M03 **431 pass**, M07 **97 pass**. Kubernetes M20 **723 pass**, finished `2026-10-19T16:27:07.583421+00:00`, но M21 failed с `M21_contracts_failed`.

## Найденная regression и минимальное исправление

Developer CI: 36 tests, 1 error `AttributeError` в `test_unknown_scanner_rejection_is_redacted`. После lazy imports scanner больше не является module-global `worker.inspect_model`; test patch обращался к удалённому имени. Intake report содержит **65 из 66** cases, отсутствует именно этот test. M21 запускает тот же contracts aggregate, поэтому Kubernetes M21 failed; Image и Tracking остановились на `qualification_failed:acceptance-dispatch-M21`. Image package scan на этой revision **не выполнялся**; прежние CVE counts нельзя выдавать за новый scan.

Локальное воспроизведение до исправления: **1 test / 1 error, 0.469 s**. Минимальное исправление меняет только patch target на `model.inspect_model`, откуда worker теперь делает lazy import. Проверки `model_profile_rejected` и отсутствия private-parser-path сохранены. После исправления focused test **1 pass, 0.459 s**. Full artifact suite: **21 tests, 20 pass / 1 environmental error, 1.027 s**; Windows запрещает создание symlink (`WinError 1314`). Тест не отключался, symlink security policy не ослаблялась. Обязательная полная Linux-проверка позднее прошла на d2c48bf; точный результат приведён в начале документа.

Poisoning остаётся fail: 10 violating / 0 inconclusive scenarios. Evasion recall drop `0.07183673469387755` превышает `0.05`; paired candidate drops `0.052244897959183675`, `0.06224066390041494`, `0.06143344709897611` также превышают порог. Это отдельные ML blockers, не следствие исправленного mock target.

## CI observations и продолжение

На **2026-10-19 16:25 UTC** API показывал все 10 workflows attempt 1 queued, включая Storage job. Позже получены завершённые logs с worker tests в 16:13 UTC и candidate report в 16:21 UTC. Следовательно, ранний queued snapshot не доказывает фактическое отсутствие выполнения; наблюдается рассогласование статусов и времени job logs. Rerun/cancel не выполнялись.

[Официальный инцидент GitHub 8tzbpcnl75jp](https://www.githubstatus.com/incidents/8tzbpcnl75jp) опубликован 2026-10-19T15:49:25Z; Actions имеет degraded_performance, статус investigating. Provider сообщает задержки обработки workflows. Это согласуется с наблюдаемой очередью, но не является доказанным root cause конкретного job. Не менять код/timeout и не ослаблять gates из-за одного наблюдения очереди.

На **2026-10-19 16:38:56 UTC** все 10 workflows terminal, attempt 1: **2 success / 8 failure**. Это зафиксированное состояние af7253e до correction, не новый all-pass.

| Workflow | Run | Terminal conclusion |
| --- | --- | --- |
| Storage | [39283688533](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688533) | success; kernel, serving, M03/M07 |
| Kubernetes | [39283688663](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688663) | failure; M20 pass, M21_contracts_failed |
| Developer | [39283688644](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688644) | failure; stale scanner patch target |
| Tracking | [39283688770](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688770) | failure; acceptance-dispatch-M21, result inconclusive |
| Intake | [39283688551](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688551) | failure; 65/66 contract cases |
| Documentation | [39283688430](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688430) | success |
| Image audit | [39283688442](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688442) | failure; candidate qualification M21, package scan skipped |
| Poisoning | [39283688619](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688619) | failure; 10 violating scenarios |
| Evasion | [39283688594](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688594) | failure; recall drop > 0.05 |
| Paired training | [39283688673](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688673) | failure; candidate recall drops > 0.05 |

Истечение локального observer timeout не означает остановку CI. Полный sanitized candidate report и kernel receipt сохранены, но component pass не принимает всю revision. Исправление test target опубликовано отдельным d2c48bf после terminal matrix и проверено новой CI matrix в начале документа; исторический 621d355 pass не переносился на af7253e.
