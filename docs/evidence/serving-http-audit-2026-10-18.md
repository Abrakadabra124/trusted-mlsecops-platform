# T16: HTTP audit lifecycle, local evidence

Работа: 2026-10-18/19, Europe/Moscow; CI timestamps ниже UTC. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Scope: [ADR 0040](../decisions/0040-serving-http-audit.md), [RB-59/PB-33](../operations/serving-http-audit-troubleshooting.md). Status: local component и native Storage qualification pass. Base: `4853e35479e7bd95eac362e70cd0542c790bef9c`; новый code commit `281e902a888348d1f39e6bad56026cde1e14897d`. Общая R1 acceptance не завершена.

## Реализовано

- Fail-closed audit до body/executor, четыре reserved events и собственный durable intent до 200.
- Pure ASGI start/completed/aborted transitions, исходный и текущий deadline после ack, private immutable context без public JSON extension.
- Владение global/client admission до завершения HTTP И executor, включая failed audit admission и отмену отправки 503.
- Required `audit_directory`, deferred owned retained lifespan, независимое ownership injected journal. Native fixture использует Linux retention, Windows fixture явно legacy single-file.
- Candidate harness добавляет две проверки bounded audit deltas 8/8 для actual HTTP ready/predict pair. Native total **74** вместо 72 подтверждён на code `281e902`, без release approval.

## Проверено локально

Windows, `uv run --locked`, текущий working tree, не clean native checkout:

| Suite | Результат |
|---|---|
| HTTP + HTTP audit, latest coverage run после null config fix | 48 methods, 46 executed / 2 Linux-only skips, 0 failures/errors, 10.990 s |
| `mlsecops.serving_http_audit` | 101 statements / 34 branch exits, 0 missing, 100% |
| Audit core/retention/admission/event regression | 77 methods, 53 executed / 24 platform skips, 0 failures/errors, 3.228 s |
| Candidate harness before added diagnostic negative test | 7 methods, 0 skips, 4.163 s; controlled pair deltas 8/8 |
| Adjacent serving/session/runtime/core/HTTP/native/access/context/candidate/outage/pause | 143 methods, 0 skips, 0 failures/errors, 31.671 s; до финального wrapper fix |
| Candidate harness + actual check_http wrapper regression после fix | 9 methods, 0 skips, 0 failures/errors, 6.743 s |
| Existing serving coverage gate | 80 methods, 0 skips, 25.961 s, aggregate 93% >=85% |
| Access gate после test cleanup correction | 32 methods, 0 skips, 3.311 s, access module 100% |
| Controlled delayed-write cleanup probe | 1 method, 0 errors/failures; injected 1.2 s, elapsed 1.312 s; closed=true, writer_alive=false, owned temporary directory removed |

Локальные single-file/controlled результаты сами по себе не принимают Linux retention или M13; отдельная Linux qualification приведена ниже.

## Failure-first и review

До implementation новые HTTP tests дали четыре missing API errors и неожиданный 200 без journal. Отдельные negative cases воспроизвели раннее освобождение global slot, отсутствие owned lifecycle и invalid ASGI transitions. Исправления не меняют public response contract или trust thresholds.

Implementation review cycle 1 нашёл ранний release при missing journal/reserve/first emit failure. Новый regression сначала дал **12 failures**, затем прошёл в 48-method suite: обе protected routes, три отказа, completion/cancellation. Scope получает Delivery до его `start()`, отказ audit не теряет HTTP ownership.

Cycle 2 нашёл потерю `audit_status` на `functools.partial` внутри actual `check_http`, не в прямом `site` fixture. Regression на реальном HTTP path воспроизвёл AttributeError до container probe; wrapper теперь явно сохраняет тот же bounded status source. После fix 9 targeted tests pass.

Cycle 3 выявил принятие `audit_directory: null` в configured path: приложение запускалось без обязательного owned journal. Negative test сначала дал 1 failure в 27-method suite. Добавлена валидация absolute string до создания Engine/Journal; null, bool, number, empty string, array, object и relative path отклоняются. Повторные 48 HTTP methods подтвердили fix. Три implementation review cycles завершены; четвёртый не запускался. Финальная маленькая config correction проверена тестами автором, не новым fresh-context review. Внешняя модель не использована по выбору пользователя.

Дополнительный Windows access coverage прогон первоначально дал 2 cleanup errors в 32 methods: `audit_shutdown_pending` после default 1 s close, затем WinError 32 при удалении ещё открытого файла. Только base HTTP fixture использует разрешённый `close(timeout=5)`; production default/lifespan остаётся 1 s. Controlled 1.2 s delayed-write probe подтвердил clean close, отсутствие живого writer и удаление собственного temp directory. Причина Windows fsync задержек не объявлена устранённой. Первый diagnostic probe имел ошибку проверки несуществующего Journal.path; исправленный probe проверяет реально созданный TemporaryDirectory, а не выдуманный attribute.

Windows concurrent real-fsync headroom оказался невоспроизводимым: writer был внутри `os.fsync`, возникли исходные deadline denials. Это сохраняется как **inconclusive**, не исправленная проблема. Controlled real-HTTP headroom отделён от Linux retained real-fsync теста; production limit_concurrency=16 и global=8 сохранены. Подробная причина/симптомы и безопасная диагностика в RB-59.

## Граница результата

Нет утверждения о client receipt, атомарности network/filesystem, all-output privacy, arbitrary network DoS resilience или production rollout. Native report должен сохранять `release_ready=false`; qualification permit не является approval. Полные M13/R1, image/ML failed gates и прежний M07 reliability debt остаются открытыми. Private journals, credentials, payloads и raw logs не публикуются.

## Native Storage qualification 281e902

[Run 39165939564](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939564), job **117788771210**, attempt **1**, conclusion **success**. [Полный sanitized candidate report](serving-http-audit-281e902-native.md) сохраняет 74 уникальных cases и finished_at **2026-10-18T21:09:39.405618+00:00**.

| Проверка | Подтверждённый результат |
|---|---|
| HTTP + audit suites | **48 methods / 0 skips**, 4.594 s; оба Linux-only сценария выполнены |
| Новый HTTP audit middleware | 101 statements, 34 branch exits, 0 missing, **100%** |
| Journal suites | 77 methods / 0 skips, 3.755 s |
| Отдельный branch gate | Core 94/98 = 95.9184%; retention 102/102 = 100%; threshold 95% не изменён |
| Existing gates | Serving 80 methods / 0 skips, 15.505 s; client access 32 / 0 skips, 2.031 s, access 100% |
| Actual candidate | **74 cases pass**, clean checkout, `release_ready=false` |
| Actual HTTP audit pair | accepted_delta=8, durable_delta=8, reservations drained; finite summary, не private journal export |
| Golden / stopped worker | max error=0; stopped-worker denial 2.016759058 s |
| Quotas | 422/429/422/429, refill 200/200, admissions 2/2/4; window 0.005972538 s |
| Trust outage | 44 observations, client-completed first 503 **59.752797617 s**; assessment пересчитан из сохранённого report и совпал |
| Paused established SQL | 503 за **10.003294379 s**; ACTIVE timestamp до completion, query ещё pending, generation fenced |
| Signed expiry | 503 за **5.683820823 s**, до signed expiry; renewal и fresh readback version 3 |
| Earlier scoped gates | M03 431 cases pass, M07 97 cases pass; прежний connection failure не объявлен исправленным |

Source fingerprint: `1f10698960fc441afecf5efd72ccd2d81505f66ff9aeb3fbdaa7fdfc81f6c234`. Runtime image: `sha256:024a93eefb810821d54b33a1ed264736baee1daa315179e51f34fa1dd34bac4c`. SHA-256 canonical JSON сохранённого candidate report: **`7272fbda4c5790230d549e804d8f79fc709aeefbe724b8ae346200e10adaff23`**.

Проверка saved report отдельно подтвердила source revision, dirty=false, unique cases, audit deltas, ACTIVE-before-denial/pending SQL и signed expiry/renewal. Это подтверждение конечного состояния, не только zero exit code команды. Windows concurrent real-fsync остаётся отдельным inconclusive result, не исправленным Linux pass.

## Матрица CI code commit

Все 10 runs относятся к `281e902`, attempt 1 и завершены: **6 success / 4 failure**; rerun/cancel не выполнялся. Kubernetes job **117788770963**: M20 **723** cases pass, finished **2026-10-18T21:15:19.016715+00:00**; M21 **122** cases pass, finished **2026-10-18T21:17:39.369384+00:00**. Source revision обоих совпадает с code commit, M21 dirty=false. Итог подтверждён 2026-10-19 по Europe/Moscow.

| Workflow | Run | Conclusion / наблюдение |
|---|---|---|
| Documentation | [39165939579](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939579) | success |
| Intake | [39165939504](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939504) | success |
| Developer runtime | [39165939562](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939562) | success; 3 fresh trainings, max probability difference 0, parity 2.086162567138672e-7 |
| Storage | [39165939564](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939564) | success; native audit и candidate checks выше |
| Tracking | [39165939428](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939428) | success; M06 18 cases |
| Kubernetes | [39165939473](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939473) | success; M20 723 / M21 122 cases pass |
| Image audit | [39165939451](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939451) | failure; все 4 scan выполнены, SBOM validated, scanner exit 2 |
| Poisoning | [39165939681](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939681) | failure; 10 violating / 0 inconclusive scenarios; evidence integrity pass |
| Evasion | [39165939545](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939545) | failure; recall drop 0.07183673469387755 > 0.05 |
| Paired training | [39165939484](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939484) | failure; candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05 |

Image Critical/High: worker **0/56**, storage **9/132**, worker-candidate **0/55**, storage-candidate **1/85**. HTTP audit increment не исправляет эти findings и не меняет ML/security thresholds. Успешная инфраструктурная проверка не разрешает promotion failed candidate.
