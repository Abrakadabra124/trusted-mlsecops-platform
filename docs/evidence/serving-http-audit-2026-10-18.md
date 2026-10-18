# T16: HTTP audit lifecycle, local evidence

Дата: 2026-10-18. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Scope: [ADR 0040](../decisions/0040-serving-http-audit.md), [RB-59/PB-33](../operations/serving-http-audit-troubleshooting.md). Status: local component pass; native CI нового increment ещё не подтверждён. Base: `4853e35479e7bd95eac362e70cd0542c790bef9c`, поверх опубликованного admission code `01ec902`.

## Реализовано

- Fail-closed audit до body/executor, четыре reserved events и собственный durable intent до 200.
- Pure ASGI start/completed/aborted transitions, исходный и текущий deadline после ack, private immutable context без public JSON extension.
- Владение global/client admission до завершения HTTP И executor, включая failed audit admission и отмену отправки 503.
- Required `audit_directory`, deferred owned retained lifespan, независимое ownership injected journal. Native fixture использует Linux retention, Windows fixture явно legacy single-file.
- Candidate harness добавляет две проверки bounded audit deltas 8/8 для actual HTTP ready/predict pair. Ожидаемый native total 74 вместо 72 пока является целью проверки, не результатом CI.

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

Native CI будет добавлен только после получения результата. Локальные single-file/controlled результаты не принимают Linux retention или M13.

## Failure-first и review

До implementation новые HTTP tests дали четыре missing API errors и неожиданный 200 без journal. Отдельные negative cases воспроизвели раннее освобождение global slot, отсутствие owned lifecycle и invalid ASGI transitions. Исправления не меняют public response contract или trust thresholds.

Implementation review cycle 1 нашёл ранний release при missing journal/reserve/first emit failure. Новый regression сначала дал **12 failures**, затем прошёл в 48-method suite: обе protected routes, три отказа, completion/cancellation. Scope получает Delivery до его `start()`, отказ audit не теряет HTTP ownership.

Cycle 2 нашёл потерю `audit_status` на `functools.partial` внутри actual `check_http`, не в прямом `site` fixture. Regression на реальном HTTP path воспроизвёл AttributeError до container probe; wrapper теперь явно сохраняет тот же bounded status source. После fix 9 targeted tests pass.

Cycle 3 выявил принятие `audit_directory: null` в configured path: приложение запускалось без обязательного owned journal. Negative test сначала дал 1 failure в 27-method suite. Добавлена валидация absolute string до создания Engine/Journal; null, bool, number, empty string, array, object и relative path отклоняются. Повторные 48 HTTP methods подтвердили fix. Три implementation review cycles завершены; четвёртый не запускался. Финальная маленькая config correction проверена тестами автором, не новым fresh-context review. Внешняя модель не использована по выбору пользователя.

Дополнительный Windows access coverage прогон первоначально дал 2 cleanup errors в 32 methods: `audit_shutdown_pending` после default 1 s close, затем WinError 32 при удалении ещё открытого файла. Только base HTTP fixture использует разрешённый `close(timeout=5)`; production default/lifespan остаётся 1 s. Controlled 1.2 s delayed-write probe подтвердил clean close, отсутствие живого writer и удаление собственного temp directory. Причина Windows fsync задержек не объявлена устранённой. Первый diagnostic probe имел ошибку проверки несуществующего Journal.path; исправленный probe проверяет реально созданный TemporaryDirectory, а не выдуманный attribute.

Windows concurrent real-fsync headroom оказался невоспроизводимым: writer был внутри `os.fsync`, возникли исходные deadline denials. Это сохраняется как **inconclusive**, не исправленная проблема. Controlled real-HTTP headroom отделён от Linux retained real-fsync теста; production limit_concurrency=16 и global=8 сохранены. Подробная причина/симптомы и безопасная диагностика в RB-59.

## Граница результата

Нет утверждения о client receipt, атомарности network/filesystem, all-output privacy, arbitrary network DoS resilience или production rollout. Native report должен сохранять `release_ready=false`; qualification permit не является approval. Полные M13/R1, image/ML failed gates и прежний M07 reliability debt остаются открытыми. Private journals, credentials, payloads и raw logs не публикуются.
