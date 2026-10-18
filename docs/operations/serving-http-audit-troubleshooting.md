# RB-59 / PB-33: HTTP audit admission, send lifecycle и cleanup

Scope: [ADR 0040](../decisions/0040-serving-http-audit.md), disposable reference serving. Ответственный: владелец serving/audit controller и оператор стенда. Это инструкция по диагностике реализованного компонента, не отчёт о production-инциденте. [Evidence](../evidence/serving-http-audit-2026-10-18.md) отделяет выполненные проверки от pending native acceptance.

## RB-59: сначала read-only диагностика

Prerequisites: известны checkout revision, owned private config/journal directory и pinned Python environment. Не запускать локальные Docker/WSL, не открывать второй writer и не печатать private config/JSONL. Нужны только конечные коды и bounded counters из уже владеющего журналом процесса.

```powershell
git rev-parse HEAD
git status --short
uv run --locked python -m unittest scripts.serving_http_qualification scripts.serving_http_audit_qualification
uv run --locked python -m unittest scripts.candidate_serving_native_qualification
```

Команды tests создают только собственные temporary journals и loopback servers; не подключаются к существующему SQL. Не передавать им реальный journal path. Native-only tests на Windows пропускаются явно, не дают Linux pass.

| Симптом | Диагностика и безопасное действие |
|---|---|
| Config rejected или сервер не стартовал | Проверить наличие absolute `audit_directory` и owner/permissions по RB-56. Managed writer открывается на lifespan, не при чтении config. Не удалять guard для «починки» старта. |
| Live 200, protected 503 до body | Проверить budget/trust/worker по RB-53, затем `healthy`, `failure`, `pending`, `reservations`, `held_slots`, `unconfirmed` у имеющегося Journal. Missing audit и failed reserve также дают 503; generic response специально не раскрывает причину клиенту. |
| Intended 200, actual 503 | Сопоставить private server request ID внутри разрешённой границы. Durability ожидание могло пересечь исходный deadline или новое более раннее expiry. Не продлевать 10 s/lease и не подменять actual context успешным. |
| Start send не вернулся | Не утверждать, что 200 отправлен. При exception/cancel ожидается aborted с null status; quotas удерживаются до cleanup, а pending executor может удерживать их дольше. |
| Нет completed после actual send | Sink мог отказать уже после передачи сообщения серверу. Это gap/unknown terminal outcome, а не доказанный transport abort. Запретить новые protected admissions, сохранить spool; не дописывать выдуманный completed. |
| 429/занятые slots после отмены | Проверить pending executor и незавершённую отправку 503. Удержание обоих ресурсов намеренно; не reset quotas и не cancel синхронный SQL как будто он завершился. |
| Healthy writer долго не становится durable | Сохранить только ограниченные counters и место ожидания, не payload. Healthy значит отсутствие обнаруженного failure, не своевременный fsync. Deadlines должны давать 503, а не молча ждать бесконечно. |

Recovery storage следует [RB-56/PB-30](audit-retention-troubleshooting.md), admission - [RB-58/PB-32](audit-admission-troubleshooting.md). Trust recovery требует verified reload по [RB-53](serving-deadline-troubleshooting.md). Не ослаблять pinned identity, permissions, caps или проверку digest ради восстановления.

## Проблемы, встретившиеся при реализации

1. **Преждевременный release после audit denial.** Endpoint finally освобождал client/global slots до фактического send 503, если Delivery constructor не завершился. Reviewer воспроизвёл множество pending ответов при свободных quota counters. Регрессионный test дал 12 failures: ready/predict, missing/reserve/first-emit fault, completion/cancellation. Теперь scope ownership передаётся ДО потенциально неуспешного `start()`. Во время blocked send остаются 7 свободных global slots и один client in-flight; повтор того же клиента получает 429, после завершения ресурсы освобождены.
2. **Неверный критерий завершения HTTP.** Worker finish не равен response finish, а return response не равен send. Negative tests воспроизвели ранний release, out-of-order body и duplicate start; middleware теперь проверяет transitions, а release ждёт HTTP и executor независимо.
3. **Windows fsync и concurrent headroom qualification.** В исходной реальной single-file проверке writer наблюдался внутри `os.fsync`, до инъекции целевой остановки intent; accepted=16, durable=3/4. Один прогон получил восемь 503 после примерно 10.321 s. Причина задержки ОС/устройства не установлена. Successful isolated rerun не объявлен исправлением. Проверки разделены: controlled writer для HTTP concurrency и отдельный Linux retained real-fsync test. Обычные локальные HTTP tests по-прежнему используют настоящий single-file fsync. Конкурентная Windows real-fsync qualification остаётся inconclusive.

Test-only ожидание startup/injection не является production deadline. Удалён произвольный новый assertion 0.5 s для headroom health; теперь проверяется ответ health при всё ещё остановленном writer. Production response/trust limits и M14 не ослаблены и не переопределены.

4. **Native wrapper потерял diagnostic method.** `functools.partial` сохраняет вызов transport, но не копирует его `audit_status` attribute. Direct site test проходил, actual `check_http` path дал бы AttributeError/inconclusive до audit pair. Ошибка воспроизведена loopback regression до container probe, затем исправлена явным переносом того же status callback. Это не новый public API и не публикация private events.

5. **Null audit config.** Наличие ключа не доказывало валидный path: JSON null включал программный no-journal режим. Теперь configured path требует absolute string до создания Engine/Journal. Regression сначала дал failure, после исправления invalid types/relative path отклоняются без startup side effects.
6. **Teardown открытого Windows fixture.** Default close 1 s не успел завершить writer, затем удаление tempfile дало WinError 32. В base HTTP test fixture задан поддерживаемый timeout 5 s; production default не изменён. Controlled delayed-write 1.2 s проверил не только возврат close, но closed status, writer termination и исчезновение собственного temp directory. Это исправление test cleanup budget, не доказательство устранения filesystem latency или production bounded shutdown.

## PB-33: воспроизводимая последовательность

1. Зафиксировать revision/dirty state. Прочитать этот scope и RB-56; никаких mutating commands против текущей инфраструктуры.
2. Выполнить две HTTP suites и candidate harness commands выше. Expected: нет failures/errors; записать executed/skipped отдельно. Проверить regression stalled send, cancellation и denied audit, а не только HTTP status после завершения.
3. Выполнить coverage ниже. Expected: новый middleware 100%, прежние gates остаются независимыми. Docs checker проверяет структуру/ссылки, не runtime correctness.

```powershell
uv run --locked coverage run --data-file=.coverage-http-audit --source=mlsecops.serving_http_audit -m unittest scripts.serving_http_qualification scripts.serving_http_audit_qualification
uv run --locked coverage report --data-file=.coverage-http-audit --fail-under=100
uv run --locked python scripts/check_docs.py
```

4. На disposable Linux GitHub CI подтвердить retained lifespan и stalled-sink headroom без skips, actual candidate ready/predict pair с accepted_delta=8 и durable_delta=8. Finite counters не заменяют private event chain или all-output canaries. Записать commit/run/job/attempt и все terminal workflows; failed attempts не стирать повтором.
5. При реальной неисправности остановить новые protected requests, дождаться HTTP и executor cleanup, проверить `pending=reservations=held_slots=0`, durable/accepted consistency и clean close. Не делать вывод по одному successful stop command. Если ownership, writer completion или crash state неизвестны, эскалировать и сохранить единственную копию spool.
6. Изменяющее действие recovery допускается только для явно owned disposable state и по RB-56: никакого автоматического purge/reset. После восстановления новый проверенный процесс должен показать healthy audit, защищённый отказ для invalid input/trust и допустимый verified response без обхода gate. Live 200 один этого не доказывает.

Rollback: остановить ingress/producer, дождаться завершения реальной работы, сохранить journal, затем вернуть совместимый code/config. Старый код без обязательного HTTP-аудита нельзя выставлять как восстановленный сервис с теми же гарантиями; безопасный fallback - недоступные protected endpoints, не unaudited 200. Сам restart/recovery production не выполнялся этой процедурой. Критерий закрытия component defect - воспроизведение до исправления и подтверждённое конечное состояние после, не закрытие полного T16/M13.
