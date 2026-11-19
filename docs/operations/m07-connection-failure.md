# M07: connection failure is not budget exhaustion

Неделя 13, T21. Scope: безопасная диагностика конкретного native отказа и
исправление отдельно подтверждённого незакрытого stdout pipe. Причина native
connection failure пока не установлена; M07 не объявлен исправленным.
Parent владеет последующей hosted qualification. Workflow не меняется.

## Подтверждённые факты

Приватный журнал run `43627872617`, job `132547717602`, source `983db0c`
прочитан локально без публикации raw contents. Он подтверждает 32 attempts,
точные accepted slots 2-32, `complete: true`, `invalid_receipts: 0` и единственный
код `storage_connection_rejected`. Slot 1 ранее использован первоначальной
оценкой. Это не ожидаемый отказ `holdout_budget_exhausted`; отказ M07 корректен.
SQLSTATE, driver class и исходная транспортная причина в сохранённом журнале
отсутствуют. Повторение симптома не доказывает timeout, TLS, capacity или race.

В [storage.connect](../../mlsecops/storage.py) любой `psycopg.Error` от открытия
соединения преобразовывался в одинаковый `Rejected`. Затем
[attempt](../../mlsecops/holdout_budget_qualification.py) возвращал только строку
ошибки через process result. Поэтому сведения драйвера не доходили до parent.
Ошибка открытия происходит до INSERT данного claim; это не свидетельство
исчерпания бюджета и не причина повторять запрос или возвращать слот.

Три ResourceWarning относятся к вызовам executor в `pipeline.py:67`,
`artifact_intake.py:257`, `pipeline.py:165` исходного source. У
[sandbox.run_worker](../../mlsecops/sandbox.py) после чтения и ожидания процесса
оставался открытым `process.stdout`. Реальный локальный Python subprocess
воспроизвёл открытый BufferedReader после успешного возврата executor до patch.
Причинная связь этой утечки с отказом PostgreSQL не установлена.

## Изменение и сохранённый acceptance

[storage_connection_diagnostics](../../mlsecops/storage_connection_diagnostics.py)
сохраняет только ограниченные поля. Исключение остаётся подклассом `Rejected`
с точной строкой `storage_connection_rejected`, поэтому существующие consumers
и CLI сохраняют прежний fail-closed контракт. Raw driver message, cause,
connection parameters, host/port, paths и credentials в diagnostic не входят.

[reserve](../../mlsecops/holdout_budget.py) только отмечает номер неудачного slot.
Алгоритм INSERT/ON CONFLICT, commit, cap 32 и расход без refund остаются прежними.
`attempt` переносит безопасный объект через process result;
[check_claims](../../mlsecops/holdout_diagnostics.py) валидирует закрытую схему.
Malformed/extra fields не выводятся. Максимум 32 диагностических объекта.

При неудаче parent получает дополнительный массив
`diagnostics.holdout_concurrency.connection_failures`:

| Поле | Значение и предел интерпретации |
| --- | --- |
| `stage` | Всегда `connect`, не statement или commit |
| `driver` | Allowlisted psycopg class category; `connection-timeout` сохраняет точный тип ConnectionTimeout |
| `sqlstate` | Только разрешённые коды, иначе `unavailable`/`unclassified` |
| `message_hint` | Constant category по известному marker в первых 8192 символах сообщения; это подсказка, не доказательство root cause |
| `elapsed_ms` | Время открытия после проверки client files, ограничено 0-60000; 60000 означает не менее 60 секунд |
| `slot` | Slot 1-32, на открытии соединения для которого произошёл отказ |
| `prior_conflicts` | Только подтверждённые конфликты этой попытки, строго `slot - 1` |

**Исходный acceptance не изменён:** нужны ровно 31 exact receipt для slots 2-32
и ровно `{"rejected":"holdout_budget_exhausted"}` от оставшейся попытки.
Даже при полном ledger connection failure оставляет
`holdout_qualification_failed:concurrent-over-budget-denied`, M07 fail/exit 1.
Диагностика не может превратить отказ в success или служить reservation.
Retries, timeout/threshold increases, новый SQL algorithm и rollback ledger
в этом patch отсутствуют. Успешный diagnostic report сохраняет прежнюю схему.

Executor теперь закрывает stdout и stdin в owning reader/writer thread через
контекстные менеджеры. Warning filters не меняются. Проверяются success,
nonzero worker exit, invalid JSON и deadline; незакрытый pipe не маскируется.

## Действия parent и граница восстановления

1. Интегрировать source и собрать обычный pinned runtime; запускать native
   campaign только в уже разрешённом owned hosted окружении.
2. При повторении читать safe diagnostic, сохранив оригинальный failed report.
   `connection-timeout` и длительность, SQLSTATE `53300`, TLS/refusal hints
   помогают выбрать следующую проверку, но сами по себе не доказывают серверную
   причину. При `unavailable/unclassified` потребуется scoped private server
   evidence по времени события. Не печатать raw connection errors или SQL logs.
3. Не считать заполненный ledger заменой правильного отказа. Не retry/refund,
   не ослаблять TLS или таймауты и не объявлять старый source прошедшим M07.
4. После установленной причины проверить четырёхпроцессную native campaign,
   точные receipts, правильный отказ, запреты scorer/publisher и сохранность
   ledger после restart. До этого connection blocker остаётся открытым.

Rollback этого patch убирает дополнительную диагностику и исправление pipe;
исходный budget contract не требует миграции. Автоматической очистки ledger,
контейнеров или чужих state каталогов здесь нет.

## Локальная проверка и ограничения

[Diagnostic tests](../../scripts/storage_connection_diagnostics_qualification.py)
исполняют настоящие `reserve`, `claim`, `connect`, `attempt`, `check_claims` над
моделью атомарного INSERT с четырьмя concurrent callers и подменённой границей
psycopg. Проверяются правильное exhaustion и тот же failure symptom, no retry,
uncertain commit, закрытая схема, redaction, bounded output, serialization и
передача diagnostic в M07 fail report. Это воспроизведение контракта, не
доказательство причины реального сетевого отказа PostgreSQL.

[Pipe tests](../../scripts/sandbox_pipe_qualification.py) запускают только
локальные Python subprocesses и реальные OS pipes, подменяя Docker boundary.
Проверяют `closed` до возврата и отсутствие ResourceWarning при сборке мусора.

```bash
python -B -W error -m unittest scripts.storage_connection_diagnostics_qualification scripts.sandbox_pipe_qualification scripts.holdout_budget_qualification scripts.evaluation_gate_qualification
python -B scripts/check_docs.py
```

Локальные Docker/WSL/Kubernetes/SQL, внешние модели, hosted dispatch и публикация
private logs не выполнялись. Настоящая конкуренция PostgreSQL и native pipeline
cleanup после patch остаются за parent. M18/R1 и независимый M22 не закрываются.

Проверка на pinned Python 3.12.15: 97 tests pass, 0 skips. Это 13 новых tests
и 84 смежных проверки budget/evaluation, worker privacy, trust authority/targets
и promotion recovery. Coverage `storage_connection_diagnostics`,
`holdout_diagnostics`, `holdout_budget`: 114/114 statements, 32/32 branches.
Это не coverage всего storage/sandbox runtime. Ruff check/format и check_docs pass.

## Review fix round 1: отказ Docker cleanup

На `6f1577e` вызов `docker rm` предшествовал local process kill/wait и join
reader/writer threads. Его `TimeoutExpired`/`OSError` пропускал остаток cleanup
и заменял исходный `worker_deadline`. Red-test с настоящим Python child,
который не читает stdin, 1 MiB input и deadline 1 s подтвердил живой процесс
после выхода executor. Fixture всегда завершает принадлежащий ей child,
дожидается потоков и закрывает pipes, включая отрицательный baseline.

Cleanup Docker и local CLI теперь независимы: отказ `rm` не пропускает
kill/wait/join; проверяется конечное состояние child, двух потоков и pipes.
Семантика best-effort `rm` с `check=False` сохранена: исходный `docker run --rm`
может уже удалить контейнер до этого вызова. Повторов нет.
Первичное исключение и его cause сохраняются; вторичная ошибка добавляется
через `add_note` как `worker_cleanup_failed:<constant categories>` и видна
в обычном traceback/`__notes__`. Consumer, выводящий только `str(error)`, должен
отдельно читать notes для диагностики cleanup. Raw stderr/commands/paths не
добавляются. Если worker завершился успешно, cleanup failure запрещает success
и поднимает `Rejected` с тем же безопасным diagnostic. Warning filters не меняются.

Проверки охватывают обычный `rm`, timeout, OSError, прежний best-effort exit status, блокировку
1 MiB stdin, сохранение deadline, явный отказ cleanup после успешного worker,
мёртвый child, завершённые потоки и закрытые pipes до fixture cleanup.
Остановка local Docker CLI при отказе `rm` не доказывает удаление контейнера:
эта native ownership-проверка остаётся parent. SQL/M07 diagnostic helpers,
budget cap, TLS, retries и workflows этим fix round не меняются.

Финальная проверка fix round 1 на pinned Python 3.12.15: 102 tests pass,
0 skips за 26.026 s с `-B -W error`; из них 7 pipe tests. Ruff check/format,
check_docs и diff check прошли. Это локальная проверка, не native M07 pass.

### Дополнительная qualification cleanup branches

Отдельный test-only follow-up к `9c6343d` добавляет отказ kill, wait timeout и
wait OSError, проверку `local_cleanup_incomplete`, image/source guards и output
limits. При отказе kill настоящий child и pipe threads остаются живы до fixture
cleanup: проверяется исходный `worker_deadline` и точная secondary note, затем
fixture обходит внедрённый отказ и завершает child, join и закрытие обоих pipes.
Wait-failure cases внедряют ошибку API после реального завершения child; проверяют
notes при первичном отказе и явный `Rejected` после успешного worker. Это controlled
process contract, не доказательство настоящего OS kill/wait failure.

```bash
python -B -Werror -m coverage run --branch --data-file=.runtime/pipe-review.coverage --source=mlsecops.sandbox -m unittest scripts.sandbox_pipe_qualification scripts.worker_privacy_qualification
python -B -m coverage report --data-file=.runtime/pipe-review.coverage -m
```

Результат на pinned Python 3.12.15: 24 tests pass, 0 skips, 9.351 s.
Sandbox: 92/93 statements, **27/28 branches (96.43%)**, 98% combined.
Все новые cleanup branches покрыты; единственная оставшаяся непокрытая ветвь
строки 109 относится к прежнему `worker_empty_output`. Production code в этом
follow-up не менялся; native qualification остаётся за parent.
