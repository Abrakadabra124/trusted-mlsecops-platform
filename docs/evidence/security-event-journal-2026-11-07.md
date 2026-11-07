# T29/M23: постоянный журнал и восстановление

Дата: 2026-11-07. Статус: **компонент проверен; полная M23 не принята**.
Source: `d17434b2fbb0fe393fc2027721c99f674af8c1c4`.
Реализация появилась в `b6d0365`; следующий commit добавил проверки I/O faults
и запись в ранбук, не изменяя runtime code и порог coverage.

## Что работает

`security_event_ledger` проверяет подписи, роли, историю ingest и signed receipts.
`security_event_store` сохраняет журнал в private Linux directory: lock,
проверка identity/config, запись временного файла, fsync, atomic rename,
directory fsync и readback. Runtime не инициализирует отсутствующий state.

Первый ingest оставляет событие pending. Подтверждение доставки записывается
отдельно и требует signed receipt для исходных event/route/ingest/late.
Повтор возвращает исходную запись, в том числе после восстановления и после
истечения обычного пятиминутного event age, пока registry ещё действителен.
Это проверка уже принятого события, а не разрешение нового replay.

Приём не по порядку сохраняет late marker. Конфликт sequence, неверная подпись,
повреждение журнала, неправильные права/identity и переполнение приводят к отказу.
Лимиты: 1024 события без eviction, snapshot 16 MiB, reorder window 64.
[ADR0058](../decisions/0058-security-event-contract.md) описывает trade-offs;
[ранбук](../operations/security-events.md#журнал-диагностика-и-восстановление)
содержит диагностику, ограничения recovery и команды.

## Проверки и воспроизводимость

[Linux CI42347317046](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42347317046),
job128327762659, terminal success в `2026-11-07T06:30:44Z`:

| Группа | Tests | Skips | Время |
| --- | --- | --- | --- |
| Подписанные event/config contracts | 21 | 0 | 0.223 s |
| Существующие key/monitoring/release-policy regressions | 25 | 0 | 0.076 s |
| Ledger и Linux filesystem/restart | 24 | 0 | 0.908 s |
| Всего Linux | 70 | 0 | Три отдельные suites |

Использованы реальные временные Ed25519 keys и Linux files. Fault injection
моделирует ошибки write/replace/readback. Отдельные дочерние процессы выполняют
реальный `Store.ingest` и завершаются через `os._exit(23)` непосредственно до либо
после rename. Это abrupt process termination, а не реальный power-loss test.
Parent ожидает exit и проверяет восстановленный журнал и единственность event ID.

Подтверждены:

- восстановление pending и acknowledged record, exact retry без дополнительной записи;
- отказ conflicting sequence/receipt, forged retry, старого нового события и backward clock;
- сохранение всех 1024 записей при отказе 1025-й, без вытеснения deduplication history;
- out-of-order 1,3,2 с late только у 2 и сохранением признака после восстановления;
- отсутствие auto-init при пропавших identity/state, неправильном pin и лишних файлах;
- отказ symlink, hardlink, group/world-readable file, unsafe directory и concurrent lock;
- неизменность старого committed state после partial/zero write и отказа до rename;
- exact retry после неизвестного исхода после rename/readback failure;
- обнаружение роста/изменения metadata во время чтения и запрет oversized snapshot;
- очистка `.pending` только после успешной проверки committed state;
- чтение и проверка сохранённой записи отдельным процессом.

В чистом Windows checkout того же source создана новая `.venv` из locked
dependencies, Python 3.12.15. Выполнены 70 tests за 3.123 s, **17 skips**:
14 новых Linux filesystem cases и 3 существующих POSIX cases.
Import/executable paths относятся к этому checkout; git status после тестов пуст.
Windows результат не доказывает native filesystem durability.

## Покрытие, привязанное к source

| Модуль | Statements | Branches |
| --- | --- | --- |
| `security_events` | 105/105 | 42/42 |
| `security_event_config` | 101/101 | 32/32 |
| `security_event_ledger` | 106/107 | 31/32 |
| `security_event_store` | 139/140 | 36/36 |

Первые два модуля сохраняют 100%. Для каждого нового модуля отдельно соблюдён
порог >=95% statements и >=95% branches. Пропущенные строки не скрыты исключениями.
Source из обоих coverage reports сверён с `d17434b`.
Ruff/format и documentation checks прошли; чистый Linux checkout содержит 849 files,
307 Markdown documents и 2301 local links.

Первый [CI42347131488](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42347131488)
на `b6d0365` завершился failure: 21+25+19 tests прошли без skips, но store branch
coverage составлял 30/36 и не достиг 95%. Добавлены пять I/O fault tests,
порог не менялся. Этот failed run сохранён в истории, не объявлен pass.

## Границы результата

В workflow не создавались SQL, Docker или Kubernetes. Локальные запрещённые
среды не запускались; дочерние test processes завершены через bounded subprocess
calls, временные каталоги удалены cleanup. Private raw logs и ключи не опубликованы.

Журнал не доставляет события внешнему получателю и не выдаёт release permission.
Heartbeat/sequence-gap scheduler, durable heartbeat history, actual source adapters,
аутентифицированный HTTP, измерение deadlines 60/120 s и fail-closed promotion при
sink outage остаются обязательными следующими этапами. Также пока нет безопасного
registry rollover, backup/restore или защиты от удаления/rollback volume его
администратором. Fsync предполагает поддерживающую его persistent filesystem.

Общий M23 и M18/R1 не закрыты. Успешные прежние M13/M15 runs относятся к другому
source/candidate и не заменяют финальную объединённую приёмку.
