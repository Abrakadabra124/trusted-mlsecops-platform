# T29: HTTP-источник identity.denied

Проверенный source: `b12ae89d8c44a1ca2d4183439e366315cad6db01`.
Linux runtime fingerprint:
`5c0e3e6402ba7e728e026b72a8121ad9f3d3133361c58881bdac6eb631f77fe6`.
Реализация runtime появилась в94e6d7c; следующие73a3c9f/b12ae89 исправляют
diagnostics/ожидания harness и его тесты, не production authorization.
Компонент проверен в explicit audited serving profile. Полный M23/M18/R1 открыт.

## Настоящие HTTP, child и collector

[Native job130725596973](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43078796931/job/130725596973)
завершился success. Он использует настоящий Uvicorn HTTP listener, отдельный
Python source child, persistent outbox и настоящий security collector на
GitHub-hosted Linux. Engine намеренно controlled unready: проверяется auth/audit,
а не допуск или качество ML candidate.

В новом report38 assertions, включая повторные HTTP/receipt проверки, не38
независимых сценариев. status=pass, release_ready=false; source/fingerprint
совпали с указанными выше.

- Пять запросов с отсутствующим, неверным или принадлежащим другой роли bearer
  дали401 после подтверждения доставки. Причины credential/role не раскрывают
  токен, IP, headers, body или principal. Request ID создаёт сервер.
- При остановленном collector следующий отказ дал503 security_audit_unavailable.
  Шестое событие осталось durable pending; доступ к модели не предоставлялся.
  Liveness и аутентифицированный metrics endpoint продолжили отвечать.
- Остановка serving закрыла собственный child и port. Новый запуск с pending
  и offline collector был отклонён до активации engine. Исходный pending record
  сохранился без изменения envelope.
- После восстановления того же collector startup probe доставил исходное
  событие. Подтверждены все6 подписей/receipts, correlation с HTTP request IDs,
  service reference, bundle=null и маршрут security.identity. Повтор retry=0.
- У всех трёх server lifecycles подтверждена очистка собственных child.
  Проверены закрытие listener, отсутствие credentials/canary в outbox/private
  server log, cleanup collector/private files и неизменность checkout.
- Максимальное время HTTP-запроса в этой последовательной кампании:
  **0.096482335 s**. Это измерение малого harness, не production throughput/SLO,
  не нагрузочная M14 и не полный M23 delivery SLA.

В том же job повторились25 promotion и37 trust observer assertions с настоящими
SQL/collector операциями и проверкой owned cleanup. Они не заменяют полную
приёмку R1 на одном candidate.

## Регрессия настоящего candidate

[Run43078796872](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43078796872)
и job130725637984 завершились success на том же source/fingerprint.
Fresh owned SQL pipeline подготовил данные, обучил и оценил synthetic candidate
`c6b82cafeedcf0aaa3dab1af11264ac34c6d5e73a913c7525d9d2604422de759`.
Прошли54 unit tests,37 inventory assertions и45 promotion CLI cases.
Последние45 напечатаны дважды одним report, это не90 независимых проверок.

Actual candidate по-прежнему получает release_assurance_required. Положительный
promotion/Reader/HTTP/ONNX путь использует отдельно обозначенные controlled
acceptance reports. Это регрессия прежнего профиля, не fresh M13/M14 с включённым
identity source. Проверены owned cleanup и остановка source SQL через readback
State.Running=false; удаление source SQL volume здесь не заявляется.

## Contracts и чистый checkout

[Run43078796931](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43078796931)
завершился success. Contracts job130725598036:551 Linux test executions без
пропусков (21+25+47+10+1+24+85+65+9+14+60+31+30+129). Native assertions
учитываются отдельно. Ruff/format/docs также прошли.

Локальные30 tests проверили config pin/role/finite projection, отсутствие
body/model access при отказе,401/503, параллельный liveness, busy admission,
таймауты, отмену caller, delayed spawn, concurrent close и kill/reap.
Отдельный тест действительно запускает и завершает принадлежащий ему Python
child. Другой использует настоящий Uvicorn startup refusal до открытия listener.

В30-test Linux наборе оба новых runtime модуля покрыты полностью:
security_identity_events51statements/10branches;
security_identity_http97statements/30branches. Это coverage именно этих модулей,
не всей платформы. Дополнительный30-й тест относится к native harness.

Detached checkoutb12ae89 с новой locked .venv, Python3.12.15:
`uv sync --locked --no-build --python 3.12.15 --link-mode copy`.
Фактические interpreter/import paths проверены; после проверки git status пуст.

```text
python -W error -m unittest scripts.security_identity_events_qualification scripts.security_identity_http_qualification scripts.serving_http_qualification scripts.serving_access_qualification scripts.serving_lifecycle_qualification scripts.serving_http_audit_qualification scripts.serving_metrics_qualification scripts.monitoring_http_qualification scripts.monitoring_dashboard_qualification scripts.serving_privacy_qualification
Ran 159 tests in 23.329s
OK (skipped=3)
```

Три пропуска требуют Linux. Локальные Docker/WSL/Kubernetes/SQL не запускались.
Raw logs/state/credentials остаются private, не входят в этот документ.

## История ошибки проверки

Первый[run43077798952](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43077798952)
и diagnostic[run43078298893](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43078298893)
сохраняют failure. При ожидаемом отказе startup Uvicorn0.54.0 возвращал
STARTUP_FAILURE=3, тогда как harness ожидал1. После повторного падения cleanup
маскировал исходный assertion. Finite diagnostics показали21 завершённый assertion,
два cleanup marker, startup rejection, exit3 и закрытый port.

Unit с настоящим Uvicorn сначала воспроизвёл необработанный SystemExit3.
Harness теперь преобразует только известный STARTUP_FAILURE в конечный отказ
после проверки cleanup. Остальные SystemExit не превращаются в success.
Отдельно SIGINT, повторно поднятый Uvicorn после shutdown, обрабатывается с
проверкой lifecycle status и child handles. Условия401/503, запрета startup,
проверки receipt и очистки не ослаблены. Это исправление тестового harness.

## Эксплуатационные границы

[Ранбук и плейбук](../operations/identity-security-events.md),
[ADR0063](../decisions/0063-identity-security-source.md),
[план](../../tasks/identity-events-plan.md).

Один owned child на app instance, без очереди ожидания. Busy/timeout/outage
отклоняют запрос с503, но каждый overload503 не считается доставленным event.
Child имеет ту же OS identity: это граница управления ресурсами, не изоляция
credentials. Stdout/stderr/stdin child в HTTP-пути направлены в DEVNULL.
Startup probe с пустой очередью не доказывает fresh collector health.
service_sha256 задаёт оператор; deployed descriptor/runtime не аттестуется.

Audited profile пока явный optional. Mandatory deployment, producer heartbeat,
периодический trust observer, elapsed sequence-gap campaign, потеря security
audit при здоровой ML dashboard и полный M23 ещё нужны. Fresh M13/M14 с этим
профилем также не выданы этим компонентным report. M10/M19/M22/M16/M17 и M18
на одном candidate остаются обязательными; независимый M22 reviewer здесь
не заменён self-review или моделью.
