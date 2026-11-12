# T29: восстановление после подтверждённой конкуренции за journal

Runtime source `80dea7027bf721609dff913f56b6a0f34e3f2775`.
[CI43149916553](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43149916553)
завершился success: contracts job130956403821 и native job130956403944.
Это приёмка ограниченного исправления observer, не полный M23 или R1.

## Причина и изменение

В предыдущем ad53e3e/43146211890 child завершился с подтверждённым `journal_busy`.
При следующей попытке только через30s первое committed event не уложилось в
45s qualification wait. PID конкурирующего держателя в том запуске неизвестен.
Другие исторические таймауты без такой диагностики не считаются объяснёнными.

После exit42 supervisor допускает максимум два повтора с1s backoff в том же30s
cycle. Он подтверждает завершение предыдущего child и до/после backoff проверяет
остаток времени для10s child и двух1s ожиданий terminate/kill. Неизвестная очистка
фатальна; stop прекращает повторы. Остальные причины отказа не получают retry.
Heartbeat по-прежнему может записать только child после проверки signed history
и receipts. Увеличения сроков приёмки или ослабления integrity checks нет.

## Причинная проверка на hosted Linux

Native fixture удерживал lock своего producer outbox, затем записал настоящий
revocation в SQL. Он дождался точного `journal_busy` и проверил неизменность
heartbeat у независимого collector. После освобождения lock исходный event
получил проверенный signed receipt в исходном45s окне от commit, без нового отсчёта.

| Измерение | Результат | Сохранённое ограничение |
|---|---:|---|
| Unlock -> receipt |1.123634229s |В пределах исходного45s commit wait |
| Максимум commit -> receipt |31.000750327s |<=60s |
| Интервал наблюдаемого heartbeat |31.178s |25-40s |
| Остановка source -> signed telemetry gap |90.204897724s |<=120s |

Пройдены17continuous-observer assertions, включая отсутствие ложного heartbeat
при занятом журнале/недоступном source, сохранение исходного event при collector
outage, restart с прежним history/counter и запрет fresh promotion audit при
потере source. Два завершения supervisor подтверждены вместе с отсутствием
дочерних процессов; collector/private state и собственный SQL volume очищены.

Остальные native components также прошли:25promotion/audit/SQL assertions,
37committed-history/rotation assertions и46HTTP identity/lifecycle assertions.
Последние проверяют реальные HTTP/identity child на controlled unready engine;
их нельзя выдавать за M13/M14 или полный M23.

## Unit и воспроизведение

Contracts job выполнил950test executions в21batch без skipped summaries. Это
число выполнений, включая повторные вызовы общих suites, не число уникальных tests.
Точное покрытие source adapter:191/192statements,85/86branches; supervisor:
112/113statements,31/32branches. Все доли выше обязательных95%.

Чистый detached checkout80dea70 с собственным locked Python3.12.15 environment:
54tests pass,3Linux-dependent skips на Windows, warnings as errors. Интерпретатор
и import path принадлежат этому checkout; Ruff903files, docs949files/344Markdown/
2519local links и чистое Git tree подтверждены. Linux-specific поведение проверено
отдельно указанным hosted CI.

- [Supervisor](../../mlsecops/security_trust_service.py).
- [Отрицательные тесты retry/stop/budget/reap](../../scripts/trust_observer_retry_qualification.py).
- [Настоящий fault/recovery playbook](../../scripts/security_trust_service_native.py).
- [Workflow](../../.github/workflows/security-events-contracts.yml).
- [Команды диагностики и воспроизведения](../operations/periodic-trust-observer.md).

Raw logs и JSON reports сохранены приватно. Локальные Docker/WSL/Kubernetes/SQL
не запускались. M11 ad53e3e остаётся failure с неизвестной точной причиной после
actual-candidate-policy-change; для него подготовлена отдельная ограниченная
диагностика source location. Mandatory serving heartbeat, общая конфигурация всех
callers, M10 actual admission и остальные незакрытые R1 gates этим результатом
не заменяются.
