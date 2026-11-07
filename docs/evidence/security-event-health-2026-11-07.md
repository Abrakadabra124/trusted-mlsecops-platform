# T29/M23: durable heartbeat и пропуски событий

Дата: 2026-11-07. Статус: **компонент проверен, полный M23 не принят**.
Source: `d7ccb42326c7f42cc8d6a28620fe788225ceb895`.
[ADR0058](../decisions/0058-security-event-contract.md) задаёт профиль;
[ранбук](../operations/security-events.md#heartbeat-gap-episodes-и-journal-v3)
содержит диагностику и воспроизведение.

## Реализация и проверенные свойства

В существующий atomic Store встроен `security_event_health`. Journal v3 хранит
последний подписанный heartbeat каждого producer, исходное admission time,
время открытия незакрытых пропусков и поколения outage episodes.
`Store.poll` атомарно сохраняет clock checkpoint и health transition.

- Без первого обязательного heartbeat состояние unhealthy. Exact retry возвращает
  исходную запись и не продлевает срок наблюдения.
- Forgery, conflicting/backward counter, обратный observed time/last-event claim,
  claim дальше received high+64 и подмена heartbeat между streams отклоняются.
- Новые claims и частичное заполнение пропуска не меняют исходное время episode.
  Late arrival может восстановить continuity; receipt/late semantics сохранены.
- Notice ID сохраняется при reopen журнала и при получении другого уже старого
  heartbeat. После настоящего восстановления следующий outage получает новый ID.
- Poll unhealthy при gaps, отсутствии/expiry heartbeat, pending delivery или full
  journal. Projection всегда содержит `release_ready=false`.
- Повреждённые control timestamps/counters/ownership и старые schema1/2 не становятся
  пустым healthy state. Переполнение generation counter не коммитит часть события
  или receipt. Реальная миграция старых volumes не заявляется.

Детекция начинается после **90 s**, обязательный предел остаётся **120 s**.
Три фиксированных heartbeat periods оставляют 30 s на scheduler и I/O.
Профиль зафиксирован до live measurements. Controlled tests проверяют границы
89.999/90 s и сохраняемый hard deadline120s; это не измеренная runtime latency.

## Доказательства

[CI42349487413](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42349487413),
job128334360394, terminal success `2026-11-07T07:01:39Z`:

| Linux suite | Tests | Skips | Время |
| --- | --- | --- | --- |
| Подписанные contracts | 21 | 0 | 0.292 s |
| Existing key/monitoring/release-policy | 25 | 0 | 0.158 s |
| Journal, filesystem, heartbeat/gaps | 38 | 0 | 3.685 s |
| Всего | 84 | 0 | Три отдельные suites |

Проверены реальные Ed25519 signatures, Linux private files, сохранение и reopen
Store с heartbeat и открытым sequence gap, первоначальный admission time и
стабильные notice IDs. Предыдущие crash/write/rename/readback fault tests остаются
в составе обязательной suite. Время в health scenarios задаётся контролируемо.

| Модуль | Statements | Branches |
| --- | --- | --- |
| security_events | 105/105 | 42/42 |
| security_event_config | 101/101 | 32/32 |
| security_event_health | 134/134 | 54/54 |
| security_event_ledger | 138/139 | 35/36 |
| security_event_store | 143/144 | 36/36 |

Source во всех пяти coverage records сверён. Каждый модуль соблюдает свой
неизменённый порог; exclusions не добавлены. Ruff/format и docs checks прошли:
чистый Linux source содержит852files,308Markdown documents,2312local links.

Чистый Windows checkout того же source с новой locked `.venv`, Python3.12.15:
84tests за4.382s, **18 skips** (15 Linux filesystem/control +3 existing POSIX).
Import/executable paths и schema3 проверены, git status после тестов пуст.
Windows не подтверждает пропущенные filesystem checks.

Промежуточный [a08c3f1 /42349020295](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42349020295)
прошёл83Linux tests/0skips, но timing profile v2 объявлял потерю ровно на120s.
При review выявлен отсутствующий запас для реального scheduler. Новый test на90s
сначала воспроизвёл отсутствие сигнала, затем профиль изменён и schema поднята
доv3. Это изменение проекта до live campaign, не tuning по успешной метрике.

## Открытые требования

Periodic scheduler, authenticated HTTP collector/router, создание подписанных
telemetry.gap events, actual source adapters и fail-closed promotion ещё требуют
реализации. Реальное обнаружение<=120s и доставка<=60s должны быть измерены в
полной M23 campaign с retained evidence и cleanup. Успешный ручной poll этого
не доказывает. Нет готовой миграции старого volume или защиты от host-admin rollback.

Локальные Docker/WSL/Kubernetes/SQL и внешние модели не запускались. CI не создаёт
такую инфраструктуру; test processes и temporary directories завершены cleanup.
Private raw logs и ключи не опубликованы. T29/M23 и общий M18/R1 остаются открытыми.
