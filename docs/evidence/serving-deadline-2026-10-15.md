# HTTP deadline: evidence, 2026-10-15

Scope: increment после `309fbc36`/code `e9120e0`; T14/T15, не full M11/M12/R1. [ADR 0034](../decisions/0034-serving-response-deadline.md), [RB-53/PB-27](../operations/serving-deadline-troubleshooting.md).

## Failure-first и исправление

- До исправления HTTP ждал blocked reader вместо раннего 503; после timeout требуется сохранять pending task и slot до завершения thread.
- Старый queued request не передавал generation в Engine; approval expiry не ограничивал response budget. Тест expiry показал почти 10 s при permit, истекающем менее чем через 2 s.
- Fenced generation с заполненными слотами возвращала 429 вместо 503; body занимало около 1 s при 50 ms общем budget; fence во время response serialization всё ещё допускал 200. Все сценарии воспроизведены до corrections.
- Scoped same-model review воспроизвёл shortening race с настоящим подписанным `trust.Lease`: после admission deadline 110 новая policy сократила lease до 101, а response в 101.1 всё ещё был 200. Добавлены failure-first regressions финальной проверки и ожидания. Теперь min(initial,current) recheck не делает DB I/O и не продлевает исходный request budget.
- Смежная regression сначала нашла fixture без обязательного `expires_at`; исправлена только fixture, production expiry validation не ослаблена.
- Второй scoped review нашёл late-pause после finally и false-positive только по marker перед `execute`. Поздний connect воспроизведён Event-controlled тестом: старый harness делал pause после выхода из контекста. Теперь guard/closed сериализуют восстановление, а native assessment требует реальный libpq ACTIVE плюс незавершённый execute. Idle connection или уже завершённое чтение не дают pass.

## Проверки

Локально прошли **163 adjacent methods за 14.669 s**, **66 serving methods за 5.481 s**; combined Python branch coverage 93% (684 statements, 202 branches). Отдельный paused-query harness: **7 methods, 94% coverage** (105 statements, 20 branches). Ruff lint/format и diff whitespace passed. Docs check: 362 files, 133 Markdown, 965 local links. Coverage не означает проверку Linux Docker или полноту state space.

Локальные tests используют controlled worker/DB faults и настоящий loopback HTTP для harness contracts. Docker/WSL на компьютере пользователя не запускались. Новый native harness подключён к storage workflow, но до terminal CI нельзя считать paused-query эксперимент подтверждённым. Точный commit и native trace будут добавлены после выполнения.

## Границы

Внешняя модель по решению пользователя не использовалась. Review - scoped same-model, не полный security audit. Нельзя переносить результаты старого `e9120e0` на новые bytes. Старые image/ML failures не считаются устранёнными; thresholds, signatures и release approval не обходятся. Actual candidate остаётся qualification-only.
