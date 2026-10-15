# Paused SQL у signed-policy expiry: evidence, 2026-10-15

Increment после code `ed87e97` / docs `a11c719`. Scope T14/T15; полный M11/M12/R1 остаётся открыт. [ADR 0034](../decisions/0034-serving-response-deadline.md), [PB-27/RB-53](../operations/serving-deadline-troubleshooting.md).

## Что проверяется

Прежний paused-query native trace проверял 10 s request budget при свежем lease. Новый профиль публикует **настоящую signed trust-policy successor с lifetime 8 s** в отдельной owned qualification authority. Production policy/permit, модель, source CAS и working runtime не переписываются. Версия и digest успешного baseline read обязаны совпасть с receipt публикации; текущий approval/permit истекает позже trust policy. Clock monkeypatch есть только в unit fixtures, не в native runner.

Пауза после TLS handshake удерживает настоящий SQL exchange. Первый HTTP 503 должен завершиться до lease deadline и signed wall-clock expiry. Затем authority остаётся paused до фактического expiry, повторный запрос должен начаться после expiry и снова вернуть 503 при незавершённом SQL. Unpause выполняется до drain; новый подписанный policy version сам не активирует serving. Только explicit verified activation с чтением именно новой version/digest возвращает прежние golden scores через новый worker.

## Исправления доказательств и failure-first tests

- Review обнаружил, что ACTIVE, прочитанный после клиентского 503, не доказывает ACTIVE до этого ответа. В `ed87e97` такой строгой временной отметки не было. Старые timestamps denial/recovery сохраняются, но более сильное утверждение требует нового прогона.
- Добавлен concurrent read-only observer: фиксирует wall/monotonic после наблюдения libpq ACTIVE, пока основной thread ждёт HTTP. Приёмка требует `request_started <= active_observed <= response_finished`. ACTIVE, появившийся только после ответа, и отсутствие наблюдения не дают pass. ACTIVE может относиться к implicit BEGIN; успешное исполнение SELECT из него не выводится.
- У observer проверяются остановка, ошибка чтения состояния и неуспешный thread start. Он не получает keys или raw SQL payload и не изменяет connection.
- Слишком длинный/уже истёкший lease, foreign version/hash, reused receipt, более ранний approval, late denial, early post-expiry probe, stale renewal и foreign recovered policy не должны приниматься.
- Если scheduler задержался и expiry уже наступил после своевременного первого 503, ожидание пропускается. Фактическое время второго запроса всё равно проверяется; extra grace не добавляется.
- Default request-deadline и near-expiry traces имеют отдельные runtime keys и private files. Case prefix `near-expiry-` не позволяет смешать два опыта или перезаписать первый.
- Последующий scoped review воспроизвёл race публикации observer: проверка читала новое поле, хотя trace уже сохранил null. Теперь pass проверяет тот же snapshot, который опубликован; управляемая late-publication regression отвергает такой отчёт.
- Baseline 503 раньше происходил до создания evidence. Теперь начальный inconclusive trace с receipt сохраняется до runtime access, а `finally` публикует его даже при раннем отказе. Проверены оба профиля; stdout использует отдельные `http_paused_query` / `http_expiring_query`.

## Локальная проверка

Paused-query harness: **14 methods pass**, Python branch coverage **94%** (175 statements, 52 branches). Смежная suite: **170 methods pass за 14.690 s**. Ruff lint/format и diff check прошли; docs check: 364 files, 135 Markdown, 979 local links. Unit checks используют controlled clocks/DB/Docker; они не доказывают native timing. Неполный или отвергнутый эксперимент не получает pass; сохранённый trace и reason нужно читать вместе с общим inconclusive report.

## Остаточный scope

Новый native профиль до завершения CI не считается проверенным. Он не является root rotation, dataset transitive revoke, production Reader release acceptance, bounded shutdown при бесконечном socket blackhole, полным M13 privacy/audit или M14 load benchmark. Старые image/ML gates не ослабляются; qualification не даёт final release approval.
