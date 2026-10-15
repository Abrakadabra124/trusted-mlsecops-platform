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

Native профиль проверен на `960091f`, но не является root rotation, dataset transitive revoke, production Reader release acceptance, bounded shutdown при бесконечном socket blackhole, полным M13 privacy/audit или M14 load benchmark. Старые image/ML gates не ослабляются; qualification не даёт final release approval.

## Clean-checkout native CI 960091f

[Storage run 38779625543](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625543), job `116576139028`: completed/success. **62/62 actual-candidate cases pass**, code `960091f23a68a124a05648fb980c7d9c2db523d4`, source_dirty=false. Campaign `028fd5c47a5145698e7db951e83b2d93`, UTC 2026-10-15 `17:49:23.607120` - `17:50:59.459521`. Полный [sanitized report](serving-expiry-960091f.md), canonical SHA-256 `314cad1dd093b0301508a2750c14d5f5e8d4f4d51b457a7510dc0b26f99f4ba7`.

| Наблюдение | Проверенный результат |
|---|---|
| Genuine short policy | Подписанная version 2; baseline version/hash совпали с publication receipt; signed expiry `1792086656` |
| Near-expiry ACTIVE | monotonic `618.017026505`, внутри запроса `617.924771601` - `624.619762057`; сохранён именно проверенный timestamp |
| Near-expiry HTTP | 503 за **6.694990456 s**, при незавершённом ACTIVE query и fenced generation |
| Запас до границ | Клиент завершил ответ за **0.248570806 s до lease deadline** и **0.407325029 s до signed expiry**; это измерение одного lab run, не SLO |
| После expiry | Новый запрос начался wall `1792086656.050124`, получил 503; SQL всё ещё ACTIVE и unfinished |
| Renewal/recovery | Только после unpause/drain подписана version 3 с новым hash; публикация сама не вернула serving. Explicit activation читает именно version 3/hash и запускает новый worker |
| Обычный paused query | 503 за **10.001981965 s**, ACTIVE timestamp также внутри запроса |
| Stopped authority | Первый 503 через **59.740655877 s**, последний 200 через 59.729039985 s после verified read; 140 observations, no 200 после deadline/denial |
| Golden/worker | 3 synthetic rows, max error 0.0; stopped-worker denial 2.015423597 s |
| Конечное состояние | Старые workers удалены; финальный signed model revoke снова даёт 503; qualification authority/private key удалены; source CAS/budget/envelopes/checkout не изменены |

Model `09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f`, image `sha256:675a34f2db1818b539940d5693c1d7a2716e2f8ec327061e0f0c9b80a5b77f0a`, source fingerprint `fef6e6505f3836daa47a56c77bfd36619aa59c13adb63f3e64d699e4c2c514dd`. Fingerprint production source не изменился; diagnostic scripts привязаны к exact clean Git revision. Proposal/permit/evaluation/subject bindings сохранены в полном report. `release_ready=false`, `full_M12=inconclusive` остаются обязательными.

Storage CI повторил M03 431/M07 97, trust 45, Reader 18, fixture HTTP 34 и serving unit suite 66 methods. Новый pause harness: 14 methods, coverage 94%. Локально из опубликованного report пересчитаны outage assessment и temporal/binding assertions обоих paused profiles; они совпали. Это проверка сохранённых данных, не второе native испытание. Working Docker/WSL/Kubernetes пользователя не запускались; внешняя модель не использовалась.

## Terminal CI matrix: 6 success / 4 failure

Все 10 workflows `960091f` completed, pending/cancelled нет. Последняя M21-проверка завершилась в `2026-10-15T17:57:43.889180Z`. Документация публикуется после terminal state; docs-only commit не заменяет проверенную code revision.

| Workflow | Проверенный статус |
|---|---|
| [Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625543) | success; 62 actual-candidate cases, M03 431/M07 97 |
| [Developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625330) | success; 3 fresh trainings, probability difference 0, export parity 2.086162567138672e-7 |
| [Tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625246) | success; M06 18 |
| [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625795) | success; M20 723, M21 122, reports bound to 960091f |
| [Intake](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625305) | success |
| [Docs](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625311) | success |
| [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625252) | failure; Critical/High: worker 0/56, storage 9/131, candidates 0/55 и 1/85 |
| [Poisoning](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625528) | failure; complete, 10 violations, 0 inconclusive; primary integrity pass, 35 cases/251 files |
| [Evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625296) | failure; complete/primary pass, recall drop 0.07183673469387755 >0.05 |
| [Paired research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625391) | failure; complete/primary pass, candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 >0.05 |

Все четыре image scans выполнены, SBOM validated, scanner exit 2; это реальные findings, не отсутствующий scanner. Campaign IDs: poisoning `93a2c63219344912ae56993d0f185aa5`, evasion `2b7f9ea763294dd38ee6f84a9d8b22f6`, paired `f18fb061ff0b429881a1804e1d3c758e`. Serving increment не исправляет эти failures и не снижает их thresholds.

Следующий шаг по [плану](../../tasks/plan.md) - T16: authenticated principals, per-client quotas, минимальный audit, bounded telemetry и canary/redaction qualification. План дополнен первоисточниками OWASP/OpenTelemetry/Prometheus, но эти будущие функции ещё не реализованы. Финальная docs-проверка: 365 files, 136 Markdown, 985 local links; external links/runtime этим checker не валидируются.
