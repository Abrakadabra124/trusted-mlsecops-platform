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

Локальные tests используют controlled worker/DB faults и настоящий loopback HTTP для harness contracts. Docker/WSL на компьютере пользователя не запускались. Финальный scoped review двух harness corrections не нашёл новых замечаний, 2 targeted tests pass; это не полный аудит.

## Clean-checkout native CI ed87e97

[Storage run 38774146548](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146548), job `116557300727`: completed/success, code `ed87e975e03a76c1529cf442a140a508fc4cddd4`. Полный [sanitized report и traces](serving-deadline-ed87e97.md); canonical SHA-256 `6b4be2bc0a1df2f70ace939858ff821700f5785804854d2ca68e73db0b245222` перепроверен локально, outage assessment независимо пересчитан тем же strict assessor из сохранённых 137 observations.

**52/52 actual-candidate cases pass**, campaign `6a581a24d7ba49d0bca4294e527330ba`, UTC `17:10:02.559988` - `17:11:28.500946` 2026-10-15. Source dirty=false; исходные CAS/budget/envelopes и checkout не изменены. Qualification authority/private key удалены, signed model revoke после восстановления снова дал 503. `release_ready=false`, `full_M12=inconclusive` сохраняются.

| Наблюдение | Проверенный результат |
|---|---|
| Golden consistency | 3 synthetic rows, max error 0.0, same actual model bytes |
| Stopped worker | HTTP denial 2.015382126 s; owned cleanup подтверждён отдельно |
| Stopped authority | Первый клиентский 503 через 59.748078461 s после verified read; последний 200 через 59.740031386 s |
| Outage lease | 137 observations, неизменные sequence/deadline; no 200 после deadline/первого denial; post-deadline 503 присутствует |
| Paused established SQL | 503 через **10.002350314 s** от запроса, 10.049137872 s от last verified read; query ACTIVE и ещё не завершён, generation fenced |
| Recovery | Unpause до drain, старый worker удалён; late read не включает serving; explicit activation + fresh read + прежние golden scores |

Bindings: image `sha256:1480c39bc063468b87121e2695a3faef01580762f223803b733fb0a73b035eb6`; source fingerprint `fef6e6505f3836daa47a56c77bfd36619aa59c13adb63f3e64d699e4c2c514dd`; model `09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f`; subject `9ed3e08c258678ce8f3e3666c54001af6de71d0b9bb4c80b101af02e8d7a8f95`. Остальные proposal/permit/evaluation bindings в полном report. Source fingerprint покрывает production Python/lock/build/policy; diagnostic scripts привязаны дополнительно к clean exact Git revision, не к этому fingerprint.

Storage CI также повторил M03 431/M07 97, trust 45, Reader 18 и contract-fixture HTTP/ONNX 34 cases. Native paused-query проверен при свежем lease: старый lease не успевал истечь, сработал общий 10 s request deadline. Более короткий/сокращающийся lease покрыт controlled tests; отдельный paused-query native профиль у самого expiry ещё не выполнен. Не смешивать эти доказательства.

## Terminal CI matrix: 6 success / 4 failure

Все 10 workflows этого code commit completed; pending/cancelled нет. Последняя M21-проверка завершилась 2026-10-15T17:20:17.204967 UTC. Публикация этих документов не заменяет проверенную code revision.

| Workflow | Проверенный статус |
|---|---|
| [Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146548) | success, 52 actual-candidate cases |
| [Developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774147042) | success; 3 fresh trainings, probability difference 0, export parity 2.086162567138672e-7 |
| [Tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146621) | success; M06 18 |
| [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146629) | success; M20 723, M21 122; full reports привязаны к ed87e97 |
| [Intake](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146634) | success |
| [Docs](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146561) | success |
| [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146626) | failure; worker 0 Critical/56 High, storage 9/131; candidates 0/55 и 1/85 |
| [Poisoning](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146632) | failure; execution complete, 10 violations, 0 inconclusive, primary reconciliation выполнена |
| [Evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146697) | failure; execution complete/primary pass, recall drop 0.07183673469387755 >0.05 |
| [Paired research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146908) | failure; complete/primary pass, candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 >0.05 |

Все четыре image scans действительно выполнены, scanner exit 2, SBOM validated. Ошибка gate не подменяется отсутствующим scanner. Poisoning campaign `3f5c333d599d41c6b2348edf1d0146d9`, evasion `e0f7a150fe6640839c4ef06a385a093d`, paired `c1feb84b10524d4fa5c940943c9b1a55`. Их fail не устранён serving increment и не обходится qualification permit.

## Границы

Внешняя модель по решению пользователя не использовалась. Review - scoped same-model, не полный security audit. Нельзя переносить результаты старого `e9120e0` на новые bytes. Старые image/ML failures не считаются устранёнными; thresholds, signatures и release approval не обходятся. Actual candidate остаётся qualification-only.
