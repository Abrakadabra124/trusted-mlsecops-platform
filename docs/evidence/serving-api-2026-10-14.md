# Persistent isolated serving и API: 2026-10-14

Parent: `a711ffa99b7cfa8594c7cf0832e4fc3dda66f3f6`. Scope: T15 implementation component. Полные M12/M13/M14/R1 остаются открытыми; runtime commit и native CI будут записаны после публикации.

## Локальные проверки

Negative-first suites сначала падали на отсутствующих модулях. Текущая suite: **41 methods pass**, controlled Python branch coverage **94%** (502 statements / 150 branches). Это не 100% и не доказательство Docker isolation. Проверены настоящая ONNX InferenceSession на synthetic bytes, real OS pipe timeout/EOF/oversize, loopback Uvicorn HTTP, crypto rebinding fixture и controlled Docker config/lifecycle cases. Объединённая adjacent suite: **138 methods pass за 10.920 s**. Ruff check/format pass, 315 files; docs check 344 files / 123 Markdown / 885 local links pass.

Проверены schema/version/extra fields, row/nonce/model/request digest mismatch, malformed model, repeated load, scanner/runtime version, retained process/session, exact bytes, mixed score/abstain, load failure/expiry/revoke, 401/413/422/429/503 contract, eight-slot overload и cancellation. После ошибки request features модель остаётся работоспособной; после worker/trust failure - нет. Полная M13 privacy campaign, реальные per-client quotas и audit ещё не выполнены.

Отдельный failing regression воспроизвёл освобождение admission slot до завершения отменённого HTTP inference thread: ожидалось 7 свободных слотов при одном ещё работающем запросе, фактически стало 8. После deferred release test проходит, включая late exception без private canary в response. Это controlled defect, не production incident.

Независимый автоматический review этого increment не заявляется. Предыдущая попытка fresh-context review завершилась ошибкой инструмента без результата; выполнены source review и исполняемые проверки. Внешние модели/CLI не запускались.

## Native CI

Пока не запущен. Local working Docker/WSL не изменялся. Новый CI stage использует реальный Docker worker, две disposable TLS SQL authority/storage, current Reader, loopback HTTP и одноразовые test roots. Positive reports являются contract fixtures, **не настоящими passed gates**. Новый source candidate с failed image/poisoning/evasion/robustness не принимается.

Runner проверяет actual ready/load, real CPU golden parity, persistent session reuse, wrong-input errors, stopped worker deadline/cleanup, explicit verified reload и actual signed revocation -> prediction/readiness 503. Итог должен сохранять `release_ready=false`, `full_M12=inconclusive`, clean source revision/fingerprint, campaign/time и runtime metrics. Raw logs, models, keys и tokens не публикуются.

## Оставшаяся работа

Candidate-bound full M12 qualification без фиктивных gates, настоящий HTTP trust outage deadline trace, root rotation/rollback protocol, scoped serving permissions, M13 logs/metrics/traces privacy and audit, per-client quotas, M14 load profile, monitoring/recovery и общая M18/R1 приёмка. Loopback bearer token и owned Docker subprocess не объявляются production identity/TLS ingress или multi-node HA.

[ADR 0031](../decisions/0031-isolated-serving-api.md), [API](../serving-api.md), [PB-25/RB-48/RB-49](../operations/serving-troubleshooting.md).
