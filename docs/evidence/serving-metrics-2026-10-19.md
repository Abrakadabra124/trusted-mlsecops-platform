# T16: bounded serving metrics, 2026-10-19

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0043](../decisions/0043-serving-metrics.md), [RB-62/PB-36](../operations/serving-metrics-troubleshooting.md). Base HEAD 803d0e75f44e22be4657326efad40c8149314199; локальные изменения ещё не являются clean-checkout native proof.

## Реализованная граница

Private per-app collector экспортирует 69 заранее определённых samples, без IDs/body/query/exception text. Отдельный operator-only GET /metrics, ограниченные admission и send, monotonic duration, outer ASGI outcome после audit/server replacement. FastAPI ambient telemetry остаётся выключенной. Добавлена только prometheus-client 0.26.0, существующие версии lock не обновлены; дополнительные серверы не устанавливались.

Независимый probe проверяет точные имена/labels/HELP/TYPE, размер, canaries, отсутствие timestamps/exemplars, finite nonnegative values, целочисленные counters, cumulative histogram и согласованность count/outcomes. Native helper использует отдельный operator token; actual-candidate privacy matrix получает новый case и approved_metric_series, но не release approval.

## Failure-first и исправления

- Первая новая suite падала на отсутствии module. После первой реализации review-cycle 1 воспроизвёл три failures: запись только после выхода приложения, неправильный учёт внешнего 500 и раннее освобождение operator slot. Исправлены внешним ASGI wrapper, записью после final send и ticket в response lifecycle.
- Review-cycle 2: три targeted tests, **2 failures / 1 pass**. Подтверждены потеря observed disconnect и отсутствие deadline у отказов до admission; исправлены прозрачным receive observer и timeout response для всех ветвей handler. Multiprocess test заменён на cold-import subprocess в uppercase/lowercase environment, с positive-control Counter, который действительно создаёт файл.
- Интеграционный прогон **96 tests, 1 error, 2 skips** выявил list/dict mismatch headers. Исправлено сохранением списка заголовков и проверкой duplicate values. Следующий прогон **25 tests, 1 failure** обнаружил stale expected case count 24 вместо 25; expectation обновлено вместе с утверждением approved_metric_series=69. Эти failed attempts не объявляются successful runs.
- Проверки переполнения, private registry, concurrent updates, send cancel/timeout, 200 unique URLs, quota/auth, schema/canary corruption и audit 200 -> 503 replacement входят в qualification.
- Финальный review-cycle 3 воспроизведён двумя тестами с **7 failing subcases**: лишний header/credential, комментарий с начальным пробелом, пустая посторонняя family и metadata после samples. Probe теперь проверяет весь bounded header allowlist, значения Content-Length/Date, exact family name/type/documentation/sample membership. Это дефекты detector, не установленная утечка текущего exporter. Все три review cycles закрыты исправлениями и regression tests; внешняя модель не использовалась по выбору владельца.

## Локальные результаты

Windows, Python 3.12, uv.lock. Первоначальный adjacent прогон: **81 tests / 0 failures / 0 errors / 2 skips**, 15.736 s. До финального усиления probe broad regression: **157 tests / 2 skips**, 28.479 s. Финальный metrics gate: **35 tests / 0 skips**, 6.148 s; collector **115 statements / 30 branches / 100%**, независимый probe **69 statements / 36 branches / 100%**. Existing privacy probe + candidate harness: **25 tests / 0 skips**, 6.466 s, 181 statements / 84 branches / 100%. Skips adjacent suite относятся к existing POSIX checks; native Linux всё ещё требуется. pip-audit --strict: **No known vulnerabilities found** в текущем Python environment; это не результат container image scan.

Локальные Docker/WSL/Kubernetes/SQL не запускались и не изменялись. Controlled loopback использует fixture Engine, не настоящую модель и не доказательство M13. Actual-candidate CI, полная terminal matrix и проверка remote publication на этом этапе **pending**.

## Оставшиеся границы

Финальная broad regression после всех исправлений: **159 tests / 0 failures / 0 errors / 2 skips**, 27.800 s. Ruff check/format pass, documentation checker: 430 files / 177 Markdown / 1267 local links. Lock сравнен с base: единственный новый пакет prometheus-client, прежние версии не изменены. Эти результаты локальные; подтверждение native CI будет добавлено отдельно.

Full M13/T16/R1 открыты. Нет доказательства client receipt, всех необнаруженных disconnects, hard realtime timeout, multi-process/HA, controller core policy, всех platform output channels, end-to-end public export/correlation, differential privacy или business utility. Исторические image/ML failures сохраняются в [предыдущей matrix](worker-privacy-2026-10-19.md); новая metrics qualification их не отменяет.
