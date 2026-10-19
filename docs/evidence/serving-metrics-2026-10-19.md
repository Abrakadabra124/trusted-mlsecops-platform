# T16: bounded serving metrics, 2026-10-19

## Проверено на native 93de1b6

Code commit `93de1b6af0abdbe3072579b2c48c0ac35db4c176`. [Полный candidate report и kernel receipt](serving-metrics-93de1b6-native.md). **78 unique cases pass**, source_dirty=false, release_ready=false. Export: **69 approved samples**, 12 canary requests / 36 confirmed audit events / 3 owned audit files, ambient telemetry выключена.

- Metrics gate: **35 tests / 0 skips, 3.692 s**, collector 115 statements / 30 branches / 100%, probe 69 statements / 36 branches / 100%.
- Existing privacy + candidate harness: **25 tests / 0 skips, 4.045 s**, probe 181 statements / 84 branches / 100%. HTTP audit 48 / 0 skips, serving regression 81 / 0 skips, access 32 / 0 skips.
- Worker privacy: **13 tests / 0 skips, 0.363 s**, guard 100%; dumpable=0, core limits=0:0, SIGABRT child без core flag/owned files.
- Golden inference: 3 rows, maximum error 0; stopped worker denial 2.015491578 s. Outage recomputation pass: 44 observations, first 503 через 59.741589330 s. Paused SQL denial 10.003021881 s, expiry denial 5.684416941 s; запрос ещё ACTIVE/pending, generation fenced, renewed trust version 3. Это измерения controlled CI, не production SLO.
- Canonical candidate report SHA-256: `b70bb8eb3100e390a1656e4c23cc5fa4b50d666d62437de7fcaa87ef0e7b17f6`. Проверены exact revision, source_dirty=false, уникальность cases, пересчёт outage assessment и SQL denial state.
- Serving image: `sha256:327d592c3ddfe67575da95e799acaa188a8e3a8e60242c1952bfe18176f518ba`; source fingerprint `30fbd2ef30fb192ca941fedb35916f66413091d50a656cd525706aafbc9b192a`. Образ привязан к измерению, bit-for-bit rebuild здесь не заявляется.

### Полная terminal matrix

На **2026-10-19 17:49:35 UTC** все 10 workflows attempt 1 завершены: **6 success / 4 failure**. Нет cancellation/rerun. Прежний failed attempt 4c86fcb сохранён отдельно; новая matrix не переписывает его.

| Workflow | Run | Результат |
| --- | --- | --- |
| Developer runtime qualification | [39294934949](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294934949) | success; 36 intake methods / 74 developer cases |
| Documentation integrity | [39294935200](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294935200) | success; documentation checks |
| Frozen evasion and domain guard | [39294935366](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294935366) | failure; execution complete, recall drop 0.07183673469387755 > 0.05 |
| Frozen poisoning research matrix | [39294935628](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294935628) | failure; 10 violating / 0 inconclusive scenarios |
| Intake evidence contracts | [39294935351](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294935351) | success; 66 intake cases |
| Kubernetes isolation qualification | [39294935534](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294935534) | success; M20 723 / M21 122 |
| MLflow tracking compatibility and private service | [39294935242](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294935242) | success; M06 18 |
| Paired robust training research | [39294935164](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294935164) | failure; candidate recall drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05 |
| Storage role and TLS qualification | [39294934944](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294934944) | success; metrics 35 tests, actual candidate 78 cases, M03 431 / M07 97 |
| Worker and storage image audit | [39294935405](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294935405) | failure; all 4 exact images scanned, SBOM validated, scanner exit 2 |

Image audit действительно исполнен, а не skipped: Critical/High = worker **0/56**, storage **9/132**, worker-candidate **0/55**, storage-candidate **1/85**. Это package findings, не доказанная exploitability каждого CVE; policy остаётся fail. Poisoning/evasion/paired training завершили реальные эксперименты, не прошли прежние пороги. Их ошибки не скрыты успешными metrics/M20/M21 checks. Production promotion и полный M13/T16/R1 не разрешены.


Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0043](../decisions/0043-serving-metrics.md), [RB-62/PB-36](../operations/serving-metrics-troubleshooting.md). Исходная база 803d0e75f44e22be4657326efad40c8149314199; история локальных проверок и первого failed attempt сохранена ниже, окончательный native proof относится к 93de1b6.

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

Локальные Docker/WSL/Kubernetes/SQL не запускались и не изменялись. Controlled loopback использует fixture Engine, не настоящую модель и не доказательство M13. На этапе этих локальных прогонов actual-candidate CI ещё не был выполнен; последующий native результат 93de1b6 приведён отдельно в начале документа.

## Первый native attempt и source correction

[Полная matrix и M03 report 4c86fcb](serving-metrics-4c86fcb-native.md): **2 success / 8 failure**, все 10 terminal. Metrics gate прошёл **35 tests / 0 skips**, 100% обоих модулей; worker guard 13 tests / 0 skips, 100%. Actual-candidate steps не выполнялись: изменение uv.lock не было отражено в data.lock, source verification остановила M03. Это обнаруженный integration defect, не успешная приёмка.

Локально воспроизведён source_lock_mismatch_explicit_update_required. Сравнение inputs показало только uv.lock; generated output прежний, 1 915 576 bytes / 1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473. После явного обновления только этой provenance-привязки validate_lock pass, две fresh generations побайтно равны и verified-cache pass в отдельном TemporaryDirectory без инфраструктуры. Poisoning contracts: **9 tests / 0 skips, 4.818 s**. Пороги и dataset output не изменялись; последующая clean CI 93de1b6 подтвердила correction, не устранив statistical/image blockers.

Финальная broad regression после всех исправлений: **159 tests / 0 failures / 0 errors / 2 skips**, 27.800 s. Ruff check/format pass, documentation checker: 430 files / 177 Markdown / 1267 local links. Lock сравнен с base: единственный новый пакет prometheus-client, прежние версии не изменены. Эти результаты локальные; подтверждение native CI будет добавлено отдельно.

## Оставшиеся границы

Full M13/T16/R1 открыты. Нет доказательства client receipt, всех необнаруженных disconnects, hard realtime timeout, multi-process/HA, controller core policy, всех platform output channels, end-to-end public export/correlation, differential privacy или business utility. Исторические image/ML failures сохраняются в [предыдущей matrix](worker-privacy-2026-10-19.md) и вновь подтверждены текущими экспериментами; metrics qualification их не отменяет.
