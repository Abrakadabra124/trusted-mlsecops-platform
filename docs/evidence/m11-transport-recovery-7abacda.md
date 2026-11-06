# M11: bounded transport regression, 2026-11-06

Source `7abacdab0b0dcc33b875072ccb9a7ad35311a6ec`,
[run 42287772130](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42287772130),
job `128132951031`: success, full M11 report pass, 143/143 cases.
Это отдельная source-bound регрессия, не M18 и не приёмка R1.
Actual production release по-прежнему не разрешён без общей assurance.

Предшествующий `5f6fb84` / [42284704218](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42284704218)
завершился `kube_serving_shutdown_deadline` после live trust blackhole.
Повторно используемое SQL-соединение могло ждать потерянный ответ дольше
shutdown grace. Исправление добавляет libpq TCP user timeout 5000 ms и
keepalive idle/interval/count 5/1/3, сохраняя HTTP и shutdown deadlines,
TLS verify-full, role/host pins и отказ при недостоверном trust document.

На исправленном source тот же native lifecycle завершился штатно:

| Наблюдение | Client-finished first 503 |
|---|---:|
| Actual blackhole | 12.744253833 s |
| Actual outage | 59.770523187 s |
| Actual key revocation | 4.569166414 s |
| Actual model revocation | 4.771452522 s |
| Actual policy change | 4.766729234 s |
| Actual root rotation | 4.371019360 s |

Эти интервалы измеряются от соответствующего fault, а не являются общим
HTTP request timeout. Отрицательные clock/cache сценарии включают invalid
signature, monotonic backward, server skew, wall backward и wall jump.
Подготовительные Linux suites: 670 method executions с повторами, без skips.

Source/policy hashes независимо пересчитаны из Git archive: 156 runtime blobs
и 442 method/material blobs. Canonical M11 primary SHA-256:
`dcd592ac04c67ebae4bc7dcf1ff8f25dff8c7dbd3d62c97349def6fcf01e4dfb`.
Source SQL stop с проверкой Running=false завершился в 20:44:41 UTC;
owned cluster deletion и отсутствие cluster подтверждены в 20:44:46 UTC.
Private primary и проверочный receipt сохранены вне tracked tree.

Результат подтверждает устранение наблюдавшегося отказа на этом Linux runner
в этом опыте. Он не доказывает универсальную границу остановки для любой ОС,
сети или libpq-сборки. Последующие изменения Session требуют свежих регрессий;
R1, M14 latency, M22 independent review и итоговый one-candidate M18 остаются открытыми.
