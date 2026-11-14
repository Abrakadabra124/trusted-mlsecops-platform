# M14 и M15 на одном замороженном предложении

Hosted job `132324852541`, run `43554717635`, attempt 1, завершился с `success`
на source `e59a06cae46983f5cf41ac328c5a0fdc9ec53c01`. Профиль synthetic local-cpu.
Полное время job 15 мин 55 с. Между завершением freeze и завершением M15 прошло
12 мин 25 с. Оба native gate проверяли действующий descriptor в исходном signed окне.
[Hosted job](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43554717635/job/132324852541)

| Шаг | UTC 14 ноября 2026 | Результат |
| --- | --- | --- |
| M14 | 04:06:52 - 04:13:09 | 153 pass, 8215 из 8215 корректных ответов за 120 с, 68.46 RPS, неожиданных HTTP 5xx 0 |
| Пересоздание Kubernetes | 04:13:09 - 04:14:19 | Удаление первого кластера, проверка отсутствия, перенос его markers, bootstrap второго |
| M15 | 04:14:19 - 04:19:17 | 188 pass, 12 000 наблюдений, 10 clean и 2 shift windows, 3 подписанные доставки |
| Остановка host SQL и удаление второго кластера | 04:19:17 - 04:19:21 | Проверены stopped container и отсутствие named cluster |
| Offline replay | 04:19:21 - 04:19:23 | Обе цепочки проверены по исходным owner pins и хешам, снятым до очистки |

M14 дал p95 192.813370 мс и p99 212.615755 мс для всех запросов и для успешных
при порогах 200 и 500 мс соответственно. В отдельном overload из 40 попыток
10 дали правильный ответ, 30 получили ограничение, неожиданных ошибок 0.
Последующий запрос подтвердил восстановление. Максимальная задержка доставки
M15 составила 0.297271184 с при пороге 120 с. Для 10 feedback records создана
одна quarantine row, retry сохранил состояние. Зафиксированы 15 прямых SQL
отказов, сохранность защищённых таблиц и состояния promotion.
`training_eligible=false`, `verified_labels=false`.

| Общая привязка | SHA-256 |
| --- | --- |
| Raw proposal report | `55e4517efe1cbc4c2bdea9068d723f90899ed9ca0c481e7806eec8f54deaed7e` |
| Raw storage-demo | `ae4d882800fc6c406464ba2f9b2135406b6093901fd01d31c6a04456d913ee9d` |
| Raw trusted-keys | `1e5fc30d4364e3c6d03c1a1203d8aa6f891c1659a38a722b1e58c23c7daea521` |
| Raw storage-trust | `d6411b81c02e97087341b3efb478aa9d1da69e2ffa9fafc02e6971f276cdf347` |
| Candidate reference | `d0c7cfa9f8af7a5d595ebf8dadc9137a754ef0b370034a817a30c6bcda095653` |
| Signed evaluation reference | `c7a6c5eb9cac6fc9e9d02dcf57f981f8dea1e92078e0d1713bf518f50948e2f4` |
| Signed proposal reference | `b9af6a3b4be9940b3ba2055486e448891a87116cc71e94efff9b1b2f6ea067db` |
| Subject | `f627817f2e38a799e3a47f41a0e2df6936ed3cf37a160d2770e62645eca64793` |
| ONNX model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Source fingerprint | `c16dc543dde9b9ab4bb51c0f6e137ff763a47632bc5ace612c7cc46052ff513f` |
| Worker image | `sha256:1fc9811ced24a3517dc58e6b54b166cd2bdf9430eefa29488e906420581da4d8` |
| M14 qualification permit | `c31ba5180f350b492cfbf0fd81844811f6b518243e039dbf44d9c379f8fae7bd` |
| M15 qualification permit | `7bd93fa31c40345ff43bc3b27dbebca62c071e1fbab6d34d63d7034eddb110d8` |
| M14.json, raw с LF | `4eb3ae506885b80847dd8608b249f47d41298ed2a7f98258e996d984985094c5` |
| M15.json, raw с LF | `fe5e8df428d2aed7dd1394f80bff81960af76437ca277deef7483c4a84281587` |

По двум конечным `report` в последнем шаге отдельно пересчитаны
`sha256(canonical(report) + LF)`, проверены уникальные ID и исходы каждого
критерия, общий candidate, подписанная оценка, proposal, subject, model и image.
Хеши закрытых admissions маскированы. Повторная интеграция использует свои
pins и отчёты на своей ревизии. [Интерфейс capture и replay](../operations/load-profile.md#замороженный-proposal-для-m14-и-m15)
