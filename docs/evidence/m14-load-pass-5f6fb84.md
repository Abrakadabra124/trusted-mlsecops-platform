# M14: успешный профиль на 5f6fb84

[Run 42284595297](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42284595297),
job128122034767, source `5f6fb845a2b83c1c740f31419c13b575e4a0b3a8`: success.
Это первый **pass фиксированного actual-candidate baseline**. Общая композиция
M14 на этом commit ещё не реализована, поэтому `full_M14=inconclusive` и R1
не завершён. Qualification permit не разрешает production release.

Профиль не ослаблен: 10 s warmup, 120 s measurement, 10 closed-loop клиентов,
одна pinned golden row, отдельное TCP-соединение на каждый запрос.

| Метрика | Наблюдение |
|---|---:|
| Корректные / все measured ответы | 8330 / 8330 |
| RPS | 69.416667 |
| p50 | 138.391411 ms |
| p95, предел 200 ms | 167.744114 ms |
| p99, предел 500 ms | 184.403221 ms |
| Максимальная latency | 243.960846 ms |
| Wrong / 429 / 5xx / timeout / transport | 0 / 0 / 0 / 0 / 0 |
| Отдельный overload | 40 попыток, 10 корректных, 30 ограниченных, 0 ошибок |
| Длительность overload | 165.298655 ms |
| Recovery | pass |

Наблюдение полное, cap не достигнут, CPU/RAM для обоих containers собраны
независимым оператором. Это sampled memory, не настоящий peak. Все одиннадцать
проверок клиентского профиля прошли. Изменение относительно
[506a762](m14-fifo-2026-11-06.md) перенесло проверку файлов полностью внутрь
владельца SQL-сессии и убрало внешний повтор; подписи, fresh policy queries,
host/role/TLS validation и response budget сохранены. По одному запуску на source
не делаем вывод о production SLA или статистической значимости разницы.

Linux: 81+133+124 test methods, 0 skips. Clean Windows checkout того же commit:
117 methods / 2 Linux-only skips / 15.509 s, повторно использована locked venv;
это не новая установка dependencies. SQL stop подтверждён 2026-11-06 20:07:00 UTC,
отсутствие owned cluster - 20:07:05 UTC.

Независимо пересчитаны 155 Git archive blobs, source fingerprint, summary и
diagnostics hashes; worker cleanup и retained packet recheck подтверждены.

- Canonical primary SHA-256: `1872b58cfc81568df84d40bfe60daf7b52803e4b1d5db4f995466492c0ffce87`.
- Source fingerprint: `3ab23e1541de140c80237dc00a9e42ab619af24fce4bcc861994314e764513ec`.
- Image: `sha256:e7c2161e17f52441e250b02366acd93dece6efb8f4fdac585f93c2bf18162b3d`.
- Summary: `852b628d267c767a742048cf665d5949e55db9f965ef197747a90fb708cf63c3`.
- Diagnostics: `eb58c08ca851c2e13f29a1349a1bac749dae484559ec41f7ff49d62d9f88b2ee`.

Перед close audit был healthy: accepted=36204, durable=36203, pending=1,
unconfirmed=0. Это не утверждение о полном durable acknowledgement на момент
снимка. Последующий shutdown проверил lifespan failure flags и owned cleanup.

На том же source [M13 regression 42284900412](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42284900412)
прошла 443 cases: 435 controlled methods и 8 aggregate criteria. Четыре закрытых
service windows, четыре leak controls, 36 privacy durable events, terminal worker
output и перечитывание private packets подтверждены. 439 method/source blobs и
policy digest сверены независимо. Canonical M13 SHA-256:
`a6e0bf527da9023ee6d3d07f67f4d47897d662095316df074a8a99ce70c73de7`.
SQL stop 20:09:04 UTC, cluster absence 20:09:09 UTC. Это отдельный candidate/run
на том же source, не общая M18-приёмка одного release. Ограничения M13, включая
отсутствие независимого CLI admission observation, сохраняются.

Дальше: fresh M14 composition с исходными client/resource packets, M11 regression
и остальные CP4/CP5. [Runbook](../operations/load-profile.md) содержит команды
воспроизведения только в разрешённом hosted disposable окружении.
