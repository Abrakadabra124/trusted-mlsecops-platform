# M14: fresh load acceptance on bbff69e

Неделя 10, T17, synthetic local-cpu profile.
Source `bbff69e714dcce4f2560fb40365030d27651e23b`.
[Run 42297023903](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42297023903),
job `128164825053`: success. **Полный M14 report: pass, 143 cases =
137 controlled methods + 6 aggregate criteria.** R1/M18 не приняты.

## Профиль и результат

Новый actual signed candidate, отдельный qualification permit, один CPU ONNX
worker, 10 clients, новый TCP connection на запрос, одна pinned golden строка.
Прогрев 10 s и measurement 120 s; request deadline 2 s, cap 200000 attempts.
Qualified candidate не является одобренным production release.

| Метрика за measurement window | Наблюдение | Критерий |
|---|---:|---:|
| Попытки / корректные ответы | 15672 / 15672 | >=1000, без неверных ответов |
| Throughput | 130.6 requests/s | измеренное значение |
| p50 | 71.133872 ms | измеренное значение |
| p95 | 103.052346 ms | <=200 ms |
| p99 | 117.668110 ms | <=500 ms |
| Maximum | 176.576635 ms | измеренное значение |
| 429 / 5xx / timeout / transport / wrong | 0 / 0 / 0 / 0 / 0 | нормальная нагрузка без скрытых исключений |

Все десять клиентов участвовали в прогреве и measurement. Полное окно
подтверждено, cap не достигнут. Отдельный overload burst: 40 attempts,
10 correct + 30 bounded 429, 0 errors, 106.147857 ms, recovery=true.
Overload не включён в normal percentiles.

Независимый operator проверил UID/spec/image/restarts и получил по 44 Kubelet
samples controller/worker. Максимальный upper-bound gap 11 s у обоих,
requested window 120 s. Controller average CPU 0.976076125 cores,
max sampled usage 233877504 bytes, RSS 152854528 bytes.
Worker average CPU 0.064790361 cores, usage 41807872 bytes, RSS 40628224 bytes.
Limits сохранены: controller 2 CPU / 1 GiB, worker 1 CPU / 1 GiB.
Sampled memory не равна измеренному true peak.

## Что связывает результат

Gate запускает текущий inventory controlled contracts и новый native опыт.
После owned cleanup перечитывает три retained packets: start, finish, resource
samples; заново вычисляет summary/resources и проверяет hashes четырёх candidate
artifacts. Подмена source, image, methods, candidate/model/subject, времени,
golden payload или retained packet не разрешает pass.

Первичный M14 report независимо сверён после получения из CI:

- 156 runtime Git blobs и 442 method/material blobs пересчитаны из Git archive.
- Policy digest и полный список 137 method IDs совпадают с этим source.
- 6 aggregate criteria, итоговые 143 typed cases и measurement binding совпадают.
- Primary SHA-256: `554d4f1e15ee6f15c27b83508a34dffbaaeafe1c1c5cefa3c20d24fd8e7a0bcf`.
- Baseline SHA-256: `ec48218044925e0983c8ec7ee2926643dac4be58fed92545b05cc532e35e64a9`.
- Source fingerprint: `e44585e3fee5d0f1c48252d7df050a1904d74d144f9af8922b14196fae77df87`.
- Image ID: `sha256:addf9c277f4c6f544b86d340d85d8010e986e0827d8393d5e56d9fac5563c62b`.

Raw retained packets повторно проверял CI gate. Локальная независимая сверка
проверяла source/report bindings и inventory, а не скачанные raw request records.
Private packets, client tokens и ключи в публичный репозиторий не включены.

## Shutdown, cleanup и проверки кода

Снимок аудита перед закрытием: accepted=68032, durable=68031, pending=1,
unconfirmed=0, reservations=0, healthy=true. Это не утверждение о том, что
все записи уже были durable в момент снимка. Затем успешное завершение
lifespan проверено явно, worker absence и retained readback подтверждены.

Source SQL stopped с readback Running=false: 2026-11-06 21:35:01 UTC.
Удаление owned cluster и `No kind clusters found`: 21:35:06 UTC.
Подготовительные suites: 109 + 133 + 124 + 8 = 374 Linux executions,
без skips; fresh gate отдельно выполнил 137 methods.
Нельзя складывать повторные executions и объявлять их уникальными tests.

Изменённый prepare runner и gate проверены 14 local tests / 0 skips:
42 statements / 6 branches и 136 / 20 соответственно, все 100%.
Clean remote checkout того же source: 14 / 0, 3.148 s, tree clean.
Использован ранее установленный locked Python 3.12.15 environment, не fresh
dependency installation. Полный hosted run сам установил locked dependencies.
Локальная инфраструктура Docker/WSL/Kubernetes/SQL не запускалась.

## Исправления и оставшиеся ограничения

- FIFO HTTP scheduling и engine-owned SQL Session убрали лишнюю конкуренцию
  и повторное открытие transport. Каждый trust read сохраняет новую проверку
  signed document, clock/version/revocation и credential files.
- Validation/fingerprint используют одни прочитанные bytes; проверки role/host,
  TLS verify-full, закрытие при изменении credentials и post-connect check сохранены.
- Подписанный proposal теперь готовится перед candidate checks через существующий
  prepare path. Temporal predicate не ослаблялся.
- M11/M13 regression на `982b7ad`: [143 / 443 cases](tls-materials-regressions-982b7ad.md).
  Это отдельные runs/candidates, не one-candidate M18 на `bbff69e`.
- Исторические shutdown failures `982b7ad` и `521e6af` не воспроизвелись
  в последних двух опытах, но их первичная причина не установлена. Новая finite
  диагностика размещена внутри privacy wrapper; разбор остаётся reliability debt
  в R1-B08 до финальной приёмки. Нельзя назвать его исправленным по этому pass.
- Различие throughput/latency между runners само по себе не доказывает ускорения
  кода. Это один lab profile, не месячный SLO или production capacity guarantee.
- M15/M16/M17/M19/M23, M10, independent M22 challenges 0/2, image findings
  и общий M18 остаются обязательными. Следующий этап - T18/M15.

Воспроизведение: [RB load profile](../operations/load-profile.md) и
[workflow](../../.github/workflows/kubernetes-load.yml). Стартовать на новом
разрешённом disposable hosted runner из этого commit; старый baseline не
заменяет fresh acceptance.
