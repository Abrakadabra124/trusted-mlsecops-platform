# Проверки общей TLS/session логики на 982b7ad

Source: `982b7ad9cddc47c6c37e922ec37335fb53d2ce8e`.
Дата native запусков: 2026-11-06 UTC. Все результаты относятся к synthetic lab.

## Изменение и controlled checks

`storage.connection_materials` читает client settings, CA, certificate и key
по одному разу за validation. Fingerprints вычисляются из проверенных байтов.
Каждый reuse повторяет чтение; новый connect дополнительно проверяется после
установления соединения. Trust documents, signatures, version и revocation
не кешируются. `connection_parameters` сохраняет прежний вызываемый интерфейс.

70 controlled tests прошли без skips за 17.076 s. Проверены повторное
использование и expiry, изменённые файлы/role/host, отказ до query и закрытие
предыдущего соединения, новая identity при изменении JSON whitespace,
граница 65536 bytes, отсутствие повторного чтения одного файла внутри validation,
закрытие Engine и восстановление диагностических обёрток.
Coverage проверенного набора: `connection_materials` 25 statements / 12 branches,
Session 51 / 16, diagnostics 99 / 22, все 100%.
Это function scope для storage, не покрытие всего storage-модуля.

Чистый remote checkout того же commit: 70 tests, 0 skips, 15.386 s,
Git tree clean. Использован прежний locked Python 3.12.15 environment;
это не новая установка dependencies. Локальные Docker/WSL/Kubernetes/SQL
не запускались.

## Native регрессии

| Gate | Run | Результат |
|---|---|---|
| M11 | [42291878143](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42291878143) | pass, 143 cases; 670 подготовительных Linux method executions с повторами, 0 skips |
| M13 | [42291882402](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42291882402) | pass, 443 cases; 257 подготовительных Linux method executions, 0 skips |
| M14 | [42291837843](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42291837843) | fail на shutdown; полноценный baseline отсутствует |

M11 actual blackhole first completed 503: 12.550908126 s;
actual outage: 59.767969511 s. Обе величины относятся к началу fault,
не к отдельному HTTP request timeout. Ротация/отзыв/clock checks прошли.

Для M11 и M13 пересчитаны method/source materials из Git archive и policy digest.
M11: 156 runtime blobs и 442 method/material blobs.
M13: 442 method/material blobs.

Canonical primary SHA-256:

- M11: `94391152bfb2154a349c3736a35f7f011b3931fab6f83f2f5697c5dbfc26ab59`.
- M13: `64c0ca11f007349aec47d32c7cb7fadf88c5b990e1dbe00ffdf1e68b3fdac02e`.

Проверенная cleanup по UTC: M11 source SQL 21:13:49, cluster absence 21:13:54;
M13 20:57:18 / 20:57:23; failed M14 20:57:44 / 20:57:48.
Raw logs, primary packets и credentials не включены в публичный репозиторий.

## Ограничения

Три запуска используют отдельные candidates/окружения на одном source.
Их объединение не является one-candidate M18. Нет принятого p95 для этого
M14, поэтому ускорение по native latency здесь не заявляется.
Shutdown failure расследуется по [RB load profile](../operations/load-profile.md).
Последующий диагностический pass не должен стирать исторический fail или
объявляться доказательством устранения его причины. R1 остаётся незавершённым.
