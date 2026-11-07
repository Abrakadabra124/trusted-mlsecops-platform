# Fresh M13: monitoring и feedback

Дата 2026-11-07, Неделя 10 «Нагрузка и ML monitoring», T18.
**M13 принят для synthetic serving с включёнными monitoring и feedback. Полный R1 не принят.**
Исторический M13 `b03a5d9` не покрывает добавленные operator ingress и feedback.
Этот increment соединяет их с фактическим candidate; полный R1 остаётся открытым.

Source [582b34c1b5683d4005ee4e847ab5ba7cd0081116](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/582b34c1b5683d4005ee4e847ab5ba7cd0081116),
[M13 run 42337722963](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42337722963),
job 128298329207: **success**. Проверены полный envelope, exact method IDs,
source/policy/method hashes из Git blobs, завершение cleanup и offline ingress replay.
Машиночитаемый результат: [finite summary](m13-monitoring-feedback-summary.md).

## Подтверждённый результат

| Проверка | Результат |
| --- | --- |
| M13 | 491 pass: 483 обязательных метода и 8 aggregate criteria, без пропущенных, лишних или повторных IDs |
| Linux executions | 287 qualification methods + 483 preflight + 483 fresh gate contracts = 1253, с повторами, без skips; это не 1253 независимых теста |
| Gate и inventory | 13 tests; 161/161 statements и 24/24 branches, 100% |
| Три новых/изменённых privacy helpers | 28 tests; каждый module >=95% statements и branches, точные значения ниже |
| Actual candidate / controlled CLI | 31 / 22 native checks, разные subjects и полномочия |
| Monitoring | 1014 observations; матрица добавила 1000 через 10 HTTP batches |
| Operator API | 4 unauthorized requests, 9 отклонённых labels/framing, accepted label 1 и retry 0; quota burst 7 accepted / 13 limited, затем recovery |
| Audit и metrics | 35 observed responses, 108 events, 18 correlated requests; operator matrix добавила 40 events; 69 разрешённых metric series |
| Feedback | 3 успешные и 8 отклонённых ordinary CLI команд; 1 claim / 1 quarantine row, retry без новой строки |
| Разделение полномочий | 15 прямых SQL отказов; защищённые таблицы, promotion и состояние после rejected commands не изменились |
| Service outputs | 5 закрытых окон, 5 обнаруженных leak controls и 5 перечитанных private packets |
| Worker | Terminal stream проверен, native stderr 0 bytes, отсутствие worker подтверждено |
| Clean Windows checkout | 41 test, 0 skips, 8.140 s, отдельный venv из lock-файла, Git status clean |

SQL stop/readback завершён в **04:23:17 UTC**, удаление owned cluster с проверкой
отсутствия в **04:23:22 UTC**, offline replay новых ingress packets в **04:23:23 UTC**.
Все три шага отдельно подтверждены Jobs API. Offline replay не выполняет live SQL
или CAS чтение после остановки базы: он перепроверяет сохранённые байты новых
monitoring/feedback packets относительно уже принятого private observation.

Canonical primary SHA-256: `807abc51af651950dcc77e52962ac1fecb6586e0840c8f991d1c38feed3e127f`.
Method materials: `8f9d03b524469deca544a653a252fd29c2324654f52d26bebf417522f141aa95`.
Проверены 484 method blobs и 171 runtime blob из exact Git archive. Policy digest
считается от canonical JSON, а не от форматированного файла; Windows CRLF не
подменяет исходные Linux bytes. Все pins приведены в finite summary.

## Что изменено

- Privacy probe использует ordinary configured monitoring Runtime и signed sink.
  Frozen reference строится из approved validation того же model/bundle отдельным
  worker. `monitor-worker.json` и `monitor-reference.json` добавлены к четырём
  существующим candidate artifacts и перечитываются по точным hashes.
- Матрица operator API из [предыдущего компонента](monitoring-privacy-2026-11-07.md)
  выполняется внутри полного capture lifecycle. Старые девять input canaries
  остаются в HTTP/worker/service/FD scans. Collector должен получить1014obs:
  четыре успешных golden batches по3, два single-row privacy requests и1000 новых
  наблюдений. Direct engine calls, 401/429/503 и operator status не считаются.
- Host повторно проверяет monitoring proof, actual reference, epoch, счётчик,
  подписанные receipts и finite summary. Shutdown scheduler обязателен.
- Первый действительно admitted HTTP200 из retained audit связывает feedback с
  actual model/bundle/request, row0. Короткий M13 профиль содержит1claim;
  прежний отдельный M15 профиль с10claims сохранён.
- Запускается ordinary `python -m mlsecops.feedback`: submit, retry, curator inspect
  и8 отказных команд. Захватываются оба полных ограниченных потока вывода до exit.
  Проверены malformed/oversize JSON, лишние поля, неверная label, duplicate record,
  отсутствующий файл, неправильная роль и неверный reference. Непроверенные claims
  остаются только в quarantine, не становятся ground truth или training dataset.
- Исходная SQL дополнительно проверяется по owned container identity, времени
  старта и runtime logging settings. Закрытое окно Docker stderr имеет start/end,
  неизменный prefix, девять canaries и положительный leak control. Чужой container,
  stdout вместо ожидаемого stderr, restart, потеря начала и недоступный capture
  не дают pass. Это пятое service window, дополнительно к четырём cluster windows.
- После отрицательных CLI cases source tables и cluster promotion snapshot должны
  совпадать с состоянием после единственной разрешённой quarantine insert.
  Existing15 direct SQL denials и запреты использования feedback как authority сохранены.
- После остановки SQL и удаления кластера отдельно перечитываются новые ingress
  packets и hashes относительно уже принятого private observation. Этот offline
  шаг не объявляется повторным live CAS чтением после отключения базы.

## Локальные доказательства перед hosted запуском

28 новых/смежных методов прошли без skips за6.322s. Coverage: monitoring privacy
144/144statements63/64branches; feedback privacy92/92 и26/26; source SQL privacy
89/90 и29/30. Gate/inventory13tests pass,161/161statements24/24branches.
Проверки не запускали локальные Docker, WSL, Kubernetes или SQL.

Контроль отказа запуска второго reader thread подтвердил, что только собственный
child завершён, pipe descriptors закрыты. Existing `binary_command` по-прежнему
отказывает при nonzero exit или stderr; новый `binary_streams` позволяет проверять
ожидаемый отказ ordinary CLI, не отбрасывая его diagnostic stream.

Полный Windows запуск собрал483метода за55.894s:46skips,1failure и9errors в
Linux `runtime_bootstrap` tests (`resource`/native privacy initialization).
Этот Windows запуск **не является pass M13**. Последующий hosted inventory
исполнил все 483 метода без skips; вместе с 8 aggregate checks приняты 491 case.
Отказ Windows сохранён как ограничение платформы, проверки не отключались.

## Смежная M15 regression

[Contracts 42337722781](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42337722781)
прошли: 142 + 50 + 77 + 52 теста, без skips.
[Native M15 42337722795](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42337722795)
также завершился успешно: 12000 observations, 10 clean и 2 shifted windows,
3 signed receipts, максимальная задержка 0.427241999 s; feedback 10 claims / 1 row,
15 SQL denials, retry и защищённое состояние не изменились.
SQL cleanup 04:20:29 UTC, cluster absence 04:20:33 UTC, retained replay 04:20:34 UTC.

Это отдельный candidate на том же source: M15 image
`sha256:1afe053ed9258e5add5a15e152bf802dfd0bfe3d77cd6af8a74f2a95afecc80d`,
M13 image `sha256:51d86940e52dbcb60ca2aedb9c6d43bebe8b66f7c2334b43fa12d113970785e8`.
Разные digests не доказывают bit-for-bit reproducibility и не составляют M18
на одном candidate. Полный M15 пока имеет `inconclusive`; следующий шаг - его
общая acceptance, затем остальные обязательные CP4/CP5 gates. Independent M22
остаётся 0/2, M10/M19 и остальные release blockers не закрыты.

## Воспроизведение

На разрешённом disposable hosted Linux runner:

```sh
uv run --locked python -m scripts.privacy_contracts
uv run --locked python -m mlsecops.acceptance --gate M13 --profile local-cpu --state .runtime --output .runtime/evidence/M13.json
```

Ownership/bootstrap/teardown и offline replay выполняет workflow
`kubernetes-privacy.yml`. Raw packets, input canaries, keys и logs остаются в
`.runtime`, в публичный отчёт попадают только finite counters и разрешённые
source/candidate bindings. Диагностика: [M13 ingress playbook](../operations/kubernetes-privacy.md#m13-monitoring-и-feedback).

Для переносимой части без локальной инфраструктуры на exact source:

```sh
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.monitoring_privacy_qualification scripts.feedback_privacy_qualification scripts.source_sql_privacy_qualification scripts.feedback_native_qualification scripts.privacy_gate_qualification
```

Этот subset содержит 41 метод. Полный M13 требует разрешённого disposable Linux
runner и всех 491 criteria. Qualification permit и отдельный controlled release
проверяют инженерные механизмы, но не заменяют actual production assurance.
Проверка не доказывает защиту от администратора host, injected exporters,
membership inference, сохранность истории monitoring после rollback filesystem
или пользу модели на реальных данных. Требования к purpose, retention и
независимой оценке остаются обязательными.
