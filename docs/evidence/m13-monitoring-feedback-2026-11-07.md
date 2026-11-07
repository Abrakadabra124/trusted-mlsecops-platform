# Fresh M13: monitoring и feedback

Дата2026-11-07, Неделя10/T18. **Реализовано, hosted acceptance ещё не подтверждена.**
Исторический M13 `b03a5d9` не покрывает добавленные operator ingress и feedback.
Этот increment соединяет их с фактическим candidate; полный R1 остаётся открытым.

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
Это **не pass M13**. Mandatory hosted inventory должен исполнить все483 без skips;
при успехе вместе с8 aggregate checks ожидается491case. Числа будут приняты только
после проверки фактического полного envelope.

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
