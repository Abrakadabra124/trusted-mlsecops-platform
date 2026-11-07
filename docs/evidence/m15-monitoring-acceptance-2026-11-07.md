# M15: общая приёмка мониторинга и обратной связи

Неделя 10 «Нагрузка и ML monitoring», T18. **M15 принят для synthetic CPU профиля. Полный R1 не принят.**
Source [bd9028651cc8b2f42462995cae3e682bb0c20369](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/bd9028651cc8b2f42462995cae3e682bb0c20369).

[Native run 42339902029](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42339902029),
job 128305052251: **success**. Сверены полный acceptance envelope, source/image,
canonical policy, exact method IDs и terminal cleanup. [Finite summary](m15-monitoring-acceptance-summary.md)
содержит проверенные метрики и digests.

## Подтверждённый результат

| Проверка | Результат |
| --- | --- |
| Полный M15 gate | 167 pass: 160 обязательных executable contracts и 7 aggregate criteria |
| Native workflow | 142 component methods + 8 gate methods + 160 fresh contracts = 310 executions с повторами, без skips |
| Наблюдения | 12000 actual ONNX predictions через 120 HTTP batches, по 1000 observations в каждом из 12 окон |
| Clean control | 10 окон без alarm; это не production false-positive estimate |
| Drift | Два последовательных shifted окна, отдельные data/prediction alerts |
| Delayed labels | 200 подписанных positive labels, ухудшение recall, отдельный quality alert; повтор принял 0 новых labels |
| Доставка | 3 signed receipts; максимальная задержка 0.437768848 s при обязательном лимите 120 s |
| Feedback | 10 actual prediction claims, 1 quarantine row, retry без новой строки, curator readback |
| Полномочия | 15 direct SQL denials, protected tables и promotion state не изменились |
| Восстановление evidence | После shutdown worker, SQL stop/readback и cluster absence primary packets перечитаны; metrics совпадают |
| Новая gate logic | 183/183 statements и 24/24 branches, 100% в каждом из двух modules |

SQL stop/readback **04:52:17 UTC**, cluster absence **04:52:25 UTC**,
post-cleanup replay **04:52:28 UTC**. Все шаги отдельно подтверждены Jobs API;
один зелёный acceptance step не использовался вместо проверки teardown.

Canonical primary SHA-256: `9f7cf68459c2eefd8a6fc6c32841d4f153dc0096e4ea41ce2708632ba6431fd9`.
Method-material hash: `95baf4a800dd32354b69086b4e7803489ea701738bcdd137bbfbcc1f82be28e4`.
Проверены 487 method blobs и 172 runtime blobs exact Git archive. Из AST source
восстановлены все 160 method IDs, controlled report hash и семь aggregate IDs;
они точно совпали с полным envelope. Метрики совпали с offline post-cleanup report.

## Что соединено

[Gate](../../mlsecops/monitoring_gate.py) заново исполняет обязательный
[inventory](../../scripts/monitoring_contracts.py), создаёт свежую actual campaign,
фиксирует source/image/time и сверяет signed proposal, model, qualification permit,
lineage и approved validation. Подпись frozen reference, digest/size/rows validation
и шесть candidate artifacts связывают monitoring с фактической моделью.

Existing verifier повторно строит 12 окон из 120 HTTP batches, проверяет десять
clean controls, две последовательные shifted windows, delayed labels и подписанные
receipts. Это проверка primary records; количество alerts из произвольного JSON
не является достаточным доказательством. Feedback проходит обычные submit/retry
и curator inspect, остаётся в quarantine, не становится approved dataset или
ground truth. Проверяются прямые SQL denials и неизменность защищённых таблиц
и promotion state.

Live source verification выполняется до остановки SQL. Отдельный offline шаг
после cleanup перечитывает сохранённые monitoring/feedback packets, exact hashes
и конечные metrics относительно принятого private observation. Он не имитирует
повторное чтение остановленной SQL и не восстанавливает истёкший permit.

## Контрактные проверки и чистое воспроизведение

- RED: отсутствие модуля gate воспроизведено до реализации.
- Локально: 8 методов, 0 skips, 21.765 s; gate/inventory 183 statements и 24 branches,
  100% в каждом модуле. Проверены stale/cross-candidate inputs, неполный inventory,
  изменённые primary/artifacts, подписи и validation bindings, отказ source/method
  consistency, private mutation и неуспешный offline replay.
- Чистый Windows checkout exact source, отдельный venv из lock-файла: 8 методов,
  0 skips, 17.812 s, Git status clean. Локальная инфраструктура не запускалась.
- [Contracts 42339901861](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42339901861)
  success: 142 + 50 + 8 + 77 + 52 = 329 Linux method executions, без skips.
  Новый gate/inventory подтвердил 183/183 statements и 24/24 branches.

## Воспроизведение

Переносимые контрактные тесты из чистого checkout:

```sh
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.monitoring_gate_qualification
```

Полная приёмка требует разрешённого owned disposable Linux runner:

```sh
uv run --locked python -m scripts.monitoring_contracts
uv run --locked python -m mlsecops.acceptance --gate M15 --profile local-cpu --state .runtime --output .runtime/evidence/M15.json
```

[Workflow](../../.github/workflows/kubernetes-monitoring.yml) выполняет bootstrap,
полный gate, always cleanup и post-cleanup replay. [Ранбук](../operations/model-monitoring.md#общая-m15-acceptance-и-восстановление-после-отказа)
описывает диагностику, ownership, сохранение evidence, rollback и эскалацию.
Raw HTTP records, features, keys и private packets остаются вне публичного отчёта.

## Границы результата

Это synthetic CPU профиль. Десять clean windows не оценивают production
false-positive rate; PSI/recall thresholds требуют калибровки на реальных данных.
Qualification permit не разрешает production promotion и не заменяет actual
assurance. Epoch/restart contracts проверяют fail-closed reuse и explicit history
loss; восстановление всех observations/labels и PV durability не заявлены.

Свежие M13 и M14 ранее приняты на отдельных candidates. M15 не превращает их
в M18 на одном release candidate. Independent M22 остаётся 0/2; M10/M19,
M16/M17/M23, image findings и другие обязательные R1 blockers сохраняются.


M15 закрывает технический gate качества и обратной связи. Общий пункт T18 шире:
operator JSON endpoint существует, но отдельная визуальная dashboard ещё не
поставлена; security-event delivery относится к обязательному M23. Эти задачи
не объявляются завершёнными по M15 pass. Следующий шаг - завершить операторское
представление T18, затем T19/M16 и остальные CP4/CP5 gates.
