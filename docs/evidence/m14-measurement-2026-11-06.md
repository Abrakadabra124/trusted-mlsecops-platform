# M14: проверка клиентского измерителя, 2026-11-06

**Компонент проверен. Native M14 и R1 не приняты.** Здесь нет фактического
измерения latency модели, CPU/RAM настоящих containers или overload recovery.

## Проверенный source

- Commit: `41127b12f92a5fdb1f9d713e74c55c782216919e`.
- [Linux workflow 42255604415](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42255604415),
  job `128021849665`: success. Первичные job logs прочитаны отдельно от статуса workflow.
- 21 controlled test, 0 skips, 1.281 s на Linux. HTTP fixtures действительно
  открывают только временный loopback listener; ML/Kubernetes в этом запуске нет.
- `mlsecops/load_golden.py`: 45/45 statements, 12/12 branches.
- `mlsecops/load_measurement.py`: 107/108 statements, 37/38 branches.
  Неисполненная ветка - внутренний guard расхождения begun/completed count;
  cancellation отдельно проверена и не возвращает успешный report.
- Ruff и документационные проверки CI прошли.

## Что подтверждено

Клиент учитывает начало и завершение каждой попытки, отделяет прогрев по start
timestamp, сохраняет tail, ошибки и таймауты. Проверены десять concurrent tasks,
ограничение числа попыток, отмена, bounded HTTP body/headers и абсолютный timeout.
Подмена 200-ответа, неверный digest/schema/score и даже truthy non-boolean validator
не превращаются в успешное предсказание. Результат содержит исходный client profile,
counts/RPS/quantiles/histogram, но не credentials, request IDs, body или exception text.

Статистические fixtures подтверждают точные границы p95/p99 и 5xx, наличие всех
клиентов в warmup/measurement и полный observation window. Значения latency в
этих fixtures искусственные и не являются результатом нагрузки настоящей модели.

## Воспроизведение из чистого checkout

Выполнен новый clone опубликованной ветки, проверен точный HEAD `41127b1`, создано
новое `.venv` через `uv sync --locked --no-build --python 3.12.15`.
Windows: 21 test, 0 skips, 1.441 s; после тестов `git status --porcelain` пустой.
Из-за разных дисков uv использовал copy вместо hardlink; это не изменение lockfile.

```powershell
git clone --single-branch --branch codex/cp4-m14-load-20261106 https://github.com/Abrakadabra124/trusted-mlsecops-platform.git m14-check
cd m14-check
git checkout --detach 41127b12f92a5fdb1f9d713e74c55c782216919e
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.load_golden_qualification scripts.load_measurement_qualification
git status --porcelain
```

Этот exact-source report не распространяется автоматически на последующий
resource parser, native coordinator или будущую оптимизацию. Полный путь нагрузки,
подтверждение ресурсов/ownership, controlled overload, cleanup и M14 envelope
должны пройти отдельную native проверку. [Метод](../decisions/0056-load-measurement-profile.md)
и [ранбук](../operations/load-profile.md) сохраняют исходные требования.

## Следующий проверенный компонент: resource parser

Source `1706fc36cb5fe87b8c99bfe3544861517b6c5c9c`,
[workflow 42256745055](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42256745055),
job `128025828394`: success. Первичный job log проверен через GitHub connector
после TLS handshake timeout при первой попытке загрузки через CLI.

29 tests, 0 skips, 1.146 s на Linux: прежние 21 и 8 новых resource contracts.
`scripts/load_resources.py`: 66/66 statements и 26/26 branches; показатели
двух предыдущих модулей сохранились. Проверены exact PodRef/container,
missing/stale/future data, reset/change, cached readings, двустороннее покрытие
120-секундного окна и максимальные интервалы между наблюдениями.

Тот же свежий clone переведён на exact `1706fc3`; dependency descriptors
(`pyproject.toml`, `uv.lock`, `.python-version`) совпали с `41127b1`.
Повторный locked sync в созданном ранее чистом окружении и 29 Windows tests
прошли: 0 skips, 1.434 s. Import path указывал на reproduction checkout,
`git status --porcelain` остался пустым. Это не второе заново созданное окружение.

Для воспроизведения ресурсного компонента использовать `1706fc3` и добавить
`scripts.load_resources_qualification` в unittest command выше. Источник
resource fixtures искусственный: живой Kubelet в этих тестах не опрашивался.
Native workload, coordinator, overload recovery и полный M14 остаются открытыми.
