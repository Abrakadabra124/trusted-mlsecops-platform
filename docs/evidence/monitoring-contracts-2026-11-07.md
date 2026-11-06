# T18/M15: статистика, агрегирование и signed delayed labels

Результат: **component pass**, полный M15/R1 остаётся **inconclusive**.
Source `7969d32e5eed2e78e0944444957c4231500a4d42`,
[CI 42312591898](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42312591898),
job `128217408356`, success. Это проверки компонентов, не наблюдение работающего
candidate endpoint или подтверждение alert delivery <=120s.

## Что проверено

- Frozen reference связан с model/bundle/dataset/evaluation/source digests.
- Fixed bins/PSI, два последовательных достаточных окна одной серии,
  10 clean controls, 999 versus1000, zero bins и abstentions.
- Exact replay идемпотентен; stale/conflicting/overlapping windows отклоняются;
  sequence/time gaps и недостаточные окна не подтверждают прежний drift.
- Aggregator принимает только immutable serving trace с совпадающими bindings,
  проверяет batch целиком и ограничивает размер окна. Raw features и scores
  после агрегации не сохраняются.
- Private prediction ledger содержит hash observation ID и binary decision.
  Его digest включён в окно, counts и positive decisions сверяются.
- Настоящие Ed25519 signatures для delayed labels: wrong signer/kind, изменённый
  payload, чужое окно, future/expired labels, duplicate/conflicting/unmatched
  IDs и malformed ledgers отклоняются. Идентичный retry не увеличивает выборку.
- Recall drop сравнивается строго с0.05 при >=200 positives целочисленным
  выражением; этот сигнал отделён от data/prediction drift.

## Проверки и воспроизведение

| Module | Statements | Branches | Linux CI |
|---|---:|---:|---|
| `monitoring.py` | 119/119 | 46/46 | 100% |
| `monitoring_stream.py` | 93/93 | 36/36 | 100% |
| `monitoring_labels.py` | 64/64 | 30/30 | 100% |

Linux CI: 32 tests, 0 skips, 0.519s. Fresh locked installation через uv,
Python3.12.15, без SQL/Kubernetes. CI проверяет statements и branches отдельно
для каждого из трёх модулей, а не только общий процент.

Windows: 32 tests, 0 skips, 1.030s при coverage. Чистый detached checkout того
же `7969d32`: 32 tests, 0 skips, 0.412s, Git status пустой. Он использовал
существующий locked venv Python3.12.15; это проверка checkout/imports/tests,
а не отдельная повторная установка зависимостей. Команды приведены в
[ранбуке](../operations/model-monitoring.md). Lockfile и зависимости не менялись.

## Исправление предшествующего storage CI

Отдельный source `52c79bbce31ad0fe5cd02bdba7e6a765139610a7`,
[storage CI 42310400834](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42310400834),
job `128210109618`, success; owned SQL cleanup success. Проверка authority:
45 tests, 0 skips, 0.949s, 259 statements/102 branches100%. Предыдущий
`2df0220` / run42298587187 проходил42 tests, но не покрывал factory branch16->27.
Добавлены проверки host pin, сохранения document/root verification и отсутствия
fallback transport при отказе factory. Runtime trust code и fail-under100
не изменены. [Разбор и команды](../operations/trust-troubleshooting.md#отказ-coverage-после-добавления-session).

## Обязательное продолжение

Подключить collector к реально завершённым HTTP predictions, создать и проверить
signed reference из actual candidate materials, реализовать scheduler,
authenticated sink/receipt, dashboard и bounded retention/restart behaviour.
Затем показать реальные clean/shift/delayed-label окна, telemetry outage,
feedback quarantine и отсутствие auto-promotion на свежем candidate. Повторить
M13/M14 для изменённого serving path и выполнить полный source-bound M15.
Эти шаги не выполнены данным CI; M18 остаётся последней общей приёмкой.
