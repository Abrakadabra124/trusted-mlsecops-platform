# Исходный candidate в новом consumer: попытка 377cb4a

## Идентичность проверки

- Source: `377cb4a1bd4da95ca95779e2b573c58166b005db`.
- [Run 44648432999](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44648432999).
- [Job 135996898546](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44648432999/job/135996898546).
- Итог GitHub: **failure**. Полный native consumer не принят; M18/R1 не завершены.
- Профиль: бесплатный disposable public hosted runner, исходный synthetic
  candidate, новый SQL workspace, зашифрованный перенос внутри одного job.

Закрытые публичные проекции сверены с конечным состоянием job и exact source.
Приватные пакеты, ключи, candidate pins и исходные reports не публикуются.
Документация на последующих commits не меняет source этой проверки.

## Проверенные результаты

| Участок | Наблюдение |
| --- | --- |
| Transfer preflight | 61 tests pass, 27.118 s |
| Объединённый consumer preflight | 147 tests pass, 39.733 s; per-module coverage checks pass |
| Bootstrap | CPU runtime, producer cluster, SQL, M01, M02 и начало M21: success |
| M07 | CLI exit 0, закрытая проекция `status=pass` |
| Holdout budget | 32 attempts; 31 receipts для slots 2-32; один `holdout_budget_exhausted`; 0 invalid receipts |
| Producer cluster cleanup | `required=1`, `verified=1`, success |
| Consumer native | failure, `stage=cleanup`, `cause=rejected` |
| Consumer SQL | `cleanup.sql=true` в основной и повторной cleanup-проекциях |
| Consumer cluster | `cleanup.cluster=false` в обеих проекциях; полная очистка не подтверждена |
| Source SQL stop | success; обязательные marker/offline проверки выполнены |

M07 выполнялся с 00:49:41 до 00:58:43 UTC. Consumer выполнялся с 00:58:45
до 01:23:41 UTC. Последующий cleanup CLI завершился failure в 01:23:43 UTC.
Сетевые ошибки `gh run watch` были ошибками наблюдения: отдельные API reads
подтверждали продолжающийся тот же job; повторного dispatch не было.

## Как читать отказ

Обе consumer-проекции содержат `gate_counts={M11: 0, M12: 0}`. Эти поля
заполняются только после retention и его replay. Нули нельзя трактовать как
количество реально выполненных критериев или доказательство, что gates не
вызывались.

По проверенной последовательности [driver](../../scripts/ci_consumer_native.py)
основной `stage=cleanup` достигается после проверок M11/M12 reports и receipt.
Это вывод из control flow; исходные reports оставались приватными на runner.
Он не заменяет проверку полного consumer result: cleanup отказал, а следующие
retention/replay этапы не были достигнуты. Точные gate counts этого run не
заявляются. Общая приёмка M11/M12 в новом consumer остаётся открытой.

Текст приватного recovery exception и inspect snapshots недоступен после
завершения runner. Поэтому конкретная причина отказа пока не установлена.
Завершение disposable job само по себе не доказывает успешный exact-ID cleanup.

## Воспроизведённый дефект сравнения mounts

При разборе [recovery](../../scripts/ci_consumer_recovery.py) воспроизведён
отдельный дефект: одинаковые полные mount-словари в другом порядке приводят
к отказу identity comparison. Шесть offline-проверок показали:

1. Неизменный список разрешает cleanup.
2. Только перестановка элементов даёт RED для ожидаемого успешного cleanup.
3. Изменение `RW`, добавление дубликата и подключение volume к чужому
   Docker-контейнеру корректно запрещают удаление.
4. Driver/recovery с boundary fixtures воспроизводит наблюдаемую закрытую
   проекцию `stage=cleanup`, `sql=true`, `cluster=false`, нулевые итоговые
   counters и отсутствие retention при уже проверенных fixture reports.

Историческая возможность произвольного порядка mount points описана в
[Moby PR 53534](https://github.com/moby/moby/pull/53534). Это обоснование для
сравнения полных записей независимо от порядка, а не доказательство причины
данного run. Фактическая версия Docker daemon и его inspect snapshots здесь
не подтверждены.

Исправление должно сохранять все поля, число одинаковых записей и прежние
ID/labels; сортировка требуется для текущего наблюдения и ранее записанного
witness. Нельзя принимать новые ID или labels из текущего inventory, удалять
узел только по имени либо ослаблять проверку эксклюзивности volumes.
На момент фиксации этого отчёта исправление и следующий hosted replay ещё
не подтверждены.

## Следующее действие

Исправить воспроизведённое сравнение, проверить отрицательные сценарии и
scoped review. Добавить закрытые cleanup stage codes без raw exceptions,
путей, ID и pins, чтобы следующий отказ можно было локализовать. Затем
выполнить один новый clean-checkout hosted run с новым явно указанным source.
Не продлевать original proposal/permit windows и не переносить результат
старого candidate на новый commit.

[Порядок запуска и восстановления наблюдения](../operations/ci-consumer-native.md).
