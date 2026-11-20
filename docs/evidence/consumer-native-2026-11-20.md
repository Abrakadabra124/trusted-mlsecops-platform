# Исходный candidate в новом consumer: отказ и успешный повтор

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

При разборе [recovery](../../scripts/ci_consumer_recovery.py) на `4109c5d` воспроизведён
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
## Исправление и offline-проверка

Исправление `0da94dec7ae1c902ccd27aa0a6cffec4e22bf8d5` нормализует
полные mount-записи с обеих сторон сравнения. Все поля и duplicates сохранены,
legacy witness не перезаписывается. Дополнительно `cleanup_diagnostics`
показывает только разрешённые статические этапы SQL/cluster cleanup; неизвестные
значения становятся `unavailable`. Raw exceptions, пути, resource IDs и pins
не экспортируются. Boolean cleanup result остаётся отдельным обязательным
условием успеха.

Родительская проверка на Python 3.12.15: **101 tests pass за 20.417 s**, включая
producer wrapper. Покрытие native: 236/236 statements и 24/24 branches;
recovery: 186/186 statements и 40/40 branches. Scoped review APPROVE, отдельно
reviewer выполнил 35 выбранных tests. Эти результаты подтверждают исправление
offline-дефекта, но не причину исторического отказа. Результат отдельного
hosted replay приведён ниже; он не устанавливает причину прежнего failure.

## Порядок повторной проверки

Выполнить один новый clean-checkout hosted run с новым явно указанным source.
Не продлевать original proposal/permit windows и не переносить результат
старого candidate на новый commit.

[Порядок запуска и восстановления наблюдения](../operations/ci-consumer-native.md).

## Повтор после исправления

[Run 44655346292](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44655346292)
проверяет source `f9bf7c5af538eb34a885e82659f4ac886787efc8`. Он включает
нормализацию mounts, закрытые cleanup diagnostics и offline qualification
validation-импорта в preflight. Этот run не запускает native M13/M14/M15.
Конечное состояние [job 136020067276](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44655346292/job/136020067276)
и закрытые проекции проверены: **success**, основной consumer `status=pass`,
`stage=complete`, `cause=none`. Source проекции совпадает с указанным выше SHA.

| Участок | Проверенный результат |
| --- | --- |
| Transfer preflight | 61 tests pass за 50.475 s |
| Объединённый consumer preflight | 188 tests pass за 116.759 s; отдельные thresholds statements/branches для семи modules пройдены |
| M07 | CLI exit 0, diagnostic `status=pass`; 31 receipts slots 2-32, один `holdout_budget_exhausted`, 0 invalid receipts |
| Producer cluster cleanup | `required=1`, `verified=1`, pass |
| M11 | 149 критериев по проверенному original receipt |
| M12 | 201 критерий по тому же original receipt |
| Consumer cleanup | `sql=true`, `cluster=true`, оба diagnostic codes `none` |
| Retention и offline replay | Достигнуты обязательные проверки перед `stage=complete`; original receipt совпал с replay |
| Source SQL stop | success с marker/offline проверкой |
| Повторный consumer cleanup CLI | pass, SQL/cluster снова подтверждены |

Job выполнялся 01:40:42-02:25:37 UTC, 44 min 55 s. Основной consumer шаг:
01:56:14-02:25:32 UTC, 29 min 18 s. Отдельный cleanup CLI завершился
02:25:35 UTC. Один TLS timeout наблюдателя был перепроверен через API;
нового dispatch из-за него не создавалось.

SQL cleanup означает подтверждённую остановку записанного контейнера,
а не удаление его network/volume. Для cluster проверены отсутствие записанных
Docker IDs, owned volumes и имени kind. Retention/replay идут после очистки
инфраструктуры, пока owning file context ещё открыт; затем context удаляется.
Второй native replay после удаления файлов consumer этим driver не выполняется.
Такой сценарий отдельно проверен offline qualification самого retention helper.
Приватные primary, pins и ключи не экспортировались с disposable runner.

Это успешный original-candidate consumer M11/M12 внутри одного hosted job,
не cross-job transport и не завершённый R1. `release_ready=false` сохранён.
M13/M14/M15, общий candidate/M18, image audit blockers и независимые M22
challenges остаются обязательными. Native success на `f9bf7c5` не переносится
на более новые commits и не доказывает точную причину отказа на `377cb4a`.
