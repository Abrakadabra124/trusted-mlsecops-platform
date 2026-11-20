# Исходный кандидат в новом consumer: M11/M12

## Назначение и границы

Этот playbook соединяет исходное обучение и оценку с новым SQL workspace,
подписанным proposal и полной совместной проверкой M11/M12. Один disposable
GitHub-hosted runner выполняет producer и consumer последовательно. Передача
проходит через настоящий зашифрованный пакет и отдельный файловый workspace.
Это проверка механизма переноса внутри одного job, не независимость двух
администраторов, не приватный межмашинный transport и не завершение M18/R1.

Запуск разрешён только в публичном репозитории на бесплатном disposable runner.
Локальные Docker, WSL, Kubernetes и SQL для этого playbook не запускаются.
Пакеты, ключи, исходные отчёты и recovery records остаются в приватной `.runtime`.
Workflow не загружает их в Actions artifacts и не передаёт через step/job outputs.
Существующий writer M21 направляется в приватный файл внутри `.runtime`,
а входы следующей стадии сохраняются отдельным приватным producer record.

## Последовательность

1. [Workflow](../../.github/workflows/consumer-candidate.yml) устанавливает
   зависимости из lock-файла, проверяет контракты и покрытие каждого нового
   security module. Версии Python, uv и Actions закреплены.
2. Producer создаёт owned cluster и SQL, выполняет M01, M02, начало M21 и M07.
   После оценки удаляется исходный cluster. SQL пока доступен для создания
   единственного исходного proposal.
3. [Driver](../../scripts/ci_consumer_native.py) проверяет clean source и image,
   создаёт исходный proposal один раз, сохраняет frozen files и M18 receipt.
   [Мост передачи](ci-candidate-transfer.md) шифрует исходную замкнутую коллекцию
   артефактов с новым случайным ключом в памяти. Контекст и хеши задаются caller.
4. SQL producer останавливается. [Consumer state](consumer-candidate-state.md)
   сохраняет исходные candidate, trust identity и proposal в новом workspace.
   Новый SQL имеет другой workspace ID, container ID и порт 15440.
5. [Импорт](consumer-candidate-storage.md) проверяет фактическое владение SQL,
   TLS identity, внешние pins и исходное временное окно. Он публикует прежние
   bytes обычным release publisher, затем перечитывает их serving identity.
   Новые подписи и разрешения для actual candidate не создаются.
6. Consumer поднимает собственный cluster и выполняет исходные actual probes
   M11/M12. Его host SQL тоже останавливается. Затем выполняются явно выделенные
   controlled tests и обычные полные acceptance gates M11 и M12.
7. После cleanup перечитываются исходные reports и shared receipt. Первичные
   материалы [сохраняются вне временного consumer workspace](m18-shared-primary.md)
   и проходят offline replay. Удаление workspace допускается после сохранения
   доказательств.

Исходные 1800 секунд proposal и требование минимум 600 секунд перед actual
проверкой не продлеваются. Исторический replay завершённых проверок не выдаёт
новое разрешение на запуск. Истечение окна означает отказ и новый полный run
с новым явно зафиксированным candidate, а не обновление timestamps в отчёте.

## Воспроизведение

Ответственный - владелец репозитория или оператор разрешённого hosted CI.
До запуска проверить exact commit, отсутствие конкурирующей кампании на том же
runner и доступность бесплатного публичного runner. Ветка qualification запускает
workflow при push; если workflow уже зарегистрирован, доступен ручной запуск:

```powershell
gh workflow run consumer-candidate.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref qualify/original-consumer-native
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --workflow consumer-candidate.yml --limit 5
```

Сверить `headSha` выбранного run с опубликованным commit. Наблюдать этот же run
до конечного состояния; timeout команды наблюдения не является основанием
повторно запускать обучение.

Если `gh run watch` завершился с `TLS handshake timeout`, отдельно запросить
`gh run view <run-id> --json headSha,status,conclusion,jobs`. Ошибка связи
оператора с API не является результатом job. Если exact `headSha` совпадает
и job ещё выполняется, восстановить наблюдение за тем же run. Не делать новый
workflow dispatch и не останавливать ресурсы из-за ошибки наблюдения. В попытке
44648432999 это произошло после успешного M07: повторный API read подтвердил
продолжающийся consumer на `377cb4a`, новый workflow не запускался.

## Диагностика отказа

Публичный результат driver содержит только фиксированный stage, категорию
ошибки, source commit, счётчики gates и состояние cleanup. Значения исключений,
ключи, приватные pins и raw stdout/stderr вложенных процессов туда не входят.
Приватная диагностика остаётся в `.runtime/evidence/ci-consumer-native-run.log`.
Её нельзя публиковать целиком или выгружать в публичные Actions artifacts.

- `proposal`, `freeze`, `seal`: проверить source/image и исходные M07/frozen
  receipts. Не заменять неподходящий report отчётом другого run.
- `consumer_sql`, `import`: проверить workspace/container identity, TLS,
  соответствие clients и pins. Неполная запись допускает повтор только тех же
  bytes в том же owned SQL и в ещё действующем исходном окне.
- `window`, `actual`: проверить фактический остаток времени. При недостаточном
  окне остановить попытку; изменение threshold или повторное подписание запрещено.
- `M11`, `M12`, `receipt`: сохранить original refusal и проверить связанные
  primary materials. Успешный импорт или отдельный probe не заменяет gate.
- `retention`: считать run неполным, даже если gates ранее прошли. Без сохранённых
  preimages нельзя заявлять воспроизводимое доказательство результата.
- `cleanup`: считать очистку неподтверждённой до проверки записанных resource IDs.
  Ошибка SQL cleanup не должна отменять попытку очистки cluster, и наоборот.

## Безопасная очистка и восстановление

Driver сохраняет recovery witness в producer `.runtime/ci-consumer-native/`
до опасных операций. Фиксируются пустой baseline, run ownership и реальные IDs.
Внешний `always()` step повторяет проверку, даже если consumer context завершился:

```bash
uv run --locked python -B -W error -m scripts.ci_consumer_native cleanup
```

Эта команда предназначена для того же hosted run и owned state. При отсутствии
record, несовпадении run/owner, замене resource ID или недоступности Docker API
нельзя трактовать неопределённость как успешную очистку. Не использовать global
prune, удаление по одному имени, восстановление секретов из логов или изменение
чужих ресурсов. При таком отказе сохранить закрытую диагностику и передать её
оператору; disposal hosted runner остаётся отдельной границей жизненного цикла.

Producer cluster имеет отдельный witness, записанный до bootstrap. Его cleanup
использует Docker IDs и закреплённые volumes, поэтому отказ Kubernetes API сам
по себе не препятствует очистке. Если source SQL bootstrap оборвался до записи
`storage.json`, SQL cleanup завершается отказом: отсутствие marker не доказывает
отсутствие частичных volume/network/container. Такой run не принимается; ручная
проверка остатков или disposal runner обязательны до заявления об очистке.

## Критерий успешной проверки

Требуются одновременно exact clean source, исходные candidate/proposal pins,
новый owned SQL с readback, полные M11/M12 pass, подтверждённый offline SQL,
очистка cluster, неизменный shared receipt после неё и retained offline replay.
Любое `skipped`, неизвестное состояние или ошибка teardown не считается pass.
Даже успешный результат этого workflow не снимает остальные M-gates,
независимые M22 challenges, image findings и обязательный финальный M18.

Native результат для этого нового workflow ещё не подтверждён. Статус будет
дополнен только после проверки конкретных source SHA, run, reports и cleanup.

Перед первым dispatch parent проверил компоненты на Python 3.12.15 с `-B -W error`:
23 SQL importer tests, 24 upstream/M18 reader tests, 66 driver/recovery tests,
24 retention tests и 20 producer cleanup tests. Каждый из пяти новых модулей
workflow покрыт на 100% statements и branches отдельно. Scoped reviews пройдены;
12 shell blocks и 5 inline Python blocks проверены на синтаксис. Это offline
qualification с контролируемыми границами инфраструктуры, не native evidence.

## Первый hosted preflight: зависимость теста от порядка импортов

[Run 44644016424](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44644016424)
на `f17f847a78cc6d5e038c32d541e8d6b6c7e66047` остановился до bootstrap.
61 transfer test прошёл. В объединённом наборе из 133 tests один test
`test_delayed_helpers_receive_independent_pins_and_replay_is_required` получил
`TypeError` из-за четырёх отсутствующих keyword-only arguments.

Причина установлена: предыдущие tests уже импортировали настоящие helpers и
Python сохранил их в package `scripts`. Подмена только `sys.modules` в driver
fixture не заменяла эти package attributes. Изолированный запуск driver suite
не воспроизводил тот же порядок импортов; это дефект изоляции test fixture.

Локальный повтор с предварительным импортом обоих helpers воспроизвёл тот же
отказ. Fixture исправлена подменой функций настоящих modules через `patch.object`
с восстановлением исходных attributes после test. Production importer, driver,
критерии, аргументы и gates не изменены. Повтор с предварительными импортами
прошёл. Новый hosted run должен подтвердить весь объединённый набор и native
цепочку; первый отказ не считается свидетельством прохождения M11/M12.

## Второй hosted run: M07 refusal после успешного preflight

[Run 44644611943](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44644611943)
на `da34657f4acc2f4221828bb394bf52d78d05700a` подтвердил исправление fixture:
61 transfer test и 133 tests объединённого набора прошли, включая per-module
coverage checks. Build, producer cluster, исходный SQL, M01, M02 и начало M21
завершились success. M07 завершился с exit code 1; consumer не запускался.

Producer cluster cleanup вернул `required=1, verified=1`, а source SQL stop
прошёл обязательную проверку marker и `Running=false`. Это первое native
подтверждение нового producer cleanup. Общая цепочка M11/M12 этим run не принята.

Точная причина M07 не установлена: отчёт и traceback остались приватными на
уже завершённом runner. Этот отказ нельзя приписывать исторической connection
ошибке без новых наблюдений. Следующий diagnostic run должен вывести только
заранее разрешённые reason codes и проверенную схему holdout diagnostics.
Raw logs, candidate pins и значения произвольных исключений остаются закрытыми;
исходный M07 exit code управляет шагом независимо от diagnostic projection.

M07 вызывается обычным `mlsecops.acceptance` CLI в отдельном процессе; launcher
передаёт прежние workspace и M21 pins через environment. Это возвращает
проверенный process boundary и создание начального inconclusive report, но
само по себе не доказывает причину предыдущего отказа. Shell сохраняет exit
code процесса до диагностического вывода и завершает шаг с тем же значением.

[Diagnostic helper](../../scripts/ci_m07_diagnostic.py) читает не более 1 MiB,
принимает только M07 status/exit-code пары и точные статические reason codes.
Неизвестная причина становится `unclassified`; неверная вложенная схема -
`diagnostic_invalid`; недоступный файл - `unavailable`. Счётчики и категории
connection failures проходят закрытую проверку. Это диагностические данные,
а не gate evidence или разрешение выпуска. 52 родительских теста на Python
3.12.15 прошли; helper имеет 45/45 statements и 16/16 branches, privacy review
одобрен. Ни эта проверка, ни восстановление CLI не заменяют новый hosted run.

## Отказ consumer cleanup после M07 pass

[Попытка 377cb4a](../evidence/consumer-native-2026-11-20.md) прошла M07,
но вернула `stage=cleanup`, `sql=true`, `cluster=false`. Отдельный cleanup
CLI также отказал. Не считать такой run принятым даже при ранее проверенных
M11/M12 reports: retention и replay после очистки обязательны.

Нулевые итоговые gate counters заполняются только после retention, поэтому
не доказывают отсутствие выполненных проверок. Сначала сверить exact source,
основную и cleanup-проекции, состояние job и доступные приватные witnesses.
При неполных доказательствах оставить причину неизвестной. Не обновлять
доверенные ID/labels из текущего inventory и не применять name-only deletion.

Offline обнаружено, что порядок одинаковых mount-записей ошибочно влияет на
ownership comparison. Корректное сравнение обязано сохранять все поля и
duplicates, но учитывать одинаковое содержимое независимо от порядка. Новый
hosted replay требуется после исправления и scoped review; успешный offline
тест не закрывает native cleanup.
