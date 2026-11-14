# M11 и M12 на одном исходном proposal

В [сквозном запуске 43561580336](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43561580336/job/132346238429)
M02 остановил выполнение с `source_lock_mismatch_explicit_update_required`.
Причина установлена: добавление времени проверки в `mlsecops/datasets.py` для
offline M06 изменило закреплённый исходный файл, а `data.lock` сохранил старый
digest. После проверки всех входов lock обновлён явно. Два повторных вычисления
синтетического источника сохранили 1 915 576 байт и прежний SHA-256
`1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`.
Preflight теперь запускает `scripts.data_source_lock_qualification` до сборки
образов и создания ресурсов. При новом несовпадении сначала проверить diff
каждого входа и воспроизвести данные; CI не должен автоматически переписывать
lock. Полная проверка M02 и последующих gates после исправления ещё требуется.

В общем задании восстановления шаг `stop_sql` фиксирует идентификатор
контейнера исходной SQL, время запуска и остановки и счётчик перезапусков.
После M11, M12 и удаления кластера шаг `joint_receipt` заново читает это
состояние через Docker и сверяет его хеш. При расхождении общий отчёт
отклоняется. Для диагностики сравните состояние исходного контейнера в двух
точках одного задания. [Общий workflow](../../.github/workflows/storage-recovery.yml).

Кампания использует один hosted job, один checkout и один образ. Владелец фиксирует SHA-256 файла `evidence/release-native.json` и файла `storage-demo.json` после единственного вызова `scripts.release_native`. Первый digest отличается по смыслу от `proposal_reference`, который адресует подписанный envelope в хранилище. В обоих gate должны совпасть и digest файла, и ссылка на proposal. Пример вызова и teardown находятся в [отдельном workflow](../../.github/workflows/shared-serving.yml).

| Момент | Команда или функция | Обязательные входы и выход |
| --- | --- | --- |
| Сразу после фиксации proposal и до остальных долгих операций | `python -m scripts.shared_serving_native actual` | Передать одинаковый digest proposal в `M11_PROPOSAL_SHA256` и `M12_PROPOSAL_SHA256`, digest storage demo в `M11_DEMO_SHA256`. Шаг публикует `sha256` раннего пакета |
| После actual и штатной остановки исходного SQL, до teardown, в том же job | `python -m scripts.shared_serving_native controlled` | Те же три входа плюс `M11_M12_ACTUAL_SHA256` из раннего шага. Шаг публикует `sha256` позднего пакета |
| После controlled, пока доступны кластер и необходимые локальные маркеры | Два вызова `python -m mlsecops.acceptance` с `--gate M11` и `--gate M12` и отдельными output | Добавить `M11_M12_NATIVE_SHA256` из позднего шага. Каждый gate самостоятельно читает и проверяет пакеты. Совместный режим несовместим с одиночным `M12_EARLY_SHA256` |
| После подтверждённых SQL stop и cluster teardown | `python -m scripts.shared_serving_receipt` | По тем же pin сверить оба сохранённых отчёта, 11 первичных файлов, идентичность candidate, evaluation, model, subject, proposal, image, source и permit. Выход содержит SHA-256 отчётов и фактические времена |

**Исходное окно.** Ранний шаг проверяет подпись исходного proposal, подпись evaluation и её полное совпадение с данными владельца. Production-путь должен вернуть `release_assurance_required`. После provisioning второй authority и reference inference оператор выдаёт один qualification permit до минимума из `issued_at + 600` и исходного `proposal.expires_at`. Начало actual должно следовать за выпуском proposal. Завершение actual вместе с возвратом ownership должно попасть в срок permit. При недостатке времени, потере байтов или смене runner attempt шаг останавливается.

**Первичные наблюдения.** Исходная M11 выполняет живую ротацию корня, затем baseline, outage, blackhole, смену policy, раздельные необратимые отзывы и два холодных отказа. Baseline на primary содержит золотые предсказания и полную HTTP-матрицу M12. Каждый authority имеет собственный SQL store, endpoint, CA, volume и историю. Обе стороны явно принимают один следующий trust root. После отзыва модели на peer primary сохраняет состояние. После отзыва ключа на primary peer сохраняет состояние. В каждой фазе проверяются снимки SQL-хранилища модели и promotion journal. При передаче позднему шагу оператор заново читает обе authority и SQL snapshot. Обычные контролируемые тесты продолжают работу на действующем ключе primary и проверяют ещё одну ротацию. Финальный peer readback должен совпасть с ранним.

**Две приёмки.** M11 применяет свои проверки trust trace, replay, revoke, approval expiry, rollback и независимых signer rotations. M12 проверяет исходные 62 записи по их идентификаторам, типам и ожидаемым значениям, включая оба digest permit, затем запускает свою полную controlled contract suite и проверяет ordinary CLI до approval, после approval и после revocation. Полный baseline остаётся в первичных файлах обеих приёмок. Поздний пакет с собственным `actual_inference` отклоняется.

**Хранилища после M17.** Исходный Docker PostgreSQL останавливает `scripts.m17_recovery_native stop`. Сохранить его локальные маркеры и файлы proposal, evaluation и ключей, кластер модели и обе trust authority. `late` читает журнал и таблицы модели через `kube_storage.admin`, а `lookup` использует pinned файлы и проверяет владельца кластера. Контролируемые signer rotations M11 создают и удаляют собственные временные PostgreSQL. Qualification workflow сверяет digest исходного container ID, StartedAt, FinishedAt и RestartCount до late и после обеих приёмок, с `Running=false` и `Status=exited` в обоих наблюдениях.

Границы доказательства задаёт конкретный source и конкретная попытка. `release_ready` остаётся false. Общая кампания M18 и два внешних challenge для M22 требуют своих доказательств.

## Измерения 14 ноября 2026 UTC

В [job 132338202094, run 43558988807](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43558988807/job/132338202094) на `b03535d518a286578784b0722d4d1850ce5c7676`, attempt 1, штатные M11 и M12 прошли на одном proposal. Job длился 26 мин 58 с. Исходный Docker SQL был остановлен перед late. Это отдельная hosted qualification порядка стадий. Интеграционная попытка родительского storage-recovery имеет собственный source и evidence.

| UTC | Наблюдение |
| --- | --- |
| 04:57:06 | Выпущен proposal с исходным сроком до 05:27:06 |
| 04:58:53.372 | Начат actual. Последовательно пройдены root rotation, HTTP matrix, outage, blackhole и policy change |
| 05:05:09 и 05:05:39 | Начались отзыв модели на peer и отзыв ключа на primary. Проверены cold denials и возврат ownership |
| 05:07:03.318 | Завершён actual, остаток исходного окна 20 мин 02.682 с |
| 05:07:06 | Подтверждена остановка исходного SQL. Начался late |
| 05:21:21 | Late завершён. Пройдены ordinary serving, expiry, replay, rollback и controlled rotation |
| 05:22:02 и 05:22:10 | M11 pass, 149 критериев. M12 pass, 201 критерий, в том числе 62 native |
| 05:22:11 | Совпал digest остановленного контейнера до late и после обеих приёмок |
| 05:22:13 | После подтверждённого cluster teardown завершена повторная сверка двух отчётов |

| Сохранённый идентификатор | Значение SHA-256 |
| --- | --- |
| Файл исходного proposal | `6b9e0c0bba278adf09ddc9e00434de6c91373d580f033a27534e1f89947475b2` |
| Подписанный proposal | `896cd406ad16707915fae3b1b7e6be4a21a3ccbb4b6678e0f256c1cb2c1bc7c8` |
| Qualification permit | `35ef6ec89c4729575191ab8c5195932b8364385d71c32234527440b955b944f0` |
| Полный baseline probe | `3f3aed5d1d25e494ce620b25978bb290ffae5ab4ddad56320cb3fcbe56c5fd2c` |
| Ранний пакет | `608fc72a0ae561a7ff57fe2e14266a3df919d001533f8018814cb627fa796885` |
| Поздний пакет | `47e2104f6df32102c5857e6cb6c96d5a8d6e51fa3a8b7f8d68df2ac5c14b1b01` |
| Состояние остановленного источника | `b419b22acd3789f5aa143da0f5d8b2a8663f8f9edf7635b6ba18727e6a3b91d9` |
| Отчёт M11 | `20bef3063a79e37dbc1590908e4afb21ebcb00809ebb181c4b6b60a2cdb1d74c` |
| Отчёт M12 | `1b486d1df48c19da1b43e6ee447b7c8eafc5bcde9d1462354f0be0a46e87fde4` |

Ранее [job 132333532292, run 43557494875](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43557494875/job/132333532292) на `0f9993e9e991826c9caa785cd5f7900c987aa4aa` также прошёл M11 (149) и M12 (201) в одной попытке. Там исходный SQL был остановлен после M12. Сверка между двумя gate выполнена отдельно внутри каждой попытки.

## Проверенный общий запуск на 89c5107

[Задание 43560587341](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43560587341/job/132343145276)
завершилось успешно на `89c51079acb60d95a0ef846cae09c0b535b4c6bb`.
13 отчётов относятся к одному кандидату `27b61a4cadf6119d1852b7978c788b2099bc28454222cb574cc9dd4b414b7ef2`.
Их SHA-256 пересчитаны по исходным JSON из журнала (канонический JSON и завершающий LF)
и совпали с delivery receipt. Проверены source revision, source fingerprint,
candidate/evaluation, а для M10/M11/M12 также модель, proposal и release subject.
Все cases этих отчётов имеют статус pass.

M11 проверил 149 условий, M12 - 201, включая 62 native cases.
Отказ actual candidate в production сохранил причину `release_assurance_required`.
M17 восстановил 1 000 точных прогнозов за 6,010975338 с; RPO составил 1,509349 с.
Это измерения одного лабораторного запуска. Trigger расписания был контрольным;
суточная периодичность не наблюдалась.

После успешной остановки исходной SQL и удаления кластера offline replay заново
проверил исходные материалы M01/M02/M03/M07/M10, включая подписанные отказы M10.
Хеш frozen inputs равен
`f684f40036c24e6ca13c893249ca5d5d90da7444bcc0df4d01713f1c360beb91`.
Новый full-M18 verifier и M04/M06 replay, добавленные позднее, этим запуском
не проверены.

| Gate | SHA-256 исходного отчёта |
| --- | --- |
| M01 | `eebddcd0c79d311eabf7cb1ea78bf52da3417f17ee0f7d8d03309b3ae2335641` |
| M02 | `044556062929ffc3dbee4916e7ca3979b66c2af3fa168503539c962987ef59d0` |
| M03 | `a2dc0171defda19e96448b4dc1a9b736a819cf39317b9023bbcdb9cb394e64c2` |
| M06 | `e71a8f3b0ea0c96b20ff3146ffa565a095c8dc3fb0a06a1cb66e7528cdb52271` |
| M07 | `53f77f71f31267dc1231a38026c7a9899f75834116b791714f5530bfa367c5d0` |
| M08 | `35e21b2f4e319db6b431426c151a2e417aa35e20bbecdfac1f0ad3141968e0bc` |
| M09 | `274bebd02b10d7cbf33f45e46167af67fc25a137b1cac5fa4a4679220980265b` |
| M10 | `0cae4ee5a93f266fb8eef083d24a3e154c9c4a1947698ad5202c85cc374090ee` |
| M11 | `897497885f0fc5a9b009846380fcc9931f6730a2f1df2ca72fa69e96e58a4c47` |
| M12 | `0e8774f17e665e5f5504a0238ef1a2031d7471fda65d84df3e749b61d2a879a8` |
| M16 | `2cbe07d150af8abaf11302885db1a5d7eac2ba20d08d429e528b73de39b23cad` |
| M17 | `1b21022e584033b41846e8c67217b888c21377cf850240ce3a00c8513d2720e7` |
| M19 | `c80f118af874b5620d500e911ac06e6d8e4897d978d1ada2b62c5e931c797d06` |

M18 вернул `inconclusive`: на этом кандидате отсутствуют отчёты
M04, M05, M13, M14, M15, M20, M21, M22 и M23. Другие кандидаты не заполняют эти
пробелы. Этот запуск не является завершённым R1 и не разрешает production release.
