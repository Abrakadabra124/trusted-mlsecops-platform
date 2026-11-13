# T29: первичные доказательства доставки security events

Эта процедура относится к сохранению и повторной проверке доказательств M23.
Она не заменяет общий gate, независимые M22 challenges или итоговый M18.
Ответственный - оператор конкретного owned CI run; reviewer сверяет исходный
commit, методы, привязки и полноту сценариев отдельно от автора защиты.

## Что проверяется

Подпись подтверждает издателя и целостность записи. Она сама по себе не доказывает,
что источник действительно отклонил запрос, что процесс завершён или что часы
наблюдателя независимы. Поэтому первичный пакет сохраняет разные виды evidence:

- подписанный registry с публичным корнем и digest, зафиксированными оператором;
- полные producer outbox и collector journal, включая envelopes и receipts;
- выгрузку incidents, совпадающую с доставленными записями collector;
- наблюдения конкретного source decision, его subject и реального вызова;
- исходный commit, fingerprints методов и подтверждение terminal cleanup.

Общий [проверяющий модуль](../../mlsecops/security_source_evidence.py) повторно
проверяет registry, каждую подпись, очередь, полный журнал и receipt. Он требует
согласия трёх представлений записи, ожидаемого subject и фиксированного маршрута.
Неподтверждённая запись в экспортируемой очереди или collector запрещает успешный
результат. Время ingest-to-route проверяется по подписанной квитанции с исходным
порогом 60 секунд. Ожидание при отключённом collector учитывается отдельно.

Корень, digest registry и ожидаемые события передаются проверяющему модулю из
контекста оператора. Копировать эти значения из проверяемого пакета и объявлять
их независимой проверкой нельзя. Дополнительные telemetry notices могут быть
в журнале; они не увеличивают число проверенных source cases автоматически.

## Диагностика до изменений

1. Зафиксировать URL run, commit и конечный код ошибки. Убедиться, что run принадлежит
   этой задаче. Не читать или менять чужие журналы и окружения.
2. Сохранить приватные primary files вместе с исходными digest до окончания
   disposable runner. Не публиковать raw logs, токены, ключи, headers или тела
   запросов. Полные signatures и synthetic observations остаются в `.runtime`.
3. Проверить совпадение source и method materials с запускавшимся checkout.
   Изменённый метод требует нового запуска, а не редактирования старого evidence.
4. Различить `security_source_evidence_invalid` и отказ самого источника. Первый
   означает, что сохранённые доказательства не прошли проверку. Успешный exit code
   отдельной команды не исправляет пропущенную запись или потерянный receipt.

Pure regression запускается без Docker, WSL, Kubernetes и SQL из корня checkout
с подготовленным locked Python environment:

```powershell
& .venv/Scripts/python.exe -B -W error -m unittest scripts.security_source_evidence_qualification
& .venv/Scripts/python.exe -B -W error -m unittest scripts.security_source_campaign_qualification
```

Тесты используют временные синтетические ключи и реальные подписи. Они проверяют
подмену authority/subject/route, отсутствие journal/receipt/incident, лишний
incident, разногласие двух валидных receipts и превышение delivery deadline.
Это проверка кода replay, не повторение native source campaign.

В разрешённом disposable hosted Linux CI source campaign вызывается командой
`uv run --locked python -B -W error -m scripts.security_source_campaign`.
Она сохраняет `security-source-private.json` и `security-source-private.bindings.json`
в `.runtime/evidence`. Первый содержит primary observations; второй сохраняет
пины оператора, source и методы. Scanner executor в этой campaign остаётся
synthetic/in-process; отдельный HTTP collector работает настоящим процессом.
Из этого результата не следует проверка Kubernetes isolation worker.
Digest обоих файлов сохраняется в публичном конечном результате; содержимое
файлов остаётся приватным. Binding-файл не является независимой аттестацией
оператора, он сохраняет ожидаемые значения исходного запуска.

Повторная проверка выполняется на том же hosted runner после удаления fixture
и остановки её процессов. Это не долговременный архив: workflow не выгружает
private packets в публичные GitHub artifacts. После уничтожения runner сохранятся
только опубликованные конечные статусы и hashes. Для нового исследования исходных
bytes потребуется новый разрешённый run; наличие hash не заменяет доступ к файлу.

Повторная проверка конкретного сохранённого файла доступна через
`scripts.security_source_campaign.replay(path, expected=bindings, expected_sha256=hash)`.
Digest берётся из доверенного результата запуска, а bindings - из сохранённого
оператором контекста. Файл без совпадающего digest не разбирается как успешный
результат. Три source decisions и вручную созданный transport control учитываются
раздельно; ожидание collector outage не включается в online delivery latency.

В workflow [kubernetes-security-outage](../../.github/workflows/kubernetes-security-outage.yml)
inventory запускается после `storage_pipeline` и использует его существующего
SQL-кандидата. Последующий outage использует ту же модель. После остановки owned
SQL и удаления owned cluster выполняются оба replay, затем сверяются candidate,
evaluation, model, image, source revision и source fingerprint. Несовпадение хотя
бы одной привязки запрещает успешный результат связки. Эта проверка двух компонентов
не закрывает M18 и не объединяет автоматически остальные пять типов M23.

## Ветви восстановления

При review до публикации воспроизведены signed counterexamples: online-вызов
заканчивался раньше указанного в receipt route; вручную созданный transport
control подменялся событием другого зарегистрированного producer; старый
подписанный denial мог засчитываться как recovery новой outage campaign.
Это дефекты проверки сохранённых доказательств, не доказанный обход production
promotion. Regression-проверки переподписывают изменённые записи и пересчитывают
внешние hashes, поэтому отказ должен происходить из-за нарушенной связи, а не
просто несовпадающего hash.

Для этих hosted campaigns процессы и контейнеры используют часы одного Linux
хоста. Поэтому source occurrence, ingest, route и момент наблюдения должны
соблюдать причинный порядок. Общая допустимая погрешность сетевого протокола
не разрешает подтверждать delivery до фактического вызова или после его ответа.
Защита этого лабораторного профиля не доказывает синхронизацию часов разных узлов.

| Наблюдение | Действие | Критерий восстановления |
| --- | --- | --- |
| Сохранился только summary или hash projection | Запустить исходную owned campaign с полным retention; старый результат оставить компонентным | Есть первичные подписанные записи и успешный replay после cleanup |
| Outbox содержит pending event | Проверить доступность и identity исходного collector, выполнить штатный retry | Тот же event ID и envelope получил исходно корректный receipt без нового incident |
| Outbox и collector расходятся | Сохранить оба снимка, проверить исходный registry pin и источник readback | Согласованы исходная запись, receipt и alert route; данные не переписаны вручную |
| Registry/root/epoch не совпадают | Остановить приёмку этого пакета и проверить provenance конфигурации | Подтверждён исходный authority, либо выполнена новая отдельная campaign |
| Capture взят во время незавершённой записи | Повторить bounded consistent readback до очистки; не увеличивать deadline без разбора | Полный конечный журнал совпадает с выгрузкой incidents |
| Cleanup не подтверждён | Проверить только owned PID, port, UID и ресурсы конкретного run | Есть проверка завершения процессов и удаления/остановки принадлежащих run ресурсов |

Запрещены исправление подписанных bytes, создание новых ключей для признания
старого evidence, очистка outbox ради зелёного статуса и глобальный prune/reset.
Если primary packet утрачен после удаления runner, восстановить его из summary
нельзя. Нужен новый разрешённый hosted run, а прежняя неполнота остаётся в истории.

Оставшееся диагностическое ограничение: вторичная ошибка остановки owned identity
process в `finally` может заменить исходное исключение на внешней границе.
Она не даёт успешный результат, но при расследовании нужно сохранять контекст
первичного сбоя и конечные результаты cleanup. Общий reliability debt R1 этим
этапом не закрывается.

## Плейбук приёмки

1. Запустить существующие source campaigns из чистого зафиксированного checkout.
2. Захватить full records до уничтожения fixture, не передавая signing keys.
3. Проверить exact source case inventory и разделение actual candidate, controlled
   graph, controlled service и controlled authorization subjects.
4. Подтвердить очистку и завершение фоновых потоков/процессов.
5. Атомарно сохранить private packet, перечитать его, сверить digest и выполнить
   replay с закреплёнными оператором bindings.
6. Публиковать только конечные метрики, статусы, hashes и ограничения. Общий M23
   разрешён лишь после объединения всех семи типов, transport negatives,
   missing sequence/heartbeat и здорового ML во время audit outage.

Смежные процедуры: [audit outage](security-outage.md),
[producer heartbeat](producer-heartbeat.md), [audit TLS](audit-tls.md).
