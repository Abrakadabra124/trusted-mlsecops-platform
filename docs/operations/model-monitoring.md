# T18/M15: мониторинг распределений и качества

Ответственные: platform-owner за сбор/доставку, model-owner за reference/quality,
data-owner за проверенные labels. Scope: [ADR 0057](../decisions/0057-fixed-monitoring-contract.md).
Сейчас реализованы статистическое ядро, bounded accumulator и signed label join.
Actual HTTP collector, scheduled alert
delivery, dashboard и full M15 пока не приняты. Команды ниже не запускают
Docker, WSL, Kubernetes или SQL.

## Диагностика без изменения состояния

1. Сверить revision и digest reference с доверенной конфигурацией candidate.
   Не заменять reference текущими данными, чтобы убрать предупреждение.
2. Проверить sequence, times, суммы histogram и abstentions. Окно с999
   observations недостаточно; отсутствие alert при недостатке данных не значит
   нормальную работу. Public metrics не должны содержать feature values или IDs.
3. Различать `data_drift`, `prediction_drift` и будущую доставку
   `quality_degradation`. PSI не доказывает падение recall или poisoning.
4. При `telemetry_gap` найти потерянное окно/интервал и неисправный collector.
   Не восполнять потерю синтетическими наблюдениями. После восстановления
   требуется новая последовательность достаточных окон.
5. При ошибке reference/root/model binding остановить приём такого потока,
   сохранить private digest/sequence и эскалировать model-owner. Не отключать
   проверки и не ослаблять порог ради зелёного отчёта.

## Воспроизводимая проверка ядра

В отдельном checkout с pinned Python3.12.15 и установленным locked окружением:

```powershell
uv run --locked python -m unittest scripts.monitoring_qualification scripts.monitoring_stream_qualification scripts.monitoring_labels_qualification
uv run --locked coverage run --branch --data-file=.runtime/evidence/.coverage-monitoring --source=mlsecops.monitoring,mlsecops.monitoring_stream,mlsecops.monitoring_labels -m unittest scripts.monitoring_qualification scripts.monitoring_stream_qualification scripts.monitoring_labels_qualification
uv run --locked coverage report --data-file=.runtime/evidence/.coverage-monitoring --fail-under=95
```

Ожидаются отказ неизвестных/нецелочисленных counts, immutable reference,
идемпотентный repeat, отказ replay/conflict/overlap, сброс streak при gap или
недостаточной выборке, десять clean controls и точная граница recall0.05.
CI отдельно требует >=95% statements и branches каждого нового модуля.
Это controlled tests; они не являются доказательством доставки alert <=120s.

## Восстановление и ограничения

### Доставка и её диагностика

Для component проверки реального loopback HTTP, подписей, replay и таймаута:

```powershell
uv run --locked python -m unittest scripts.monitoring_alerts_qualification scripts.monitoring_delivery_qualification
```

Sink и producer должны иметь разные ключи и одинаковые pins reference/epoch.
HTTP200 без подлинной связанной квитанции не означает доставку. При timeout
повторять то же подписанное событие с прежними sequence/admission/expiry;
не обновлять expiry для обхода120s. После истечения срока результат delivery
не подтверждён. Cache128 receipts ограничен; старое вытесненное событие
не должно приниматься повторно. Candidate-bound gate и durable restart пока не приняты.

При реализации найдено два controlled отказа:

- Тест blackhole зависал в cleanup: Python3.12 `Server.wait_closed()` ждёт также
  закрытия активных соединений. Исправлен порядок: перестать принимать подключения,
  отменить только owned handler tasks, дождаться их `finally` с закрытием writers,
  затем ждать server closure с отдельным3s пределом. Первый зависший процесс
  был остановлен только после сверки PID/командной строки; автоматическая очистка
  временных файлов прерванного запуска не подтверждалась. Не завершать все Python
  процессы или чужие listeners. Повторные16 tests завершились штатно за4.128s.
- Oversized ASGI chunk сначала копировался, затем отклонялся. Failure-first
  allocation-guard test подтвердил дефект; теперь размер проверяется до `extend`.
  Отказ не потребляет alert sequence. Это ошибка разработки до публикации,
  не зафиксированный production-инцидент.

Оба новых модуля локально покрыты полностью:194 statements/70 branches. Native
HTTP candidate/SLO ещё не подтверждены. Raw traceback и private envelopes
хранить только вне публичного evidence.

После восстановления collector повторить только существующие неизменные окна
с прежними IDs; новое reference допустимо только как отдельное явное
переконфигурирование с подтверждённым candidate и сохранением прежней evidence.
In-memory evaluator ещё не содержит durable checkpoint: его restart сейчас
не разрешает заявлять отсутствие gaps. При неизвестной истории сохранить
inconclusive, а не подтверждать promotion.

Delayed labels не принимать из произвольного HTTP payload или feedback как
доверенные. `monitoring_labels.Labels` проверяет отдельную подпись, window/reference,
срок документа, совпадение observation ID с private prediction ledger и отсутствие
конфликтов. При `monitor_label_unmatched` проверить нужное окно и исходный request
ID/row index в private workflow; не добавлять отсутствующее предсказание вручную.
При конфликте сохранить оба envelope приватно и передать data-owner. Public key
не заменять ключом из отвергнутого запроса. Actual label delivery и persistence
ещё не реализованы; bounded in-memory retention описан ниже. Численная `quality()` сама по себе не проверяет
происхождение агрегатов. Ни comparator,
ни drift alert не разрешают retrain, promotion или rollback автоматически.

В incident record указать reference/window digest, sequence, sample sizes,
точный отказ, наличие delivery receipt и пределы наблюдения. Не сохранять
сырые признаки, тексты labels, токены и ключи в публичных reports. Native
recovery и alert delivery будут проверяться только в owned disposable hosted CI.

## Подключённый HTTP collector и scheduler

`serving_http.create_app(..., monitor=Runtime(...), metrics_token=...)` подключает
collector к завершению реальной ASGI-отправки. Учитывается только `/v1/predict`
с фактически отправленным200. Ready, ошибки входа/auth, audit substitution503,
истечение budget и прерванная отправка не добавляют наблюдений. Context берётся
из immutable `ServingResult`, а не текущего состояния engine; ссылки на признаки
и predictions очищаются в `finally`. Ошибка collector после отправки200 уже не
может изменить ответ: она выставляет постоянный fault `observation`.

Runtime принадлежит одному event loop и lifecycle приложения. Окно закрывается
при >=1000 наблюдений либо через60s; маленькое окно остаётся `insufficient`.
Последнее неполное окно закрывается и при остановке. Пределы:32 ожидающих окна,
64 alerts,20 окон и максимум20000 сохранённых prediction IDs,128 receipts.
При заполненной очереди alerts готовое окно сохраняется, пока доставка освобождает
место. Окно с неподтверждённым alert не вытесняется. Это bounded память процесса,
не durable backup и не гарантия сохранения при аварии процесса.

Подпись label authority, producer и sink используют три разных ключа. Wall clock
нужен для подписанных сроков, monotonic clock для измерения120s; обратный ход или
расхождение >5s дают clock fault. Retry сохраняет исходный event/sequence/deadline.
Квитанция после120s не превращает просроченную доставку в pass. Ошибка доставки
видна оператору; успешный retry снимает только delivery fault, не другие ошибки.

Оператор с отдельным metrics credential читает `GET /monitoring`: bounded JSON
с окнами, quality reports, агрегированными receipts и health. HTTP503 означает
неактивный/stale scheduler либо fault, HTTP200 означает здоровье сборщика, но
не достаточность выборки и не разрешение выпуска (`release_ready=false`).
Нет raw features, labels, private keys и подписанных envelopes. Сохраняются
существующие rate limits и timeout отправки операторского endpoint.

Диагностический плейбук на разрешённом CPU/loopback окружении:

```powershell
uv run --locked python -m unittest scripts.monitoring_runtime_qualification scripts.monitoring_http_qualification
uv run --locked python -m unittest scripts.serving_http_qualification scripts.serving_metrics_qualification scripts.serving_http_audit_qualification scripts.serving_lifecycle_qualification
```

Для первой команды локально проверены28 tests/0 skips; runtime215 statements и
70 branches100%. Для второй смежной кампании вместе с monitoring HTTP suite:
84 tests,3 Linux-only skips на Windows. Отдельный CI запускает Linux-проверки;
их конкретный результат фиксируется после завершения, а не предполагается.

При clock fault проверить синхронизацию времени и reference; не менять часы
автоматически и не продлевать уже подписанные сроки. При queue fault сохранить
pending counts/window digests приватно, восстановить sink и проверить receipts.
При `monitor_shutdown_pending` задача ещё жива: её handle сохраняется, процесс
нельзя объявлять очищенным. При `monitor_shutdown_unconfirmed` остановка owner
или доставка не подтверждены полностью: проверить `task.done()`, faults и
очереди отдельно. Cleanup engine и audit исполняется даже при ошибке monitor.
Эскалировать владельцу потерю истории и неподтверждённые receipts; перезапуск
со старым epoch без восстановления состояния не разрешён.

Controlled ошибки разработки и исправления: неправильный тип подписанного
label payload теперь даёт contract rejection; отмена shutdown остаётся отменой;
субмиллисекундное округление не отвергает корректную свежую метку; неполное
окно не теряется при штатной остановке. Failure-first tests сохранены в suites.
Это не записи production-инцидентов.

Ещё не подтверждена native сборка reference от actual candidate; остаются
durable restart, feedback quarantine composition и полный native M15.
Новый HTTP hook требует свежих M13/M14 на общем candidate; старые результаты
не переносятся автоматически. Этот компонент не имеет promotion API.

## Конфигурация и отдельный sink CLI

В serving JSON добавлены `monitor_file` и обязательный при этом
`metrics_token_file`. Значение `monitor_file` - абсолютный путь к JSON с точными
полями ниже. Неизвестные поля, относительные пути, неправильная подпись, другой
digest и смешанные ключи отклоняются до создания engine или сетевого listener.

| Поле producer config | Значение |
| --- | --- |
| schema_version | Целое1 |
| reference_file | Абсолютный путь к DSSE `monitor-reference` envelope |
| reference_sha256 | SHA-256 canonical payload эталона, заданный оператором |
| reference_public | Pinned Ed25519 public key издателя reference, canonical base64 |
| producer_key_file | Абсолютный путь к private Ed25519 key отправителя alerts |
| label_public | Отдельный pinned public key проверенной label authority |
| sink_public | Отдельный pinned public key подписанта receipts |
| sink_port | Порт loopback receiver1024..65535 |
| epoch | Явный уникальный для запуска идентификатор32 lowercase hex |

Четыре роли используют разные ключи. Подпись не доказывает корректность выбора
эталонной выборки: reference builder от actual candidate остаётся обязательным
незавершённым шагом. Подменять его произвольным вручную подписанным histogram
для итоговой приёмки нельзя. Public pins устанавливает доверенный оператор,
а не входящий envelope. Existing key_files проверяет private key identity,
размер, symlinks и POSIX owner/mode. Windows ACL этим не доказываются.

Sink JSON содержит ровно `schema_version`, `reference_sha256`, `producer_public`,
`receipt_key_file`, `port`, `epoch`; пути абсолютные. Reference/epoch должны
совпадать с producer. Загрузчик не запускает процессы, задачи или listener.

Команды на разрешённом disposable Linux runner после подготовки private configs:

```sh
uv run --locked python -m mlsecops.monitoring_cli --config /work/private/sink.json
uv run --locked python -m mlsecops.serving_http --config /work/private/serving.json --port 8080
```

Это два отдельных foreground процесса, каждый с известным владельцу PID.
Sink слушает только127.0.0.1; внешние host/proxy/redirect options не принимаются.
CLI включает существующую Linux process privacy: core dumps запрещены,
dumpable=0. На Windows CLI корректно отказывается, не обходить эту проверку.
Локальные Docker/WSL/Kubernetes/SQL для воспроизведения этой задачи не запускать.

После SIGINT ожидается закрытый listener, завершённый процесс с кодом130 и
одна постоянная diagnostic строка `monitoring_sink_rejected`, без traceback
и содержимого config. Сам код130 не доказывает cleanup: проверить завершение
PID и недоступность прежнего loopback port. Тест `monitoring_cli_qualification`
проверяет настоящий дочерний процесс только на Linux; на Windows он skipped.
In-memory receipt cache теряется при аварии. Сохранять private evidence и
назначать новый epoch после ручного разбора; reused epoch без восстановления
истории не считается безопасным restart и не принимается полным M15.

## Построение frozen reference

`monitoring_reference.build` проверяет весь signed release package существующим
`release_bundle.verify`, затем связывает отдельные validation bytes с descriptor
`split_manifest.objects["validation.json"]`: точные digest, размер и число строк.
Дополнительно проверяются canonical encoding, уникальные entity IDs, числовой
домен и labels0/1. Для reference требуется >=1000 строк и >=200 positives.
Holdout не читается; текущий inference stream не используется для настройки bins.

Далее builder создаёт `PredictionBatch` и передаёт запрос владельцу isolated
worker. До подписи проверяются model/request/row bindings и scan receipt ответа.
Histogram и исходный recall вычисляются из настоящих validation features/labels
и возвращённых scores. Model/bundle/dataset/evaluation/source pins извлекаются
из проверенного package до worker callback. Повторно проверяется время действия
package после вычисления; clock rollback/expiry не создают подписанный reference.
Reference signer отделён от publisher, curator и evaluator.

Выход: DSSE `monitor-reference` и ограниченное evidence с validation digest/bytes,
prediction receipt и `release_ready=false`. Для итоговой native приёмки вызывающий
controller обязан сохранить private request/response, execution metadata и
подтверждение очистки реального worker. Успешный callback сам по себе не доказывает
изоляцию процесса; controlled tests не заменяют этот этап.

Диагностика перед подписью:

```powershell
uv run --locked python -m unittest scripts.monitoring_reference_qualification scripts.candidate_lineage_qualification scripts.material_bundle_qualification scripts.release_bundle_qualification
```

Локально61 tests/0 skips, builder36 statements/10 branches100%. В fixture
используются1000 уникальных synthetic rows и настоящий набор подписанных
материалов, но worker response controlled, не actual ONNX execution. При
`monitor_validation_binding` заново получить validation по digest из подписанного
manifest через разрешённую read-only роль. Не подставлять train/holdout, не
дублировать строки для достижения порога, не переподписывать изменённые байты.
При insufficient positives сохранить inconclusive; замена labels запрещена.
При expiry нужно заново авторизовать campaign, а не менять время в отвергнутом
package. Native candidate-bound сборка и полный M15 ещё не приняты.

## Приватный пакет сквозного наблюдения M15

Workflow `.github/workflows/kubernetes-monitoring.yml` запускается только на
disposable hosted runner. Он использует прежние pinned tools, source SQL,
Kubernetes worker/controller и действующий qualification permit. Это проверка
кандидата, не разрешение production release. Локальную инфраструктуру не запускать.

1. Проверить подписи proposal/package и source/image pins. Прочитать validation
   через существующую read-only роль publisher; trainer SQL identity отсутствует.
   Сверить digest, размер, строки и labels с подписанным descriptor.
2. До выдачи короткого permit выполнить validation inference настоящим isolated
   worker. Сохранить private request/response/execution metadata и подписать
   frozen reference отдельным ключом. Holdout и inference traffic для reference
   не использовать.
3. Поднять loopback HTTP serving с действующим worker, scheduler и signed sink.
   Отправить 10 контрольных окон по 1000 наблюдений и два окна shift fixture.
   Источник каждого окна - действительно завершённые HTTP 200 ответы.
4. Отдельно передать 200 положительных delayed labels для выбранных отрицательных
   предсказаний. Это намеренно ухудшающий recall synthetic fixture, не реальные
   исправления ground truth. Повтор того же подписанного пакета должен принять
   ноль новых labels. `/monitoring/labels` требует operator credential, точную
   подпись и bounded JSON body; обычный inference credential доступа не даёт.
5. Проверить три подписанных receipt, monotonic delivery time <120 секунд,
   reference/context/window/evidence bindings, отсутствие alarm в первых десяти
   окнах и `release_ready=false`. Сверить окно с собственными HTTP records.
6. Закрыть HTTP, scheduler, audit и worker; проверить отсутствие worker pods.
   Host сохраняет packet только из owned probe pod, закрепляет UID и подтверждает
   digest. Повторный pod/неверный campaign/потеря packet не дают success.
7. После удаления owned Job/ConfigMap, остановки source SQL и удаления кластера
   перечитать private primary packet и выполнить тот же пересчёт без инфраструктуры.

На разрешённом подготовленном runner команды:

```sh
uv run --locked python -m scripts.kube_monitoring_native
uv run --locked python -m scripts.kube_monitoring_native --reverify
```

Вторая команда не создаёт окружение. Private packet, reference/worker records,
ключи и bindings находятся в `.runtime`; raw artifacts не загружать в публичный
GitHub. Публичен только ограниченный summary с hashes, counts и состоянием.
Digest сам по себе не доказывает независимость администратора: ключи lab sink
и labels принадлежат доверенному qualification probe; это не внешний audit.

При `monitor_probe_windows_incomplete` сначала проверить bounded diagnostic и
health snapshot: количество закрытых окон, faults scheduler/delivery, реальные
HTTP статусы. Не увеличивать counters вручную. При недостатке отрицательных
предсказаний для recall fixture сохранить fail, не уменьшать 200 positives.
При `monitor_operator_*` или `monitor_packet_*` сверить ownership, UID, campaign,
подписи и неизменность private файлов. Не пересоздавать binding для изменённого
пакета и не заменять primary evidence одним summary. При ошибке очистки
не объявлять observation завершённым; пользоваться существующим owned cleanup.

Локальные controlled tests проверяют настоящий HTTP/подписи, но используют
контрольный predictor. Hosted результат нужно подтвердить отдельно. Полный M15
остаётся inconclusive до общей приёмки, feedback quarantine, recovery/restart и
смежных regression checks. Alert не запускает обучение или promotion автоматически.
