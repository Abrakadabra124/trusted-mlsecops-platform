# Приватное задание shared для M11 и M12

Вызов выполняет интегратор hosted workflow на свежем runner после проверки точного
source image. Нужны read-клиент приватного хранилища, внешний файл исходного trust
key, 32 байта AES-ключа и открытый ключ подписи из независимого выхода producer.
Исходный `run_owner` содержит repository, run_id, run_attempt и producer_job равный
`producer`. В `source` передаются source_revision, source_fingerprint и image_id.
Клиент `source_api(method, path)` читает публичный исходный репозиторий для
проверки workflow через `ci_campaign_guard.authorize`.

```python
from scripts import ci_shared_job

result = ci_shared_job.run(
    root,
    source_api=public_reader,
    api=reader,
    trust_key_path=trust_file,
    key=aes_key,
    trusted_public=producer_public,
    run_owner=producer_owner,
    source=verified_source,
)
```

После успеха `destination` (Path), `index_pin` и `arguments` позволяют повторить
проверку набора первичных доказательств в пределах жизни runner. В `replay`
находится проверенная квитанция. Поле `origin` передаёт подписанное наблюдение
producer о его рабочей области, контейнере и остановке SQL. На этом runner
`consumer_offline` получен собственной проверкой локального SQL, а `cleanup_owner`,
`cleanup` и `gate_counts` относятся к заданию shared. В результате `release_ready=False`.
Весь словарь остаётся приватным. Постоянное хранение потребует отдельного
экспорта и проверки сохранённых байтов.

## Порядок проверок

1. На входе job сверяет текущие repository, run, attempt, роль `shared`, commit
   и локальный идентификатор image. Общий guard проверяет разрешённый hosted
   workflow до чтения приватного пакета.
2. На этом runner создаётся новый каталог `.runtime/ci-shared-job` с собственным
   workspace ID. В нём `Recovery` фиксирует исходное состояние ресурсов. Если путь
   уже занят, повторный запуск останавливается до чтения пакета.
3. `open_consumer` проверяет подпись producer, открывает `candidate-shared` в
   фазе `M11-M12` и материализует временную рабочую область. Job сверяет её marker,
   pins архива, исходного владельца и source. SQL этого consumer использует порт
   15440. Исходный producer, локальный witness и материализованный consumer имеют
   три различных workspace ID.
4. Штатный `ci_consumer_native.consumer` импортирует исходного кандидата,
   выполняет M11 и M12, проверяет остановку своего SQL, очищает свой кластер и
   сохраняет исходные файлы и отчёты. После выхода из контекста job проверяет
   отсутствие временной рабочей области и повторяет cleanup по локальному
   witness. Затем `m18_shared_retention.replay` открывает retained-каталог
   по pins из памяти, проверяет объекты и сопоставляет квитанцию с первой.
   Перед возвратом job повторно сверяет локальные run, attempt, commit и image.

## Отказ и повторная очистка

При отказе записывать исключение только в приватный лог. Внутри вызова cleanup
использует локальные записи о контейнерах и томах. Для повторной проверки в
отдельном шаге того же задания, пока точный source image ещё доступен, вызвать

```python
cleaned = ci_shared_job.cleanup(
    root, source_api=public_reader, run_owner=producer_owner, source=verified_source
)
```

Ожидаемый результат - `{"sql": True, "cluster": True}`. SQL-проверка подтверждает
остановку собственного контейнера. Проверка кластера подтверждает удаление
собственного узла и его учтённых томов. Отсутствующий witness, чужой владелец
или неполный cleanup требуют разбора приватного `ci-consumer-native/recovery.json`
в каталоге задания. Сохранять исходный witness и retained-объекты до решения
владельца. При сбое replay исходные отчёты остаются диагностическими данными.
Публикацию evidence разрешает отдельный шаг после успешного результата.

## Локальная проверка

```console
python -B -W error -m unittest scripts.ci_shared_job_qualification scripts.ci_consumer_native_qualification
```

Ожидаемый результат - `OK`. Тесты используют подписанные синтетические данные,
штатные retention и replay. Транспорт, hosted guard и эффекты SQL и кластера
в этих тестах контролируются локально. Дополнительный тест меняет retained-объект
после удаления временной рабочей области и требует отказа replay.

[Сохранение и восстановление первичных свидетельств после остановки runner](ci-primary-recovery.md).
