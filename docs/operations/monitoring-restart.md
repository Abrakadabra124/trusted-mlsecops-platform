# Восстановление мониторинга после потери памяти процесса

Scope: существующий synthetic Linux CPU lab, producer и loopback sink. Владелец
операции - доверенный оператор конфигурации. Это cold recovery с явным разрывом
истории. Окна, очереди, labels и receipt cache из памяти не объявляются
восстановленными. Выдача release по факту запуска мониторинга запрещена.

## Первоначальная подготовка

Только перед первым запуском на разрешённом Linux runner создать отдельный
реестр. Родительский каталог уже должен существовать и быть доверенным:

```sh
uv run --locked python -m mlsecops.monitoring_state \
  --directory "$GITHUB_WORKSPACE/.runtime/monitoring-epochs"
```

Команда создаёт новый directory0700 и identity0600, выполняет fsync и возвращает
`state_sha256`. Уже существующий путь не перезаписывается. Две конфигурации,
producer и sink, должны получить `state_directory` с абсолютным путём и
`state_sha256` из этой receipt. Это fingerprint локального реестра, не секрет
и не подпись конфигурации. Сам config, paths и public pins задаёт оператор.

Реестр должен переживать замену процессов. При переносе runtime его нужно
сохранить в том же доверенном storage вместе с конфигурацией. Автоматически
инициализировать новый directory при каждом запуске запрещено. Native disposable
campaign создаёт новый реестр только для новой независимой lab campaign; это
не доказательство сохранности при пересоздании Kubernetes volume.

## Порядок запуска и защита

1. Загрузчик проверяет reference, pins, роли и пути, не запускает сеть.
2. В ASGI startup sink закрепляет использованный `sink-<epoch>` в реестре.
   До admission HTTP сообщения не принимаются. Ошибка admission даёт startup
   failure и exit1 CLI с постоянной диагностикой без пути/credentials.
3. Перед созданием scheduler producer закрепляет `producer-<epoch>`.
   Используется lock на directory, O_EXCL, запрет symlinks, owner/mode/nlink
   checks, запись с обработкой short write и fsync файла/directory.
4. Marker остаётся после штатной остановки, SIGKILL, ошибки записи или запуска
   scheduler. Даже пустой marker означает использованный epoch. Смена reference
   не разрешает повторно использовать epoch той же роли.
5. Повторный start уже работающего Runtime не создаёт новую задачу и не требует
   второго admission. Новый процесс со старым epoch получает отказ.

Реестр ограничен 1024 markers суммарно для двух ролей. При заполнении новый
admission запрещён. Автоматического удаления старых markers нет: это позволило бы
повторить старую сессию. Проверка POSIX filesystem выполняется на Linux; Windows
ACL или сетевой filesystem этим не квалифицированы.

## Плейбук после остановки или аварии

1. Read-only диагностика: проверить PID/порт только собственного процесса,
   последний epoch/reference и доступность существующего реестра. Сохранить
   время, pending counts и последние подтверждённые receipts, если они доступны.
   Не считать потерянные окна clean или доставленными.
2. Остановить оставшийся процесс этой пары штатно и подтвердить закрытие его
   PID/порта. Не завершать чужие listeners и не удалять markers.
3. Если directory отсутствует, identity изменена, есть неизвестные entries,
   небезопасные permissions или повреждение storage, сохранить отказ и передать
   владельцу storage. Не выполнять init заново для обхода отказа. Восстановление
   доверенного реестра требует отдельного подтверждения его полноты; snapshot,
   созданный до последнего epoch, может разрешить replay и не является безопасным
   автоматическим rollback.
4. При сохранном реестре назначить новый случайный epoch32hex одновременно
   producer и sink, сохранив model/reference и доверенные keys. Запустить сначала
   sink, затем serving командами из [основного ранбука](model-monitoring.md).
   Различающиеся epoch дают отказ в доставке, а не совместимость со старым sink.
5. Producer с ранее использованным реестром формирует `telemetry_gap` с причиной
   `new_epoch_history_unavailable`; deadline остаётся120s. Сверить подписанную
   receipt, `epoch_admission.history_unavailable=true`, `history_restored=false`
   и новый epoch в operator report. До новых достаточных окон статус данных
   `insufficient`; старые delayed labels без сохранённых окон не принимаются.
6. Возобновить сбор новых observations. Подтверждённая доставка gap не восстанавливает
   потерянную историю и не разрешает promotion. Зафиксировать интервал неизвестной
   наблюдаемости в incident record. Если gap не подтверждён, диагностировать
   delivery fault по основному ранбуку, не продлевать старый deadline.

Новые labels и окна текущей сессии по-прежнему ограничены memory retention.
История и markers имеют разные назначения: последние предотвращают reuse, но
не являются backup observations. Защита от администратора host, способного
изменить registry и config вместе, и rollback целой файловой системы не заявлены.

## Проверка и evidence

```sh
uv run --locked python -m unittest scripts.monitoring_state_qualification scripts.monitoring_restart_qualification
```

Suites проверяют malformed config, filesystem identity, missing state, partial
write, fsync failure, capacity, lock contention, crash child, отказ старому epoch,
явный gap и отсутствие restoration claims. Native Linux тест запускает sink CLI,
получает настоящую подписанную receipt, завершает только свой PID через SIGKILL,
подтверждает закрытие порта, проверяет отказ повторному запуску и новый epoch с
отказом старому событию, затем штатную очистку замены. Windows skips не заменяют
этот тест. Результат hosted CI публикуется отдельно в [STATUS](../../STATUS.md);
наличие теста не является доказательством его успешного запуска.
