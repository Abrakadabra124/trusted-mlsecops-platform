# Файлы ключей и проверки SQL при оптимизации Python

Статус: исправления U01/U02 реализованы, Windows pure/mocked tests пройдены; Linux native validation ожидается. Полный внешний аудит не закрыт. U03 для общих файловых helpers остаётся отдельной незавершённой работой. Эти проверки не заменяют независимые ML challenge cases M22.

## Что обнаружено и изменено

Внешний supplemental review выявил поздний `chmod` после записи signing key (U01). В POSIX при umask 022 и доступных родительских каталогах файл мог временно иметь права чтения для других пользователей. У существующего ключа права не проверялись. Возможность такого чтения зависит от реального окружения; подтверждённой компрометации ключей нет.

[key_files.py](../../mlsecops/key_files.py) создаёт файл эксклюзивно с mode 0600 до первой записи. POSIX открывает родительский directory descriptor, использует `O_NOFOLLOW`, а тип файла, число hard links, owner и права проверяет через `fstat` открытого descriptor. FIFO открывается неблокирующим способом и отклоняется как не regular file. Чтение ограничено 4096 байтами, до и после чтения сверяется identity/size/time metadata. Данные передаются PEM parser только после этих проверок. После записи выполняется flush/fsync.

Это ограниченная защита signing files. Доверенная иерархия родительских каталогов и отсутствие враждебного процесса с той же identity остаются предпосылками. Это не универсальная защита всех path races и не исправление `contracts.bounded_read`, `safe_child` или `atomic_write` из U03. POSIX mode не является Windows ACL: существующие Windows ACL не проверяются и не исправляются этим helper. Cross-user denial на Windows пока не доказан.

U02 касалось двух `assert` в [tracking_sql_probe.py](../../scripts/tracking_sql_probe.py). При оптимизации Python такие инструкции исчезают. Теперь несоответствие identity/database/TLS или привилегированной роли вызывает явный отказ независимо от optimization level; privilege flags должны быть именно boolean. Отрицательные соединения по-прежнему требуют положительного control после каждого отказа. Ошибка соединения без работающего control не считается доказательством изоляции.

## Диагностика

Ответственный: оператор signing state / владелец CI. Начать с read-only inspection конкретного собственного файла. Не выводить PEM, private key или содержимое каталогов с credentials.

В Linux проверить только метаданные, задав точный путь вместо placeholder:

```sh
stat -c 'type=%F mode=%a owner=%u links=%h size=%s' -- /absolute/owned/path/key.pem
namei -l -- /absolute/owned/path/key.pem
```

В Windows ACL требуется отдельная проверка действительных principals и inherited entries:

```powershell
Get-Acl -LiteralPath 'C:\absolute\owned\path\key.pem' | Format-List Owner,AccessToString,AreAccessRulesProtected
```

Эти команды не доказывают отсутствие прошлого раскрытия. Не запускать рекурсивный chmod/icacls и не менять права неизвестного или общего каталога.

| Отказ | Действие |
| --- | --- |
| `signing_key_file_permissions` | Проверить owner и POSIX mode. Не чинить автоматически, не продолжать подпись. Установить причину широких прав и необходимость ротации. |
| `signing_key_file_identity` / `symlink_key` | Проверить тип/links и непосредственный parent. Не следовать ссылке, не заменять файл до проверки ownership. |
| `signing_key_file_changed` / `signing_key_file_size` | Сохранить метаданные и digest в закрытом evidence, остановить использование ключа. Проверить конкурентную запись, повреждение или неправильный путь. |
| `invalid_signing_key` после прерванного создания | Пустой/частичный файл остаётся отказом; повтор не генерирует новый ключ поверх него. Восстановление должно сохранять привязку к опубликованному trust root. |
| `signing_key_file_unavailable` | Проверить отсутствие/права/доступность parent. Сообщение специально не содержит файловый путь или OS stderr. |
| SQL probe `status=fail` | Сверить role/database/TLS, privilege flags и positive controls в закрытом окружении. Запуск с `-O` не должен превращать отказ в pass. |

## Плейбук восстановления

1. Приостановить использующий ключ собственный signer. Serving не переключать на неподтверждённый trust root. Сохранить закрытое evidence и текущее public key binding.
2. Если файл существовал с широкими правами, оценить возможное раскрытие. Простое сужение прав не отзывает уже скопированный ключ; при подозрении нужна явная ротация и отзыв по правилам trust lifecycle. Этот документ не реализует отсутствующий общий rotation gate M11.
3. Если это прерванный bootstrap, проверить, опубликован ли trust root. Для опубликованной identity восстановить проверенную резервную копию того же ключа либо выполнить утверждённую ротацию. Не удалять marker и не регенерировать ключ для обхода mismatch.
4. Только для нового disposable CI state без действующей identity допустим повтор всего bootstrap в новом state. Существующие ключи, данные и revocation history не удаляются.
5. После восстановления выполнить проверку подписи/верификации и совпадения public binding, затем соответствующий integration workflow. Успешный chmod или отсутствие исключения не заменяют проверку конечного состояния.

## Воспроизведение проверок

Локально разрешены pure/mocked tests без Docker/WSL/SQL/Kubernetes:

```powershell
uv run --locked python -m unittest scripts.key_files_qualification scripts.bootstrap_qualification scripts.tracking_sql_probe_qualification
```

В Windows три POSIX-only test methods будут явно skipped. Linux native canary запускается только внутри GitHub-hosted runner:

```sh
uv run --locked python -m scripts.key_files_native
```

Canary использует исключительно строку `SYNTHETIC-CANARY`. Каталог намеренно доступен для traversal: положительный файл 0644 должен читаться другим UID, приватный 0600 должен давать PermissionError и до первой записи, и после закрытия. Проверяются owner readback, mode и очистка собственного временного каталога. Timeout, отсутствие sudo или неожиданный stderr считаются отказом, а не pass. Реальные signing secrets другому UID не передаются.

SQL contracts компилируют фактическую функцию с optimize=0/1/2, подставляют controlled ответы и проверяют ошибочные identity/TLS/privileges, bypass отрицательных подключений, неработающий positive control и CLI exit code. Это проверка поведения кода, не новое доказательство живой SQL/TLS-изоляции. Native tracking остаётся отдельным workflow.

Регистрация: [configured serving](../../.github/workflows/kubernetes-serving.yml), [runtime](../../.github/workflows/runtime.yml), [tracking](../../.github/workflows/tracking.yml). Порог branch coverage key helper >=95%; SQL probe coverage 100%. Публиковать только очищенные результаты, commit/run и ограничения; исходный внешний архив и raw logs остаются приватными.
