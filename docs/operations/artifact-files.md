# Файловые границы артефактов: U03

Статус: [Linux tests, native serving и cleanup прошли](../evidence/artifact-files-2026-10-29.md), `6c65a83` / run `40945576220`: 379 methods, 0 skips, contracts 146 statements / 50 branches 100%. Windows compatibility не закрывает ACL/reparse races. Полный R1 не принят. Код: [contracts.py](../../mlsecops/contracts.py), тесты: [artifact_files_qualification.py](../../scripts/artifact_files_qualification.py).

## Контракт и границы доверия

`bounded_read` читает только regular files. Размер проверяется до выделения буфера и после чтения с запасом в один байт. До/после сравниваются device, inode, размер, mtime и ctime; прочитанная длина должна совпадать с исходным размером. Device/FIFO/directory не являются допустимыми входами. Это обнаружение наблюдаемого изменения, не криптографическая аутентификация: подписи, expected digest, quarantine и независимое approval остаются обязательными.

В Linux каждый компонент родительского пути открывается отдельно с `O_DIRECTORY | O_NOFOLLOW`, начиная с корня filesystem. Открытый directory descriptor удерживается для операции. Leaf открывается с `O_NOFOLLOW | O_NONBLOCK`; FIFO без writer не должен блокировать процесс. `..` и NUL запрещены. Замена pathname родителя на symlink после открытия не перенаправляет чтение/запись в другой каталог. Операция может продолжиться в уже открытом каталоге, даже если его переименовали.

`atomic_write` создаёт случайный temporary file через exclusive create с mode 0600. Запись/flush, POSIX fchmod и fsync выполняются на descriptor, затем replace и cleanup используют тот же parent descriptor. POSIX fsync каталога следует после rename. Чужой файл при collision не удаляется. Если отказ наступил до rename, старый target сохраняется; если directory fsync отказал после rename, новый полный файл может уже существовать. Ошибка команды не означает rollback файла.

Контракт требует доверенного каталога для записи. Он не защищает от другого процесса с правом изменять сами entries этого каталога, администратора, враждебного filesystem или переименования доверенного root до его открытия. `safe_child` проверяет относительное имя и containment; он возвращает pathname, не долговечное разрешение доступа. Объект должен дополнительно проверяться по подписи/digest на границе использования. Hard links обычных артефактов разрешены; в отдельном signing key helper действует более строгий запрет.

Windows поддерживает совместимый путь с предварительной проверкой symlink/junction и regular-file metadata. Он **не доказывает** отсутствие Win32 reparse races, корректность ACL или POSIX fsync semantics. Runtime target этого доказательства - Linux. Kubernetes projected symlink tree напрямую не поддерживается: передавать разрешённую копию в owned regular-file storage либо уже предусмотренный subPath mount. Не добавлять `resolve()` как способ обойти отказ и не отключать no-follow проверки.

## Диагностика без чтения содержимого

Ответственный - оператор owned artifact storage / CI. Сначала остановить публикацию этого артефакта и сохранить существующий approved объект. Не выполнять cat/PEM dump, массовую очистку, chmod/chown всего дерева или автоматический reset.

Для известного собственного файла в Linux:

```sh
stat -c 'type=%F mode=%a owner=%u links=%h size=%s inode=%i' -- /absolute/owned/path/artifact
namei -l -- /absolute/owned/path/artifact
```

Проверить ожидаемый root, mount и владельца. Эти команды дают snapshot метаданных, не доказывают отсутствие races. Не открывать подозрительный FIFO/device для проверки содержимого. Оригинальный внешний audit/архив и локальные diagnostic logs не публиковать; GitHub Actions logs являются публичными, поэтому tests используют только synthetic canaries.

| Отказ | Проверка и действие |
| --- | --- |
| `artifact_file_type` | Убедиться, что вход - regular file. Не преобразовывать device/FIFO в файл копированием неизвестного потока. Получить новый разрешённый артефакт через intake. |
| `artifact_unavailable` | Проверить существование, доступ, symlink/junction каждого компонента, место и состояние storage. При записи определить, произошёл ли rename; проверить полный результат по доверенному digest. |
| `artifact_changed` | Исключить параллельного writer. Сохранить исходные evidence, повторить intake на immutable owned snapshot и подтвердить подпись/expected digest. Не повторять бесконечно на изменяемом источнике. |
| `artifact_too_large` | Сравнить размер с утверждённым контрактом. Не увеличивать лимит, чтобы пропустить неизвестный файл. |
| `invalid_artifact_path` / `symlink_rejected` | Исправить источник имени или storage layout, не ослаблять verifier. Проверить возможность подмены пути и ownership. |

## Плейбук проверки и восстановления

1. Зафиксировать commit, безопасный код ошибки, gate/candidate digest и метаданные собственного target. Не включать private content.
2. Проверить владельца и причину. При непонятной подмене, неизвестном writer или нарушенном root остановиться и передать владельцу безопасности; новый release не разрешать.
3. Восстановить разрешённый immutable source из известного backup через обычный intake. Не редактировать approved digest/подпись и не использовать revoked модель как fallback.
4. Если atomic write завершился ошибкой, проверить actual file state и известный digest до повторного действия. Отдельно проверить отсутствие собственных pending files; чужие entries автоматически не удалять.
5. Выполнить тесты и текущий admission/serving путь. Положительный JSON readback сам по себе не доказывает доверенность release.

```powershell
uv run --locked python -m unittest scripts.data_source_lock_qualification scripts.artifact_files_qualification scripts.artifact_intake_qualification scripts.intake_gate_qualification scripts.intake_denial_qualification
```

В Windows семь POSIX methods явно skipped. Это не Linux acceptance. В configured-serving/runtime CI тесты проверяют настоящий FIFO с subprocess timeout, leaf swap при open, ancestor symlink, parent swap при read/replace, old-target preservation и cleanup после ошибки, post-rename fsync failure, metadata mutations и descriptor cleanup. Отдельно контролируются statements и branches >=95%. Полная integration проверка остаётся отдельным обязательным результатом.

Изменение `contracts.py` требует явного обновления `data.lock`. Перед обновлением подтвердить неизменность generated synthetic output: 1 915 576 байт, SHA-256 `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`. Нельзя регенерировать lock автоматически в CI. Rollback к старому helper возвращает audit deficiency; предпочтительно исправить storage/регрессию, сохранив fail-closed поведение. При невозможности - оставить promotion запрещённым до отдельного проверенного решения.

Основа descriptor API: [Python 3.12 os: dir_fd, open и replace](https://docs.python.org/3.12/library/os.html). Переносимость зависит от платформы; успешные mocked tests не заменяют проверку ядра Linux.
