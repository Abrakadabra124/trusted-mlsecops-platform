# PB-21 / RB-40 / RB-41: promotion state и восстановление

Ответственный: platform-owner; policy/approval решает отдельный approver. Scope: synthetic local CPU. [Архитектура](../promotion-ledger.md), [evidence](../evidence/promotion-ledger-2026-10-14.md). Запись journal не означает работающий serving.

## PB-21: проверка в disposable PostgreSQL

Read-only сначала: `git status --short`, `git rev-parse HEAD`, состояние Docker и ownership конкретного state. На текущем Windows host Docker Engine оказался недоступен через dockerDesktopLinuxEngine pipe. Это установленное ограничение данной сессии, не повреждение БД: working Docker/WSL не запускали и volume/network не сбрасывали. Native проверка перенесена в свежий CI runner.

Локальные controlled tests без Docker:

```powershell
uv run --locked python -m unittest scripts.promotion_state_qualification scripts.promotion_qualification scripts.promotion_native_qualification
```

Native command запускается в [storage workflow](../../.github/workflows/storage.yml) **после** прежних backup/restore/M07/intake checks, только в его fresh owned state:

```powershell
uv run --locked python -m scripts.promotion_native --state .runtime --confirm-disposable
```

Изменяющие действия: создание отдельной schema, controlled authority/selection rows и CAS objects; в конце - restart только проверенного контейнера этой disposable лаборатории. Это не read-only doctor. На рабочем state не выполнять ради демонстрации. CLI требует явного флага, ownership проверяется до записи evidence.

Проверяются реальное ожидание row lock, same/conflicting concurrent requests, stale/gap sequence, policy/environment, malformed payloads, rollback, SQL права всех ролей, запрет неполного backup и сохранение state после restart. Request/proof в этих SQL tests имеют controlled transport scope: они **не являются одобренными моделями или all-pass acceptance reports**.

Успех означает component status=pass, full_M10=inconclusive, release_ready=false. Evidence хранится в `.runtime/evidence/promotion-native.json`; публично публикуются только очищенные агрегаты. Один прежний pass-файл не подтверждает новый запуск: проверять exit, campaign/source и законченный readback. При ownership failure исторический report намеренно не переписывается в потенциально чужом state.

Проверено 2026-10-14 на `fab7294`: 108 native SQL checks pass, включая restart, плюс 12 release checks с настоящим missing-assurance SDK denial. Локально 106 adjacent methods pass. Точные campaign/source/migration bindings и завершённый storage run находятся в evidence. Положительный native ML promotion, полное recovery ledger и power-loss проверка этим не заявляются.

## RB-40: sequence conflict, timeout или ambiguous commit

1. Прекратить автоматические повторы. Сохранить точные proposal/proof/request references, environment, source и время в приватном evidence. Не выводить signing keys или connection credentials.
2. Read-only прочитать head:

```powershell
uv run --locked python -c "from mlsecops.promotion_state import state; from mlsecops.contracts import canonical; print(canonical(state('.runtime/storage-clients/serving','local-cpu')).decode())"
```

Команда предназначена для уже установленного/configured environment. Missing table/environment - неполная установка или recovery, не повод автоматически создать sequence=0. В CI test environment имеет controlled campaign prefix, его не заменять на production.

3. `P1004` означает stale/gap/conflicting sequence. Если текущий request совпадает, тот же действующий approval допускает idempotent retry. Если head уже продвинут другим request, нельзя переименовать старый approval или изменить его sequence: нужно новое обоснованное решение.
4. `P1003` означает future/expired request. Проверить server time и подписанные windows, не менять часы и не продлевать подпись вручную. Даже после успешной предварительной проверки ожидание lock может исчерпать срок.
5. `P1002` - неизвестный environment или policy mismatch. Не менять pin на значение из отвергнутого пакета. Проверить trusted configuration и эскалировать approver/platform-owner; rotation отдельно ещё не реализована.
6. `promotion_commit_unconfirmed` не различает снаружи rollback и committed-but-response-lost. Read-only сверить immutable event для ожидаемого environment/sequence и его request bytes, не только latest head. При недоступной БД сохранить outcome unconfirmed. Автоматического retry в SDK нет.
7. Retry выполняется только с прежними документами, прежним environment/sequence и ещё действующим approval через полный admission. Успех требует совпадения SQL receipt и последующего event/CAS readback. `recorded-not-activated` не разрешает вручную обходить loader или включать endpoint.

`P1001` означает некорректный request или отсутствующий связанный material. Сверить schema, точные bytes/digests и наличие proposal/proof, не подставлять документ с похожим именем. `P1005` означает расхождение head и immutable event: остановить promotion, сохранить состояние для platform-owner и не восстанавливать недостающую строку ручным INSERT. Ошибки SQL transport/parse могут иметь стандартный SQLSTATE вместо P100x; неизвестный код не считать безопасным retry.

Реально найдено: первоначально новый request содержал текущее время попытки, поэтому повтор через секунду получал другой digest и sequence conflict. Controlled regression сначала воспроизвёл отказ; request теперь использует signed approval issued_at. Это дефект реализации до выпуска, не production-инцидент.

## RB-41: backup отказал после появления journal

`backup_promotion_ledger_not_supported` - намеренный fail-closed. Старый экспорт охватывает только CAS tables и не сохраняет head/events/authority. Не удалять schema, не откатывать sequence и не выключать guard ради зелёного backup.

1. Проверить, что отказ относится к нужному owned state и актуальному процессу. Существующий backup-файл может быть историческим, до первого promotion, и не восстанавливать текущий journal.
2. Сохранить единственную копию БД и evidence. Не запускать global prune, DROP, volume reset или restore поверх исходного state.
3. Полный backup/restore journal пока требует следующего implementation stage. До его проверки не разрешать рабочий deployment этой версии ledger. Service restart test подтверждает только сохранение обычного committed состояния после перезапуска, не power-loss/offsite disaster recovery.
4. После restore отсутствие ledger означает неполное recovery. Не выполнять install/configure как способ обнулить историю: это потенциально возвращает возможность replay старых решений. Эскалировать platform-owner; serving должен оставаться недоступным до восстановления согласованного доверия.

Ревью обнаружило TOCTOU (time-of-check/time-of-use): schema могла появиться между отдельным preflight и открытием snapshot. Исправление проверяет отсутствие ledger в том же REPEATABLE READ snapshot, что и исходные таблицы. Controlled regression запрещает false/unknown scope до pg_dump, native component отдельно проверяет реальное snapshot rejection после установки ledger. Нативная гонка именно concurrent schema installation не заявляется проверенной без отдельного evidence.

Rollback кода возможен только reviewed revert с сохранением БД. Старая версия не понимает новый journal и не должна автоматически становиться serving authority. Работающий schema reset не является безопасным rollback. При неожиданно разрешённом DML, изменённом migration checksum, пропавшем event или расходящихся receipt/readback остановить promotion и сохранить материалы для расследования.
