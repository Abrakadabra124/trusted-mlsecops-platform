# Проверка исправлений U01 и U02 внешнего supplemental audit

Общий статус: **U01 в POSIX scope и U02 исправлены и проверены; serving и tracking CI после обновления data.lock прошли**. Внешний аудит полностью не закрыт. [Ранбук и карта U03](../operations/signing-files-and-sql-probes.md).

## Воспроизведённые дефекты и исправления

В U01 signing key создавался через `open("xb")`, записывался, затем получал mode 0600. На POSIX исходный mode зависел от umask, а существующие права не проверялись. Commit `554045c` перенёс private mode в саму операцию exclusive create. Открытый descriptor проверяется до чтения/записи: regular file, один link, правильный POSIX owner, отсутствие group/other permissions. Leaf и immediate parent используют no-follow проверки, чтение ограничено 4096 байтами и сверкой metadata до/после. Прерванное создание не вызывает скрытую регенерацию identity.

В U02 два security `assert` исчезали при Python optimization. Commit `e8f2906` заменил их явным отказом и проверкой boolean privilege flags. Отказ при неправильных TLS/identity/privileges сохраняется при optimize=0/1/2; positive control обязателен после отрицательной проверки соединения.

## Подтверждённый Linux результат

[Run 40939316791](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40939316791), commit `82e575d6055f5d2529d1ebbd38d52379fa69994c`, job `123678163925`:

- Шаг `Locked dependencies and serving boundary tests`: success, **355 test method executions, 0 skips**. Из них 23 signing/bootstrap и 4 SQL methods; остальные относятся к прежней serving regression.
- `mlsecops/key_files.py`: **47 statements / 14 branches, 100%**.
- `scripts/tracking_sql_probe.py`: **33 statements / 12 branches, 100%**.
- Native canary: **6/6 checks pass**. При umask 022 в намеренно traversable каталоге другой UID читает public control 0644, но получает PermissionError для private file до первой записи и после закрытия. Owner readback работает; mode 0600 с момента открытия и после закрытия.
- SHA-256 canonical canary report с LF: `09c9458f82bba794c5c3d686ea0103220dcb370461282bfd44004b547d1fd08f`.

Canary не содержит настоящего ключа. Контрактные tests также проверяют специальное устройство, FIFO, leaf symlink несмотря на предварительную path-проверку, hard link, чужой owner, широкие права, изменение metadata, слишком большой файл, сбой/частичную запись и отказ local/self-hosted native execution. Non-POSIX branch проверяется как controlled dispatch; это не проверка Windows ACL.

**Весь run завершился failure**, на шаге подготовки source candidate с причиной `source_lock_mismatch_explicit_update_required`. Serving/fault stage не выполнялся. Оба cleanup steps success. Положительный canary не выдаётся за успешный сквозной запуск.

## Исправление source-lock integration

Причина отказа установлена: `signing.py` входил в `data.lock`, но его изменение не сопровождалось обновлением lock. В `9362c04` новый `key_files.py` также включён в declared inputs, чтобы связанная signing dependency не оставалась вне pin. Саму проверку lock и численные acceptance thresholds не ослабляли.

Перед записью нового lock выполнена свежая генерация и проверено совпадение output с прежним:

| Материал | Результат |
| --- | --- |
| Synthetic source | **1 915 576 байт**, bytes/digest unchanged |
| Source SHA-256 | `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473` |
| Новый data.lock SHA-256 | `bdbe17046990a9d352e10af8c1fc0676d992a073cfd46ece578075ec68366717` |
| Изменённые input pins | `data_source.py`, `signing.py`, добавлен `key_files.py`; остальные inputs сохранены |
| Git readback | Все **8 inputs** совпадают с байтами и SHA-256 committed Git blobs |

Новый preflight test сначала воспроизвёл stale lock и отсутствие helper pin, затем прошёл. Мутация каждого из трёх signing-related inputs отклоняется. Проверка зарегистрирована перед созданием инфраструктуры в serving/candidate/runtime/tracking workflows. Локально 29 test methods, 3 явно skipped POSIX-only на Windows; lint/format/docs прошли.

Проверки исправленного source: [serving 40940461445](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40940461445) и [tracking 40940542906](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40940542906) **success**, commit `9362c04c8b79d3f4fa6f53b7a2f3b1a371d8d5f7`.

## Сквозной serving с исправленным signing code

Run `40940461445`, job `123682183607`: **357 Linux test method executions, 0 skips**, повторный native canary 6/6, key helper и SQL probe снова 100% statements/branches. Source candidate успешно подготовлен с новым lock, затем пройдены configured serving, actual qualification, expiry/sequence replay, outage/blackhole/policy, clock/signature faults и независимые terminal revocations.

Actual группа: **903 typed assertions с повторениями**: base 193, outage 231, blackhole 194, policy/replay 131, model revoke 78, key revoke 70, два final cold Jobs 6. Model/key first completed 503: **5.297531804 / 5.381769362 s**. Final cold причины `trust_artifact_revoked` / `trust_key_revoked`, ноль workers, peer history unchanged; версии primary 7/7/8, model authority 1/2/2. Общий CAS/promotion snapshot совпадает до/после всех проверок. Source SQL остановлена и owned cluster удалён, оба cleanup steps success.

Максимальная golden prediction error 0.0. Production promotion actual candidate по-прежнему корректно отказан по `release_assurance_required`; qualification permit не подменяет полную приёмку. Source fingerprint проверен по 139 Git blobs и совпал с tracking source fingerprint ниже; image и candidate относятся к отдельному serving run.

| Материал | SHA-256 |
| --- | --- |
| Serving image ID | `1cd154e0dd12cd2e182edf542685e16d75172c6912aeaa84dfee0158ec37333f` |
| Candidate | `329fd0e01b7dd7943d15fa53cb3707ec6e38b0f8ed52cb77d47f19cfe36f287f` |
| Model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Subject | `1d443300cfc3a64dfb93f476bc7d0599d0d47a4739ace03a434e6f96ff37ceb0` |
| Full serving report | `9d728b61a09114b5893eed552e1def3dd8aeffdb81f8b6335ec685ddd30b5bd0` |
| Independent authorities report | `50eba5deaf164abac55b3c3fa29922992a3cba55d7e9b48a4d134186dd85855f` |
| Full CAS/promotion snapshot | `cc90b1b07a0c1ebbd938cffe4c873e1bbcca2ff8bc0846826e73ca819fa27526` |

## Реальный tracking и M06 после обновления lock

Run `40940542906`, job `123682476975`: **70 native tracking cases**, включая **16 SQL/TLS checks** исправленного probe. Роли/БД/TLS проверены на настоящем PostgreSQL; cross-database/cross-identity/plaintext/missing-client-cert/untrusted-CA/wrong-hostname отказаны с последующим positive control. Это обычный native interpreter run; поведение optimize=0/1/2 подтверждено отдельно controlled tests.

M06: **18 cases pass**, 6 fresh trainings / predictions / tracking publications: три базовых повтора и три мутации seed/data/environment. На общих 3000 golden rows максимальная разница вероятностей и AUPRC между базовыми повторами **0.0**. Мутации получили точную причину `reproducibility_inputs_changed`, persisted material readback проверен. Это synthetic local-CPU scope, не общая M18-приёмка.

Source fingerprint пересчитан по 139 Git blobs; отдельно пересчитан digest всех host scripts. Clean source и оба binding совпали с отчётами. Read-only doctor и cleanup success; отчёт подтверждает остановку owned containers с сохранением volumes, которые находятся только на disposable runner.

| Материал | SHA-256 |
| --- | --- |
| Source fingerprint | `45dd0c7e99818b39cfbab07604fb3157444f037358991d30616a0c852f60f14a` |
| Host scripts | `311b5b794195a3f27c6fffa6fcaae68e34b0bd7198cbcf40411ec94caad4935a` |
| Tracking report | `79c92bd81752758f360ac3a18310585f5e06462ac63f7276be76078523d1978c` |
| M06 report | `f46339726924150bd656f8df0829936201cc771b328c070fc59e2c63deeaa61c` |

Serving и tracking собирают образы в отдельных CI jobs. Совпадение source commit не означает один и тот же image/candidate для всех gates и не закрывает M18.

## Границы результата

U01 подтверждён в указанном POSIX scope. Existing Windows ACL, все ancestor directory races и противник с той же identity не покрыты этим доказательством. U03 общих filesystem helpers остаётся открытым. SQL optimization tests используют controlled database responses; настоящая SQL/TLS-изоляция проверяется отдельным tracking workflow.

Основной `security-review.ru.md`, на который ссылается переданный supplemental audit, отсутствует среди полученных материалов. Этот отчёт не отменяет его неизвестные findings. Независимые ML challenge cases M22 по-прежнему 0/2. R1, полный M11/M18 и оставшиеся image/security/operations gates не закрыты.
