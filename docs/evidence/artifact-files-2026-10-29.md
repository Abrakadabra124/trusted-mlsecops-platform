# U03: descriptor-based чтение и атомарная запись артефактов

Статус: **U03 исправлен и проверен в Linux scope; native serving и cleanup прошли**. Source commit `6c65a83ef0b3443e63b265a47d7dcf3b944482ac`, [run 40945576220](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40945576220), job `123699922093`, conclusion success. Это исправление файловых границ, не приёмка полного R1 и не независимые ML challenges. Windows reparse/ACL остаются вне подтверждённого scope.

## Основание и изменение

Внешний supplemental audit подтвердил, что прежний `bounded_read` принимал Windows NUL. Проверка symlink и открытие были отдельными операциями; regular-file requirement и проверка изменений при чтении отсутствовали. Внешний reviewer не заявлял воспроизведённый FIFO hang, удалённый exploit или обход подписи. Эти различия сохранены.

В [contracts.py](../../mlsecops/contracts.py) POSIX операции теперь проходят через открытые directory descriptors для каждого компонента пути. Leaf read использует no-follow/nonblocking open; regular-file type, размер и metadata проверяются на descriptor. Write использует exclusive private temporary file, fchmod/fsync на descriptor и replace/cleanup относительно одного parent descriptor. Проверки подписи/digest и карантин сохранены.

Если parent pathname заменили после открытия каталога, операция остаётся связана с прежним открытым directory object. Это не обещание, что pathname никогда не менялся или что запись остановится при любом переименовании. Каталог записи и root до открытия должны оставаться доверенными. Условия и восстановление после ошибки: [ранбук U03](../operations/artifact-files.md).

## Локальные проверки

Сначала новые negative tests запущены на прежней реализации. Получены 5 failures / 3 errors внутри 9 test methods, 2 POSIX skips. В частности, специальное устройство прочитано и изменение данных не обнаружено. После изменения кода исходные failing cases прошли.

Итоговая локальная группа: **103 methods, OK, 10 POSIX skips**. Это source-lock, 22 новых filesystem methods, signing/bootstrap, SQL optimization contracts и intake. Windows skips не объявлены Linux доказательством. Дополнительный вызов фактического `intake.submit` с synthetic NUL подтвердил сохранённый отказ `artifact_file_type`, parser calls 0, rows/bytes 0, approved outputs 0 и отсутствие `records.json`.

Матрица [artifact_files_qualification.py](../../scripts/artifact_files_qualification.py) включает положительные read/write и точный лимит, изменение metadata/размера, FIFO без writer с deadline 5 s, symlink в ancestor, leaf swap во время open, parent swap во время read/replace, exclusive-create collision, fdopen/fsync failure, закрытие descriptors и сохранение чужого canary. Отказ directory fsync после rename отдельно подтверждает, что новый полный файл может уже существовать.

## Linux и native integration

**379 test method executions, 0 skips**, включая 22 filesystem methods. `contracts.py`: **146 statements / 50 branches, 100%**. Signing helper: 47/14, SQL probe: 33/12, оба 100%; прежний cross-UID canary 6/6 снова совпал с ожидаемым canonical report. Новый reader проверен реальным Linux FIFO без writer и реальными symlink/rename operations; fault timing контролируется hooks в тестах. Это детерминированная проверка конкретных interleavings, не доказательство всех возможных filesystem races.

Native report выполнен с `20:06:10.917600` по `20:18:53.616181 UTC` 2026-10-29. Подготовка source/storage/candidate, обычный CLI и изолированный worker, inference, expiry/replay, outage/blackhole, изменение policy, независимый отзыв model/key и обе финальные cold checks прошли. **849 actual typed assertions с повторениями**: base 193, outage 192, blackhole 179, policy/replay 131, model 78, key 70, final cold 6. Это не число независимых сценариев.

| Actual-candidate fault | Первый полный HTTP 503 |
| --- | --- |
| Model revocation | 4.181707631 s |
| Key revocation | 4.383692924 s |
| Trust outage | 59.805493420 s |
| TCP blackhole | 13.338456731 s |
| Policy change | 4.149204371 s |

Для model/key финальные cold Readers дали точные `trust_artifact_revoked` / `trust_key_revoked` и не создали worker. Раздельные CA/PVC/authority history сохранены; версии primary 7/7/8, model authority 1/2/2. Peer history не изменена. Проверены mTLS 1.3, SQL permission denials и cross-CA refusal. Все relevant CAS/promotion snapshots совпали; old signed trust version 5 ещё имела 3378.282340 s срока, но после version 7 получила точный `trust_version_replay`. Пять clock/signature injections дали 25 отказов, последующее golden/recovery difference 0.0.

Проверяющий скрипт сначала исключил последнюю группу из 28 tests из-за секундной точности API step timestamps. Реальный log завершил её в `20:03:59.4832593`, а следующий step group начался в `20:03:59.8229381`. Граница исправлена по точным log group markers. CI и исходные результаты не менялись и не перезапускались.

`Stop verified owned source SQL` и `Remove verified owned disposable cluster` завершились success; конечное состояние проверено исполняемыми cleanup-командами workflow. Native report дважды напечатан идентично и сверён с исходниками. Actual production promotion по-прежнему отказан с `release_assurance_required`; `release_ready=false`, `full_M12=inconclusive`. Qualification permit не подменяет обязательные gates.

| Привязка | SHA-256 |
| --- | --- |
| Source fingerprint, 139 проверенных Git blobs | `e8462e60b5f57f14566fec34e48d14a4cc502021378d6a2c8bc5ccbf791e0d9d` |
| Worker image | `c6ffef45fdfa4d3e47fb42b77e0804f59ef197dbc396f8c0c6524bc52b641e3c` |
| Full native report, canonical JSON + LF | `28cc563f5fabe8ece215412a6e9f1407c3bd00fef7ff99a1711b44b0641e8dc9` |
| Independent-authority pair report | `a65dd1bf232c722c2ceb21e47addb852f462fdf78b2ff12efbd87e30772cd576` |
| Full promotion/CAS snapshot | `c9ec10fcedfd461b8b7ef853816716985620544a44d13d84d366ce083dc77e19` |
| Candidate | `751ab5fcdac78c06bd70c64f5b23644d04e01c032181daafde5d03051883723a` |
| Model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Subject | `891e8bb70f52a30dd2995f1f005df0a42698d6b0e2a54e4226a31e7695f96677` |
| Proposal | `cf8bdde2fcb0b8d5485f97154411f69fe0e0689f42916d5f37a58b39844b3dac` |

## Source lock и воспроизводимость

Старый `data.lock` после изменения helper ожидаемо отказал: `source_lock_mismatch_explicit_update_required`. Выполнено явное обновление только pin `mlsecops/contracts.py`. Все 8 input pins сверены с байтами Git blobs в `6c65a83`. Test mutation contracts.py теперь также должен отказать до запуска инфраструктуры.

Generated synthetic output остался неизменным: **1 915 576 байт**, SHA-256 `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`. Это конкретная проверка данных; она не доказывает тождественность всей сборки или принятие одного общего release candidate по M18.

## Остаточные ограничения

- Windows compatibility branch не доказывает ACL и отсутствие reparse races. Native runtime scope - Linux.
- Недоверенный writer внутри самого каталога, враждебный filesystem, администратор и подмена root до открытия не покрываются. Metadata stability не заменяет подпись/digest. Общие artifacts допускают hard links; signing keys используют отдельный более строгий helper.
- Основной `security-review.ru.md` не был предоставлен с supplemental audit. Полный внешний аудит не объявляется закрытым.
- Independent M22 challenge cases остаются 0/2. Отдельный code audit не подменяет их.
- Полные M11/M18/R1 остаются незавершёнными; обязательные trust lifecycle, operations и единая приёмка сохраняются.

Исходный внешний архив, private diagnostics и локальные verification outputs не коммитятся. GitHub Actions logs публичны; в tests используются только синтетические файлы и test identities. Этот документ содержит очищенные выводы и ссылки для воспроизведения.
