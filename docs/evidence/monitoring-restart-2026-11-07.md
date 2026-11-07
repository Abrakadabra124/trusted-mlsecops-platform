# T18: безопасный cold restart мониторинга

Дата: 2026-11-07 МСК. Source:
[`361b7dd084dbc2dc05d66da86558abfdcaee825d`](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/361b7dd084dbc2dc05d66da86558abfdcaee825d).
Scope: сохранение запрета reuse epoch и явное сообщение о потере in-memory
истории. Это не восстановление прежних observations, labels и receipt cache.
Full M15 и R1 остаются открытыми; `release_ready=false`.

## Изменённое поведение

Конфигурации producer и sink требуют заранее созданный private Linux registry
и его identity fingerprint. Загрузка config не создаёт registry. При startup
каждая роль однократно закрепляет свой epoch через directory lock, O_EXCL и
fsync. Directory/file owner, permissions, тип, links и размер identity проверяются;
неизвестные entries, отсутствие state или заполнение 1024 markers дают отказ.
Marker не удаляется при завершении процесса и не считается свободным, если его
запись прервалась. Инициализация существующего directory запрещена.

Producer с новым epoch после прежних запусков сообщает
`epoch_admission.history_unavailable=true`, `history_restored=false`, начинает
с insufficient и отправляет отдельный signed `telemetry_gap`. Старые окна не
восстанавливаются счётчиками. Sink не принимает HTTP alerts до admission, старый
epoch не совместим с новым. Ни restart, ни receipt не разрешают выпуск модели.

## Контрактные и native-process проверки

[Linux contracts 42327687983](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42327687983)
/ job128266687931: **success** на source выше.

- 142 monitoring/feedback/state/restart tests / 0 skips / 44.034s.
- 77 HTTP/audit/lifecycle tests / 0 skips / 7.154s.
- 52 material/lineage/release tests / 0 skips / 2.057s.
- 17 modules: 1438/1442 statements, 468/470 branches; каждый отдельно >=95%.
- Новый `monitoring_state`: 104/106 statements, 24/24 branches. Покрытие не
  заменяет ниже перечисленные отрицательные сценарии.

Проверены неправильные paths/pins/roles, owner/mode/nlink, symlink, missing state,
пустой marker после прерванной записи, short write, write0, fsync error, полный
registry, concurrent lock и исключительность повторного epoch. Отдельный child
записал marker и завершился через `os._exit(0)`; новый объект Guard в другом
процессе отказал в повторном epoch. Новый epoch сохранил признак неизвестной
предыдущей истории.

Native Linux sink test получил настоящую signed receipt, завершил свой процесс
через SIGKILL и подтвердил закрытие порта. Повтор с той же конфигурацией получил
exit1; после явной смены epoch старое signed событие отклонено, новое принято,
identical retry вернул прежнюю receipt. Замена завершена штатным SIGINT, PID/порт
закрыты. Это проверка process crash на локальном filesystem runner, не отключение
питания, не Kubernetes volume restore и не защита от host administrator.

Controlled Runtime test с настоящим loopback sink подтвердил подписанную доставку
telemetry_gap и insufficient/0observations после нового admission. Локально
Windows общий suite до последнего cleanup patch:142tests/8Linux skips/61.164s;
после cleanup patch probe6/1skip/0.462s; после exit fix9/2skips/1.152s. Linux
результат выше относится к окончательному runtime commit и включает все эти paths.

## Первый отказ и исправление

[`4efc28a`](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/4efc28a66db24c11e856a5c16df9f3b40ae4004f)
не принят: [contracts42327456211](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42327456211)
и [native42327456343](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42327456343)
остановились на contract step до создания инфраструктуры. Старый epoch был
правильно отвергнут, но Uvicorn завершил startup с SystemExit3, тогда как CLI
контракт требовал exit1. Wrapper нормализует SystemExit в постоянный refusal;
controlled regression дополнительно проверяет code0 и code3. Успешный retry не
стирает исходный failure и не закрывает прежний R1-B08 shutdown debt.

Подготовка registry теперь выполняется до открытия candidate reader. При ошибке
конструирования engine session закрывается; соответствующие negative cases
добавлены. Это локальная исправленная ветка cleanup, не доказательство устранения
всех исторических отказов эксплуатации.

## Actual-candidate composition

[Native campaign42327687810](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42327687810)
/ job128266687327 завершился **success** на том же runtime source. Checkout
чистый, pinned dependencies и образ собраны на hosted runner. Обязательный
epoch admission включён в actual producer/sink. Это свежая candidate campaign;
SIGKILL/restart проверялся отдельно описанными выше native-process tests.

| Проверка | Результат |
| --- | --- |
| Actual HTTP observations | 12000, 10 clean windows, 2 shift windows |
| Signed receipts | 3, max delivery0.471294143s <120s |
| Delayed-label fixture и retry | 200 positive labels, повтор не увеличил число |
| Feedback quarantine | 10 claims/1 row, exact retry, curator readback |
| Direct forbidden SQL operations | 15/15 permission denials42501 |
| Protected source tables и cluster promotion | unchanged |
| Worker/source SQL/cluster cleanup | verified / stopped / absent |
| Post-cleanup primary reconciliation | success, monitoring и feedback proof |
| Full M15 / release_ready | inconclusive / false |

[Полный публичный summary](monitoring-restart-2026-11-07-summary.md) сохраняет
source/image/model/subject/reference bindings. Monitoring packet:
`64c3d7fd20e55efa8a28e2817a3f11c250bcec6ee082a3a691f2469f16549075`.
Feedback proof:
`59245837ba23ea6ce6263d8419c7afe314e3d112a0ab3995f7cec4a345b46750`.
Probe elapsed26.243217s относится к observation Job, не является M14 load gate.
Raw primary packets, payloads и keys не опубликованы.

## Эксплуатация и следующий шаг

[Ранбук и плейбук восстановления](../operations/monitoring-restart.md) задают
первоначальный provisioning, диагностику, остановку своей пары процессов,
новый согласованный epoch, проверку gap receipt и escalation при потере реестра.
Автоматический reset, удаление markers и восстановление старого snapshot без
доказательства полноты не предлагаются.

Для полного M15 остаются свежие M13/M14 с включённым monitoring и общая приёмка.
M18 выполняется последним на одном candidate; независимые M22 остаются0/2.
