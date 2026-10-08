# M20: worker/evaluator authority boundary

[План и ограничения](decisions/0013-worker-authority-acceptance.md). Новый runner объединяет уже проверенные компоненты, но не использует их прежний pass как разрешение: каждый запуск выполняет все suites заново. До подтверждения конечного runtime/CI результата статус реализации сверять в [STATUS](../STATUS.md).

## Полный путь проверки

1. Проверить source/image и owned controller profile, сохранить текущий private SQL ledger.
2. Заново выполнить Kubernetes isolation suite: реальные API/role/network/resource probes.
3. Выполнить protocol contract suite, включая одноразовый consume, неизвестные fields, sizes, scores и replay.
4. Запустить настоящие publisher/scorer и независимые workers, получить новый candidate и подписанную evaluation. Проверить сохранённую подпись через отдельный reader.
5. Запустить qualification scorer с той же identity, реальным key/SQL bundle и общим Pod builder. Он выполняет 21 новый prediction Job: два положительных контроля и 19 намеренно повреждённых response cases. На каждом negative сначала получен и проверен чистый response настоящего worker, затем тестовый executor меняет форму/поле **после transport**. Production worker и его admission не получают test mode.
6. Проверить точный отказ consumer, отсутствие sign/SQL put calls и неизменность evaluation history для каждого negative. Spies оборачивают реальные функции, не подменяют их успешными ответами. Positive controls действительно подписывают, сохраняют и независимо перечитывают свои reports.
7. Выполнить [live access matrix](live-worker-boundary.md) на том же image/dataset с одновременно живым scorer witness.
8. Проверить source/image/policy/dataset/candidate/model binding, уникальность case IDs, protected ledger и cleanup. Evidence сохраняется отдельно по компонентам с SHA-256; отсутствие, fail, inconclusive или неправильный binding не дают pass.

## Native negative matrix

| Вводимая неисправность | Требуемый отказ |
|---|---|
| Arbitrary text, лишнее/отсутствующее поле | `unexpected_fields` |
| Missing/extra rows | `prediction_count_mismatch` |
| Перестановка/повтор row ID | `prediction_response_row_binding` |
| Bool, отрицательная probability, значение >1 | `invalid_probability` |
| NaN/Inf | `invalid_json_value` |
| Response >16 MiB | `prediction_response_limit` |
| Неверные version/batch/model/request digest | `prediction_response_binding` |
| Unsupported scan | `prediction_scan_contract` |
| Response предыдущего настоящего batch | `prediction_response_binding` |

Отсутствующий/упавший worker, TLS/SQL error или timeout не засчитываются как ожидаемый protocol rejection. Fault injection проверяет receive/signing/publication boundary, не означает успешную эксплуатацию ONNX parser. Два положительных контроля не позволяют получить pass просто от отключённой БД, отсутствующего ключа или неработающей модели.

## Команды

Требуется owned [scoped controller lab](scoped-controllers.md) с завершённой migration. В уже populated target migration не повторять и данные не удалять.

```bash
uv run --locked python -m mlsecops.authority_contract_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.controller_bootstrap --replace-profile
uv run --locked python -m mlsecops.acceptance --gate M20 --output .runtime/evidence/M20.json
```

Для fresh checkout выполните prerequisites/scoped bootstrap из runbook, затем последнюю команду. `replace-profile` только для idle owned lab; выполняется последовательно, не одновременно с другими operator jobs. M20 создаёт новый candidate и три допустимые evaluation rows: controller positive и два native positive controls. Отрицательные cases не добавляют rows. Новая история не входит автоматически в старый backup host БД; private-target backup остаётся частью M17.

Report `.runtime/evidence/M20.json` содержит gate status, время, source revision/fingerprint, policy/image/model/dataset/candidate digests, cases, метрики, artifact hashes и residual risks. Компоненты лежат в `M20-isolation.json`, `M20-protocol.json`, `M20-controller.json`, `M20-outputs.json`, `M20-access.json`, `M20-contracts.json`; связующий report - `authority-qualification.json`. Это очищенные синтетические результаты, не архив keys/labels/raw diagnostics. CLI сначала инвалидирует прежний output как running/inconclusive. Exit 0 = pass конкретного gate, 1 = failure, 2 = missing prerequisites/inconclusive.

Для импортированных component cases без собственных `expected/actual` агрегатор записывает ожидаемый и наблюдённый status; он не изобретает отсутствующие raw measurements. Подробные условия проверок остаются в component code/reports. Постоянные contract tests проверяют замену stale pass при missing prerequisites, ожидаемом отказе, I/O error и необработанном crash. Эти tests выполняют CLI в отдельном временном каталоге, не портят действующий lab и не заменяют его живую приёмку.

## Связь с требованиями M20

| Требование | Исполняемое доказательство |
|---|---|
| Нет labels, keys, tokens и соседнего `/proc` у workers | `access:*`, настоящий scorer witness и обе worker identities |
| Нет доступа к SQL/control-plane API | `access:*` network probes с положительными контролями; `controller:*` RBAC/admission negatives |
| Разрешённый batch сохраняется и подписывается | `outputs:positive-before:*`, `outputs:positive-after:*`, независимое повторное чтение `gate:positive-*` |
| Малформатный/replayed/oversized response не получает authority | `outputs:*:exact-rejection`, `no-sign-or-write`, `history-unchanged` для 19 cases |
| Model parser не работает рядом с signer | `gate:parser-outside-privileged-scorer`, observed separate worker Pod UIDs |
| Нельзя подставить чужие/старые component reports | Свежий запуск всех suites, subject binding и `contracts:aggregate:*` negatives |
| Ошибка проверки не оставляет прошлый pass | Invalidation в acceptance CLI и `contracts:cli-*` |

CI повторяет полный путь в disposable cluster из clean checkout. Ссылка на подтверждённый run и точные measurements публикуются в STATUS только после чтения результата, а не сразу после push.

## Границы результата

M20 не закрывает M01 vulnerability audit, M04 serving permissions, M05 serving SLO при exhaustion, M07 persistent holdout budget, M11 release replay, M21 independent scanner или M23 защищённый audit sink. Host/cluster admin и shared kernel остаются доверенными; все covert channels и корректно оформленные ложные scores не исключены. Повтор synthetic holdout в qualification не разрешает reuse настоящего business holdout. Полный R1 и production promotion не следуют из одного M20 pass.

Код: [native probe](../mlsecops/authority_probe.py), [aggregator](../mlsecops/authority_qualification.py), [negative contract suite](../mlsecops/authority_contract_qualification.py), [acceptance CLI](../mlsecops/acceptance.py).
