# PB-10 / RB-20 / RB-21: проверенный candidate lineage

Сфера: [collector T25](../candidate-lineage.md), не production serving. Ответственные: platform operator, curator для источника, ML/evaluation owner для training/report binding. Права: чтение существующих client configurations и metadata, запись локального diagnostic report. Collector не получает signing keys; TLS client keys нужны существующему SQL transport.

## PB-10: диагностика без изменения SQL

Prerequisites: pinned environment, working Docker engine, запущенный owned PostgreSQL, свежий `storage-demo.json` с candidate/evaluation того же checkout, `storage-trust.json`. Не запускать против чужой папки или неизвестного endpoint. Команда не обновляет grants и не восстанавливает отсутствующие inputs сама.

Из корня checkout:

```powershell
git status --short
git rev-parse HEAD
docker ps --format '{{.Names}} {{.Ports}}'
uv run --locked python -m scripts.candidate_lineage_native --state .runtime
```

Для другого проверенного state заменить только аргумент пути. Expected: exit 0, `status=pass`, `cases=10`, `full_M19=inconclusive`, `release_ready=false`. Report в `evidence/candidate-lineage-native.json` содержит verified graph из 5 nodes и impact из dataset/run/model. Сравнить exact IDs/edges с привязанными материалами приватно, не ограничиваться подсчётом nodes. Не загружать полный report или client directories в Git. Локальный native run и [clean-checkout CI 38157424563](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38157424563) на `c2597e5` подтвердили 10 checks, без write SQL или grant changes; полный M19 не заявляется.

Native checks намеренно пробуют прочитать holdout от publisher и promoter: ожидается SQLSTATE 42501, permission denied. Это отрицательная проверка на собственном lab state, не обход прав. Между двумя snapshots неизменны ID sets manifests, lineage, candidates, evaluations, включая budget receipt. Отсутствие report или digest mismatch не разрешает fallback на registry alias.

## RB-20: binding и потеря provenance

| Причина | Что сверить | Безопасное действие |
| --- | --- | --- |
| Missing candidate/report | Точные references и выбранный owned SQL state | Восстановить разрешённый immutable object; не сочинять report и не подставлять другой candidate |
| Source/image mismatch | Checkout revision/fingerprint и image label против candidate metadata | Для fresh qualification использовать соответствующий checkout либо новый candidate из текущих inputs; не редактировать metadata задним числом |
| Dataset/material mismatch | Curator signature, dataset/lineage refs, все split digest/bytes/rows | Исправить producer binding, сохранить rejected objects; повторить dataset/independent evaluation controls |
| Wrong signer/expired approval | Независимые trust roots, payload type и source expiry | Передать curator/security reviewer; не заменять trusted key ключом из envelope |
| Holdout digest/rows mismatch | Evaluation subject и curator manifest, без чтения labels collector-ом | Остановить promotion, проверить scorer; новый report только через штатный evaluation budget |
| Unknown owner/SQL identity | Externally managed owner allowlist и publisher/promoter client identity | Подтвердить mapping отдельно; не выдавать collector scorer/admin права |
| SQL/source/input changes during collection | Before/after evidence и одновременную работу другого процесса | Считать попытку недействительной, повторить после установления причины; не reset ledger |

**Проблема, выявленная при реализации:** первая версия projection давала одинаковый model ID для одинаковых bytes из разных runs. При будущей наивной сборке словаря один node мог затереть dependency другого. Regression test воспроизвёл коллизию; исправление использует candidate reference в ID, оставляя model digest отдельным. Теперь сохраняются обе dependencies, а content-equivalent aliases отзываются вместе. Это controlled design defect, не потеря реальных production данных.

Проверка:

```powershell
uv run --locked python -m unittest scripts.candidate_lineage_qualification.CandidateLineageContracts.test_same_model_bytes_keep_both_run_dependencies_when_projected
uv run --locked python -m scripts.candidate_lineage_qualification
```

## RB-21: невозможно записать diagnostic evidence

**Симптом:** qualifier возвращает exit 1; каталог evidence недоступен, linked или нет места/прав. Проверять путь и права приватно; не печатать содержимое client configs или keys.

Первый fault-injection test показал вторичный необработанный OSError: после неудачной записи inconclusive обработчик пытался записать fail туда же и мог вывести private path в traceback. Исправление сохраняет nonzero exit, подавляет только повторную ошибку записи и выводит общий diagnostic message без private exception body. Тест воспроизводит ошибку до исправления и проверяет её после.

```powershell
uv run --locked python -m unittest scripts.candidate_lineage_native_qualification.NativeLineageContracts.test_cli_does_not_write_outside_state_or_leak_write_errors
uv run --locked python -m scripts.candidate_lineage_native_qualification
```

Report сначала заменяется на inconclusive, при обычном отказе - на fail. Если файловая система вообще не позволяет запись, **старый report может остаться**: nonzero exit делает текущую попытку недействительной независимо от старого `status=pass`. Не использовать наличие файла как успех. Проверить exit code, fresh observed time и source/input binding. Исправить disk/ownership permissions без ослабления защиты, затем повторить. Symlink state отвергается до записи; не удалять чужую целевую папку.

## Восстановление и rollback

Collector не меняет SQL, поэтому database rollback после его запуска не требуется. Если SQL остановлен, восстановление сервиса выполняется отдельно по действующему storage bootstrap/recovery, только после проверки ownership/configuration; diagnostic helper намеренно не стартует его автоматически. Не переносить credentials между чужими states, не заменять volume, не сбрасывать budget и не удалять единственную копию evidence.

После исправления metadata выполнять штатный новый candidate/evaluation flow и затем collector. Прежний результат не переименовывать в новый. Нативный local test использовал отдельный fresh state; после успешной проверки именно его owned SQL container остановлен, volume и evidence сохранены. Текущие tracking/cluster services не менялись. Recovery команды для production, signed graph persistence и serving lease ещё не проверены, M19 остаётся inconclusive.
