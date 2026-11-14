# Local frozen candidate transfer prerequisite

Неделя 13, T21: bounded prerequisite для отдельных same-candidate jobs.
Это exporter/verifier, без parallel workflow, инфраструктуры и публикации архива.
Владелец интеграции: parent. [Модуль](../../scripts/frozen_candidate_transfer.py),
[qualification](../../scripts/frozen_candidate_transfer_qualification.py).

## Причина и контракт

Parent сообщил: full21 run `43623884406`, job `132535347498`, source `ed33`
остановился до M13 на `serving_retention.window`, поскольку у оригинального
proposal оставалось менее 600 секунд. Cleanup прошёл. Последовательные fresh
clusters и M23 расходуют исходное окно 1800 секунд. Этот patch не продлевает
окно, не повторяет proposal и не объявляет multi-job проблему решённой.

Exporter читает только pinned `evidence/M18-frozen-inputs.json`, четыре original
freeze files (`storage-demo.json`, `storage-trust.json`, `trusted-keys.json`,
`evidence/release-native.json`) и exact signed closure из M18-objects:
policy_reference, original proposal envelope, capsule, девять release documents
и все descriptor objects подписанного capsule. Исходные байты не меняются.
Повторный экспорт с теми же inputs даёт тот же manifest pin и архив.

Никакого обхода `.runtime`, чтения `keys/*.pem`, SQL credentials, tokens, private
review packets или raw audit logs нет. `trusted-keys.json` содержит только четыре
public verification keys; приватные ключи не нужны. Capsule namespaces строго
проверяет обычный material_bundle verifier. Qualification permits и runtime
credentials в allowlist не входят. Модуль не подписывает, не обучает, не создаёт
новый proposal, не refreeze и не выпускает/продлевает permits.

## External authority и вызов

Вызывающая сторона получает inputs из первоначальных producer outputs и своей
run identity. Локальный authority JSON содержит строго четыре поля:

- `freeze_pin`: первоначальный SHA-256 M18 freeze receipt.
- `freeze`: exact map четырёх путей freeze files на первоначальные SHA-256.
- `expected`: `source_revision`, `source_fingerprint`, `image_id`,
  `candidate_reference`, `evaluation_reference`, `proposal_reference`,
  `subject_sha256`, `model_sha256`.
- `run_owner`: `repository` вида `owner/repo`, положительные целые `run_id`,
  `run_attempt`, строка `producer_job`.

Эти данные доверенные и внешние по отношению к архиву. Reader также требует
полученный доверенным способом `manifest_pin`, не извлекает authority из архива.
Run owner сравнивается с caller expectation; это не независимая аттестация GitHub.
`image_id` означает оригинальный content digest из source receipt, а не registry
tag и не факт наличия или запуска образа у consumer.

Library API:

```python
result = export(root, source_state, **authority, clock=current_epoch_seconds)
summary = verify(
    root, Path(result["path"]), manifest_pin=trusted_manifest_pin,
    **authority, clock=current_epoch_seconds,
)
with materialize(
    root, archive_path, manifest_pin=trusted_manifest_pin,
    **authority, clock=current_epoch_seconds,
) as (temporary_state, summary):
    # Only approved files exist here; ordinary offline readers can use this state.
    # The context manager removes its own temporary state on exit or failure.
    pass
```

Imports: `export`, `verify`, `materialize` из `scripts.frozen_candidate_transfer`,
`Path` из `pathlib`. Caller передаёт актуальные UTC epoch seconds отдельно для
каждого вызова. Нельзя брать время из архива, повторно использовать старые часы
или выбирать историческое время, чтобы обойти expiry.

CLI из clean source checkout, с собственными фактическими paths и clock:

```bash
python -B -m scripts.frozen_candidate_transfer export --authority "$AUTHORITY" --clock "$CURRENT_EPOCH" --state "$SOURCE_STATE"
python -B -m scripts.frozen_candidate_transfer verify --authority "$AUTHORITY" --clock "$CURRENT_EPOCH" --archive "$LOCAL_ARCHIVE" --manifest-pin "$TRUSTED_MANIFEST_PIN"
```

Exporter пишет только `.runtime/frozen-transfers/<manifest_sha256>.zip`, возвращает
локальный path, manifest/archive hashes, classification и `release_ready: false`.
Существующий отличный архив не перезаписывается. Directory/file создаются с
POSIX modes 0700/0600; проверка Windows ACL и гарантия против Win32 races отсутствуют.
Архив не зашифрован, хранить только в доверенном private local workspace.

## Verification и временные границы

Manifest связывает external owner, identity, исходные freeze pins, оригинальное
proposal window, classification и SHA-256/size каждого файла. ZIP без compression,
links/directories, extra entries, duplicates, comments, preamble или trailer.
Reader не использует `extractall`: после проверки allowlist и exact closure
создаёт новый собственный временный каталог. Destination в существующем state
передать невозможно. Размер ограничен 80 MiB, число payload files 64;
внутренние object/document limits остаются из обычных verifiers.

Обычный `final.frozen` проверяет исходные signatures, bytes, model/candidate,
data.lock, dependency lock и historical proposal. Дополнительно проверяются
чистый source до и после операции, exact caller identity, текущая policy и
source approval по caller clock. Повторно используется `serving_retention.window`
с исходным минимумом 600 секунд: `issued <= clock < expires`, clock не раньше
первоначального capture, remaining >= 600. Policy также должна иметь >=600 секунд.
Это проверка на момент caller clock, не резерв времени. Перед native operation
consumer обязан снова проверить актуальное окно обычным owner/permit flow.

Expired/future/less-than-600 proposal, повреждённая подпись, неверный source или
candidate, изменённый внешний pin, missing/extra object блокируют результат.
Повторный outer hash не заменяет original signatures или caller authority.
Credentials markers/fields в выбранных bytes дополнительно отклоняются; эта
защита не доказывает отсутствие произвольно закодированных секретов в модели.

## Классификация и чувствительные материалы

Классификация всегда **private-local-only**, `public_synthetic_proven: false`.
Из проверенного signed closure извлекаются model-card classification,
source approval purpose и hashes dataset/source approval/data.lock. Обычный
верификатор связывает synthetic-only model card и synthetic-lab source approval
с тем же candidate. Эти признаки не дают разрешения публичной публикации всех
материалов и не доказывают независимым анализом содержимое binary model.

Архив содержит model bytes, training/evaluation metadata и metrics, lineage,
release/source/image identifiers, public keys и key IDs, owner/run identity,
policy, dependency versions и исходные timestamps. Это потенциально внутренние
материалы. Отдельных source rows и private M22 review/audit packets нет в
allowlist. Публичная synthetic classification для реального native архива
не заявлена. Не загружать пакет как public artifact/release или в Git.
Этот patch не даёт разрешения ни на private hosted upload, ни на secrets settings.

## Диагностика и ограничения

При отказе проверить producer pins, время и сохранность оригинальных files
локально. Не печатать package, payloads или credentials. Восстановление допустимо
только из аутентичной копии с теми же исходными pins; иначе результат inconclusive.
Нельзя переиздать proposal или снять time/closure checks ради успешного transfer.
Для rollback parent может не использовать exporter; source state остаётся
неизменным, автоматической очистки исходных файлов нет.

```bash
python -B -W error -m unittest scripts.frozen_candidate_transfer_qualification
python -B scripts/check_docs.py
```

Локальная проверка на pinned Python 3.12.15: 13 transfer tests и 49 смежных
regression tests pass, 0 skips. Coverage нового модуля: 203/204 statements,
33/34 branches (97.1% branches, 99% combined). Ruff check/format и check_docs pass.
Coverage относится только к exporter/verifier, не ко всей платформе.

Tests используют подписанные controlled fixtures и проверяют полный local replay
после удаления исходных allowlisted files. Native models/packets из hosted run
здесь не экспортировались. Source cleanliness в fixture подменена, настоящие
signatures, closure и `final.frozen` работают без подмены. POSIX permission checks
исполняются только на POSIX. Локальные Docker/WSL/Kubernetes/SQL, external models,
upload, dispatch и secrets settings не нужны и не выполняются. Multi-job native
qualification, transfer channel и consumer provisioning остаются задачей parent.
M18/R1 не закрыты; independent M22 0/2 и strict child criteria не изменены.
