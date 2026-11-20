# Private original M11/M12 primaries for later M18

Неделя 13, T21 «Сквозной release acceptance»: collector и offline reader исходных
M11/M12 preimages. Это подготовка оригинального evidence, не полная приёмка M18,
не новый gate report и не разрешение выпуска. Native integration принадлежит
parent consumer driver; этот модуль не запускает инфраструктуру.

Код: [m18_shared_retention.py](../../scripts/m18_shared_retention.py).
Проверки: [qualification](../../scripts/m18_shared_retention_qualification.py).

## Причина и решение

На baseline `bf4ba7e` shared capture/late сохраняют исходные private observations,
а shared receipt возвращает сводку с хешами. Consumer materializer удаляет всё
временное представление при выходе из context. Одна сводка после этого не даёт
preimages для обычных file readers или будущего M18 object store.

Collector читает только согласованный allowlist и подписанную frozen closure,
сохраняет точные bytes в content-addressed storage (CAS, объекты с именем SHA-256)
и проверяет восстановленное представление. Повторное измерение gates и перенос
всего runtime не нужны. Reader требует первоначальные внешние pins; private
index не является источником доверия к самому себе.

План реализации: negative tests для missing/tampered/repinned inputs; сбор точных
preimages; historical semantic replay; проверки bounded I/O и owned cleanup;
per-module line/branch coverage и документация. M18 acceptance/PRIMARY, existing
M11 archive и native driver этим изменением не редактируются.

## API и место вызова

Оба API принимают `pathlib.Path`. `root` - clean checkout того же producer source.
`state` - ещё существующее consumer temporary view. `destination` - новый каталог
внутри `root/.runtime`, снаружи `state`. Каталог не должен существовать; collector
не перезаписывает предыдущий результат. Родитель отвечает за приватность и
retention внешних pins и файлов. POSIX directories создаются private, файлы 0600;
Windows требует корректного private ACL родительского `.runtime`.

```python
from scripts.m18_shared_retention import retain, replay

# Inside consumer materialize context, AFTER both M11/M12 reports and cluster cleanup.
arguments = dict(
    **owner,  # freeze_pin, freeze, expected, run_owner from the trusted caller
    report_pins=report_pins,  # exact raw evidence/M11.json and evidence/M12.json hashes
    actual_pin=actual_pin,   # original shared-serving-actual.json bytes
    native_pin=native_pin,   # original shared-serving-native.json bytes
)
index_pin = retain(root, state, destination, **arguments)
checked = replay(root, destination, index_pin=index_pin, **arguments)
assert checked["release_ready"] is False
# Keep index_pin and arguments privately, then allow consumer context cleanup.
```

`retain` возвращает строку SHA-256 private index. `replay` возвращает dict с
`scope`, `classification`, `release_ready=False` и результатом обычного
`shared_serving_receipt.receipt()` в поле `receipt`. API ничего не печатают.
Не выводить `index_pin`, `arguments`, возвращённый receipt или raw exceptions в
публичный stdout, GitHub outputs/artifacts либо summary. CLI публикации нет.

Все аргументы обязательны. `freeze` имеет исходные четыре file pins; `expected`
содержит точную `frozen_candidate_transfer.IDENTITY`, включая source/image и
candidate/evaluation/proposal/model/subject. `run_owner` содержит repository,
run_id, run_attempt, producer_job исходного freeze. Shared producer записывает
только GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, GITHUB_JOB: первые два сверяются с
run_owner, consumer job не приравнивается к producer_job. Repository передаёт
доверенный caller; shared packet не содержит отдельного repository observation.

## Точный набор и формат

Пути относительно `state`; epoch берётся из externally pinned actual packet,
проверяется как 32 hex characters. Никакого recursive glob consumer state.

| Набор | Файлы |
| --- | --- |
| Shared | `evidence/shared-serving-actual.json`, `evidence/shared-serving-native.json` |
| Campaign | `candidate-inference/<epoch>/config.json`, `request.json`, `reference.json`, `probe.json`, `root-rotation.json`, `independent-authorities.json`, `outage.json`, `blackhole.json`, `policy-change.json`, `key-revocation.json`, `model-revocation.json` |
| M11 | `evidence/trust-frozen.json`, `evidence/kubernetes-serving.json`, `evidence/release-key-native.json`, `evidence/release-key-serving.json`, `evidence/trust-contracts.json`, `evidence/M11.json` |
| M12 | `evidence/inference-native.json`, `evidence/inference-contracts.json`, `evidence/M12.json` |

Итого 22 именованных файла. Producer `write_json` записывает canonical JSON с LF;
сохраняются именно эти bytes, включая LF. M11 `method_materials` и M12
`contract_materials` - два дополнительных canonical preimages без LF, построенных
из того же source snapshot. Их хеши должны совпасть с уже записанными artifact
hashes; пересчёт source не разрешает изменить report pin. Полный original probe
сохраняется целиком; выборка M12 cases существует только в памяти reader.

Существующий `frozen_candidate_transfer.checked_files` читает четыре исходных
freeze files, `evidence/M18-frozen-inputs.json` и точную signed package closure:
policy reference, proposal envelope, capsule, `release_bundle.DOCUMENTS`, все
capsule descriptors. `trusted-keys.json` содержит публичные verification keys и
необходим для проверки. Private keys, kubeconfig, credentials, logs и raw
train/holdout/validation files не выбираются. Signed split manifests сохраняются
как исходные metadata в closure, без чтения самих выборок.

В `destination/evidence/M18-objects/<sha256>` находятся все точные preimages и
сам private index. Index связывает исходные paths с hashes и objects с размерами,
сохраняет внешние owner pins. Каждый M11/M12 `artifact_hashes` обязан иметь
preimage; лишние или отсутствующие refs отвергаются. Отдельной копии named files
в destination нет. Временный rehydrate создаёт их для ordinary readers и удаляет
только собственный каталог при успехе или исключении.

Ограничения: каждый объект не более 16 MiB; полный retained набор с index не
более 256 MiB; сам index не более 1 MiB; число paths не более 64 frozen + 22 shared;
два canonical maps не добавляют named paths. Более строгие исходные ограничения
frozen closure остаются в силе. Большой native packet отклоняется, не обрезается.

## Историческая проверка после cleanup

Reader проверяет clean source revision/fingerprint до и после обработки и
повторно вычисляет обе source maps. Signed frozen reader проверяет оригинальный
package на исходном capture timestamp. `shared.retained`, `trust_delivery.retained`,
trust/inference reconcile и shared receipt проверяют исходный permit, proposal,
candidate, source/image, original observations, authority transitions и reports.
M11 signer observations и исходные report cases/metrics также сверяются.

Истечение proposal после завершённой qualification не запрещает историческое
чтение. Текущий minimum 600-second operational window не вызывается. При этом
исходный permit должен иметь правильную подпись, исходные issued/expires и
допустимые recorded execution times. Новые proposal, permit, подпись, ключ,
approval или gate report не создаются. Для нового выполнения или promotion
необходимы отдельные актуальные проверки, которые этот reader не заменяет.

`shared.lookup/capture/late` и обычные gate `qualify` требуют живую инфраструктуру
и здесь не вызываются. Offline reader не использует Docker, SQL, cluster owner
lookup или `offline_pin()` с Docker inspect. Он не подтверждает заново факт
реального native исполнения или cleanup, а проверяет сохранённые наблюдения и
их bindings. Parent обязан выполнить cleanup до retain.

## Отказы, восстановление и rollback

Missing/tampered bytes, noncanonical named JSON, altered maps, wrong external
pins, mixed candidate/source/image/run-attempt, repinned inconsistent references,
лишние index/CAS entries и неверные historical timings дают отказ. До успеха
reader collector не возвращает index pin. Ошибка записи или конечной проверки
удаляет только эксклюзивно созданный destination; соседние данные сохраняются.

Начать диагностику с сохранности первоначальных pins и private inputs. Не
подменять pins хешами повреждённых файлов, не refreeze/reseal для обхода отказа.
Если context ещё открыт, устранить проблему с диском/путём и повторить в новом
owned destination. Если original view уже удалён и retained copy нет, evidence
не восстановлено: campaign нельзя объявить пригодной для M18 по summary.
Escalation владельцу parent: утрата originals, превышение лимита, mismatch
источника или отказ обычного verifier. Не удалять единственную retained копию.

Повторный `replay` read-only и не меняет retained bytes. Повторный `retain` в тот
же destination отказывает даже для того же содержимого; существующий результат
проверять через replay. Rollback интеграции исключает вызов нового helper, но
сохраняет private evidence и не переводит обязательные gates в pass.

## Проверка и пределы доказательств

```bash
python -B -W error -m unittest scripts.m18_shared_retention_qualification
python -m coverage run --branch --source=scripts.m18_shared_retention -m unittest scripts.m18_shared_retention_qualification
python -m coverage report --fail-under=95
python -B scripts/check_docs.py
```

Отдельно проверять line и branch percentages по coverage JSON, каждый не ниже
95%. Общий coverage percentage не заменяет эти два порога. Qualification
использует реальные fixture signatures, frozen readers, shared.retained,
trust/inference reconcile и object I/O; native observations синтетические,
source cleanliness для подписанных fixture roots контролируется тестом.
Это компонентное доказательство. Native consumer, Linux permissions и полный
M18/index assembly требуют отдельной проверки parent после интеграции.

Локальная qualification 2026-11-20: Windows, Python 3.12.14 и уже установленные
project dependencies; строгий запуск с `-B -W error` прошёл 24/24 tests, 0 skips,
340.749 s. Coverage collector: 196/196 statements, 34/34 branches, оба 100%.
Отдельно пройдены `ruff check`, форматирование и `check_docs.py`. Positive case
удаляет весь consumer state в owned fixture и повторяет object-only replay после
истечения proposal; subprocess, live lookup и operational window при этом
запрещены тестом. Native qualification и target Python 3.12.15/Linux этим локальным
результатом не заявлены. Никаких скачиваний, запуска кластера/SQL или публикации.
