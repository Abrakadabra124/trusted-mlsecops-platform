# Приватный export original serving primary

## Назначение и границы

[Exporter](../../scripts/ci_serving_retention.py) сохраняет оригинальные preimages M02/M03/M07
и M13/M14/M15 до удаления consumer context. Отдельный offline reader восстанавливает
временный view из архива и вызывает существующие frozen/upstream readers,
`m18_serving_retention.capture/replay` и `serving_campaign.replay`.
Это компонент подготовки evidence для R1. Он не принимает M18, не изменяет
PRIMARY/acceptance и всегда возвращает `release_ready=False`.

Архив, его index pin и возвращённые receipts имеют классификацию
`private-local-only`. Они могут содержать исходную модель, validation observations,
внутренние идентификаторы и hashes. Synthetic provenance не разрешает публикацию.
Модуль ничего не печатает, не пишет Actions outputs, не загружает artifacts,
не вызывает SQL, Docker, Kubernetes, network или модель.

## Контракт lifecycle

Ответственный за вызов - trusted lifecycle caller, который ещё владеет consumer
context. До `__exit__` необходимо получить шесть исходных reports, три admissions,
две original transition records и подтверждённые lifecycle cleanup results.
Этот exporter не выполняет cleanup инфраструктуры и не устанавливает его успех
по наличию transition records. Caller отдельно проверяет свои cleanup witnesses.

Из доверенного состояния caller передаёт:

- `freeze_pin`, `freeze`, `expected`, `run_owner` по контракту
  [frozen transfer](frozen-candidate-transfer.md);
- `report_pins` с точным набором M02/M03/M07/M13/M14/M15;
- `admission_pins` с точным набором M13/M14/M15;
- `transitions`: два dict с `before`, `after`, `source_sql`, где обе стороны
  содержат только `namespace` и `volume`; это исходные результаты переходов;
- `consumer_storage_pin`: SHA-256 исходного consumer `storage.json`.

Все вложенные аргументы snapshot-ятся до artifact I/O. Запрещено получать
ожидаемые owner/pins из экспортируемого index или чужого receipt.
`run_owner` привязывает архив к caller-supplied repository/run/attempt/job;
сам по себе архив не доказывает исполнение этого job в CI.

```python
from scripts import ci_serving_retention

# authority, report_pins, admission_pins, transitions и consumer_storage_pin
# уже зафиксированы trusted caller. Не вычислять их из экспортируемого index.
arguments = dict(
    **authority,
    report_pins=report_pins,
    admission_pins=admission_pins,
    transitions=transitions,
    consumer_storage_pin=consumer_storage_pin,
)
result = ci_serving_retention.retain(root, state, destination, **arguments)
assert result["release_ready"] is False
index_pin = result["index_pin"]  # Сохранить только в private caller state.

# После consumer __exit__, без исходного state и инфраструктуры:
verified = ci_serving_retention.replay(
    root, destination, index_pin=index_pin, **arguments
)
assert verified["release_ready"] is False
```

`retain` возвращает `index_pin`, `receipt` от ordinary campaign replay,
`replay` от ordinary serving retention, `scope`, `classification` и
`release_ready=False`. `replay` возвращает те же поля кроме `index_pin`.
Ни один результат не является новым proposal, permit или release approval.

## Состав и ограничения

Collector читает fixed allowlists и адресованные references, без recursive glob:

1. `frozen_candidate_transfer.checked_files`: исходный freeze receipt, четыре
   frozen файла и точное signed capsule/package closure. Подписи проверяют
   прежние обычные readers.
2. `ci_upstream_transfer._inventory`: три upstream reports, шесть fixed primary
   файлов и три `evaluation-gate/<campaign>/{contracts,native,budget}.json`.
3. `m18_serving_retention.inventory`: original trio files, admissions, private
   packets, candidate artifacts и producer canonical maps. Raw JSON с LF и
   canonical preimages сохраняются раздельно согласно исходным producer hashes.
4. Все `artifact_hashes` шести pinned reports, retained admissions и точное
   signed closure. CAS читается только по этим references.
5. Исходный `storage.json`, необходимый обычному `serving_campaign.replay`.

Ключевые PEM, kubeconfig, raw logs, storage clients и посторонние CAS objects
не выбираются. В выбранных bytes дополнительно действует существующая проверка
`no_credentials`; это не универсальный классификатор приватности.

Один object ограничен 16 MiB, index - 1 MiB, общий объём уникальных objects с
index - 256 MiB. Максимум 384 file references и 512 objects плюс index.
Более строгие существующие лимиты frozen/upstream readers остаются в силе.

Destination должен находиться под producer `root/.runtime`, иметь существующий
trusted private parent и не пересекаться с consumer state. Symlinks, junctions
и `..` отклоняются. Все проверки и запись выполняются в owned private staging;
полный каталог переименовывается в destination после успешного offline replay.
При отказе временные каталоги удаляются. Existing destination допускается только
при точном совпадении вычисленного index и всех bytes, без ремонта или перезаписи.
На replay перечисляются только три фиксированных уровня archive directory;
лишние файлы, отсутствующие preimages и несогласованный inventory отклоняются.

Parent должен быть недоступен другим писателям. POSIX использует существующие
no-follow file operations и private modes. Windows compatibility path проверяет
reparse points, но не заявляет race-safe Win32 handles или настройку ACL.
Архив переживает удаление consumer context на том же диске. Сохранение после
удаления всего runner требует отдельного private storage lifecycle и этим API
не обеспечивается.

## Исторический replay

Проверяются exact source revision, полный fingerprint и чистота checkout до и
после обычных readers. Исходные подписи, reports и permit timestamps не меняются.
Проверка использует original capture/permit times обычных frozen и serving readers,
а не новые 600 секунд от текущего времени. Истёкший сейчас proposal не препятствует
чтению достоверного исторического evidence и не получает продления.

## Диагностика и восстановление

Отсутствующий preimage, неверный pin, чужой owner/source, неверная transition
chain, несовпавшая подпись, лишний файл или превышенный лимит означают отказ.
Не удалять consumer context, пока `retain` не вернул проверенный private receipt.
Не маскировать отказ повторным вычислением expected pins из повреждённого archive.

При destination collision сравнить independently retained index pin и owner;
не удалять и не перезаписывать чужой каталог. При I/O failure сохранить consumer,
устранить причину на owned private storage и повторить с теми же external pins.
Повтор успешного export идемпотентен по bytes. Rollback этого компонентного шага
означает прекращение dispatch и сохранение исходных private materials, а не
выдачу нового permit. Если оригиналы уже потеряны, summary не восстановит primary;
эскалировать владельцу lifecycle как потерю evidence.

## Qualification

20 ноября 2026 года [qualification](../../scripts/ci_serving_retention_qualification.py)
прошла на Python 3.12.15 из уже подготовленного parent venv:
24 tests, 0 failures, 0 errors, 0 skips, 216.449 s.
Statements 166/166 и branches 32/32, оба 100%, без exclusions.
Проверены отрицательные owner/pin/source/path/foreign-file cases, bounded limits,
write/reader/rename failure cleanup, exact-byte idempotency, сохранение original
bytes, real signature denial, ordinary replay после удаления consumer и при
историческом clock 2099 года. Неверная подпись и выход observation за original
permit window отклоняются даже при обновлённых outer hashes.
TDD зафиксировал RED -> GREEN для отсутствующего exporter, parent junction и
продолжения directory enumeration после первого foreign entry.
Fixtures заменяют native measurements, audit I/O и git source probe; frozen
package signatures, permit verification и ordinary replay остаются настоящими.
Это offline component evidence, не native M13/M14/M15 или M18 acceptance.
Review этой реализации пока является self-review автора; независимый review
перед интеграцией остаётся задачей parent.

Из корня точного checkout, на уже подготовленном Python 3.12.15:

```text
python -B -W error -m coverage run --branch --source=scripts.ci_serving_retention -m unittest scripts.ci_serving_retention_qualification
python -m coverage report
python scripts/check_docs.py
```

Не публиковать coverage/test logs, если локальная диагностика включает private
paths или packet identifiers. Для review достаточно очищенного результата и
точного commit; интеграцию lifecycle выполняет владелец driver.
