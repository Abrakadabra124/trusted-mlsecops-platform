# Приватный мост frozen candidate и AES

Неделя 13, T21: необходимый мост для параллельных CI-заданий одного кандидата.
CI (continuous integration) - автоматические проверки изменений. Это локальный
API, без CLI, workflow, сети, публикации и настройки секретов. Владелец дальнейшей
интеграции - parent; этот компонент не закрывает общую T21/M18-приёмку.

[Реализация](../../scripts/ci_candidate_transfer.py) соединяет существующие
[frozen exporter/reader](frozen-candidate-transfer.md) и
[AESGCM transport](ci-transfer.md), не меняя их контракты или лимиты.
AES-GCM - стандартное шифрование с аутентификацией; AAD - контекст, который
защищается authentication tag вместе с ciphertext.

## Вызов и внешний trust boundary

Caller передает `root`, исходный `state`, 32-байтовый `key`, `phase` и четыре
внешних authority inputs: `freeze_pin`, `freeze`, `expected`, `run_owner`.
Их схемы остаются из frozen transfer. Authority не берется из окружения или архива.
`phase` выбирается заранее: `M23`, `M13`, `M14`, `M15` или `M11-M12`.

```python
from scripts.ci_candidate_transfer import materialize, seal

sealed = seal(root, original_state, key=key, phase="M11-M12", **authority)

# Receiver expectations arrive through the independently trusted handoff.
with materialize(
    root, received_envelope, key=key, phase="M11-M12", **receiver_authority,
    expected_context=trusted_context,
    ciphertext_pin=trusted_ciphertext_sha256,
    manifest_pin=trusted_manifest_sha256,
) as (temporary_state, summary):
    # Ordinary readers use this original candidate; this grants no release.
    pass
```

`seal` возвращает приватный dict: `envelope` (bytes), `context`,
`ciphertext_sha256`, `manifest_sha256`, `handling="private"`, `release_ready=False`.
Для receiver обязательны **три независимых ожидания**: context, SHA-256 всего
шифрованного конверта и pin исходного manifest. Нельзя извлекать их из полученного
артефакта или неконтролируемого соседнего manifest. Возвращаемые sender metadata
сами по себе не создают доверенный канал доставки этих ожиданий.

Контекст связывает исходные repository/run/attempt, source revision/fingerprint,
exact image ID и phase. `candidate_sha256` берется из `candidate_reference`,
`proposal_sha256` из `proposal_reference`, `payload_sha256` хеширует весь исходный
ZIP. Purpose всегда `candidate`. Остальные identities, producer job и freeze pins
сравниваются обычным frozen reader с внешней authority и pinned manifest.

## Проверка исходных байтов и времени

Sender вызывает существующий `transfer.export`, перечитывает bounded archive,
проверяет archive/manifest pins, шифрует точные bytes и вновь проверяет исходный
пакет и актуальное окно после хеширования ciphertext, перед возвратом результата.
Задержка хеширования также не должна расходовать обязательный остаток незаметно.
Новый proposal, ключ,
signature или permit не создаются. Повторный export сохраняет исходный archive;
повторный seal использует свежий nonce.

Receiver сначала проверяет внешние bindings и AES authentication, затем пишет
plaintext ZIP только в новый owned temporary directory. Обязательный вызов
`transfer.materialize` проверяет настоящие подписи, hashes, точную closure и
исходное окно. После материализации `final.frozen` повторно проверяет пакет;
перед yield заново проверяются actual time, proposal, promotion policy и source
approval. `final.clean` сохраняется в обоих исходных компонентах и в последней
проверке моста. Текущий checkout должен соответствовать внешним source pins.

Окна proposal и promotion policy должны иметь не менее 600 секунд **до и после**
материализации. Для этих проверок UTC-время ОС округляется вверх, как в исходном
`serving_retention.window`, чтобы не дать лишнюю долю секунды. Transport issued_at
использует обычные целые Unix seconds, expires_at равен ровно
`min(original_proposal_expires_at, transport_issued_at + 1800)`.
После материализации проверяется и эта формула, и действительность транспорта.
Публичного аргумента `clock` нет; тесты подменяют часы только внутри процесса.

В ходе negative qualification воспроизведено принятие остатка 599.999999999 с
при округлении вниз. Консервативное округление исправляет этот тестовый отказ;
это не описание production-инцидента. Успешный yield не резервирует время для
следующего native шага: обычный owner/permit flow обязан снова проверить окно.

## Приватность, очистка и отказ

**Весь конверт, plaintext archive, context, pins и временный state приватны.**
Ключи запрещены в Git, logs, outputs и artifacts. Шифрование не дает права на
public upload; synthetic provenance не является публичной классификацией.
Мост не создает такого утверждения и всегда возвращает `release_ready=False`.

Receiver удаляет свои `.runtime/ci-candidate-transfers/reader-*` и временный
state обычного reader при normal exit, verification failure и exception caller.
Существующие caller state и sender archive не удаляются. Исходный exporter
сохраняет `.runtime/frozen-transfers/<manifest_sha256>.zip`; его приватная
retention/очистка остается ответственностью parent. Это удаление файлов, не
гарантия secure erase или стирания памяти; Windows ACL/race guarantees не доказаны.

Отказ verification возвращается фиксированным `Rejected("ci_candidate_transfer_rejected")`
без исходной причины. Caller exceptions после yield проходят без изменения,
при этом owned directories очищаются. Не выводить traceback locals или входы.
Проверить external pins, actual time и original source локально; не принимать
новые ожидания из отказавшего пакета и не сдвигать timestamps. Безопасный rollback
- прекратить использование моста до исправления. Незашифрованный fallback запрещен.

## Квалификация и оставшиеся зависимости

[Тесты](../../scripts/ci_candidate_transfer_qualification.py) используют real AES
и подписанные controlled fixtures с временными тестовыми keys. Это не реальные
deployment keys. Проверяются tamper, repinning, неправильные identities/attempt,
исходная подпись, expiry до/после materialization, 600-секундная граница, source
refusal и cleanup. Fixture source cleanliness подменена; подписи, hashes,
`transfer.materialize` и `final.frozen` работают без подмены успешного результата.

Локальная проверка 2026-11-14: **68 tests passed, 0 skipped** с `-W error`:
23 bridge, 32 AES и 13 frozen transfer tests. Мост покрыт отдельно:
87/87 statements и 2/2 branches, оба показателя 100%, без coverage exclusions.
Использованы существующий Python 3.12.15 и родительские cryptography 50.0.2 /
coverage 7.16.2 через process-local `PYTHONPATH`, без установки зависимостей.
Ruff check/format и check_docs прошли. Coverage собран в памяти.

```text
python -B -W error -m unittest scripts.ci_candidate_transfer_qualification scripts.ci_transfer_qualification scripts.frozen_candidate_transfer_qualification
python -B -m ruff check --no-cache scripts/ci_candidate_transfer.py scripts/ci_candidate_transfer_qualification.py
python -B scripts/check_docs.py
```

Hosted encrypted handoff, GitHub configuration, exact source/image provisioning,
доставка encryption/trust keys, независимый канал pins и публикация еще не
доказаны; их проектирует и проверяет parent. Docker, WSL, Kubernetes, SQL,
external models и live infrastructure этому компоненту не нужны и не запускались.
До проверки этих зависимостей private evidence не должен пересекать jobs.
