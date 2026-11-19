# Приватный validation companion

Неделя 13, T21: необязательный companion для M13/M14/M15, которым нужны
исходные validation rows. [Helper](../../scripts/ci_validation_transfer.py)
не меняет [frozen archive](frozen-candidate-transfer.md) и
[принятый candidate bridge](ci-candidate-transfer.md). M11/M12 продолжают
использовать прежние архивы без companion. Владелец интеграции - parent.

## Контракт и границы

Единственный источник descriptor `validation.json` - `split_manifest` исходного
release bundle, проверенного существующим frozen reader со всей цепочкой подписей.
Caller передаёт исходные `freeze_pin`, `freeze`, `expected`, `run_owner` независимо
от артефакта. `expected` сохраняет точный `image_id`, source revision/fingerprint,
candidate/evaluation/proposal/subject/model pins. `run_owner` принадлежит
original producer, включая repository, run ID, attempt и producer job.
Новый curator SQL client не заменяет original owner.

Проверяются исходные SHA-256, bytes, rows через `digest`, `decode`,
`datasets.validate_rows` и canonical equality, как в monitoring reader.
Лимит validation - прежние 16 MiB; packet ограничен размером base64 этих байтов
плюс 64 KiB metadata. Выбор split не предоставляется: train/holdout не читаются.
Companion не содержит private keys или SQL credentials и не импортирует данные
в SQL. Signed metadata из исходного candidate остаётся в его отдельном архиве.

`retain` возвращает приватный canonical packet **в память caller**. Он не создаёт
постоянный storage или путь назначения. Caller отвечает за локальное удержание
этого packet до `seal`; plaintext нельзя передавать между jobs.
`seal` использует существующий AES-GCM - шифрование с аутентификацией - с
caller-supplied 32-byte key и новым nonce. AAD, аутентифицируемый внешний контекст,
содержит исходные identities и payload SHA; последний связывает также original
freeze, producer job и split-manifest pin внутри закрытого packet.
Фазы `validation-M13`, `validation-M14`, `validation-M15` отделяют companion от
candidate archive. Новых signing authority, подписей или proposal не создаётся.

Receiver обязан получить **context и ciphertext SHA-256 независимо от envelope**.
Metadata рядом с недоверенным envelope не становится доверенной автоматически.
У исходного candidate archive по-прежнему обязательны собственные внешние
context, ciphertext pin и manifest pin. Дополнительного authority manifest у
companion нет: descriptor закреплён исходным signed package и его freeze pins.

Всё содержимое, включая envelope, packet, context, pins и summaries, остаётся
приватным. Ключи никогда не помещаются в repo, логи, outputs или артефакты.
`handling="private"` - требование обработки, не доказательство публичной классификации.

## Последовательность API

Prerequisites: чистый точный source checkout, исходный frozen state или уже
проверенный materialized view, исходные validation bytes и внешние authority
inputs. Исходные public trust keys остаются закреплёнными frozen pins;
bootstrap/rekey и private signing keys этому helper не нужны.

```python
from mlsecops.contracts import bounded_read
from scripts import ci_validation_transfer as validation

# Producer: original bytes obtained locally before source storage cleanup.
packet = validation.retain(root, original_state, original_validation_bytes, **authority)
sealed = validation.seal(root, original_state, packet, key=key, phase="M13", **authority)

# Receiver: candidate_view already opened by ci_candidate_transfer.materialize
# with its own independently trusted manifest/context/ciphertext expectations.
with validation.materialize(
    root, candidate_view, received_validation_envelope,
    key=key, phase="M13", **receiver_original_authority,
    expected_context=trusted_validation_context,
    ciphertext_pin=trusted_validation_ciphertext_sha256,
) as (validation_path, summary):
    original_bytes = bounded_read(validation_path, validation.MAX_VALIDATION_BYTES)
    # Future consumer may import these exact bytes using its new curator client.
    # SQL provisioning, import and readback are outside this companion API.
```

`seal` возвращает `envelope`, `context`, `ciphertext_sha256`, `handling="private"`,
`release_ready=False`. `materialize` отдаёт только собственный временный
`validation.json` и summary с SHA-256/bytes/rows и такими же private/not-ready flags.
Чистота source и реальное UTC-время проверяются до и после обработки/записи.
Нужно минимум 600 секунд исходного proposal window; transport expiry равен
`min(original_proposal_expires_at, issued_at + 1800)`. Transport не продлевает
proposal, source approval, policy или право выпуска. Public clock/nonce override нет.

## Отказы, cleanup и проверка

При `ci_validation_transfer_rejected` не импортировать данные. Проверить внешние
pins/owner/phase, доступность оригинального frozen state, остаток исходных окон и
source checkout. Не переподписывать proposal, не подменять validation другим split
и не снимать проверки ради retry. Если исходные bytes утрачены или окно истекло,
эскалировать producer/parent; восстановление authority не входит в API.

Временный каталог `.runtime/ci-validation-transfers/reader-*` удаляется при
обычном выходе, отказе проверки и исключении consumer. Соседние данные не удаляются.
Это файловая очистка, не гарантия стирания RAM или защищённого удаления носителя.
Caller отвечает за свой retained packet; SQL rollback этот helper не выполняет.

Focused qualification: `python -B -W error -m unittest scripts.ci_validation_transfer_qualification`.
[Тесты](../../scripts/ci_validation_transfer_qualification.py) используют настоящие
подписи controlled fixture и AES, включая чужой signed dataset, tamper, malformed
rows, oversize, owner/source/context mismatch, исходные deadlines и cleanup.
Локально прошли 23 tests / 0 skips; новый helper: statements 92/92 (100%),
branches 2/2 (100%), без coverage exclusions. Ruff и `scripts/check_docs.py` чистые.
Source-clean отказ проверяется controlled injection; fixture не является live
source/runtime qualification. Hosted handoff, GitHub configuration, доставка
ключей, SQL import/readback и M13/M14/M15 acceptance здесь не доказаны.
