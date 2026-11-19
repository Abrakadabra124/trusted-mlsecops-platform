# Приватные original receipts M02/M03/M07

Неделя 13, T21. [Companion API](../../scripts/ci_upstream_transfer.py) передаёт
существующие upstream receipts для M13/M14/M15. Он не выполняет gates, не создаёт
новые критерии, подписи или proposal и всегда возвращает `release_ready=False`.
Владелец подключения к consumer/workflow - parent; SQL import остаётся отдельным.

## Контракт и существующие readers

Caller заранее предоставляет `reports` с **ровно M02/M03/M07** и исходными pins
от trusted producer, original `freeze_pin`, `freeze`, `expected`, `run_owner`.
Authority не извлекается из полученного artifact. `expected` сохраняет точные
candidate/evaluation/proposal/subject/model, source revision/fingerprint и image ID.

Используются существующие проверки [M18 collector/reader](../../scripts/m18_delivery_freeze.py):
`verify_early(..., intake_only=True)`, `verify_integrity`, `verify_evaluation`.
По умолчанию `verify_early` по-прежнему требует M01+M02. Opt-in выбирает только M02;
политика outcomes и case inventory остаются прежними. M03 проверяет исходные
component outcomes и signed split snapshot; M07 проверяет исходные evaluation
metrics, cases и budget receipts. Реализация критериев не продублирована.

После этого выполняется настоящий `serving_campaign.bind_report` для трёх reports.
Exact bytes, включая поддерживаемую `published_report` проекцию с `report_sha256`,
сохраняются без переписывания. Криптография - существующий AES-GCM API; данные
и AAD связываются payload SHA-256, phase `upstream-M13/M14/M15` и original owner.
Receiver независимо получает AES context, ciphertext pin и original report pins.
Исходный candidate archive сохраняет собственный внешний manifest pin.

## Закрытый перечень файлов

| Материал | Original path относительно state |
| --- | --- |
| Три reports | `evidence/M02.json`, `evidence/M03.json`, `evidence/M07.json` |
| M02 primary | `evidence/data-qualification.json` |
| M03 primary | `evidence/integrity-qualification.json` |
| M03 components | `evidence/M03-filesystem.json`, `evidence/M03-storage.json`, `evidence/M03-pipeline.json` |
| M07 primary | `evidence/evaluation-gate.json` |
| M07 components | `evaluation-gate/{campaign_id}/contracts.json`, `native.json`, `budget.json` |

Всего 12 файлов. `campaign_id` допускает только 32 lowercase hex символа;
его содержимое и component pins затем проверяются существующим M18 reader.
Reports ограничены прежними 16 MiB, primary/components - прежним 1 MiB;
общий transport cap - 64 MiB plaintext плюс ограниченное base64 framing.
Нет directory scan, произвольных путей, raw logs, SQL credentials или private keys.
Существующий credential guard применяется как дополнительная проверка; это не
публичная классификация. **Весь envelope, context, pins и summary остаются приватными.**
Ключи нельзя помещать в repo, логи, outputs или artifact.

Producer должен сохранить эти original paths до `seal`. Если первичные файлы
утрачены, companion не создаёт им замену. Existing M18 readers сохраняют exact
primary preimages в `evidence/M18-objects/{sha256}` внутри временного verified view.
Original reports и source SQL при этом не изменяются.

## Вызов и подключение к consumer

Prerequisites: чистый точный source checkout, исходный frozen package, original
receipt files и independently trusted pins. `seal` использует caller-supplied
32-byte AES key; ключей и nonce override API не создаёт.

```python
from scripts import ci_upstream_transfer as upstream
from scripts import consumer_candidate_state as consumer

sealed = upstream.seal(
    root, original_state, key=key, phase="M13",
    reports=original_report_pins, **original_authority,
)

with consumer.materialize(
    root, candidate_envelope, key=key, phase="M13", **original_authority,
    trust_key_path=separately_provisioned_original_trust_key,
    expected_context=trusted_candidate_context,
    ciphertext_pin=trusted_candidate_ciphertext_pin,
    manifest_pin=trusted_candidate_manifest_pin,
) as (state, consumer_info):
    with upstream.materialize(
        root, state, upstream_envelope, key=key, phase="M13", **original_authority,
        reports=trusted_original_report_pins,
        expected_context=trusted_upstream_context,
        ciphertext_pin=trusted_upstream_ciphertext_pin,
        workspace_id=consumer_info["workspace_id"],
    ) as (same_state, receipt_info):
        original_reports = receipt_info["reports"]
        # Parent runs owned SQL import/serving, cleanup and campaign replay here.
        # replay reports = original_reports plus actual M13/M14/M15 report pins.
```

Без `workspace_id` возвращается отдельный временный frozen+receipt view, пригодный
для offline consumer checks. С ним helper проверяет существующий `workspace.json`
и присоединяет receipts к тому же state, который уже создал consumer API. Это
проверка filesystem ownership, не новая release authority. Нужен эксклюзивный
caller-owned workspace: не запускать конкурентных writers на этих путях.
Любой existing receipt вызывает отказ; existing CAS допускается только с теми же
байтами и остаётся нетронутым. Helper не читает trust private key и не трогает
workspace marker, public key registry, release-proposals или SQL metadata.

Обе формы повторно проверяют исходные подписи, `final.clean` и реальное UTC-время.
До и после материализации нужно минимум 600 секунд original proposal window.
Transport expiry равен `min(original expiry, issued_at + 1800)`; проверка sender
выполняется после hash ciphertext и очистки временного view. Граница 0,01 секунды
не округляется вниз. Никакие исходные сроки не продлеваются.

## Original SQL pin и runtime boundary

`M03.input_digests.storage_config` проверяется в `final_evidence.primary` против
`integrity-qualification.json.storage_inputs.config_digest`. Это original source
SQL experiment. Companion сохраняет оба значения и exact bytes без изменений.

Отдельно `serving_campaign.replay` закрепляет **consumer** `storage.json` через
`source_pin` и `chain(transitions, source_pin)`. `identity/transition` при capture
проверяют workspace, namespace и volume; два перехода должны описывать три разных
кластера. Нельзя переписать original M03 pin на новый consumer pin или объявить
исторические transitions доказательством нового consumer runtime.

Получение upstream receipts не доказывает полный campaign replay. Ему также нужны
настоящие M13/M14/M15 reports, admissions, retained private observations и transitions.
Сам replay работает offline после cleanup; эти дополнительные runtime observations
должны быть получены ранее. Здесь их capture, SQL import, workflow и transport
между GitHub jobs не реализованы и не проверены.

## Отказ и очистка

`ci_upstream_transfer_rejected` означает запрет использования handoff. Проверить
original pins, полный fixed gate-set, exact source/files, принадлежность workspace
и оставшееся окно. При утрате original evidence или истечении proposal обратиться
к producer/parent; не пересобирать успешные reports и не обновлять proposal.

Временный view удаляется при выходе, отказе и consumer exception. В attachment mode
удаляются только добавленные файлы и созданные для них пустые directories;
existing CAS, соседние файлы и original workspace сохраняются. Завершить caller-owned
runtime cleanup и replay до выхода из contexts. Очистка файлов не гарантирует
secure erase RAM/носителя. Rollback инфраструктуры принадлежит caller.

Проверка: `python -B -W error -m unittest scripts.ci_upstream_transfer_qualification`.
[Qualification](../../scripts/ci_upstream_transfer_qualification.py) использует
реальный signed frozen package, AES и существующие readers, а reports/наблюдения
являются controlled fixtures. M02 использует текущую policy; M03 controlled policy
не выдаётся за native acceptance. Проверены обе формы materialize, включая реальный
consumer API и сохранение его trust-key bytes. Source-clean отказ моделируется;
нового hosted доказательства M02/M03/M07/M13/M14/M15 или общего M18 здесь нет.

Локальный результат: 21 companion test + 3 существующих M18 reader tests прошли,
0 skips. Новый модуль: statements 146/146 (100%), branches 28/28 (100%), без
coverage exclusions. Ruff check/format и `scripts/check_docs.py` прошли.
