# ADR 0053: явная плановая ротация ключа trust authority

Дата: 2026-10-30. Статус: implemented, local contracts passed; native CI pending. T14, отдельная часть полного M11. Это смена ключа подписания online trust-policy, не смена release approver/publisher и не аварийное восстановление утраченного root.

## Требование и границы доверия

Оператор должен сменить ещё доверенный ключ authority, сохранив environment, promotion policy, непрерывную нумерацию документов и все revocations. Нельзя заменить root в запросе, сбросить историю или разрешить работу по старому model backup. SQL/host admin остаётся доверенным, signer material не попадает в serving/promoter Jobs.

Принцип подтверждения перехода старым и новым ключом сверён с [TUF specification, sections 5.3 и 6.1](https://theupdateframework.github.io/specification/latest/). Здесь используется собственный существующий прикладной DSSE-контракт с Ed25519, а не формат root.json, threshold-роли или TUF client. Совместимость с TUF не заявляется. Для lab используются один старый и один новый ключ; наличие двух подписей не доказывает участие двух независимых людей.

## Протокол

Package schema 1 содержит `authorization`, `acceptance` и `document`. Первые два поля - DSSE envelopes одного canonical payload в domain `trust-root-rotation`, подписанные соответственно старым и новым ключами. `document` - следующий обычный trust-policy, подписанный новым ключом. Полный rotation payload:

```json
{
  "schema_version": 1,
  "environment": "local-cpu",
  "current_root": "<canonical Base64 old public key>",
  "next_root": "<canonical Base64 new public key>",
  "previous_version": 2,
  "previous_sha256": "<SHA-256 canonical current trust envelope>",
  "next_version": 3,
  "next_sha256": "<SHA-256 canonical next trust envelope>",
  "issued_at": 1793300000,
  "expires_at": 1793300300
}
```

Числа и строки выше только пример структуры, не рабочее разрешение. Оператор отдельно передаёт ожидаемые current/next public keys. Они не берутся из package для принятия решения. [Verifier](../../mlsecops/trust_rotation.py) проверяет обе подписи, одинаковый payload, exact digests, canonical 32-byte keys, environment и next version = previous + 1. Максимальный срок rotation intent 600 s, исполнение требует действительных previous/next documents; intent не живёт дольше ни одного из них.

Policy digest и artifact revocations не меняются. Key revocations равны прежнему набору плюс fingerprint выведенного из эксплуатации ключа. Старый и новый ключ не должны быть ранее отозваны и должны различаться. Отозванный или потерянный старый ключ не получает специального обхода ради ротации. Новое обычное trust update после перехода подписывается новым ключом и сохраняет прежние отзывы.

## Хранение и переключение

[Operator module](../../mlsecops/trust_root_store.py) отдельно устанавливает additive migration 2 с таблицей `ml_trust.root_rotations`. Checksum schema v1 не меняется; authority принимает только известную полную цепочку v1 либо v1+v2. Consumer roles не получают права на запись или доступ к таблице ротаций.

Одна транзакция под существующим advisory lock повторно сравнивает current root, environment, version и document hash, проверяет время SQL clock, добавляет next document, переключает root и добавляет canonical signed package в историю. Она не удаляет прежние documents и не меняет model/promotion storage. После commit выполняются current-state и receipt readback. Неизвестный результат не называется успешным переключением.

Точный повтор текущей ротации заново проверяет обе подписи, previous history и сохранённый package и не пишет новые строки. После следующего update или истечения intent повтор отклоняется; оператор сверяет сохранённую receipt вместо создания другого timestamp. Конкурентный stale writer должен отказать на locked compare-and-set; итоговая native concurrency acceptance пока не заявляется.

## Consumer lifecycle

Действующие конфигурации закрепляют public key и минимальную trust version. Старый root после переключения не совпадает с root online authority: обычная проверка отказывает и не принимает новый ключ из ответа. Оператор явно выпускает config с новым закреплённым root и minimum_trust_version из receipt. Обычный Reader заново проверяет подписи, bundle, текущую policy и revocations перед ready.

Новая схема не создаёт release approval и не активирует ML автоматически. `rotated-not-activated` означает подтверждённое состояние authority. Existing leases сохраняют исходные fail-closed правила; отдельное измерение live root-change HTTP trace ещё требуется для полной M11-приёмки. Controlled cold refusal и явный новый serving запуск не заменяют такой trace.

## Проверка

Local: 43 methods, 326 statements / 108 branches в protocol/store/authority/native coordinator, 100%. Проверяются missing/mismatched signatures, чужие pins, schema/types/size/time, history/reference mismatch, снятие revocations, key reuse, migration checksum, unchanged retry, unconfirmed commit, bounded CLI errors и native evidence guards. SQL/HTTP локально не запускались.

Native сценарий подключён после разрешённого whole-bundle rollback. Он сохраняет synthetic revoked artifact/key, проверяет подписанные отказы, выполняет ротацию и retry, проверяет прежнюю history prefix и отказ update старым ключом. Затем обычный serving CLI со старым config должен дать exact root refusal без worker; явный новый config должен загрузить прежнюю модель и пройти golden checks. Последующая trust regression продолжает работать новым ключом. До завершения CI эти шаги не объявляются проверенными.

[Ранбук и плейбук](../operations/authority-root-rotation.md). Full M11/M18/R1, release-signing key rotation, M22 independent challenges и system-image findings остаются открытыми.
