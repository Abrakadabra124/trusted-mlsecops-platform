# Плановая смена ключа online trust authority

Статус: [native operator API и serving verified](../evidence/authority-root-rotation-2026-10-30.md), `d18c361` / 40959762631 success. 502 Linux test methods / 0 skips; ротация 2 -> 3, четыре точных отказа, unchanged retry/history, 14 old-config cold и 22 new-config serving checks. CLI routing/confirmation проверены контрактными tests; отдельный native mutation через CLI не заявляется. [ADR и полный контракт](../decisions/0053-authority-root-rotation.md). Применимо к существующей owned authority с действительным старым ключом. Потеря/компрометация root и authority disaster recovery требуют отдельного решения; эта процедура не снимает отзыв.

## Ответственные и предпосылки

Trust owner подтверждает новый public key через доверенный канал, а операторы подписания формируют authorization/acceptance. Оператор хранилища применяет подготовленный package. Оператор serving отдельно публикует новый config. В lab эти действия могут выполнять одним процессом с синтетическими ключами; это не доказательство независимости людей или production KMS.

Доступ к trusted operator workspace, текущей policy и сохранённой истории обязателен. Root public keys задаются из доверенной конфигурации отдельно от входного package. Приватные ключи не помещаются в CLI arguments, ConfigMaps, serving/promoter Jobs или отчёты. Локальные Docker/WSL/Kubernetes/SQL в текущей рабочей среде запрещены; инфраструктурные команды ниже предназначены только для разрешённого disposable hosted CI.

## Диагностика до изменения

1. Проверить ownership authority и текущие environment/root/version/document SHA через `mlsecops.trust_authority.current(state, backend=kube_trust.binding)` в доверенной operator-среде. Этот API читает данные и проверяет подпись/checksum; не выводить целиком рабочую конфигурацию или содержимое key files.
2. Проверить действительность current trust-policy, сохранённые revocations и независимый от model storage том authority. Если текущий root отозван или отсутствует достоверная история, оставить ML недоступным и эскалировать trust owner.
3. Зафиксировать ожидаемые current root, next root и previous document SHA. Новый ключ должен отличаться от старого и отсутствовать среди revoked keys. Не принимать public key только потому, что он указан во входном JSON.

## Подготовка подписанного package

Сохранить прежние environment, promotion policy и artifact revocations. В следующем trust-policy увеличить version ровно на 1, задать issued_at и добавить SHA-256 decoded old public key к sorted unique revoked_keys. Подписать этот документ новым ключом через существующий `signing.sign(payload, 'trust-policy', owned_key_path)`.

По полной структуре ADR составить intent с digest обоих canonical envelopes, current/next public keys и version. Его issued_at совпадает с issued_at нового документа; expires_at позже issued_at максимум на 600 s и не позже окончания previous/next policies. Получить две подписи одного intent через `signing.sign(intent, 'trust-root-rotation', owned_key_path)` в соответствующих signer-средах. Package: schema_version=1, authorization=old envelope, acceptance=new envelope, document=next trust envelope. `trust_rotation.verify` позволяет проверить его до записи, используя отдельно закреплённые keys, previous document и текущий clock.

## Плейбук применения

Явно подготовленные файлы и public pins в примере принадлежат оператору. Переменные `currentRoot` и `nextRoot` устанавливаются из доверенного канала, не из package.

```powershell
python -m mlsecops.trust_root_store migrate --state .runtime --backend kubernetes --confirm-authority
python -m mlsecops.trust_root_store rotate --state .runtime --backend kubernetes --confirm-authority --document .runtime/operator/root-rotation.json --current-root $currentRoot --next-root $nextRoot
```

1. Migration добавляет таблицу receipt и запись версии 2. Повтор возвращает reused=true; неизвестный checksum запрещён. Не редактировать schema v1 или migrations вручную ради прохождения проверки.
2. Rotate выполняет одну транзакцию. Успешный ответ содержит `rotated-not-activated`, next version, document SHA, root fingerprint и rotation SHA. Сверить их с заранее одобренным package.
3. Проверить сохранение всех прежних documents и добавление ровно одного нового document/rotation record. Сверить неизменность model/promotion storage. Повторить только тот же package при потере ответа и только пока его срок/current state допускают retry.
4. Старый serving config должен отказать. Оператор явно задаёт новый `trust_root` и `minimum_trust_version` из подтверждённой receipt в обычном config. Не понижать floor, не подменять release policy root и не создавать approval автоматически.
5. Запустить обычный serving, проверить точный bundle/model digest, ready, golden predictions и сохранённый отказ для revoked assets. Только это подтверждает восстановление обслуживания после изменения конфигурации.
6. После controlled qualification подтвердить остановку SQL и отсутствие owned disposable cluster. Сохранить очищенные evidence и timestamps, не публикуя key material и raw private reports.

## Отказы и восстановление

| Симптом в private diagnostics | Действие |
| --- | --- |
| `rotation_migration_required` / `trust_migration_mismatch` | Проверить явную миграцию и её checksum. Не сбрасывать schema или историю. |
| `rotation_head_changed` | Прочитать актуальное состояние. Если произошло другое update, запросить новый подписанный intent; не менять старые подписанные bytes. |
| `rotation_signed_binding` / `invalid_signature_count` / `untrusted_key` | Проверить обе подписи, их общий payload и public pins. Одна корректная подпись недостаточна. |
| `trust_update_conflict_or_unrevocation` / `rotation_policy_or_revocation_binding` | Проверить exact successor и сохранение revocations. Ротация не предназначена для одновременной замены promotion policy или снятия запретов. |
| `rotation_commit_unconfirmed` / `rotation_receipt_unconfirmed` / потеря соединения | Считать outcome неизвестным. Сверить current root/document и сохранённый package по SHA в `root_rotations`; не запускать новую ротацию с другим timestamp вслепую. |
| `trust_authority_missing_or_foreign` в старом serving config | Ожидаемый отказ после смены root. Применить отдельно проверенный новый config и выполнить полный Reader load. |
| Нет валидного нового config или target отозван | Оставить manual-review fallback без ML. Не возвращать old root, old journal или model backup для обхода отказа. |

После commit старый ключ добавлен в revocations; обратное редактирование root не является допустимым rollback. Следующий переход может выполняться только от действующего нового ключа к третьему разрешённому ключу с новой версией и сохранением истории. Legacy software, не знающее migration 2, должно отказать по checksum; его запуск поверх обновлённой authority не считается совместимым rollback.
