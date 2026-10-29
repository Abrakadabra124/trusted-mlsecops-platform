# ADR 0052: новый selection для отката неизменного bundle

Дата: 2026-10-29. Статус: implemented, local contracts passed; native CI pending. T14/M11 и подготовка T19/M16. Ротация root/key, staged traffic и общая приёмка R1 остаются отдельными обязательными работами.

## Требование

Вернуться к прежнему разрешённому compatible bundle, сохранив монотонность promotion journal, свежую проверку доверия и независимое одобрение. Старый selection нельзя повторить или записать прямо в head. Переподписание старой модели как нового bundle не доказывает восстановление точного прежнего subject.

## Решение

Обычный approval schema 1 остаётся `action=promote`, его sequence совпадает с sequence signed bundle. Approval schema 2 допускает только `action=rollback`. Он подписан текущим approver в том же DSSE domain `release-approval` и содержит прежние subject/environment/policy/assurance/time bindings плюс:

```json
{
  "schema_version": 2,
  "action": "rollback",
  "sequence": 3,
  "rollback": {
    "from_sequence": 2,
    "from_request_sha256": "<current selection SHA-256>",
    "target_request_sha256": "<older selection SHA-256>"
  }
}
```

Это только дополнительные поля, не полный approval. Полный контракт проверяет [release_authorization.py](../../mlsecops/release_authorization.py). Новый sequence равен from_sequence + 1 и больше sequence исходного bundle. Target и from различны. Bundle, capsule, model card, preprocessing и runtime references остаются прежними; меняется signed approval и selection. Decision schema 2 переносит intent в immutable authorization object; внешний selection format и SQL migration не меняются.

[release_rollback.history](../../mlsecops/release_rollback.py) проверяет существование from event с точным request hash, более раннего target event и target selection с теми же environment/policy/subject/proposal. До публикации head обязан совпадать с from. Для retry допускается только точный уже записанный новый request с previous link на from; serving требует именно это состояние. Затем обычная SQL-функция под row lock проверяет next sequence/current request. Конкурирующее решение не может переключить head повторно. При конфликте после первоначального чтения могут остаться immutable unselected CAS objects, как и в обычном promotion; это не активация.

Повторный Reader проверяет полный bundle, все reports/assurance, новый approval, history и live trust. Отозванные model, ключи, source/lineage, runtime/policy и target selection не допускаются. Scope включает target selection hash. From bundle может быть плохим/отозванным: он не становится зависимостью разрешения целевого bundle. Выполненный rollback не отменяет ни одного отзыва.

Для другого candidate оператор передаёт отдельно закреплённый context целевого bundle в существующем configuration path; он не берётся автоматически из недоверенного запроса. Policies, roots и expected runtime не заменяются запросом. Несовместимый image, чужой context, старая policy, истёкшие assurance/bundle, failed или отсутствующий gate по-прежнему отклоняются. Новое approval не продлевает срок старой assurance и не превращает skipped/inconclusive в pass.

## Проверка и ограничения

Локальные тесты сначала подтвердили отсутствие rollback protocol, затем отсутствие history guard после добавления схемы. Сейчас проверяются новый signed sequence, unchanged subject, target/from/history tampering, rollback на revoked model/selection, недоступная история, idempotent retry, Reader previous-link validation и bounded diagnostics. Три публичных кода истории имеют конечный allowlist; произвольный текст ошибки не выводится.

Native workflow должен выбрать две разные контрольные ONNX-модели и вернуть первую: sequence 1 -> 2 -> 3, модель A -> B -> A. Проверяются ordinary isolated promoter, обычный serving CLI, независимый worker, golden scores, точные history refusals и отсутствие записей после них, повтор, отзыв и очистка. Это controlled qualification с test approvals, не acceptance настоящего candidate, не staged traffic 10/50/100 и не измерение M16 <=120 s. Production path не получает fixture bypass.

Существующий trusted SQL admin остаётся вне adversary scope. Не обещается distributed transaction между trust authority и model storage; неизвестный commit остаётся unconfirmed и требует readback. Автоматический выбор предыдущего bundle и auto-approval отсутствуют: оператор и approver должны явно выбрать совместимый target. [Ранбук](../operations/bundle-rollback.md).
