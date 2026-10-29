# ADR 0051: независимые authority states для terminal revoke qualification

Дата: 2026-10-29. Статус: реализовано; [native component proof bfe295b / 40936376995](../evidence/independent-authorities-2026-10-29.md) подтверждён. Полный M11/R1 открыт.

## Требование

M11 должен доказать отдельно отзыв actual model и publisher key на одном frozen candidate/source/policy. После первого terminal revoke прежний Engine не может выдать положительный precondition для второго. Удаление revocation, reset DB, подмена Service/PVC или новый retrained candidate не доказывают независимость проверок.

## Решение

Создать до terminal faults две явно закреплённые независимые authority states в том же disposable hosted cluster. Использовать прежний pinned PostgreSQL image, schema/roles, TLS 1.3 verify-full и bounded resources. Это два изолированных тестовых состояния для одной модели, не failover production authority и не новая orchestration platform.

Разрешены только два статических target: primary (`ml-trust`) и model-revocation (`ml-trust-model`). Каждый имеет фиксированный hostname, отдельный state directory, CA/server/client certificates, immutable client Secret, PVC и полный UID-bound resource inventory. Target enum не принимает произвольный hostname/namespace/Secret. Новый endpoint доступен storage client только при явном совпадающем expected-host pin; прежний default allowlist его не принимает.

Обычный serving/promoter entrypoint сохраняет primary. Дополнительный target разрешён в явно выбранном candidate qualification Job; он монтирует только его credentials. Никакого fallback на другую authority при отказе. Подписанный actual proposal, model/subject, source/image и исходный qualification permit не меняются и не продлеваются. Root private key остаётся у внешнего coordinator; копируются только исходные разрешения в заранее созданное независимое состояние. Истории отзыва не удаляются и не переигрываются назад.

Перед terminal faults подтвердить существование обоих owned targets и совпадение policy/permit. Отзыв модели выполняется в model-revocation state, отзыв ключа - в primary; каждый имеет собственные positive inference, exact live/cold denial, no-auto-reactivation и cleanup. Изменение одного состояния не должно менять документы/UID/CA/PVC второго или CAS/promotion journal. После обоих отказов повторно подтвердить, что оба запрета сохранились. Cross-authority propagation и production HA не заявляются.

## Проверка

До native: отрицательные tests для unknown target, implicit alternate endpoint, wrong host/port/CA/Secret/namespace/UID, aliasing/foreign resources и невозможности очистить прежние revocations. Проверить совместимость primary, idempotent bootstrap, полные immutable Pod specs и named network boundaries.

В hosted CI: настоящие TLS reads обоих targets, отказ cross-CA access, роли SELECT-only, independent state bindings, один actual candidate, оба terminal revoke, полный journal snapshot и cleanup. Новые security-critical ветви >=95%, но coverage не заменяет live evidence. M11/R1 остаются открыты до выполнения полного контракта. Target binding полезен для будущего M17, однако сам по себе не доказывает new-namespace restore/RTO/RPO.
