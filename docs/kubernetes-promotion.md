# Изолированное выполнение promotion

Неделя 8, T13, CP3/R1-B04. [Kubernetes authority](kubernetes-trust.md) подключён к существующему [promotion CLI](promotion-entrypoint.md) через отдельный restricted Job. Код реализует подачу immutable references, проверку результата и очистку owned ресурсов. Полный M10 и R1 остаются открытыми до общей приёмки actual candidate.

## Оператор и исполнитель

Операторский [kube_promotion](../mlsecops/kube_promotion.py) проверяет owned model/trust services, загружает image с проверенными source labels и immutable manifest, фиксирует отдельные ConfigMap с конфигурацией и запросом и запускает Job. Только операторская команда `configure` инициализирует журнал/прикрепляет environment к policy digest. Подача `submit` не выполняет migrations, не создаёт подписи и не меняет policy.

Исполнитель запускает прежний `mlsecops.promotion_controller` в `ml-promoter` под ServiceAccount `promoter`. Ему доступны два разных read-only bundle: `/client` для моделей и `/trust-client` для authority. Ключ подписи, API token, Docker socket и host filesystem не монтируются. Init containers копируют только собственные TLS client credentials в memory-backed volumes; основной процесс имеет read-only root, UID 65532, seccomp, dropped capabilities и resource limits. Worker image проверяется до запуска и по фактически завершившемуся Pod.

Конфигурация передаётся отдельно от запроса, ограничена 512 KiB, запрос ограничен 64 KiB. Storage paths фиксированы; request schema не допускает подмену roots, policy, image или credentials. Существующий верификатор повторно проверяет цепочку signed materials/reports/approval, свежую trust policy и SQL journal. Результат разрешённой записи остаётся `recorded-not-activated`, `release_ready=false`.

Driver различает ожидаемый отказ CLI (Failed Job, exit 1, точный constant diagnostic), crash/OOM/timeout и недопустимый receipt. Успешный exit без правильных proposal/environment/sequence/digests не принимается. В `finally` удаляются только созданные им Job и ConfigMap, после сверки UID/spec; проверяется их отсутствие. Неизвестная очистка запрещает успешный итог.

## Команды

В этой задаче инфраструктурное воспроизведение разрешено только в disposable hosted CI. Workflow [kubernetes-promotion.yml](../.github/workflows/kubernetes-promotion.yml) собирает pinned image, поднимает owned cluster, два SQL service и отдельный source candidate, затем проверяет admission и удаляет собственные ресурсы. Локальные Docker/WSL/Kubernetes/SQL не запускаются.

Операторский путь на разрешённом подготовленном стенде:

```sh
uv run --locked python -m mlsecops.kube_promotion configure --state .runtime --config /private/operator-promotion.json
uv run --locked python -m mlsecops.kube_promotion submit --state .runtime --config /private/operator-promotion.json --request /private/release-request.json --image trusted-mlsecops:dev
```

Operator config соответствует [CONFIG_FIELDS](../mlsecops/promotion_controller.py), с `storage_client=/client`, `trust_client=/trust-client`; остальные roots, context и pins берутся из проверенной release цепочки. JSON request содержит только `schema_version`, `proposal_reference`, `policy_reference`, `assurance_reference`, `approval_reference`. `null` assurance/approval допустимы для проверяемого отказа, но не для разрешённого promotion. Авторизованный signed trust document публикуется отдельным authority operator, signing key в Job не передаётся.

## Проверки и границы результата

Локально прошли 41 test: 9 нового driver, 3 native harness и 29 существующих ledger/trust/controller. Driver: 131/131 statements, 40/40 branches. Native CI ещё требуется.

Native campaign отдельно формирует настоящий candidate и доказывает отказ `release_assurance_required` исходным верификатором. Его неизменённые proposal/policy bytes переносит в cluster CAS, запускает обычный CLI в Job и проверяет отказ без записи admission objects. Положительный сценарий использует явно обозначенный controlled signed fixture: missing approval отказан, initial head=0, разрешённая запись head=1, независимый SQL readback, exact retry с тем же receipt и без новых объектов, отзыв модели и отказ повторного promotion. Контрольные all-pass reports не выдаются за actual candidate acceptance.

Это соединение promotion CLI с изоляцией и authority. Оно не подтверждает штатный serving HTTP/ONNX в Kubernetes, полный M10/M11/M12/M13/M19, общий inventory или M18. [Все CP2-CP5](r1-delivery.md) сохраняются, включая system-image findings и независимые M22 challenges.

## Ранбук: отказ, неизвестный commit или cleanup

Ответственный - оператор платформы. Перед действиями нужны owned workspace/kubeconfig, точные immutable request references и операторские pins. Начать с чтения private receipt, состояния owned Job и SQL head; не печатать ConfigMap, ключи или raw service logs в публичный evidence.

1. **CLI отказал.** Проверить наличие и binding assurance/approval/reports, подписи, environment/policy/image, expiry и актуальный revocation set. Ожидаемый отказ не является crash. Не добавлять фиктивные reports и не менять policy ради зелёного результата.
2. **Job завершился аварийно или по deadline.** Проверить действительный image digest, завершение container, resource limits и доступ к двум service. `OOMKilled`, timeout или непредусмотренный stderr не считаются доказательством корректного запрета. Новый запуск допускается после установления терминального состояния прежнего Job.
3. **Получен отказ после возможного SQL commit.** Отсутствие успешного driver result не доказывает отсутствие записи. Сверить current head, event и immutable request digest с ожидаемым receipt. Повторять тот же запрос; не увеличивать sequence и не изменять approval наугад. После отзыва даже exact retry должен быть запрещён.
4. **Cleanup не подтверждён.** Сверить UID/spec с созданными ресурсами, проверить отсутствие активного Pod. Удалять только подтверждённые Job/ConfigMap. Чужой UID или неизвестный исход create требуют разбора, автоматического adoption нет. Private cleanup failure не означает автоматический rollback транзакции.

Плейбук native проверки: подготовить actual proposal -> подтвердить исходный отказ -> сверить staged CAS bytes -> выполнить изолированный отказ -> сравнить ledger -> отдельно настроить controlled authority/journal -> missing-approval negative -> positive/readback -> exact retry -> signed revoke -> denied retry -> проверить source -> удалить только owned cluster и остановить owned source SQL. Успешная очистка инфраструктуры подтверждается отдельно от результата admission.
