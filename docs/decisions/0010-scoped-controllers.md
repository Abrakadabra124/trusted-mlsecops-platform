# ADR 0010: Scoped publisher/scorer controllers

Дата: 2026-10-08. Статус: **Implemented component, локально проверен**. Slice T05/T26 после [migration](0009-storage-migration.md). Scoped resources установлены только в owned lab; документ сам по себе не выдаёт полномочия. 133 проверки прошли, точное evidence и CI записываются в [STATUS](../../STATUS.md), команды в [runbook](../scoped-controllers.md). Полные M04/M20 остаются открытыми.

## Требование и проверенные основания

Артефакты уже доступны по отдельным SQL identities, но training/evaluation запускает host administrator. Нужно перенести orchestration в два controller Jobs без host kubeconfig, Docker socket или cluster-admin. Модель исполняется только в отдельном worker Pod, без labels holdout и signing material.

Официальный Kubernetes предупреждает: право создавать workloads позволяет косвенно использовать доступные в namespace Secrets и ServiceAccounts. Поэтому отдельного запрета `get secrets` недостаточно; нужны границы namespace и проверка создаваемого workload. [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

Short-lived projected tokens предпочтительнее постоянных token Secrets. Автоматическое монтирование остаётся выключенным; credential выдаётся явно только нужному controller. [ServiceAccounts](https://kubernetes.io/docs/concepts/security/service-accounts/).

Native ValidatingAdmissionPolicy позволяет проверять поля request и объекта через CEL (Common Expression Language). Policy и binding должны действовать вместе, с отказом при ошибке, а не только аудитом. [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/). Реализацию проверять на pinned Kubernetes 1.36.4; наличие примеров в latest documentation не доказывает совместимость.

Cilium рекомендует `kube-apiserver` entity для API, а не широкое разрешение всей cluster network или `toServices` для `default/kubernetes`. [Cilium 1.20.2 L3 policies](https://docs.cilium.io/en/stable/security/policy/layer3/). Фактические маршруты/порты и denial probes должны подтвердить это на нашем kind, не приниматься по YAML.

Описанная ниже композиция - проектное решение лаборатории на основе источников, а не обещание авторов документации о безопасности всей системы.

## Реализованные полномочия

| Controller | SQL роль | Worker namespace | Разрешённый Kubernetes API |
|---|---|---|---|
| `ml-publisher/publisher` | publisher: train/validation, candidate write | `ml-train` | create/get/delete ConfigMap и Job; read Pods/status/logs для контроля исполнения |
| `ml-scorer/scorer` | scorer: holdout/candidates read, evaluation write | `ml-eval` | те же минимальные операции только в `ml-eval` |

Точный набор verbs выводится из реально используемого client, wildcard не добавляется. Нет create Pods, exec/attach/portforward, Secret get/list/watch, RBAC mutation, TokenRequest, namespace/policy/node modification, ClusterRoleBinding или доступа к другой worker зоне. Workers сохраняют нулевой API access, запрещённую сеть и отсутствие токена. Namespace-wide чтение worker metadata/logs - явный предел изоляции этого single-tenant профиля, не per-run multi-tenancy.

Создание Job проверяется на admission, а не только отказом последующего Pod. Проверки должны связывать controller identity с target namespace, worker ServiceAccount, разрешённым image и bounded resources/deadline. Запрещены secret/projected/hostPath/PVC volumes, env secret references, произвольные init/sidecar/ephemeral containers и token automount. Существующая worker Pod policy остаётся вторым барьером. Controller не может менять admission policy или namespace labels.

## Credentials и transport

Controller получает только собственный SQL mTLS bundle. Scorer дополнительно получает evaluator signing key в собственном namespace; publisher не получает signer, approver или trust keys. Загрузка такого Secret - отдельный явный bootstrap step с ownership/UID receipt, не аргумент командной строки или public evidence. CA private keys остаются на host. Cluster admin всё равно доверен; это не production KMS.

Kubernetes API доступен controller только по фиксированному HTTPS endpoint с проверкой cluster CA и hostname. HTTP redirect, произвольный URL из task payload, plaintext и отключение TLS verification запрещены. Token перечитывается для ротации, не логируется; timeouts, response size и ошибочные status codes ограничены. Не добавлять kubeconfig fallback внутри Pod.

Input ConfigMaps содержат только необходимый payload: train+validation для training worker, model+features без holdout labels для prediction worker. ConfigMaps immutable, размер ограничен, IDs/UIDs и digest запроса связываются с конкретным Job. Output проверяется до записи/подписи: schema, count, order, batch ID, digest и конечность probabilities. Нельзя считать успешный Job достаточным доказательством корректного prediction.

## Порядок реализации и приёмки slice

1. До выдачи новых прав добавить negative fixtures и зафиксировать UID существующих storage/worker resources. Развернуть отдельные owned Role/RoleBinding/admission/network objects; не переписывать foundation или private storage receipt.
2. Проверить реальные API calls под каждой controller identity: минимальный Job проходит; чужой namespace, Secret read/list, role mutation, privileged Job, другой ServiceAccount, secret mount и token projection дают точный отказ. Отдельно проверить policy evaluation errors fail-closed.
3. Реализовать bounded in-cluster transport без host CLI dependencies. Проверить TLS/name/token failures, oversized response, timeout и uncertain POST outcome. Не выполнять автоматический повтор create с новой identity после неоднозначного timeout.
4. Запустить настоящее обучение от publisher и отдельное предсказание от scorer. Подпись report остаётся вне model execution. Model bytes не парсятся в процессе с signing key; byte/hash/schema checks контроллера не подменяют отдельный intake/parser sandbox.
5. Зафиксировать build provenance для controller environment. Сейчас host path получает source revision через Git и fingerprint включает Dockerfile, которого нет в runtime image; нельзя просто вызвать этот helper внутри Pod и подставить фиктивные значения. Controller использует явно проверенные image-bound materials, без `.git` или Docker socket.
6. Измерить requests/peak memory и concurrency. Первый профиль запускает publisher и scorer последовательно, без новых постоянных сервисов. Нельзя выводить безопасность нагрузки из суммы namespace quotas; сохранить запас для control plane, PostgreSQL и будущего serving.
7. Повторить storage/isolation regressions, negative output/replay cases и clean-checkout CI. Evidence хранит фактические image/namespace/Job/Pod identities, input digests и точные причины отказов. Локальный controller component проверен отдельно; полная replay/order suite M20 и итоговая M04 приёмка остаются следующими задачами. Component pass не заменяет эти требования и тем более R1.

## Реализованный scope и остатки

Сейчас два последовательных controller Jobs действительно создают отдельные model workers. API client перечитывает projected token, проверяет CA/hostname/TLS 1.3, ограничивает HTTP body и не повторяет неоднозначный POST. Реальные API probes подтверждают правильные credentials, отказ чужой CA и неверного token. Native Job negatives проверяют конкретную policy и причину; ошибки схемы не считаются доказательством admission. Отдельно проверяются SQL signature/content, unchanged protected history и measured controller RSS.

Проверка `onnx`/`onnxruntime` imports до/после controller execution подтверждает отсутствие этих parsers в данном процессе, но не доказывает отсутствие всех возможных parser vulnerabilities. Полный ordered/replay-resistant протокол, holdout query budget, serving и production key custody ещё не реализованы. Host launcher сохраняет admin role. Обновление десяти ресурсов не атомарно и требует отсутствия параллельных запусков; crash между API mutation и receipt требует operator review. Эти границы не скрываются словом «controller».

## Откат и исключённые альтернативы

На ошибке не открывать сеть workers и не выдавать controllers cluster-admin. Остановить только созданные этим slice Jobs, удалить только записанные owned bindings после проверки UID; private SQL history, прежние receipts и исходный host path остаются. Не удалять целиком namespace или PVC ради зелёной qualification.

Один privileged orchestrator в Pod лишь переносит текущую проблему. Общий evaluator+model процесс оставляет signer рядом с parser. Новый workflow engine или GPU platform не нужны для двух последовательных CPU Jobs; их введение не решает authorization само по себе. Постоянные services и более сложная очередь откладываются до измеренной необходимости.
