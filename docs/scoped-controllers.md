# Scoped controllers: обучение и оценка без host kubeconfig

Этот component реализует следующий шаг [ADR 0010](decisions/0010-scoped-controllers.md): publisher и scorer работают в отдельных Kubernetes Jobs, а model execution остаётся в отдельных offline worker Pods. Это не полный M04/M20 и не trusted release. Точное проверенное состояние, числа и CI: [STATUS](../STATUS.md).

## Ответственность компонентов

- **Publisher** читает approved train/validation через свою SQL mTLS identity, создаёт training Job и сохраняет candidate в private PostgreSQL. Holdout и signer ему не выдаются.
- **Scorer** читает candidate и holdout своей SQL identity, передаёт prediction worker только model+features, проверяет output, считает метрики и подписывает evaluation. Model parser не загружается в процесс с signer.
- **Workers** не получают API token, database certificate, signer key или host mounts. Сохраняются прежние namespaces, admission, default-deny egress, non-root, readonly root и limits/deadline.
- **Host launcher** остаётся доверенным операторским entrypoint: устанавливает owned resources и запускает controller Jobs. Он всё ещё имеет admin kubeconfig; этот credential не копируется в controller или worker. Bootstrap не становится безопасным для недоверенного оператора от появления RBAC.

Role-Based Access Control (RBAC) ограничивает controller API его worker namespace: Jobs и input ConfigMaps create/get/delete, Pods get/list и logs get. Нет Secret API, exec/attach/portforward, Role/RoleBinding mutation, TokenRequest, node или namespace management. Доступ к metadata/logs внутри одной worker-зоны общий для её controller; per-run multi-tenancy здесь не заявляется.

Native admission проверяет Job ещё при create: controller identity, namespace, ServiceAccount, точный digest image, fixed command, отсутствие token/secret/host volumes и sidecars, resources и deadline. Это дополнительный барьер к проверке Pod, а не замена namespace isolation.

## Полный путь воспроизведения

Нужны prerequisites [Kubernetes lab](kubernetes-lab.md), Linux x86_64 containers, отдельный owned cluster и достаточно свободной памяти/диска. Исходная DevSecOps foundation не изменяется.

```bash
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git
cd trusted-mlsecops-platform
uv sync --locked --python 3.12.15
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.cluster bootstrap
uv run --locked python -m mlsecops.storage_bootstrap
uv run --locked python -m mlsecops.kube_storage
uv run --locked python -m mlsecops.kube_storage_migration_qualification
uv run --locked python -m mlsecops.controller_bootstrap
uv run --locked python -m mlsecops.controller_qualification
```

Migration qualification выполняется один раз на пустом target. Если она уже прошла, **не повторяйте её со сбросом БД**: начинайте с controller bootstrap. Inputs и trust references берутся из `.runtime/kubernetes-storage/migration-inputs.json`; это bridge к уже проверенному dataset, не универсальный ingestion API.

Для нового run после bootstrap:

```bash
uv run --locked python -m mlsecops.controller_runtime
```

Новый run обучает модель заново и добавляет candidate/evaluation history. Состояние сохраняется в private cluster SQL, а не в прежней host БД. Это не автоматическая репликация: старый host backup не содержит новых controller runs. Backup private target и полный M17 ещё нужно реализовать.

## Image binding и обновление профиля

Bootstrap проверяет source fingerprint, Docker image, containerd manifest/config digests и регистрирует точное digest-имя в owned kind image store. Kubernetes запускает это имя с `imagePullPolicy: Never`. Это важно: наличие `repoDigests` в CRI inspection само по себе не гарантировало, что kubelet сможет разрешить такое имя. При отладке это дало `ErrImageNeverPull`, а не основание отключить pin или разрешить внешнюю загрузку.

Контроллеру передаётся immutable profile. Worker image наблюдается по фактическому `imageID`, а не только желаемому Pod spec. Dockerfile теперь входит в image build context, чтобы source fingerprint можно было проверить внутри controller без `.git`, Docker socket или Git binary. Git revision приходит из проверенного image label; локальная dirty-tree сборка отдельно связана fingerprint, а CI строит опубликованный commit.

Bootstrap повторяется без смены resource UIDs. При смене собранного image обычный повтор отказывает. Явное обновление профиля:

```bash
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.controller_bootstrap --replace-profile
uv run --locked python -m mlsecops.controller_qualification
```

До replace проверяются прежние UID/spec и отсутствие незавершённых Jobs в четырёх затронутых namespaces. Это не online rollout. Не выполняйте его параллельно с ручным запуском Jobs; admission image pin меняется, source/PVC/SQL history не удаляются. Неизвестные resources не принимаются во владение. Если replace прерван между API operation и локальным receipt, требуется разбор drift, а не сброс receipt или wildcard apply.

## Credentials, TLS и секреты

API client использует фиксированный `kubernetes.default.svc:443`, cluster CA, hostname verification и минимум TLS 1.3. Он не использует proxy environment, redirect, host kubeconfig или произвольные URLs из request. Token из явно projected volume имеет запрошенный lifetime 600 s и перечитывается при запросах; kubelet управляет ротацией. Фактические server-side expiration limits определяет cluster, это не обещание ровно 600 s во всех Kubernetes distributions.

Каждый controller получает только свой SQL bundle. Scorer дополнительно получает immutable `evaluator-signer` Secret, проверенный относительно внешнего public evaluator key и отдельного UID receipt. InitContainer копирует key в tmpfs с mode 0600; worker его не монтирует. Approver, trust и CA private keys не передаются. Secret не объявляется защищённым от cluster/node admin, etcd не объявляется зашифрованным production KMS. Rotation требует отдельной migration.

Cilium API allow добавляется только publisher/scorer identities. Базовый private storage policy не переписывается; эффективный доступ этих controllers теперь SQL+DNS+API, остальных SQL identities - прежний. Workers по-прежнему offline. API authorization проверяется отдельно от сетевой доступности.

## Qualification и доказательства

Suite разделяет виды evidence:

1. Request-contract и mocked HTTP tests проверяют paths, методы, sizes, redirects, token reread, TLS configuration, error sanitization и cleanup. Это не live TLS tests.
2. Реальные role credentials выполняют разрешённый Job server dry-run и запрещённые Job variants через admission. Unsafe fixtures не создаются. Secret list, чужая worker-zone, node/role reads и TokenRequest дают действительный RBAC Forbidden. Это не `kubectl auth can-i` simulation.
3. Отдельные controller probe Pods подключаются к настоящему API с правильными credentials; чужая CA и недействительный token отказывают. Положительный control повторяется после negatives.
4. Настоящий publisher запускает отдельный training worker, scorer - отдельный prediction worker. Evaluation читается из private SQL ещё одним reader и проверяется по внешнему public key. Сверяются candidate/model/image/provenance bindings, protected tables и неизменность host source.
5. Измеряется peak RSS процессов controllers и подтверждается их cleanup. Это не node-level worst-case memory или нагрузочный serving SLO. Первоначальный профиль последовательный; requests/limits одного controller 512 MiB, training worker 4 GiB, prediction worker 1 GiB.

Admission и RBAC имеют разные причины отказа. Native policy без явно заданного `reason` использует `Invalid`, а не обязательно `Forbidden`: это описано в [Kubernetes API semantics](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#validation-expression). Поэтому negative suite требует точное имя policy/binding и ожидаемый `controller-*` reason, а не любой ненулевой exit code. Privileged fixture задаёт совместимые между собой Kubernetes fields, чтобы отказ доказал работу нашей policy, а не только встроенного schema validator. Для RBAC проверяются запрет и фактическая ServiceAccount identity; регистр слова в CLI-ошибке TokenRequest не считается свойством authorization.

Основной отчёт `.runtime/evidence/controller-qualification.json` сначала получает `inconclusive`, затем `pass` или `fail`. API/deadline/error не превращаются в пропуск. Необработанный инфраструктурный crash также не даёт pass. `.runtime/evidence/controller-demo.json` хранит metadata, ссылки и synthetic metrics, не raw train/holdout payload.

На ошибке host может сохранить ограниченный diagnostic в игнорируемой `.runtime/evidence/controller-diagnostic.log` или `controller-probe-diagnostic.log`. Эти файлы приватные, не включаются в public report или Git. Не копируйте `.runtime/` в artifacts upload. Удаление owned Job/ConfigMap не откатывает уже добавленные append-only SQL objects; при неуспешном run они не превращаются в approved release.

## Что осталось

Нет serving, promotion verifier, независимого human approval, полного holdout query budget, MLflow или динамического revocation. Полный M20 требует отдельной приёмки replay/order/output и всех runtime access scenarios; наличие controller Pods само по себе её не заменяет. Полные M04/M05/M17/M18 также остаются открытыми. Формат/parser intake и poisoning/evasion campaigns не считаются выполненными этим scope.

Код: [API client](../mlsecops/controller_api.py), [resources/admission](../mlsecops/controller_resources.py), [bootstrap](../mlsecops/controller_bootstrap.py), [worker executor](../mlsecops/controller_worker.py), [controller](../mlsecops/controller.py), [operator launcher](../mlsecops/controller_runtime.py), [qualification](../mlsecops/controller_qualification.py).
