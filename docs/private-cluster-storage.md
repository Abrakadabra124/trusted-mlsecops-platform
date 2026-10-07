# Private Kubernetes storage

Это additive component для будущих изолированных publisher/scorer controllers, не переключение рабочего SQL demo и не завершённый M04/M20. План изменения runtime: [ADR 0008](decisions/0008-private-cluster-storage.md). Актуальные измерения: [STATUS](../STATUS.md).

## Что делает этот слой

PostgreSQL хранит bytes артефактов с серверной проверкой SHA-256 и раздельными SQL правами. Kubernetes StatefulSet управляет единственным экземпляром БД; PersistentVolumeClaim (PVC) связывает его с сохраняемым диском. При пересоздании Pod остаётся прежний том, но потерю единственного kind node он не переживёт.

Cilium применяет сетевые ограничения к ServiceAccount identities. Вход к PostgreSQL разрешён только шести storage identities на TCP 5432, исходящие соединения сервера запрещены. Client namespaces разрешают только PostgreSQL и DNS; это не разрешение произвольного доступа к cluster API или Internet.

Mutual TLS (mTLS) проверяет обе стороны соединения. Сертификат сервера содержит ровно `postgres.ml-storage.svc.cluster.local`; клиент использует `verify-full` и TLS 1.3. Для этого профиля библиотека принимает только фиксированное DNS-имя и порт 5432, не произвольный hostname из входного JSON. Старый loopback profile остаётся прежним.

## Воспроизведение

Предусловия: [Kubernetes lab](kubernetes-lab.md), отдельный initialized workspace, pinned worker image. Дополнительный PostgreSQL ограничен 1 CPU/512 MiB; PVC запрашивает 2 GiB. Local-path не предоставляет физическую filesystem quota только на основании размера PVC. Проверяйте свободный диск и суммарную память node отдельно.

```bash
uv sync --locked --python 3.12.15
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops.cluster bootstrap
uv run --locked python -m mlsecops.kube_storage
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.kube_storage_qualification
```

Для disposable Linux x86_64 CI tools устанавливает `uv run --locked python scripts/install_ci_tools.py`, после чего `.runtime/bin` добавляется в PATH. Этот installer не предназначен для Windows; там используются уже установленные kind/Helm/kubectl из prerequisite runbook.

Qualification выполняет client Jobs последовательно. Дополнительные namespace quotas - верхние ограничения, не зарезервированная RAM; сумма всех возможных limits базового и нового профиля превышает 12 GiB node. Одновременно заполнять все namespaces workloads нельзя. Перед запуском постоянных controllers нужны отдельные замеры requests/limits и concurrency budget; данный increment не доказывает безопасную одновременную нагрузку всех ролей.

Bootstrap создаёт 46 явно описанных ресурсов и записывает их UID в `.runtime/kubernetes-storage/resources.json`. Повтор не применяет YAML поверх drift: сравнивает spec, identities, PVC binding и фактическую готовность PostgreSQL. Partial bootstrap можно повторить только для ранее записанных ресурсов; неизвестный существующий объект требует ручного разбора. Окно между успешным API create и записью receipt намеренно fail-closed.

Сервер получает только свой key/certificate, CA certificate и конфигурацию. CA private key не загружается в Kubernetes. Каждый client Secret содержит только одну роль; probe initContainer переносит четыре разрешённых файла из projected Secret в tmpfs с mode 0600. Это сохраняет запрет symlinks в обычном storage client, не ослабляя его ради Kubernetes projected-volume механизма. Main container не монтирует исходный Secret volume или другие ключи.

## Проверки и смысл evidence

- Реальные SQL SELECT/INSERT/UPDATE/DELETE/TRUNCATE для всех девяти таблиц под каждой из шести identities; запрещённая операция должна вернуть SQLSTATE 42501, разрешённая должна исполниться. Вставки и TRUNCATE probes выполняются в rollback transactions.
- TLS negatives: чужой SQL user с собственным certificate, неправильное имя сервера, отсутствующий client certificate, plaintext и superuser TCP login. Ошибка другого происхождения не считается ожидаемым отказом.
- Реальные Kubernetes API requests с короткоживущим role token: чтение собственных/чужих Secrets и создание privileged Pod запрещены. Токен используется только qualification harness и не монтируется runtime Pod.
- Training/evaluation workers и посторонний ServiceAccount не открывают TCP к БД; разрешённая identity подключается к тому же endpoint. Сервер не может открыть исходящее TCP соединение к DNS, доступность того же DNS TCP endpoint проверяет разрешённый client.
- Сохраняется fixture, PostgreSQL Pod пересоздаётся, сравниваются bytes fixture и PVC UID. Удаляется только собственная запись; итоговый ledger должен совпасть с исходным. Qualification временно прерывает доступ именно к новой БД, поэтому не запускать при параллельной работе с этим profile.

Итог `.runtime/evidence/kubernetes-storage-qualification.json` - component evidence. Fail записывается поверх прежнего отчёта; успешный запуск команд bootstrap сам по себе не доказывает denials, persistence или всю приёмку.

На 2026-10-08 локально и в [clean-checkout CI 37690561970](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37690561970) прошли 436 checks. Проверенный feature commit: `6577de7bc181dbdb462c08fa8eebff00f57a1e0a`. Эти числа относятся к данному component suite, не к общему M04/M20 gate.

## Ограничения и следующий этап

Нет HA, KMS, автоматической ротации TLS, node-loss recovery и завершённого native image vulnerability scan. Host storage, backup и SQL demo остаются отдельным working path. Bootstrap создаёт пустой instance; следующий реализованный компонент - [подписанная migration](cluster-storage-migration.md) dataset/model/evaluation history с role readers и golden verification. Controller RBAC, независимый scorer controller, serving API и release-ready статус ещё не реализованы. Следующий этап запускает настоящие controller Jobs с минимальными полномочиями, не выдавая им host kubeconfig.

Secrets доступны cluster administrator, а локальный etcd не объявляется зашифрованным хранилищем ключей. Default-deny не защищает от доверенного администратора, который меняет policies или node. `Retain` не равен backup: автоматическое удаление namespace/PVC/PV не реализовано. Для rollback не используйте новый profile; исходный host instance не изменён этим increment.

## Как объяснить на собеседовании

«Я отделил data plane от host orchestration: поднял закрытую PostgreSQL внутри отдельного Kubernetes namespace, сохранил SQL ACL и добавил mTLS и identity-based network policies. Проверил доступ реальными запросами из разных Pods, отказ рабочих контейнеров и сохранность bytes после пересоздания БД. Это проверяемый компонент локальной лаборатории, а не заявление о production HA или готовой MLSecOps-платформе».

Код: [bootstrap и проверки состояния](../mlsecops/kube_storage.py), [resource definitions](../mlsecops/kube_storage_resources.py), [SQL/TLS probe](../mlsecops/kube_storage_probe.py), [qualification orchestration](../mlsecops/kube_storage_qualification.py). Основание сетевой модели: [Cilium 1.20.2 Kubernetes identity policies](https://docs.cilium.io/en/stable/security/policy/kubernetes/).
