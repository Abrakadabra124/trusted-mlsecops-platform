# Kubernetes lab: запуск и проверка изоляции

Второй working increment R1, не production release. Решение и границы: [ADR 0004](decisions/0004-isolated-kubernetes-lab.md).

## Технологии и назначение

Kubernetes управляет Jobs и их завершением, ServiceAccounts разделяют identities. Pod Security Admission и ValidatingAdmissionPolicy запрещают опасные Pod specs, Cilium исполняет сетевые запреты. ResourceQuota ограничивает совокупный бюджет namespace, LimitRange задаёт максимум ресурсов контейнера. Docker backend остаётся быстрым developer-профилем; Kubernetes нужен для проверки реального оркестратора.

## Запуск

Нужны kind 0.33.0, Helm 4.2.4, kubectl 1.36.x, Linux x86_64 Docker Engine, Git и uv. Docker capacity: >=4 CPU/15 GiB RAM, свободный диск >=12 GiB. Проверяйте доступную RAM с учётом других контейнеров, а не только total. CIDR 10.78.0.0/16 и 10.79.0.0/16 должны быть свободны. Собственный node ограничен 12 GiB/4 CPU; namespace memory quotas суммарно 6.5 GiB, остальное оставлено системным компонентам. Kind может показывать kubelet память всей VM, поэтому одного node cgroup недостаточно.

```bash
uv sync --locked --python 3.12.15
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.cluster bootstrap
uv run --locked python -m mlsecops.cluster bootstrap
uv run --locked python -m mlsecops.kube_qualification
uv run --locked python -m mlsecops demo --backend kubernetes
```

Двойной bootstrap сохраняет workspace и namespace identity. CLI всегда передаёт явные kubeconfig/context; прежние `sdp`, registry и глобальный context не используются. State, signing keys и данные находятся в ignored `.runtime`, не публикуются в Git.

## Как проходит Job

Контроллер сверяет source fingerprint image и импортирует его в containerd. Job с `imagePullPolicy=Never` получает immutable ConfigMap: train + validation features для trainer либо model + features без holdout labels для predictor. Gzip ограничен 700 KiB, распакованный протокол 16 MiB. Worker не имеет host mounts, API tokens и signing keys. После завершения controller проверяет schema/count/digest/batch ID результата и удаляет Job/ConfigMap.

Проверка image учитывает дополнительный OCI index при импорте в containerd: сверяются хеши descriptors и config digest с rootfs diff IDs, а не только тег. Для single-entry index без optional platform выбор единственного manifest разрешается только с последующей проверкой Linux/amd64 в его config. Несколько неоднозначных candidates отвергаются, глубина index ограничена. [OCI index](https://github.com/opencontainers/image-spec/blob/main/image-index.md), [OCI manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md), [OCI configuration](https://github.com/opencontainers/image-spec/blob/main/config.md).

`ORT_DISABLE_TELEMETRY=1` выставлена до запуска Python; дополнительно egress запрещён. Это выключает vendor telemetry initialization, warning которой Kubernetes иначе объединяет со stdout и нарушает strict JSON protocol. Неизвестный текст по-прежнему отвергается, а не игнорируется ради зелёной проверки. [ONNX Runtime privacy](https://github.com/microsoft/onnxruntime/blob/main/docs/Privacy.md).

ConfigMap и pod logs не являются шифрованным production storage: Kubernetes admin их видит. Контроллер пока работает на доверенном host с отдельным admin kubeconfig, не с production least-privilege identity.

## Проверено локально 2026-10-07

**52 component checks прошли.** Отчёт: `.runtime/evidence/kubernetes-qualification.json`.

| Граница | Проверка |
| --- | --- |
| Admission | Valid Pod разрешён; root, privileged, writable root, token, host/secret mount и превышение CPU/RAM отвергнуты server-side dry-run |
| Identity | Реальные API запросы по short-lived token четырёх ролей дают Forbidden при чтении protected namespaces и создании Job |
| Runtime | UID 65532, CapEff=0, NoNewPrivs=1, readonly root, отдельный PID namespace; host/socket/keys/token отсутствуют |
| Resources | Фактические cgroup CPU/RAM; bounded process creation ограничена pod PID budget; memory fixture получает OOMKilled |
| Network | Trainer/predictor не подключаются к контролируемому endpoint; разрешённый клиент подключается до и после отрицательных probes |
| Deadline | Sleep fixture получает DeadlineExceeded при budget 10 s; удаление Pod проверено отдельно |
| Control | Отдельный HTTP Pod сохраняет UID, 0 restarts и доступность после stress fixtures |

Pod PID limit находится в родительском cgroup. Leaf `pids.max` не обязан показывать 64; bounded probe делает до 80 попыток и получает EAGAIN до превышения pod budget, после чего завершает всех дочерних процессов. [Kubernetes PID limiting](https://kubernetes.io/docs/concepts/policy/pid-limiting/).

Настоящее обучение и оценка через Jobs дали AUPRC 0.9323007296445032 против baseline 0.4073333333333333; ONNX parity error 2.086162567138672e-7. Это synthetic benchmark, не доказательство пользы на реальных релизах. Evaluation остаётся `unapproved`.

## Что не доказано

HTTP control fixture не заменяет будущий inference service и его SLO. Настоящие data store/MLflow/registry ACL, least-privilege controller, HA, real TLS и KMS ещё не реализованы. Отсутствие файлов в worker не заменяет storage ACL tests. Host/cluster admin и kernel escape вне lab-гарантии. M04/M05/M20 остаются неполными; component report не разрешает promotion.

## Сбои и очистка

Stale image требует rebuild, не ослабления проверки. Неизвестный existing cluster/workspace отвергается. При прерванном bootstrap ресурсы сохраняются для диагностики; не удаляйте чужие кластеры и `.runtime` рекурсивно.

Для удаления собственного lab сначала выполните `uv run --locked python -m mlsecops.cluster status`. Только после успешной проверки ownership допустим `kind delete cluster --name trusted-mlsecops --kubeconfig .runtime/kubeconfig`. Model/data/keys на host сохраняются. После teardown для нового bootstrap надо осознанно удалить только старые `.runtime/cluster.json` и `.runtime/kubeconfig`, не остальные artifacts. Это не автоматический disaster recovery.

## CI

[Workflow](../.github/workflows/kubernetes.yml) повторяет bootstrap, isolation qualification и обучение/оценку из clean checkout. CLI artifacts закреплены SHA-256; remote shell scripts не исполняются. Конкретный успешный run фиксируется после проверки в [STATUS](../STATUS.md), наличие workflow не является доказательством.

## CP1: M04/M05 и отказ training при настоящем inference

Состояние реализации 2026-10-20: gates подключены в рабочей копии, native CI ещё не выполнен. Исторический HTTP control Pod из таблицы выше не переименован в настоящий inference. Основание работы - обязательный R1-B03, не дополнительное усиление.

**M04:** [aggregator](../mlsecops/isolation_gates.py) выполняет свежие полные M20 и storage campaigns и связывает реальные API/SQL/network cases с текущими source/image, namespace UID, volume UID и dataset. Workflow вызывает эти кампании внутри M04 ровно один раз, вместо прежних отдельных шагов. Проверяются все 63 SQL/TLS cases на роль, отдельные API-denials storage ServiceAccounts, network probes, счётчик cases, hashes M20 и независимые ограничения SQL-ролей. Trainer/evaluator проверяются внутри настоящих Jobs; SQL `serving` читает releases, но не train/candidates. Сохранённый прошлый pass не заменяет новую проверку текущих прав.

**M05:** [native coordinator](../scripts/isolation_native.py) использует настоящий candidate из `storage-demo.json`, существующие signed release proposal и отдельный qualification permit. Запускает тот же HTTP app и bounded ONNX worker, что существующая candidate qualification, без production approval и без замены модели fixture. Пока service работает, отдельные training Jobs выполняют CPU loop до active deadline и расходуют память до OOMKilled. ONNX worker ограничен 1 CPU/1 GiB; отрицательный training probe использует 2 CPU/256 MiB, то есть более низкий fault budget внутри разрешённого профиля.

HTTP predictions проверяются до, во время и после каждого отказа: тот же model/bundle, те же predictions и тот же serving container. Для зачтённого concurrent sample API должен наблюдать тот же Pod в Running до и после HTTP response; дополнительно сохраняются UID Job/Pod, фактический Pod spec и причина завершения. Нет такого sample, неожиданный HTTP status, смена модели/worker или неверная termination - fail, не молчаливый пропуск. Это не заменяет M14 latency/load SLO.

### Диагностика и безопасное повторение

Ответственный - platform operator. Команды только для разрешённого disposable hosted CI, после bootstrap, storage migration и controller bootstrap данного checkout. M04 сам выполняет и сохраняет полный M20; отдельно повторять M20/storage qualification перед этой командой не нужно. Не запускать их на локальных Docker/WSL/Kubernetes/SQL и не переключаться на чужой kube context.

```bash
uv run --locked python -m mlsecops.acceptance --gate M04 --output .runtime/evidence/M04.json
uv run --locked python -m mlsecops.acceptance --gate M05 --output .runtime/evidence/M05.json
```

1. Сначала read-only: проверить status/exit code в M04/M05, hashes/source/image и наличие prerequisite reports. Missing prerequisites означают inconclusive/2. Старый component report или успешный unit test не разрешает считать native gate пройденным.
2. `isolation_access_*` / `isolation_resource_*`: проверить конкретную identity/case, сохранённые hashes и UID. Не удалять failed cases, не расширять RBAC/SQL права и не менять policy ради pass. Другой cluster/volume требует новой полной CP1 qualification.
3. `training_fault_*`: проверить Running observations, HTTP response digest, Pod spec, DeadlineExceeded/OOMKilled и неизменность serving container. Отсутствие overlap не считается доказательством влияния на service, но не даёт pass. Не увеличивать budgets/thresholds без согласованного изменения контракта.
4. После ошибки creation Job очистка не удаляет ресурс, который не был создан этой операцией. Для уже созданного Job используются его уникальное имя и namespace; native qualification завершает свои disposable serving/trust resources. При неполной очистке сохранить диагностику приватно и проверить ownership до адресного удаления. Global prune/reset запрещены.
5. Повторять checkpoint только после установленной причины и конкретного исправления. Rollback изменения не означает разрешение release; неизменённые runtime images не relabel. Нужны новая сборка и проверка source fingerprint.

Критерий закрытия R1-B03: M04/M05 pass из clean CI checkout с перечисленным evidence, а не только наличие кода. Локально проверены controlled unit cases; запуск настоящих ресурсов и окончательный статус фиксируются в STATUS после CI.

### Исправления основного CP1 review

Обнаружены три дефекта нового gate, не production incidents: cached M04 не обнаруживал изменённые grants; старый access pass оставался пригодным после нового отказа; обязательная matrix не требовала часть storage identity/TLS cases. Исправление: свежие полные native campaigns внутри каждой попытки M04, invalidation access report до проверки prerequisites, полный набор SQL/TLS/API/network cases и проверка count. M05 требует текущий успешный `M04.json`, hash соответствующего access report и неизменные успешные storage/authority/access/controller/isolation компоненты. Любой новый fail/inconclusive или изменённый компонент закрывает этот путь до запуска ресурсов.

18 targeted methods прошли; новые gate/native coordinator modules имеют 100% statement/branch coverage. Включены regressions для нового отказа при старом pass, failed storage, отсутствующих cases и несовпадающего count. Основной review закончен, проверка этих конкретных исправлений и native CI ещё не завершены.
