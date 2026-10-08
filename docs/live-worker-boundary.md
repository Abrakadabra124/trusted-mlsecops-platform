# Live worker access matrix

Компонент T26/M20 проверяет реальный доступ из обоих worker namespaces к одновременно работающему scorer witness. Это часть lab assurance, не завершённый M20 и не защита от host administrator или kernel exploit. [Scoped plan и основание](decisions/0012-live-worker-boundary.md), [текущий статус](../STATUS.md).

## Что именно запускается

Scorer witness использует общий `controller_spec` с настоящим scorer: UID/GID 65532, read-only root, dropped capabilities, RuntimeDefault seccomp, отдельная ServiceAccount, SQL mTLS credentials, projected API token и scorer signing key. Qualification command заменяет business operation, но не security context или volumes. Он читает и проверяет synthetic holdout через штатный `storage_dataset.read_dataset`, проверяет свой public key и сохраняет labels в памяти и временном tmpfs file. Последний существует только в qualification, не становится новым production data path.

Host observer связывает Kubernetes Pod UID, container ID и running node PID через read-only Container Runtime Interface (CRI) inspection. Воркер получает только PID и два ClusterIP, а не token, key, labels или путь к host socket. Scorer остаётся живым во время двух последовательных worker Jobs. В начале и конце он выполняет положительные SQL/API контрольные запросы; отказ не засчитывается только потому, что endpoint выключен.

| Под кем | Что пробуется | Ожидаемый результат |
|---|---|---|
| `ml-train/trainer`, `ml-eval/evaluator` | `/client/client.key`, certificate/connection config, `/api/token`, `/signer/key.pem`, init-only `/source` | ENOENT/EACCES/EPERM |
| Те же identities | Known host key/admin paths, default ServiceAccount token, Docker socket | ENOENT/EACCES/EPERM |
| Те же identities | Qualification holdout file в своём filesystem и в `/proc/<observed-node-pid>/root` scorer | ENOENT/EACCES/EPERM |
| Те же identities | `/proc/<observed-node-pid>/mem`, `environ`, `cmdline` и credential paths через `root` | ENOENT/EACCES/EPERM; разные PID namespaces |
| Те же identities | Точный PostgreSQL ClusterIP:5432 и Kubernetes API ClusterIP:443 | TCP timeout при успешных scorer positive controls |
| `ml-scorer/scorer` | Действительный holdout, signer key, TLS SQL identity, authenticated API list | Успех до и после worker probes |
| Host observer | Удаление собственного temporary ConfigMap с чужим UID | Conflict, исходный resource сохранён |

Это чтение известных путей и ограниченные подключения, не exploit campaign. Connection refused, неверный endpoint, прочитанный пустой файл и неизвестный errno не считаются защищённым отказом. Один общий node/kernel остаётся доверенной частью lab.

## Как воспроизвести

Нужен готовый [private storage](private-cluster-storage.md), завершённая [migration](cluster-storage-migration.md) и [scoped controller lab](scoped-controllers.md). Populated target не удалять и migration не повторять ради теста.

```bash
uv run --locked python -m mlsecops.boundary_probe_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.controller_bootstrap --replace-profile
uv run --locked python -m mlsecops.boundary_qualification
uv run --locked python -m mlsecops.controller_qualification
```

`replace-profile` разрешён только без активных Jobs и при совпадении owned resources. Новые image и source fingerprint должны совпадать. Unit suite не требует cluster; live suite возвращает exit 2/inconclusive при отсутствующих prerequisites. Failed probe не разрешает promotion.

Live suite создаёт один ConfigMap, один scorer witness Job и последовательно два worker Jobs. Scorer: 512 MiB, deadline 240 s; worker probes: 256 MiB limit, deadline 90 s. Контейнеры не получают дополнительные privileges. Удаление временных ресурсов использует API UID precondition и foreground cleanup. SQL ledger до/после совпадает; сохранённые namespace/RBAC/admission specifications не меняются.

## Evidence и ограничения

Report: `.runtime/evidence/boundary-qualification.json`. В нём source/image/profile, dataset reference, actual identities, PID namespace и enum причины отказа. Нет labels, token/key bytes, их hashes или raw diagnostic logs. Возвращаемые reports сами по себе не являются защищённым audit sink M23; host operator доверен.

Clean checkout на `9963248` подтверждён [Kubernetes CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37830459019): 137 boundary checks, каждый успешен, после реальных migration и controller runs. [Developer CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37830459002) отдельно повторил 43 unit/controlled checks, protocol и training regression. Точные fingerprints и остальные результаты: [STATUS](../STATUS.md). PID namespace inode может переиспользоваться после удаления предыдущего worker; проверяется отличие от одновременно живого witness, не глобальная уникальность inode навсегда.

Probe запускается host operator под настоящей worker ServiceAccount с другим test command и меньшим RAM request, а не через ограниченную production-команду controller admission. Производственный admission, реальное обучение/предсказание и сохранённая подпись проверяются отдельно controller suite. Workload security settings берутся из общего builder и проверяются по observed Pod; тест не включает hostPID, shared PID, ptrace, exec permission для воркеров или network exception.

В текущем scorer нет отдельного HTTP admin service. Проверяется используемый Kubernetes control-plane API и PostgreSQL metadata/artifact service. MLflow, serving и будущие API требуют своих integration probes. Полный M20 дополнительно объединяет этот live access report, protocol negatives и текущий candidate-bound controller run. Persistent holdout budget M07 и release replay protection M11 остаются самостоятельными требованиями.

Код: [probe](../mlsecops/boundary_probe.py), [contract tests](../mlsecops/boundary_probe_qualification.py), [live harness](../mlsecops/boundary_qualification.py), [общий scorer Pod builder](../mlsecops/controller_runtime.py).
