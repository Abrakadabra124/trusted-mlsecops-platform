# Выбор технологий и цена решений

Все новые ML-компоненты ниже **предлагаются**, а не объявляются установленными. Базовые определения: [словарь](glossary.md). Версии не фиксируются наугад из текущих `latest`-страниц: T02 проверяет совместимую матрицу Python/scikit-learn/skl2onnx/ONNX Runtime/MLflow/DVC и сохраняет lock + image digests.

| Ответственность | Выбор для reference | Почему так | Альтернатива и когда нужна |
| --- | --- | --- | --- |
| Исходники/CI | GitHub + существующие source gates | Уже проверенная основа, не менять CI-провайдера ради PDF | GitLab CI при реальном требовании организации |
| Python environment | uv, locked dependencies, pytest/Ruff | Согласованность с baseline | Другой manager только при доказанной несовместимости |
| Данные | DVC + отдельный signed SHA-256 manifest | Простые файловые datasets и явная граница происхождения | lakeFS при большом shared data lake и нужде в server-side branching |
| Data validation | Pydantic для API, Pandera для таблиц после compatibility spike | Разделение внешнего API и dataframe checks | Great Expectations, если понадобятся общие data-quality suites/UI; не ставить оба без причины |
| Experiments/registry | MLflow + отдельная PostgreSQL DB/role | Tracking не смешивается с хранением release approvals | ClearML при доказанной потребности в agent orchestration; миграция требует ADR |
| Artifact storage | Lab: изолированное локальное storage; pilot: поддерживаемый S3-compatible backend | Не навязывать облако и не объявлять локальный диск WORM | Managed S3 с TLS/retention/IAM после выбора провайдера и бюджета |
| Обучение | scikit-learn Logistic Regression, CPU | Простая baseline-модель, понятная оценка и небольшие ресурсы | Boosting/нейросети только при измеренном utility gain |
| DAG | Python CLI + DVC dependencies, Kubernetes Jobs | Один небольшой pipeline без отдельной control plane | Argo Workflows при сложном Kubernetes DAG; Airflow при множестве scheduled ETL и backfill |
| Serving | FastAPI + ONNX Runtime | Контролируемый небольшой surface и совместимость с foundation | KServe при множестве моделей/autoscaling/protocol needs после измерения ops cost |
| Supply chain | Cosign, provenance, SBOM + ML-BOM | Проверяемые связи вместо доверия alias | in-toto layouts при усложнении многокомандной цепочки |
| Delivery | Existing Flux/Cilium/Kyverno patterns | GitOps, network enforcement и admission уже освоены | Не добавлять Argo CD параллельно Flux без причины |
| ML monitoring | Evidently batch reports + Prometheus/Grafana | Отдельно data/prediction/label metrics | Streaming stack только при latency/volume requirement |
| Identity | Lab: раздельные credentials; production: OIDC/workload identity и KMS | Не выдавать локальные ключи за промышленное управление доверием | Конкретный IdP/KMS определяется средой, не логотипами |

Официальные основания по DVC/MLflow/форматам/drift/supply-chain собраны в [S10-S19](sources.md#s10). Выбор конкретной комбинации - проектный вывод, не рекомендация источников «поставить всё вместе».

## Почему не полная MLOps-платформа сразу

Airflow решает расписания и зависимости потоков; ClearML добавляет tracking и agents; MLflow закрывает metadata/registry; KServe стандартизует serving в Kubernetes. Их пересечения требуют ownership, auth, upgrades и backup для каждого control plane. Для одной CPU-модели дешевле проверить доверенную цепочку, чем обслуживать четыре частично дублирующих системы.

Feature store пока не нужен: нет нескольких online/offline consumers с доказанной проблемой consistency. Одинаковый preprocessing и contract в bundle проще. Service mesh, Spark, Kafka, GPU и vector database не являются обязательными признаками зрелости MLSecOps.

## Software bill of installation

| Этап | Что реально понадобится | Условие установки |
| --- | --- | --- |
| Текущий research | Git/GitHub CLI, Python stdlib; имеющиеся средства чтения PDF | Используются уже доступные инструменты; ML-stack не устанавливается |
| T01-T02 | Проверенные Docker/WSL/Linux/kubectl/foundation, отдельное Python environment | Inventory, свободные ресурсы, согласованный профиль и разрешённое обслуживание |
| T03-T08 | Locked DVC, MLflow, NumPy/pandas/Pandera/scikit-learn, storage adapters | Compatibility + security/license review |
| T12-T15 | skl2onnx/ONNX Runtime, verifier, existing signing tools | Conversion/parity spike, ограничения unsafe formats |
| T18-T20 | Evidently и минимальные exporters/backup clients | Точные integration tests, мониторинг его собственного отказа |
| Pilot | TLS, IdP/KMS, external storage/backup и on-call интеграция | Отдельное решение владельца среды и бюджета |

Для каждой зависимости: версия, источник, checksum/digest, лицензия, известные vulnerabilities, update policy, owner и процедура rollback. «Зависимость поставилась» не является доказательством совместимости или безопасного доступа.

## Ресурсный и финансовый предел

Сначала инвентаризация реально свободной памяти, CPU и диска. Начальные per-job limits даны в [приёмке](acceptance.md); отдельно надо сложить MLflow/PostgreSQL/monitoring и прежние workloads. Если headroom недостаточен, запускать фазы последовательно и оставить одну модель. Облачные расходы и GPU в 12-недельный local-reference план не включены; production стоимость оценивается отдельно по storage, egress, retention, compute и on-call.

Решения, которые дорого менять: [ADR-001](decisions/0001-reference-scope.md), [ADR-002](decisions/0002-release-trust.md).
