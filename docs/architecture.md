# Целевая архитектура

**Design proposal, не deployed state.** Решение ограничено первым табличным CPU-сценарием. Базовые допущения: [GOAL](../GOAL.md), решения: [technology decisions](technology-decisions.md).

## 1. Компоненты и границы доверия

```mermaid
flowchart TB
    External[Недоверенный источник / feedback] --> Intake
    subgraph DataZone[Data boundary]
        Intake[Quarantine и schema gate] --> Approved[Approved train snapshot]
        Intake --> Holdout[Закрытый holdout]
    end
    subgraph TrainZone[Training boundary]
        Approved --> Job[Недоверенный training worker]
        Job -->|Ограниченный output volume| Publisher[Trusted publisher и provenance wrapper]
        Publisher --> Candidate[Candidate model и run metadata]
        Publisher --> Tracking[MLflow metadata]
    end
    subgraph EvalZone[Evaluation boundary]
        Candidate --> Worker[Недоверенный prediction worker]
        Holdout --> Eval[Trusted controller и scorer]
        Eval -->|Только batches features| Worker
        Worker -->|Typed bounded predictions| Eval
        Eval --> Report[Signed evaluation report]
    end
    subgraph ReleaseZone[Release boundary]
        Report --> Verify[Policy verifier]
        Candidate --> Verify
        Approval[Отдельный approver] --> Verify
        Trust[Trust policy и revocation] --> Verify
        Verify --> Bundle[Signed ModelReleaseBundle]
        Bundle --> GitOps[Desired state по digest]
    end
    subgraph RuntimeZone[Serving boundary]
        GitOps --> Loader[Verify then load]
        Trust --> Loader
        Loader --> API[FastAPI + ONNX Runtime]
        API --> Telemetry[Метрики и audit]
    end
    Telemetry --> Review[Проверенный feedback / incident]
    Review --> Intake
    Bundle --> Ledger[Release Ledger: только запись факта]
```

Стрелка обозначает разрешённый интерфейс, а не широкую сетевую связность. Jobs не получают общий S3 root key. Namespaces не являются самостоятельной security boundary без RBAC, network policy, storage isolation и тестов запрета.

## 2. Хранение и идентичности

Предлагаемые классы объектов: `quarantine`, `approved-train`, `holdout`, `candidates`, `evaluations`, `releases`, `audit`. Разные credentials и доступы, не только названия каталогов. Для локального стенда допускается изолированный filesystem/PVC с read-only mount и проверкой digest. Он не объявляется WORM-хранилищем или защитой от host-admin. Выбор поддерживаемого S3-compatible backend фиксируется в T02 после лицензионной и security-проверки.

| Identity | Читать | Писать | Явно запрещено |
| --- | --- | --- | --- |
| ingestor | Только разрешённый источник | Quarantine | Approved, releases, signer |
| curator | Quarantine, schema, provenance | Новый approved snapshot; разделение split | Promotion модели |
| training worker | Approved train/validation, pinned deps | Только bounded output volume | Holdout labels, releases, ключи, metadata DB, production API |
| publisher/wrapper | Проверенные inputs и worker outputs | Candidates и run metadata | Holdout labels, promotion, выполнение candidate code |
| prediction worker | Один candidate и feature batches | Только typed predictions | Holdout labels, signing keys, metadata DB, promotion |
| evaluator controller/scorer | Holdout, provenance, typed predictions | Evaluation reports | Загрузка недоверенного model code, изменение train/model, promotion |
| promoter | Reports, bundle candidates, trust policy | Release envelope, GitOps proposal | Обучение и редактирование holdout |
| serving | Один approved release и актуальная trust policy | Только ограниченная telemetry | Candidate storage, training data, registry write |
| operator | Статус, разрешённые recovery interfaces | Incident actions по роли | Неаудируемый обход verification |

Ключи signer и evaluator не монтируются в workers. В production - короткоживущая workload identity и отдельный KMS; в lab - раздельные локальные ключи с явным ограничением доверия к host. Подпись job не делает job добросовестным: exporter provenance должен быть защищён от изменения самой training job.

## 3. Dataset contract и жизненный цикл данных

Планируемый manifest содержит: `schema_version`, `dataset_id`, список объектов с SHA-256 и размером, источник и разрешение, schema digest, transform commit, split manifest digest, seed, порядок строк, число строк/классов, label provenance, identity curator, timestamp, retention classification. Подпись хранится отдельно и покрывает точные manifest bytes.

```mermaid
stateDiagram-v2
    [*] --> Quarantined
    Quarantined --> Rejected: Контракт или provenance нарушены
    Quarantined --> Validated: Технические проверки пройдены
    Validated --> Approved: Data owner разрешил применение
    Approved --> Frozen: Digest и signature зафиксированы
    Frozen --> Revoked: Отзыв источника или инцидент
    Frozen --> Quarantined: Только новая версия данных
```

Одобренная версия не изменяется in-place. На чтении заново проверяются bytes, размер и разрешённый тип. Пути запрещают traversal/symlink escape; dataset архивы не распаковываются произвольным способом. Ошибка чтения, неполная версия или отсутствующий source approval дают отказ, а не скачивание `latest`.

Split выбирается по времени/группе релизов, а не случайным перемешиванием зависимых событий. Preprocessing обучается только на train. Идентификаторы одной сущности не должны пересекать train/validation/final holdout. Финальный holdout недоступен trainer; источники этого набора и разметки не контролируются тем же attacker в основном профиле.

## 4. Обучение и оценка

1. Orchestrator проверяет approved dataset, pinned code/image и разрешённые параметры.
2. Создаёт ephemeral Job с ресурсными лимитами, readonly root, seccomp, non-root и deny-by-default egress. Зависимости заранее собраны в image, online `pip install` внутри training запрещён.
3. Job обучает preprocessing + Logistic Regression, экспортирует ONNX в bounded output volume. Не может писать в registry или повысить candidate до release.
4. Доверенный wrapper фиксирует входные digest и окружение; publisher проверяет outputs и отправляет run metadata в MLflow. Произвольные HTML/модельные загрузчики не открываются автоматически в привилегированном контуре.
5. ONNX parser/prediction worker выполняет модель в отдельном ограниченном контуре; scorer вне worker измеряет clean/slice/parity/robustness по проверенным predictions и закрытым labels.
6. Report содержит все результаты, ограничения и policy digest; отсутствие теста или малый sample size дают `inconclusive`, не `pass`.

Повторный запуск с теми же inputs создаёт отдельный run, но не перезаписывает approved artifacts. Идемпотентный promotion использует `(bundle_digest, environment, policy_digest)`; повтор не меняет state и не создаёт новый неаудируемый approval.

## 5. ModelReleaseBundle: единица доверия

Это **предлагаемый проектный контракт**, не готовый industry standard. Version 1 должен связать:

| Группа | Обязательные поля |
| --- | --- |
| Идентичность | schema_version, release_id, intended_use, owner |
| Материалы | model_sha256, preprocessing_sha256, feature_contract_sha256, dataset_manifest_sha256, split_manifest_sha256 |
| Процесс | source_commit, train_image_digest, dependency_lock_sha256, parameters_sha256, seed, compute_profile, provenance_sha256 |
| Проверка | evaluation_report_sha256, evaluator_identity, evaluation_policy_sha256, model_card_sha256, ML-BOM digest |
| Эксплуатация | serving_image_digest, API contract version, compatibility_group, resource_profile, expires_at |
| Доверие | signer identity, policy version, release sequence, signature envelope |

Manifest digest вычисляется по точным сериализованным bytes с однозначным UTF-8 JSON-профилем и запретом duplicate keys, NaN, неоднозначных числовых форм. Envelope signatures и approvals **не включаются в собственный подписываемый digest**. Отдельный approval связывает bundle digest, environment, policy digest, approver и expiry. Формат и parser round-trip фиксируются до реализации; конкатенация непроверенных строк не заменяет стандартную подпись.

Preprocessing включается в ONNX-граф, где возможно. Если часть остаётся вне графа, её digest и compatibility contract обязательны. Модель и признаки не обновляются независимо.

SBOM описывает ПО, ML-BOM - модель/данные, provenance - процесс происхождения. Перечень файлов не заменяет соответствие всех actual bytes указанным digest. Связь отчёта с candidate проверяется повторно, чтобы хороший report нельзя было прикрепить к другой модели.

## 6. Promotion и загрузка

Promotion policy проверяет signature и разрешённого signer, отсутствие revocation, срок действия, policy version, все digests, независимый evaluation, обязательные gates и явный approval. Неизвестный schema version отклоняется. MLflow alias `champion` или строка в Release Ledger недостаточны.

Сначала blob хранится под content address, затем подписанный desired state указывает этот digest. Model loader скачивает в новый закрытый путь, проверяет размер/digest/envelope/approval и загружает **те же bytes**, не повторно разрешает изменяемый URL. Загрузка происходит в sandbox до готовности новой replica. Нельзя получать произвольный URL из inference-запроса: это создало бы SSRF и обход политики источников.

Serving никогда не получает signing key. На старте и периодически он проверяет актуальность release authorization. Для lab предлагается trust lease 60 s: если актуальную policy получить нельзя, после lease ML-путь прекращает обслуживать запросы. При known revocation - немедленно по получении события. Это осознанный компромисс доступности ради bounded stale trust.

Rollback допускает меньший release sequence только через **новое** rollback approval, которое указывает текущий и целевой digest, причину и действующую policy. Оно не восстанавливает доверие к отозванному signer/модели. Защита от replay не должна случайно запрещать разрешённое восстановление.

## 7. Контракт inference

Предлагается `POST /v1/predict`: именованные конечные числовые/категориальные признаки по версии схемы, до 100 строк, body до 64 KiB, без произвольных файлов и URL. Возврат: request ID, advisory score в `[0,1]`, decision=`advisory|abstain`, bundle digest, schema version, reason code. Финальный набор полей определяется T03/T15.

- Неверная схема/NaN/неизвестные обязательные категории: 422, oversized body: 413, превышение квоты: 429.
- Нет доверенной модели/истёк trust lease: 503, никакой загрузки случайного fallback.
- Данные вне заявленного диапазона: `abstain` с ограниченным reason code; это не универсальный OOD-detector.
- Время и память ограничены; timeout не должен оставлять бесконечный вычислительный процесс.
- Логи не содержат исходные features или labels; trace связывает request с digest и решением gate.

## 8. Наблюдение, восстановление и production delta

Три слоя наблюдения: инфраструктура/API, данные/качество модели, доверие/безопасность. Drift - повод проверить данные и labels; integrity failure - security incident с остановкой затронутого пути. Алерты и откат не должны зависеть от того же скомпрометированного training account.

Backup должен включать совместимые snapshots metadata и artifact references, approved datasets, bundles, policy и approvals. Private keys восстанавливаются отдельной защищённой процедурой. После restore проверяются ссылки и digest, затем пробные predictions; один успешный SQL restore не завершает ML recovery.

Production отличается от lab не именем namespace: нужны TLS, отдельный identity provider, KMS, внешняя копия, HA, capacity planning, контроль administrators, retention/удаление данных, on-call, независимый review и утверждённые бизнес-риски. Переход описан в [плане](../tasks/plan.md), процедуры - в [runbooks](runbooks.md).

## 9. Уточнение R0.2: кто исполняет модель, а кто удостоверяет результат

Этот раздел уточняет исполнение ролей из таблицы выше. `trainer` и `evaluator` - логические участники; их недоверенным worker-процессам не выдаются все полномочия orchestration identity. Основание: [ADR-003](decisions/0003-control-and-execution.md), решения D02-D04 в [карте практик](practice-adoption.md).

- **Training worker:** read-only approved train/validation mounts и отдельный output volume. Нет MLflow/storage root credentials, signing keys, service-account token, Docker socket или writable control configuration. Отдельный publisher проверяет размер/пути выходных файлов и публикует candidate; provenance о входах формирует trusted wrapper, не произвольный stdout trainer.
- **Prediction worker:** один candidate и ограниченные feature batches; нет labels, report-signing key, metadata DB access или общего artifact-store credential. Не может обращаться к controller API иначе, чем через узкий output protocol.
- **Controller/scorer:** хранит holdout labels отдельно, отправляет batches, проверяет row correspondence, type/shape/size, конечность чисел и допустимый диапазон. Метрики вычисляет сам. Report-signing permission не передаётся в контейнер, загружающий candidate.
- **Promoter:** принимает только связанное evidence, не выполняет candidate code и не использует model output как команду или authority.

Одинаковый pod с общими volumes/process namespace/credentials не считается доказанным разделением. Изоляция проверяется фактическим доступом к `/proc`, mounts, credentials, controller socket и egress. Worker неизбежно видит переданные features; ограниченные outputs не доказывают отсутствие всех covert channels. Остаточный риск и доверие к kernel/host остаются явными.

## 10. Asset graph и blast radius

Предлагаемый asset record: `asset_id`, `kind`, content digest/revision, owner, purpose, data classification, lifecycle state, dependencies, allowed environment, current policy/approval refs, expiry, retention, observed deployments. В `kind` первого профиля входят dataset, split, run, preprocessing, model, runtime image, evaluation policy/report, release, endpoint и workload identity. Prompts/agents/MCP допустимы только в отдельном будущем профиле.

Реестр хранит directed dependency graph: dataset -> run -> model -> bundle -> endpoint; runtime image и policy также связаны с bundle. Перед promotion нет dangling references, неизвестных владельцев и запрещённых cycles. Inventory reconciliation сравнивает actual running digest с approved graph, а не доверяет изменяемому alias. Публичный экспорт содержит только разрешённые поля, без приватных URLs, credentials и raw data.

При отзыве dataset строится transitive impacted set. Выпуск потомков останавливается, owner получает инцидент, действующие releases теряют доверие через механизм M11. Откат к другому потомку того же отозванного dataset запрещён. Registry corruption или устаревшая inventory snapshot не разрешают новый promotion; текущий serving соблюдает bounded trust lease.

## 11. Intake для внешних и преобразованных артефактов

MVP не требует публичных моделей, но любой появившийся импорт проходит отдельный quarantine path: source revision/license -> size/type/path limits -> format coverage -> scanner + parser policy -> isolated conversion при необходимости -> повторная проверка output -> обычная оценка и approval. У imported candidate нет исключения из общей цепочки.

Report scanner содержит version/digest/policy, все input hashes, список реально проверенных объектов, unsupported/skipped/error counts и outcome. `unsupported`, timeout, parse error, zero scanned objects или неизвестная policy дают inconclusive и запрещают promotion. «No findings» означает только отсутствие известных находок в проверенной области. Оно не разрешает unsafe format и не заменяет model quality/poisoning evaluation. Набор scanner tools выбирается после проверки ONNX coverage, не по списку каталога.

## 12. Security telemetry contract

События: `artifact.rejected`, `promotion.denied`, `trust.revoked`, `identity.denied`, `inventory.mismatch`, `worker.policy_violation`, `telemetry.gap`. Минимальные поля: schema version, event ID, producer identity, UTC event/observed time, sequence/correlation ID, asset/bundle digest, policy digest, action, outcome и ограниченный reason code. Labels/raw features, secrets и текст рассуждений модели не включаются.

Producer authentication и sequence/gap checks важнее доверия к строке `severity=critical` из worker stdout. Retry допускает повторную доставку, collector обеспечивает idempotency по event ID. Отсутствие сигналов не считается здоровьем: heartbeat и ingest lag наблюдаются отдельно. Формат можно позже переводить в Sigma/SIEM, но сначала replay должен доказать доставку и реакцию. Режим потери audit для release boundary - fail closed; уже работающий ML-path подчиняется согласованной trust policy, а не неявной логике dashboard.
