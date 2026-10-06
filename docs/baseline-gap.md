# Исходная платформа и разрыв до MLSecOps

## Что проверено 2026-10-06

Read-only проверка локального Git, исходного кода, документации и GitHub API. Рабочее дерево baseline чистое. Проверенный HEAD: `fe73d86ef8cf4564478058e50a21ac6a1d3e2dc2`; дата commit 2026-10-04. Повторный запуск инфраструктуры, нагрузочных тестов и game day в этом исследовании не выполнялся. [S22](sources.md#s22), [S24](sources.md#s24)

## Матрица переиспользования

| Область | Подтверждённая база | Недостающее свойство | Действие |
| --- | --- | --- | --- |
| Приложение | FastAPI Release Ledger, PostgreSQL, Alembic, scoped credentials | Нет сущностей dataset/run/model/evaluation/promotion | Отдельный ML control plane, связь с ledger через digest |
| CI | Lockfile, lint, unit/integration, SAST/SCA/secret/IaC/container scans | Нет ML/данных/poisoning tests | Добавить ML-gates отдельно от source quality |
| Supply chain | SBOM, подписанные образы, deploy по digest | Нет dataset/model provenance | Подписывать связанный ModelReleaseBundle |
| Kubernetes | kind, Cilium, Kyverno, ограниченные workloads | Нет training/evaluation namespaces и ролей | Проверяемое разделение identities и хранилищ |
| Delivery | Flux, подписанный OCI desired state, SOPS/age | Нет model approval/revocation | Promotion policy до GitOps и повторная проверка serving |
| Эксплуатация | Prometheus/Grafana, game-day проверки | Нет метрик feature/prediction/label quality | ML-панели, delayed-label evaluation, маршруты реакции |
| Recovery | Проверка PostgreSQL restore и rollback приложения | Нет восстановления ML-артефактов и trust policy | Согласованный backup данных, моделей, metadata и approvals |
| Изоляция клиентов | Team-фильтрация приложения | Не защита от компрометации приложения через RLS | Не заявлять сильную multi-tenancy; раздельные credentials/storage |

## Исторические доказательства, не новый замер

В приёмке 2026-10-04 записаны 92 unit/regression и 11 integration tests; combined app line/branch coverage 98.97435897435898%. Нагрузочный профиль: 13 798 запросов, 60 секунд, 10 клиентов после 10 секунд прогрева, 0 ошибок, p95 96.638815 ms. Восстановление pod 6.453 s, reconciliation drift 25.546 s, rollback 15.765 s, независимый DB restore 2.625 s. Это измерения Release Ledger, **не ML inference**. [S23](sources.md#s23)

Full-acceptance source fingerprint: `sha256:47fedbdc0bdc03239a3d1f0be180946373b35ca747ca6a2696b9e609b5d46eb8`. Он не подменяется позднейшим commit с документацией. Публичный CI для указанного HEAD завершён success, но hosted runner не исполняет локальные Kubernetes game days.

## P0-долги до нового runtime

1. **Registry:** документация фиксирует локальный runtime 3.0.0 и отдельный свежий bootstrap 3.1.2. Установка новой версии не доказывает обновление уже работающего сервиса. Сначала проверить состояние, разрешённый путь обслуживания, backup и совместимость; затем отдельная миграция и повторная приёмка. Блокировки инструментов не обходить.
2. **Доверие и сеть:** локальный HTTP registry, локальные ключи и machine credentials не являются production TLS/OIDC/KMS. Развести лабораторный и production-профили, не выставлять сервисы наружу.
3. **Scope:** системные controllers не полностью входят в прежние scan/admission gates. Новый контур должен включить MLflow, storage и training/evaluation images в инвентаризацию.
4. **Надёжность:** три kind-node на одном host не дают независимую отказоустойчивость. Мониторинг и резервные копии требуют постоянного хранения и отдельного failure domain для production.
5. **Release Ledger:** схема хранит `image`, `source_revision`, `sbom_digest` и автора записи. Это учёт утверждений, не верификатор подписей моделей. Нельзя выдавать наличие строки в БД за approval.

## Стратегия миграции

Не переписывать существующий репозиторий и не копировать весь его runtime в исследовательский. На первой неделе будущей реализации зафиксировать разрешённую версию foundation, описать адаптер и отдельный namespace/prefix ресурсов. Изменения foundation вести отдельно, маленькими PR, с сохранением его тестов и rollback. Данные production не переносить в Git.

Вначале новый путь работает как лабораторный shadow-контур без влияния на текущую доставку. Переключение на advisory API допускается только после приёмки. Отказ ML-сервиса не должен менять результат детерминированных DevSecOps security gates.
