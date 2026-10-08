# История исследовательского проекта

## R1 prediction protocol v2 - 2026-10-08

Исправлен приём неизвестной schema version и произвольного scan report. Добавлены одноразовый pending batch, точные row IDs/order, request/model binding и ограничения response до signer/SQL publication. Старый prediction v1 больше не исполняется, исторические signed evaluations не переписываются. Все callers, включая golden recovery/migration, используют общий helper. Локально прошли 164 protocol и 136 controller checks; [runbook и границы](docs/prediction-protocol.md). Полные M20/M21/M18 не объявляются закрытыми.

## R1 scoped controllers - 2026-10-08

Publisher/scorer теперь выполняются в отдельных Kubernetes Jobs без host kubeconfig или Docker socket. Добавлены bounded HTTPS client, собственные Role/RoleBinding, fail-closed native admission, отдельный evaluator Secret и image-bound provenance. Настоящее обучение и оценка записывают новую историю в private SQL; исходная host БД не меняется этим demo. Локально прошли 133 checks, включая 60 API/admission/RBAC проверок. [Инструкции и ограничения](docs/scoped-controllers.md). Это проверенный компонент, не полный M04/M20 или trusted release.

## R1 signed cluster migration - 2026-10-08

Добавлен opt-in перенос проверенного SQL snapshot в private Kubernetes storage: external trust roots, target identity binding, native advisory lock, maintenance, atomic import и signed receipt. Resume после сбоя не копирует committed данные повторно; source и последующие target rows не перезаписываются. Publisher/scorer Pods проверяют реальные migrated artifacts, отдельный offline worker выполняет 1 000 golden predictions. Локально 497 checks прошли, max error 0.0. [Runbook](docs/cluster-storage-migration.md); полные M04/M17/M20 и R1 остаются открытыми.

## R1 private storage increment - 2026-10-08

Добавлен opt-in Kubernetes PostgreSQL profile: отдельные role identities, DNS-bound mTLS, default-deny network, retained PVC и проверяемый по UID bootstrap. 436 локальных checks включают SQL/TLS/API/network denials и persistence при замене Pod. Host storage не переключён и не удалён. Исправлен Linux libpq password-file warning без ослабления TLS или JSON protocol. [Runbook](docs/private-cluster-storage.md); full M04/M20 и R1 остаются открытыми.

## R1 developer preview - 2026-10-07

Реализован подписанный native PostgreSQL backup с общим snapshot для dump/ledger и restore только в новый owned workspace. Локально прошли 430 recovery component checks, 1 000 golden predictions совпали, источник не перезаписан. Full M17 и R1 остаются открытыми. [Воспроизведение и ограничения](docs/storage-recovery.md).

Добавлен executable M03: Linux tamper/symlink/signature fixtures, реальные storage/pipeline checks и hashes SQL-dataset до/после отказов. Локально прошёл 431 case; T04 закрыта в synthetic-only профиле. Windows symlink privilege не включается, fixtures выполняются в offline Linux container. Full R1 и M04/M20 остаются открытыми. [Runbook и точное покрытие](docs/integrity-gate.md).

Третий increment добавляет source lock, signed snapshot authorization, bounded quarantine, explicit curator approval, signed data lineage и M02 acceptance с 44 проверками. После security spike DVC исключён из active dependency set, вместо CVE waiver принят ADR 0005. 74 developer и 52 Kubernetes checks на предыдущем transport increment прошли в GitHub CI. Полный R1 не принят.

Второй increment добавляет isolated Kubernetes backend, pinned Cilium/Helm/kind, native admission и quotas, actual role/network/resource qualification и отдельный clean-checkout CI workflow. Локально прошли 52 Kubernetes component checks. ONNX telemetry выключена до запуска runtime. Подробнее: [Kubernetes lab](docs/kubernetes-lab.md).

Начата реализация по запросу владельца. Добавлены frozen policy, pinned environment/image, bootstrap, DSSE signing, synthetic datasets, изолированные Docker workers, Logistic Regression -> ONNX, независимый scorer и исполняемая developer qualification. Детали и ограничения: [STATUS](STATUS.md), [журнал](docs/implementation.md). Полный R1 не принят, trusted promotion не разрешён.

## R0.2 - 2026-10-06

- Проверены новый пользовательский текст, CyberOrda и дополнительные первоисточники; реестр вырос с 24 до 44 записей. Добавлены датированный международный обзор, критический разбор и восемь traceable design decisions.
- Архитектура расширена inventory graph, worker/controller boundary и отдельным ADR, fail-closed artifact intake, absolute-budget challenges и security event contracts.
- Приёмка расширена с 18 до 23 gates, угрозы с 14 до 19, backlog с 24 до 29 задач. Старые ID сохранены; M18 остаётся финальным агрегатором.
- План пересчитан на 14-16 недель активной работы плюс 25% календарного резерва. Установка LLM/GPU/облачных платформ не добавлена.
- Документационный validator проверяет source-to-decision JSON и его связи. Это не evidence выполнения ML-контролей.

Статус всех ML implementation tasks остаётся PLANNED. Нет обучения моделей, ML runtime, новых production credentials или изменений DevSecOps foundation. R0.2 обозначает редакцию документов, не выпущенный runtime или Git tag.

## R0.1 - 2026-10-06

Первоначальный research/design snapshot: [commit 6b5e981](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/6b5e981cfa599de1530de0a0cfe9727748dcdbd2). Содержит разбор исходных PDF/схемы/PT, read-only baseline audit, архитектуру CPU reference, threat model, приёмку и первый roadmap. Обучение и эксплуатация ML не выполнялись.
