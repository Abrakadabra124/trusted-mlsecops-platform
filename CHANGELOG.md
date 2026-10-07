# История исследовательского проекта

## R1 developer preview - 2026-10-07

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
