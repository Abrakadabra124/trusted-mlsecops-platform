# ADR-0021: Bounded dependency graph без полномочий promotion

Дата: 2026-10-11. Статус: **Accepted для компонента T25**, не для полной M19.

## Контекст

Существующий `mlsecops.inventory` описывает tools/source/runtime, но не связь datasets, runs, models и deployments. M19 требует точного transitive impact, отказа при неизвестном owner, cycle, dangling reference и actual digest mismatch. Без этого откат может вернуть другую модель, обученную на том же отозванном dataset.

Исследование проверено 2026-10-11: [SLSA provenance](https://slsa.dev/spec/v1.2/provenance) связывает происхождение артефактов с процессом их получения. [OpenLineage object model](https://openlineage.io/docs/spec/object-model/) различает metadata/design lineage и наблюдения выполненных jobs. Поэтому нарисованный граф или полученный от клиента snapshot нельзя считать независимым доказательством реально работающей модели. Наш формат не заявляет совместимость с этими спецификациями или уровень SLSA.

## Решение

Ввести небольшую чистую функцию `mlsecops.asset_graph.assess`: строгий schema v1, digest-bound edges, отдельный allowlist owners, bounded directed acyclic graph (DAG), проверка полноты deployment observations и transitive impact. DAG - ориентированный граф без циклов, где потомок зависит от предка.

Первый профиль поддерживает dataset, runtime, policy, run, model, release, deployment. Run зависит от одного или нескольких datasets и ровно одного runtime/policy; model - от одного run; release - от model и тех же runtime/policy; deployment - от release. Это консервативный single-runtime профиль, не общий формат для произвольных ML pipelines. Отдельные serving/training images, preprocessing, split/evaluation/approval/identity nodes потребуют явного расширения контракта и интеграции, не молчаливого игнорирования fields.

Входные owners не берутся из asset document. Каждая ссылка содержит ID и SHA-256. Revocation имеет такую же связку. При обходе отзыва одинаковое содержимое того же kind под другим ID также затрагивается: переименование не должно обходить запрет. В обратную сторону к ancestors отзыв не распространяется.

Результат всегда содержит `release_ready=false` и `full_M19=inconclusive`. `component_status=pass` означает только согласованность представленного графа и snapshot, а не разрешение использовать незатронутые assets. Корректный snapshot с блокировками - нормальный диагностический результат, не ошибка вычисления.

## Альтернативы

- Список registry aliases не связывает bytes, runtime и ancestors и недостаточен для отзыва.
- Graph database или отдельный lineage service пока не нужны: до 1 000 nodes и 32 edges/node укладываются в bounded in-memory traversal. Новых зависимостей и сервисов нет.
- Подключение этого компонента как полного M19 было бы ложным pass: нет authenticated runtime collector, persistent revocation authority, freshness/lease и подписанной цепочки release.

## Последствия и пересмотр

Runtime source fingerprint меняется при добавлении модуля, поэтому worker images пересобираются, а существующие CI проходят повторно. Проверяются не только positive graph, но и missing edge, unknown fields, duplicate IDs/references, cycles, cross-environment inputs, partial observations, digest swaps и content aliases.

Следующий интеграционный этап должен строить graph из уже проверенных signed materials, проверять доверенный snapshot collector и текущую revocation revision, хранить monotonic state, связывать полный bundle и сверять actual serving. SHA-256 и owner allowlist сами по себе не обеспечивают authentication, completeness происхождения, replay protection или независимость от host administrator.

Контракт и команды: [asset graph](../asset-graph.md). Эксплуатация: [PB-09/RB-19](../operations/asset-graph-troubleshooting.md).
