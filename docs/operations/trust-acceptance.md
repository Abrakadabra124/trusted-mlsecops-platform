# M11: сквозная проверка trust lifecycle

Статус: runner реализован, общий native запуск ещё не принят. Исторические [root](../evidence/candidate-root-rotation-2026-11-06.md) и [signer](../evidence/release-signer-live-2026-11-06.md) проверки подтверждают компоненты; они не объединяются автоматически в новый M11 report.

## Назначение и границы

[Runner](../../mlsecops/trust_acceptance.py) выполняет свежую кампанию на одном source/image, готовит actual candidate proposal до проверок и фиксирует hashes методов, конфигурации и первичных отчётов. [Reconciler](../../mlsecops/trust_gate.py) проверяет candidate/model/subject bindings, полноту сценариев, типы результатов и сохранение независимых authority states. [Trace validator](../../mlsecops/trust_trace.py) пересчитывает ограничения времени по HTTP observations, а не доверяет заявленному `pass`.

Qualification permit разрешает только изолированную проверку настоящего candidate. Подписанные approval/rollback/signer positive controls используют отдельные явно обозначенные fixture releases. Они проверяют механизм и не подменяют независимые ML reports. Общий M18 по-прежнему требует M01-M17/M19-M23 для одного candidate, включая независимый M22; `release_ready` этого runner всегда false.

## Запуск только в disposable hosted CI

Prerequisites: разрешённый GitHub-hosted Linux runner, чистый checkout, pinned tools/image, собственный cluster и source SQL, подготовленный synthetic candidate. Текущие локальные Docker/WSL/Kubernetes/SQL запускать для этой процедуры запрещено. Использовать [существующий workflow](../../.github/workflows/kubernetes-serving.yml), который проверяет код, готовит стенд и всегда выполняет scoped cleanup.

```bash
uv run --locked python -m mlsecops.acceptance --gate M11 --state .runtime --output .runtime/evidence/M11.json
```

Последовательность: fresh prepare -> controlled contract inventory без skipped/expected-failure -> ordinary CLI expiry/replay/rollback -> actual candidate clock/cache/outage/blackhole/policy/root/model/key -> signed SQL rotation history -> live смена publisher/assessor/approver -> сверка source и первичных traces -> report. Полный backup/restore затем остаётся отдельным workflow step.

Обязательные наблюдения:

- Actual production promotion отказан без assurance; candidate/model/subject остаются привязаны к одной подготовленной proposal.
- При outage/blackhole нет ML responses после 60 s, trace продолжается за границу 60 s. Для всех trust faults требуются минимум два 503 и отсутствие последующего 200.
- При signed approval expiry были успешные ответы до срока, первый отказ в пределах двух секунд до expiry, отказ сохраняется после expiry. Просроченный promotion retry не пишет журнал.
- Действующий старый sequence отвергается именно как sequence conflict. Старый signed trust document ещё valid, но отвергается как version replay.
- Negative clock/cache injection даёт ожидаемые причины, очищает cache/Reader и блокирует прежний экземпляр. Это dependency injection, не изменение OS clocks.
- Отдельные model/key authorities сохраняют независимые CA/storage/history; отзыв одной не меняет другую. Cold Readers возвращают точные причины отзыва до worker startup.
- Разрешённый whole-bundle rollback сохраняет subject/proposal целевого комплекта, не смешивает модели. Неверные history links и revoked target отклоняются.
- После смены release signer старый экземпляр остаётся fenced; новый release без M22 не записывается; новый worker активируется явно.

## Диагностика и восстановление

| Симптом | Проверка и действие |
| --- | --- |
| Exit 2 / inconclusive | Проверить prerequisites и тип runner. Не переносить запуск на запрещённый локальный runtime |
| `M11_contracts_failed` / incomplete | Проверить inventory, import errors, skips и expected failures. Отсутствующий test module не считается выполненным |
| `M11_native_binding` | Сверить source/image/candidate/model/subject и последний stage. Не заменять mismatch редактированием готового report |
| `M11_trace_invalid` | Проверить timestamps/statuses, late 200, повторную activation, границу lease и полноту trace. Не увеличивать grace period ради pass |
| `M11_descriptor_or_time_order` | Proposal должна предшествовать checks, timestamps должны иметь timezone и правильный порядок. Новый proposal требует новой кампании |
| `M11_inputs_changed` | Source или метод изменился во время проверки. Завершить cleanup и запустить новую кампанию из чистого checkout |
| Native runtime failure | Сохранить private evidence, определить failed stage, исправить причину и повторить. Historical green не закрывает текущий отказ |
| Cleanup failure | Сверить ownership и конкретные IDs. Не выполнять global prune; без подтверждённой очистки campaign не принимается |

До запуска reporter заменяет прежний итог на `inconclusive`. Ошибка не оставляет прежний success текущим результатом. Raw logs, keys и credentials остаются в private state. После failure сохранять первичные материалы и проверять остановку source SQL, удаление собственного cluster и созданных signer targets/workers. При неизвестной причине, чужом ownership или нехватке независимого approval остановить activation и передать диагностику владельцу.

Критерий принятия: terminal success job, M11 `pass`, совпадающие hashes/current source, пройденные negative cases и подтверждённая очистка. Это проверка M11 механизма; готовность R1 требует оставшейся общей приёмки.
