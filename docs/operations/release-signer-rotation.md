# Release signer rotation: диагностика и восстановление

Статус 2026-11-06: код и локальные contract checks реализованы, native проверка готовится. Процедура не разрешена для текущих локальных Docker/WSL/Kubernetes/SQL. Исполняемый стенд ограничен disposable hosted CI; это ещё не production runbook с подтверждённым end-to-end результатом.

## Назначение и ответственность

Владелец policy root разрешает смену одной роли: publisher подписывает release package, assessor подписывает assurance, approver разрешает конкретный выбор. Online trust operator отзывает прежний ключ и меняет текущую policy. Storage operator выполняет явную миграцию и commit. Эти обязанности не следует объединять с trainer в production.

DSSE (Dead Simple Signing Envelope) связывает тип документа, канонический payload и подпись Ed25519. SHA-256 фиксирует содержимое; сам по себе hash не доказывает авторство. Lease - ограниченное по времени разрешение на основе подписанного актуального online trust, с проверкой срока, версии и отзывов.

## Диагностика до изменений

1. Подтвердить ownership окружения, исходный commit, external policy root, environment и текущий policy pin. Не выбирать pin из поступившего package автоматически.
2. Прочитать `promotion_recovery.read(name)` и `promotion_state.state(serving_client, environment)` через проверенный transport. Не редактировать sequence, head или прежние events вручную.
3. Сохранить подписанный полный backup, проверить его manifest и внешний backup-id. Backup с migration 2 обязан содержать `policy_rotations`; исходные authorities/events/heads также обязательны.
4. Проверить срок обеих политик, отдельные role identities, часы SQL и lease. Часы не корректируются этим плейбуком. Просроченная подпись требует нового разрешения владельца.

## Исполняемый порядок

API реализован в [release_key_store.py](../../mlsecops/release_key_store.py), schema и authorization в [release_key_rotation.py](../../mlsecops/release_key_rotation.py). Это операторский Python API; endpoint для trainer или serving не добавлен.

1. `release_key_store.migrate(state, backend=...)` явно добавляет schema 2 в уже установленный promotion ledger. Backend должен проверять ownership; для Kubernetes предусмотрен существующий `kube_storage.binding`. Повтор сверяет обе migration checksums. Migration 1 не переписывается.
2. Подготовить successor policy и package с полями `schema_version`, `authorization`, `previous_policy`, `next_policy`. Authorization содержит текущие sequence/request, оба policy hashes, одну роль и окно до 600 s. Подписать owner key вне worker. Сохранять package в private evidence до публикации очищенного результата; private key в package не входит.
3. Online trust operator публикует следующую policy и отзыв прежнего signer через существующий `trust_authority.update`. Прежние revocations сохраняются. Начинается окно отказа старого serving; операция не выполняет auto-reactivation.
4. `release_key_store.rotate(state, package, trusted_root=operator_root, expected_policy=previous_pin, environment=env, lease=fresh_lease, backend=...)` проверяет подписи, head, политику и online trust; атомарно записывает receipt и новый pin. Успешный ответ содержит `rotation_sha256`, новый `policy_sha256`, прежний head, trust receipt и `release_ready=false`.
5. Сверить readback и полный ledger. Для активации отдельно собрать новый release с актуальной assurance и approval, записать следующий sequence, проверить serving. Этот шаг остаётся обязательным и не подменяется controlled fixture в native script.

## Отказы и восстановление

| Симптом | Причина / проверка | Действие |
| --- | --- | --- |
| `promotion_configuration_conflict` | Обычная configure запрещает замену существующей политики | Использовать signed rotation; не удалять authority/head |
| `release_rotation_old_key_not_revoked` | Online trust не содержит обязательного отзыва | Проверить нужный authority/environment и завершить согласованный online update |
| `trust_policy_changed` | Online pin и successor policy расходятся | Сверить оба pins и authority version; не отключать lease |
| `release_rotation_head_changed` | Пока готовился переход, записана другая selection | Прочитать head и получить новое bound authorization |
| `release_rotation_expired` | Окно истекло, в том числе при ожидании row lock | Получить новое разрешение; не увеличивать срок в подписанном payload |
| `release_rotation_policy_conflict` | Другой переход уже применён либо повтор относится к другой истории | Сравнить exact package digest, head и текущую policy; не делать UPDATE вручную |
| Ошибка transport после commit | Commit мог завершиться, ответ потерян | Прочитать state/history; точный актуальный повтор идемпотентен. Не откатывать online отзыв |
| `release_rotation_commit_readback` | Readback не подтверждает ожидаемый итог | Сохранить отказ, сверить реальную историю и параллельные действия оператора |
| `promotion_backup_migration_changed` | Schema изменилась между чтением версии и snapshot | Получить новый согласованный backup после окончания миграции |
| `backup_ledger_content_invalid` после ротации | Нарушены history links, boundary или policy binding | Сохранить диагностику; не стирать старые события ради успешного backup |

Если online update выполнен, а storage commit нет, остаётся fail-closed состояние. Исправить причину и продолжить тот же разрешённый переход в пределах срока либо получить новое разрешение на текущий head. Если storage commit подтверждён, но serving ещё старый, завершить новый полный release path. Возврат к отозванному ключу запрещён. Откат кода, который не понимает schema 2, требует отдельного плана; удаление migration/history не является rollback.

При недоступности authority, непонятной истории, отсутствии owner key или независимого approval остановить activation и эскалировать владельцам. Private diagnostics и backups сохранять в `.runtime`, не публиковать credentials/raw logs. До успешной проверки конечного состояния incident не закрывается.

## Воспроизводимая hosted-проверка

[Workflow](../../.github/workflows/kubernetes-serving.yml) закрепляет инструменты/образ и сначала проверяет код. После existing serving regression запускает:

```bash
uv run --locked python -m scripts.release_key_native --state .runtime --confirm-disposable
uv run --locked python -m scripts.promotion_recovery_native --state .runtime --confirm-disposable
```

Первый сценарий использует настоящие signatures и SQL, но online lease берёт signed in-process fixture, а selections являются controlled материалами без ML approval. Второй делает backup всего ledger, восстанавливает отдельный target при выключенном source и проверяет golden predictions существующего candidate. Требуются terminal success обоих шагов, точные source/report hashes и подтверждённая очистка. Ни один шаг сам по себе не закрывает общий M11/M17/R1.
