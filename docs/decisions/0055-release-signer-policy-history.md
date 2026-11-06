# ADR 0055: ротация release signer с историей политик

Дата: 2026-11-06. Статус: [native SQL/history/restore проверены](../evidence/release-signer-history-2026-11-06.md); live release-signer serving и полный M11 остаются открытыми.

## Требование

T14/M11 требует смены и отзыва ключей без разрешения неподтверждённого выпуска. Policy root делегирует отдельные роли publisher, assessor и approver. Смена online trust root из ADR 0053/0054 не меняет эти делегированные ключи.

Простое обновление policy pin несовместимо с прежним recovery verifier: он сравнивал каждую историческую selection с текущей политикой. История корректных выпусков после ротации выглядела бы повреждённой. Удалять старые события или ослаблять проверку policy binding нельзя.

## Решение

1. Владелец policy root подписывает DSSE-документ `release-key-rotation`. Он связывает environment, роль, SHA-256 предыдущей и следующей политик, текущие sequence/request и окно не более 600 секунд. Обе политики также проверяются по внешнему root pin.
2. Следующая политика увеличивает версию ровно на один и меняет ровно один public key. Issuer, остальные роли и полный набор M-gates сохраняются; ключи остаются различными. Временные границы согласованы с обеими политиками.
3. Перед записью нужна свежая online lease: текущая policy уже новая, старый signer отозван, policy root и все новые роли не отозваны. Онлайн-изменение и SQL commit не являются распределённой атомарной транзакцией. Промежуточное состояние сохраняет отказ.
4. Под блокировкой head, затем authority оператор повторно проверяет текущий выбор, policy pin и срок. В одной SQL-транзакции добавляет immutable receipt и меняет pin. Head/events не изменяются. После commit обязательны readback и действующая lease. Точный повтор не добавляет запись и не активирует выпуск.
5. Явная additive migration 2 создаёт `policy_rotations`; migration 1 остаётся побайтно прежней. Обычные application roles не получают права изменения истории. Установка старой схемы не выполняет upgrade автоматически.
6. Backup включает receipt bytes, связи и границу sequence каждого перехода. Старые events проверяются относительно политики, действовавшей при их записи; новые относительно последнего предшествующего перехода. Проверяются цепочка версий/pins, boundary/request, package hash и текущий authority pin. Подписанный manifest по-прежнему требует внешний backup-id pin.
7. Restore в новый target устанавливает нужную схему до data-only import и сверяет весь журнал. История не выдаёт ready и не отменяет проверку текущего trust/revocation при activation.

## Границы

Ротация не переподписывает прошлые approvals и не выдаёт новые. Чтобы возобновить ML serving, требуется новый полностью проверенный release с новым policy binding, актуальными reports и независимым approval; старый signer не возвращается в trust. Существующий bundle нельзя автоматически считать разрешённым rollback target после отзыва его ключа.

Подпись старого signer не требуется: право сменить делегированный ключ принадлежит policy root, в том числе если старый ключ уже недоступен или отозван. Новым ключом потребуется подписать следующий проверяемый материал. Смена самого policy root не реализуется этим протоколом.

Плановый переход требует действующих старой и новой политик. Emergency recovery после expiry прежней policy или компрометации policy root не реализован этой операцией. Поле `reused` отражает наличие exact receipt при начальном чтении: конкурентные одинаковые callers могут оба увидеть `false`, хотя запись в БД будет одна; поле не является счётчиком записей конкретного caller.

SQL history verifier проверяет структурную связность и bytes, а не заменяет криптографическую проверку operator authorization. Подмена администратором самого verifier или policy root остаётся за trust boundary. Online service, storage и операторские pins должны управляться независимо в production-профиле.

## Проверка

Real-signature и mocked-transport тесты: [protocol](../../scripts/release_key_rotation_qualification.py), [store](../../scripts/release_key_store_qualification.py), [history/recovery](../../scripts/promotion_policy_history_qualification.py). [Native scenario](../../scripts/release_key_native.py) проверил три роли, конкуренцию, SQL отказы, права и повреждённую историю в disposable PostgreSQL; следующий CI step выполнил полный backup/restore с golden predictions. [42194888914 success](../evidence/release-signer-history-2026-11-06.md): 37 rotation + 36 recovery cases, 1 000 golden rows/error 0.0, cleanup verified. Эти component checks не закрывают M11/M17/M18/R1.

Эксплуатационный порядок: [runbook](../operations/release-signer-rotation.md).
