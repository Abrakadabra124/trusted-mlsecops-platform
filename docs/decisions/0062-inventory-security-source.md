# ADR 0062: типизированные события расхождений inventory

Статус: реализация T29, не приёмка полного M19/M23/R1.

Существующие asset_graph и candidate_lineage уже отказывают при несовпадении
связей, digest, владельцев или наблюдений. Причину события задаёт само место
проверки через подкласс Rejected с конечной категорией. Текст исключения
сохраняется для совместимости, но не используется как классификатор инцидента.
Обычные parser/SQL/I/O ошибки не становятся вымышленным inventory mismatch.

Операторский observer использует существующий durable producer, отдельные
права controller/promoter/serving и signed registry. При распознанном mismatch
сначала сохраняет событие и пытается доставить его, затем сохраняет исходный
отказ. Потеря audit даёт отдельный постоянный отказ без raw exception.
Event содержит category и subject SHA, не граф, credentials или model bytes.
Для candidate subject равен candidate reference, для graph - SHA всего pinned
request, включая snapshot, trusted owners и graph. Исходный private request
оператор сохраняет для расследования; по одному event нельзя восстановить payload.
Новая попытка проверки имеет новый correlation; retry прежней очереди сохраняет
original envelope. Это разные операции, как в существующем intake observer.

Режим candidate читает настоящие signed metadata и bounded model bytes для
проверки digest из SQL под прежними scoped ролями, без final-holdout labels,
и сверяет operator expected build. Режим graph проверяет закреплённый
input document/snapshot; сам не перечисляет Kubernetes deployments и не
доказывает достоверность внешнего observation. Operator config содержит request
SHA pin и paths; request не может выбрать producer credentials. CLI выдаёт только
конечный summary, полные projections не печатает. Никаких новых SQL прав.

Проверки: typed negatives четырёх категорий; valid input без события; invalid
input/SQL outage без ложного инцидента; wrong role/pin до source I/O; сохранение
отказа при audit outage; реальный collector/restart/receipt в hosted CI; чтение
настоящего candidate отдельно от controlled graph fixtures. Полный M19 с двумя
datasets, тремя моделями и четырьмя реальными deployments остаётся обязательным.

[План реализации](../../tasks/inventory-events-plan.md).
