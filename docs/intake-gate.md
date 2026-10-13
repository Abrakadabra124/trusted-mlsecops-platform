# M21: сверка evidence при приёме модели

Реализован executable runner `mlsecops.intake_gate`, вызываемый общей CLI acceptance. Это следующий шаг T27, **не завершённая M21-приёмка**: отсутствует отдельная scoped-controller native negative intake matrix. Пока она не выполнена и не сверена, итог `inconclusive`, exit 2 и `release_ready=false`, даже если весь Docker/SQL component прошёл. Исходный scope [M21](acceptance.md) не сокращён. Наличие отдельного workflow не означает разрешение выпуска.

## Что выполняется заново

1. Проверка owned workspace, Linux host и exact current-source Docker image. Linux нужен для настоящего symlink contract; Windows без этой возможности не получает skip-as-pass.
2. 54 controlled methods: format/graph profile, пути и mutation после conversion boundary, request/response nonce и hashes, zero/partial coverage, signed denials и persistence failures. Исполняется отдельный Python-процесс; список test IDs сверяется с актуальной suite, пропуски и expected failures не принимаются.
3. Новая owned PostgreSQL/TLS campaign на loopback port 15453. Создаются отдельные synthetic data, keys и ledger; рабочая БД не подключается и её budget не сбрасывается. Training -> intake -> prediction -> signed evaluation выполняются настоящими Docker workers.
4. Native scanner заново проверяет **те же model bytes**, которые записаны у SQL candidate. Пять cases: clean, benign renamed pickle rejection, реальный deadline replacement process, crash replacement process, clean-after-faults. Проверяются cleanup собственных fault containers и отдельные inspection IDs.
5. [PB-15](operations/intake-denial-troubleshooting.md): 25 native SQL checks, три signed denials, permissions, idempotency и fresh-process readback. Здесь malformed response введён после настоящего scanner, а timeout является transport exception fixture, не дополнительным native process timeout.
6. Reconciliation заново читает SQL candidate, signed evaluation, denials и reservations штатными readers. Проверяются actual model bytes, dataset, source revision/fingerprint, image, policy/trust hashes, signed payload equality, разные slots и временное окно текущей campaign. Старый зелёный файл, duplicate ID или изменённый summary не заменяет эти операции.

Hashes test scripts и runtime фиксируются до запуска и проверяются после него. Смена code/policy/data lock/image во время campaign блокирует результат. При завершении runner проверяет container identity и останавливает только свою временную SQL-БД; volumes/evidence остаются, глобальной очистки нет. Ошибка cleanup не разрешает pass. До начала записывается inconclusive marker, чтобы прежний pass не пережил незавершённый новый запуск.

## Карта покрытия

| Требование | Evidence | Ограничение |
| --- | --- | --- |
| Tool/policy, все входные hashes, exact counts и approved outputs | Protocol contracts + receipt validation по actual SQL model | Узкий `linear-onnx-v2`, не универсальный malware detector |
| Empty scan, unsupported/no-findings, stale/foreign report | Controlled negatives, real parser и isolated unsafe model | Не неизвестный parser exploit |
| Deadline/crash и cleanup | Native Docker replacement processes, readback cleanup | Scoped Kubernetes negative matrix ещё не выполнена |
| Traversal/symlink/modified conversion output | Настоящие Linux path fixtures | Converter service отсутствует; unsafe conversion не разрешена |
| Clean ONNX до оценки | Fresh SQL training/evaluation, independent inspect и signed reader | Synthetic model; quality gate M07 остаётся отдельным |
| Сохранение отказов | Три DSSE denial documents + SQL access tests | Не recovery после DB crash; preflight не получает такой документ |
| Полный M21 | 85 completed component cases плюс обязательный незавершённый case | Итог 86 cases, последний inconclusive; нет approval |

M20 regression доказывает свой worker/controller boundary scope, но не используется вместо отсутствующего M21-specific native replay. Future release/serving integration тоже не объявляется реализованной. Evidence current-state и CI links: [STATUS](../STATUS.md). Диагностика и воспроизведение: [PB-16/RB-34](operations/intake-gate-troubleshooting.md).
