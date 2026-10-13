# M21: сверка evidence при приёме модели

Executable runner `mlsecops.intake_gate` вызывается общей CLI acceptance. Добавлена scoped-controller negative intake matrix: M21 может стать pass только после её свежего выполнения и независимого promoter readback, вместе с Docker/SQL campaign. Без backend итог остаётся inconclusive, exit 2; release_ready всегда false. Исходный scope [M21](acceptance.md) не сокращён. Фактически проверенные commits/CI перечислены в STATUS, наличие нового кода не считается native evidence.

## Что выполняется заново

1. Проверка owned workspace, Linux host и exact current-source Docker image. Linux нужен для настоящего symlink contract; Windows без этой возможности не получает skip-as-pass.
2. 66 controlled methods: format/graph profile, пути и mutation после conversion boundary, request/response nonce и hashes, zero/partial coverage, signed denials, persistence failures и scoped intake contracts. Исполняется отдельный Python-процесс; список test IDs сверяется с актуальной suite, пропуски и expected failures не принимаются.
3. Новая owned PostgreSQL/TLS campaign на loopback port 15453. Создаются отдельные synthetic data, keys и ledger; рабочая БД не подключается и её budget не сбрасывается. Training -> intake -> prediction -> signed evaluation выполняются настоящими Docker workers.
4. Native scanner заново проверяет **те же model bytes**, которые записаны у SQL candidate. Пять cases: clean, benign renamed pickle rejection, реальный deadline replacement process, crash replacement process, clean-after-faults. Проверяются cleanup собственных fault containers и отдельные inspection IDs.
5. [PB-15](operations/intake-denial-troubleshooting.md): 25 native SQL checks, три signed denials, permissions, idempotency и fresh-process readback. Здесь malformed response введён после настоящего scanner, а timeout является transport exception fixture, не дополнительным native process timeout.
6. Reconciliation заново читает SQL candidate, signed evaluation, denials и reservations штатными readers. Проверяются actual model bytes, dataset, source revision/fingerprint, image, policy/trust hashes, signed payload equality, разные slots и временное окно текущей campaign. Старый зелёный файл, duplicate ID или изменённый summary не заменяет эти операции.
7. При наличии current owned controller profile запускается qualification scorer: 12 native cases, свежая clean evaluation и два durable denial. Scanner-only matrix не расходует holdout, evaluation/denials тратят три новых slots в cluster ledger. Promoter в отдельном Pod без API token/signing key читает signed objects заново. Проверяется отсутствие model parser в scorer, отдельные Pod UIDs, cleanup, неизменность protected storage/profile. Всего 24 scoped checks.

Kubernetes и новая Docker campaign имеют разные candidate/storage identities. Связываются exact model bytes, split materials, source/image/policy, а не объявляется один общий CAS record в двух БД. Полная M18 one-release приёмка остаётся отдельной работой. В Kubernetes deadline создаётся собственным Job с заведомо несовпадающим node selector, а crash - некорректным request digest у штатного процесса. Это actual scheduling deadline и process rejection, не parser exploit и не CPU-hang тест. Receive-boundary mutations вводятся после настоящего scanner; согласованная ложь полностью скомпрометированного scanner не объявляется обнаруживаемой этим тестом.

Hashes test scripts и runtime фиксируются до запуска и проверяются после него. Смена code/policy/data lock/image во время campaign блокирует результат. При завершении runner проверяет container identity и останавливает только свою временную SQL-БД; volumes/evidence остаются, глобальной очистки нет. Ошибка cleanup не разрешает pass. До начала записывается inconclusive marker, чтобы прежний pass не пережил незавершённый новый запуск.

## Карта покрытия

| Требование | Evidence | Ограничение |
| --- | --- | --- |
| Tool/policy, все входные hashes, exact counts и approved outputs | Protocol contracts + receipt validation по actual SQL model | Узкий `linear-onnx-v2`, не универсальный malware detector |
| Empty scan, unsupported/no-findings, stale/foreign report | Controlled negatives, real parser и isolated unsafe model | Не неизвестный parser exploit |
| Deadline/crash и cleanup | Docker replacement processes; scoped Job deadline/process failure, UID cleanup | Разные explicit fault mechanisms, не эксплуатация parser CVE |
| Traversal/symlink/modified conversion output | Настоящие Linux path fixtures | Converter service отсутствует; unsafe conversion не разрешена |
| Clean ONNX до оценки | Fresh SQL training/evaluation, independent inspect и signed reader | Synthetic model; quality gate M07 остаётся отдельным |
| Сохранение отказов | Три DSSE denial documents + SQL access tests | Не recovery после DB crash; preflight не получает такой документ |
| Полный M21 | 66 controlled + 5 Docker + 25 SQL + 24 scoped + 2 integration checks | Ожидаются 122 checks; без scoped backend остаётся inconclusive |

M20 regression не используется вместо M21-specific replay. Full campaign запускается в Kubernetes workflow после подготовки необходимых services; отдельный Intake evidence contracts workflow проверяет только contracts и не выдаёт M21 pass. Ни один gate exit code не подавляется. Future release/serving integration не объявляется реализованной. Evidence current-state: [STATUS](../STATUS.md). Диагностика: [PB-16/RB-34](operations/intake-gate-troubleshooting.md), [PB-17/RB-35](operations/scoped-intake-troubleshooting.md).
