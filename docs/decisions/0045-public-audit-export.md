# ADR 0045: bounded public audit export без приватных идентификаторов

Дата: 2026-10-19. Статус: accepted design, implementation locally verified; native qualification pending. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Продолжает [ADR 0044](0044-controller-process-privacy.md), не принимает полный M13.

## Требование и проверенный пробел

Приватный serving journal содержит request/principal IDs, timestamps и release/qualification references. Они нужны для внутренней корреляции, но не должны попадать в публичные evidence через копирование JSONL или обычное хеширование. В проекте уже есть строгая схема event v2 и retained spool с manifest, sequence и exclusive .lease; отдельного operational public export нет.

## Решение

1. Отдельная Linux CLI читает закрытый owned retained spool; нового HTTP endpoint, SIEM, БД и доступа к keys/model/data не добавляется. Kernel guard применяется до argument parsing/private I/O; CLI errors постоянные, cancellation nonzero.
2. Экспорт read-only относительно payload/manifest, но не полностью filesystem read-only: читатель атомарно создаёт собственную .lease, которую writer уже считает эксклюзивной. Active/stale lease запрещает экспорт; чужая lease никогда не удаляется. После проверки reader освобождает только свою lease, без rotation/prune/rewrite manifest. Ошибка cleanup не даёт успешный output.
3. До проекции проверяются private owner/mode, no-follow regular files, link count, bounded bytes/files, canonical manifest, exact inventory, segment identity/digest/size, последовательность и события. Проекция получает те же immutable bytes, для которых проверен digest, а не повторно открытые файлы. Missing/truncated/extra/replaced segment, unknown field/schema и несогласованность не превращаются в clean result. Пустой журнал отвергается, а не доказывает privacy. Reader не вызывает writer lifecycle/Clock: проверяет сохранённую структуру времени, не требует текущего boot ID и не удаляет expired segments.
4. Pure projection проверяет event v2, стабильность principal/route и таблицу переходов ниже. Retention может оставить неполный request: он учитывается как unresolved, а не как успешно завершённый. Response-intended не означает фактическую доставку, response-completed не доказывает получение клиентом; completed включает и HTTP 503, не означает успешный inference.
5. Public schema фиксирована: status/scope/release_ready=false, конечные counters событий и requests (completed/aborted/unresolved), фиксированные route/context-kind counters. Никаких request/principal IDs, private hashes/URLs, exact times, raw features, exception text или labels из входа. Candidate qualification не называется release approval. Unknown fields отвергаются, а не проходят generic recursive redaction.
6. Native integration экспортирует журнал реального candidate HTTP fixture после остановки server и чистого закрытия journal, до удаления только принадлежащего fixture temporary directory. Независимый verifier проверяет точную схему/counters и canaries; результаты связываются с source commit в внешнем qualification report, не добавляют private refs в public export.

### Переходы и счётчики

- Нормальная цепочка: request_started -> response_intended -> response_started -> response_completed. Aborted допустим после любого видимого нетерминального события; второй terminal, повторы и обратный порядок отвергаются.
- На request_started status/context null. Присутствующие context обязаны совпадать. Intent 200 может перейти в started 503 с null context при fail-closed замене; aborted до started имеет null status/context. После started status остаётся неизменным.
- `context_kinds` считает вид context, когда-либо наблюдавшийся в окне запроса, в том числе в intent перед 503/aborted. Это не счётчик успешно выполненных/одобренных моделей. `none` означает отсутствие context в видимых событиях.
- Если самая первая retained sequence > 1, первое видимое событие request может быть suffix без старта, даже внутри окна после полного другого request. Такой request всегда unresolved. При первой sequence=1 отсутствие старта отвергается. Пропуск промежуточного normal stage после любого видимого stage отвергается; незавершённый tail без terminal остаётся unresolved.
- unresolved имеет приоритет над видимым terminal у prefix. Суммы requests, routes и context_kinds равны числу уникальных request IDs внутри private snapshot. `status=pass` означает непротиворечивое полное окно событий, а не доступность сервиса, approval или M13. unresolved>0 даёт inconclusive и exit 2.
- Lease descriptor остаётся открытым до cleanup, закрепляя inode. При short write допускается удалить только подтверждённый записанный prefix своей nonce и исходный inode. Неизвестное ownership/content, невозможность unlink/fsync/close запрещают успешный export. После unlink нет повторного удаления имени, которое уже может принадлежать следующему владельцу.
- Runtime dependencies импортируются внутри защищённого CLI bootstrap; guard предшествует импорту reader и private I/O. Python/stdlib bootstrap до входа в модуль вне этой границы. После завершения owned work CLI явно flush-ит оба output stream и завершает собственный короткоживущий процесс через `os._exit`, чтобы повреждённый буфер не раскрыл исключение во время повторного interpreter shutdown flush. Cleanup source/lease уже завершён; atexit не используется как механизм освобождения ресурсов. При недоступном stderr диагностика может отсутствовать, но private exception не печатается. Library projection не завершает процесс.
- Manifest clock.wall/mono и segment first/last строго положительны, как в writer format. Independent verifier учитывает минимальное дополнительное intent-событие для abort с observed context и максимум три события unresolved request.

## Почему так

Allowlist projection проще проверить, чем denylist масок. Обычный SHA-256 чувствительных значений допускает словарный перебор; здесь значения вообще не нужны в публичной сводке. HMAC/token vault и random per-export identity graph не вводятся без потребителя. Приватные correlation refs остаются в закрытом журнале и отдельно должны связываться с source/run/report/approval/release; агрегаты этой связи не заменяют.

Счётчики раскрывают объём/структуру окна и не являются differential privacy или анонимизацией. Сам журнал и manifest не имеют независимого authenticated producer proof: проверка structural integrity не защищает от злонамеренного same-UID owner/host admin. Lease защищает от кооперативного writer, не от root. Новый exporter не означает безопасный экспорт всех существующих platform reports.

## Контракт приёмки

- Failure-first tests: secret/PII/hash canaries, invalid schema/shape/order/identity/context/limits, retained-prefix и incomplete-tail windows, cancellation, no arbitrary diagnostic.
- Реальный owned journal: startup/live export rejected, clean close exported; manifest/payload bytes неизменны; lease убрана только при подтверждённом ownership. Mutation, symlink/hardlink/FIFO, mode/owner, missing/extra/oversize files и failure cleanup не дают false success.
- Positive controls доказывают наличие private refs в source и их отсутствие в public projection. Два входа с разными private identifiers/times, но одинаковой разрешённой структурой дают одинаковый public output.
- CLI output bytes bounded, формируется после освобождения lease. При input/cleanup failure stdout пуст; ошибка самого stdout может оставить неполные bytes, но nonzero и independent canonical verifier запрещают считать их успешным export. Windows native tests явно skipped; Linux tests обязательны в CI.
- Independent public schema/canary verifier и actual-candidate integration; прежние audit/retention/HTTP/privacy/metrics/worker suites сохраняются. Native matrix, runbook/playbook и evidence рядом с кодом; full M13 не принимается до all-output/private lineage coverage.

## Основания

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): исключение чувствительных значений, проверка доверия источнику и testing отказов logging.
- [OpenTelemetry: handling sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/): минимизация собираемых данных и обработка перед экспортом. OTel collector ради локальной сводки не устанавливается.

Источники прочитаны 2026-10-19; это engineering guidance, не доказательство соответствия или production certification.
