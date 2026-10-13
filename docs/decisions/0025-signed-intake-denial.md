# ADR 0025: отказ intake как отдельный подписанный документ

- Дата: 2026-10-13.
- Статус: принято для synthetic SQL/scoped-controller path, native validation фиксируется в STATUS.
- Контекст: [ADR 0024](0024-independent-artifact-intake.md), [intake](../artifact-intake.md), M21/T27.

## Проблема и решение

Успешная evaluation сохранялась в SQL, но IntakeFailure существовал только в памяти caller. После завершения controller терялись структурированная причина, subject и связь с потраченной holdout reservation. Нужен durable quarantine outcome, а не разрешение повторить попытку бесплатно.

Scorer сохраняет DSSE-документ типа `intake-denial` в существующей append-only таблице evaluations, используя свою существующую identity и ключ. Это НЕ `stored-evaluation`: разрешение выпуска не следует из наличия подписи. Payload всегда содержит `decision=deny-evaluation`, `release_ready=false`, exact candidate/dataset/run/policy context, holdout reservation и очищенный intake fail/inconclusive. Reader проверяет подпись, bytes, context и существование точной reservation, не читая labels. Post-scan denial не отменяет уже потраченный slot.

Только report от штатного intake boundary после строгой проверки поля/причины/counts/subject может быть подписан. Raw stdout, exception bodies и произвольный текст worker не сохраняются. Отказ записи или readback блокирует caller с отдельным persistence failure; никакой quality report после него не создаётся. При удачной записи caller всё равно завершается nonzero, отдавая только тип отказа и CAS reference.

## Альтернативы и границы

- Console-only logging теряет историю и проверяемое связывание с candidate. Отклонено.
- Подписать raw worker response означает расширить signing oracle. Отклонено.
- Добавить новую DB role/table/sink пока не требуется: scorer уже имеет append-only evaluations, promoter читает её. Permissions и migrations не расширяются.
- Хранить отказ как обычную evaluation со status fail опасно для consumers, проверяющих лишь подпись. Выбран отдельный DSSE payload type; обычный evaluation reader его отвергает.

Повтор публикации ТЕХ ЖЕ bytes/nonce/timestamps идемпотентен по SHA-256. Новое сканирование - новая попытка, не retry записи и не refund. При неопределённом DB acknowledgement запись могла сохраниться: это не основание стирать ledger, dataset или создавать новую рабочую историю.

Сейчас сохраняются сформированные IntakeFailure на SQL path; ранние preflight отказы до scanner request и filesystem preview ещё не получают такой SQL-документ. Reader связывает отказ с candidate index/metadata и reservation; он не заменяет curator lineage reconciliation или release verification. История проверяется совместимым pinned policy/tool profile, не переписывается после upgrade. Serving/revocation/audit sink и полный M21 aggregator остаются отдельной работой.

## Проверка

Сначала negative contracts: подпись не превращает denial в approval, stale/foreign context, forged counts, отсутствие reservation, wrong signer/type, storage outage и readback mismatch блокируются. Затем actual SQL + отдельный процесс readback, настоящий unsafe ONNX intake, malformed-output injection, transport-failure fixture, неизменность исходной evaluation и spent budget. Component evidence не заменяет полную M21/M18 приёмку.
