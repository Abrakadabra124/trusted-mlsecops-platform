# ADR 0049: private primary audit evidence

Дата: 2026-10-20. Статус: implemented, native qualification pending.
Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit».
[M13](../acceptance.md#m13), [ADR 0048](0048-privacy-acceptance.md).

## Требование и граница

Проверить после завершения native child те же bytes закрытого audit window, которые были проверены внутри child, и связать их с фактическими HTTP outcomes и current signed primary materials. Согласованные summaries недостаточны. Это следующий обязательный компонент M13, не полный gate и не разрешение release.

HTTP ledger содержит ordinal exchange, private response request ID, нормализованный route, фактический HTTP status и признак подтверждённой admission. Это не анонимизация: identifiers остаются private. У unknown 404 нет response ID: сохраняется null и отдельный exchange, ID не выдумывается. Payload, URL/query, headers, credentials, raw features и их hashes не сохраняются.

## Решение

1. Existing owned snapshot reader возвращает immutable manifest bytes вместе с ordered segment bytes под прежней exclusive lease. Existing `read_closed` сохраняет контракт list of bytes.
2. Qualification transport ведёт bounded private HTTP ledger для business routes, включая unknown route. Metrics scrape не является business request и проверяется отдельным metrics probe. Каждая запись создаётся после полного чтения response, до возврата вызывающему коду, без request payload. Admission наблюдается только после успешного реального `Journal.emit(request_started)`, через метод собственного экземпляра Journal, без ослабления production type guard. Она не выводится из проверяемого журнала. Любая ошибка учёта или чтения ответа необратимо отклоняет окно, даже если вызывающий код перехватил исключение.
3. Closed callback сохраняет один canonical JSON packet: exact manifest/segments/public CLI stdout в strict Base64, HTTP ledger, campaign/source binding. Ограничение 24 MiB учитывает maximum 16 MiB journal и encoding overhead. Нет zip, исполняемых объектов или имён файлов из packet при записи на диск.
4. Pure verifier проверяет schema/bounds/canonical encoding, manifest digests/sequence, journal state machine/correlation, equality exact public export и пересчитанной projection. Каждый terminal journal request должен иметь ровно один совпадающий admitted HTTP outcome. Каждый HTTP 200/413/422 должен присутствовать в journal; pre-admission 401/404/429/503 могут отсутствовать только при admitted=false. Admitted 429/503 без journal отвергаются. Неполный/aborted window, duplicate/missing ID, wrong route/status/context отвергаются.
5. Private packet создаётся один раз в новом owner-only directory, без overwrite. File/directory fsync, bounded readback и byte equality, затем fsync parent directory для новой записи каталога. Symlink/hardlink, wrong owner/mode, stale/partial/oversized packet не дают pass. Поддерживается только Linux qualification; Windows permission semantics не эмулируются. Это не доказательство сохранности при физической потере диска.
6. Родитель создаёт случайный campaign nonce до child; nonce входит в signed qualifier permit, packet и receipt. Свежие timestamps не разрешают replay старой campaign. После полного child exit родитель заново читает verified signed proposal, qualifier permit/public key и packet из fixed owned campaign path. Expected lineage/context выводится из подписанных primary materials, а не принимается из packet. Parent сверяет digest и результаты с child receipt, затем добавляет отдельный проверенный case. Packet остаётся доступен после удаления временного source journal.

Primary proposal/model/candidate/evaluation остаются в immutable CAS; qualifier permit/public уже сохраняются в existing campaign directory. Parent повторно проверяет signatures, subject/source/image и временное окно permit. Это не attestation честности процесса/host и не защита от владельца VM, который может переписать все артефакты и код.

## Сохранность и публикация

Packet private, содержит request/principal IDs и private lineage. Не выводить его содержимое в stdout, не upload raw state и не коммитить packet. В synthetic native receipt допустимы scoped digest/counters; настоящий public export по-прежнему только фиксированные aggregate fields без identifiers/hashes.

Retention этого increment ограничен disposable CI campaign и жизнью VM. Это достаточное сохранение для независимого parent recheck после child/source cleanup, но не долговременное forensic хранилище. Production retention/encryption/access/backup требуют отдельной specification. Не удалять единственную копию автоматически ради успешного rerun; новая campaign получает новый путь, старый отказ сохраняется до завершения VM.

## Проверки

- RED: missing module/API; stale/wrong source/campaign; forged manifest/segment/hash/sequence; noncanonical Base64/JSON; limits; matching fake summaries при изменённых primary bytes.
- RED: duplicate/missing HTTP ID; wrong actual status/route; orphan journal request; successful HTTP без journal; private field injection; unresolved/aborted journal; substituted public export.
- Real signature tests: changed primary material/permit signatures and subject binding reject. IO faults: exclusive creation, partial write/fsync failure, ownership/mode/symlink/hardlink, immutable readback.
- Native: packet retained after child/source cleanup, parent independently verifies it; capture count и audited count различаются объяснимо, все checks без skips на Linux. Complete terminal CI, первый failure сохраняется.

## Основания и оставшиеся зависимости

[Python os](https://docs.python.org/3.12/library/os.html#os.open) документирует descriptor-relative операции и платформенные границы; [strict Base64](https://docs.python.org/3.12/library/base64.html#base64.b64decode) позволяет отклонять посторонние символы; canonical re-encoding дополнительно запрещает неоднозначные представления. [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) требует ограничивать чувствительные log data и проверять logging failures. Источники просмотрены 2026-10-20; это не сертификация.

Full M13 остаётся inconclusive до production lifecycle/429/503 privacy matrix, service-log observation, actual/controlled subject composition и strict public gate projection. Этот packet не подменяет их.

Результаты локальной проверки и review: [evidence](../evidence/audit-evidence-2026-10-20.md). Диагностика и безопасное повторение: [RB-68/PB-42](../operations/audit-evidence-troubleshooting.md).
