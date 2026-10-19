# ADR 0046: private source-to-request correlation

Дата: 2026-10-19. Статус: implemented, native qualification pending. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Продолжает [ADR 0045](0045-public-audit-export.md); полный M13/R1 пока не принят. [Evidence](../evidence/audit-correlation-2026-10-19.md), [RB-65/PB-39](../operations/audit-correlation-troubleshooting.md).

## Требование и фактический пробел

M13 требует связать source/run/report/approval/release/request без raw payload. Проверенные readers уже проверяют signed dataset/lineage, candidate/provenance, evaluation, release package и отдельное approval либо qualification permit. Но текущий private context schema 1 переносит только selection/permit, proposal, bundle и model refs. Полная цепочка не материализуется в request journal и отдельно не проверяется.

## Решение

1. Добавить immutable `Lineage` с восемью bounded строками по таблице ниже. Run обозначает content-addressed training metadata конкретного выполнения, не имя job и не выдуманный MLflow ID. Source approval разрешает source/purpose/owner до expiry, но не фиксирует конкретные байты. Отдельный source_sha256 идентифицирует входные bytes, о которых свидетельствует доверенный curator в signed data-lineage; его равенство stored-dataset.quarantine_object уже проверяет package verifier.
2. Ввести context schema 2: `ReleaseTrace` сохраняет поля ReleaseContext и добавляет Lineage, authorization/assurance/approval refs; `QualificationTrace` сохраняет поля QualificationContext и добавляет Lineage, но не содержит release approval. Классы frozen/slots, repr без новых private значений. Все refs берутся после полной проверки существующих readers, не из HTTP input, mutable alias или имени модели.
3. Reader продолжает проверять signatures, roles, bundle semantics, gate set, current trust/expiry и head sequence. Извлечение корреляции из уже проверенного package не заменяет эти проверки и не является отдельным криптографическим verifier. Release authorization reference адресует envelope document; assurance/approval refs соответствуют payload digests из проверенного decision. Статическое наличие правильных hex-строк не доказывает authorization.
4. Снимок привязывается к immutable loaded object и поколению Engine, как существующий context. Audit event schema 2 и bounded record <=2048 bytes сохраняются. Никаких дополнительных SQL writes, offline historical approval bypass, SIEM/collector или увеличения admission budgets. Если фактический максимальный record не помещается, остановить реализацию и пересмотреть дизайн, не повышать лимит молча.
5. Parser читает context v1 и v2 с точным набором полей. Legacy v1 остаётся пригоден для structural public export, но не проходит новую full-correlation проверку. Unknown versions/fields, mutable/invalid lineage, изменения context внутри request и несовпадение с проверенными source materials отвергаются. Легитимный новый dataset, заново согласованно подписанный trusted curator/publisher, не объявляется атакой лишь из-за другого source hash. Public export schema/counters не расширяются private refs.
6. Независимая qualification проверяет реальные private events и сравнивает каждое поле с primary signed/package materials. Для release-path нужен controlled signed authorization fixture, для actual candidate - реальный existing permit без выдуманного approval. Проверяется fresh отдельный spool этого campaign с первым sequence=1: retention не должен скрывать целиком удалённые запросы. Public evidence содержит только finite coverage/counters и status, без private graph. Missing/mixed v1 для требующего корреляции окна не становится pass.

### Точные значения Lineage

| Поле | Первичный объект и значение |
| --- | --- |
| source_revision | 40-hex Git revision из training metadata, совпадает с release source_commit и ожидаемым build |
| source_fingerprint | SHA-256 source inventory из training metadata, согласованный с projection/parameters |
| source_sha256 | Digest исходных bytes из signed data-lineage payload.source_sha256, равен stored-dataset payload.quarantine_object |
| source_approval_sha256 | SHA-256 canonical decoded source approval payload; не digest approval envelope |
| dataset_sha256 | Candidate record.dataset_reference: SHA-256 canonical signed stored-dataset envelope; не dataset_id/вложенный dataset manifest payload |
| lineage_sha256 | Stored-dataset payload.lineage_object: SHA-256 signed data-lineage envelope; не lineage_id payload |
| run_sha256 | Candidate record.metadata_object: digest canonical training metadata bytes |
| evaluation_sha256 | SHA-256 canonical signed stored-evaluation envelope; не hash вложенного report |

Негативные проверки должны подставлять другой корректный hash той же цепочки, а не только malformed hex. Это отличает проверку значения/связи от проверки формата.

## Семантика и ограничения

Context на intent описывает намерение использовать проверенную модель, не доставленное предсказание. Intent 200 может перейти в 503/aborted; preselection failures имеют context=null. Нельзя приписывать им lineage успешного inference. Существующая stage/status семантика сохраняется.

Journal/manifest проверяют structural integrity и cooperative ownership, но не дают независимо подписанного producer proof или защиты от host admin/same-UID malicious owner. Новые ссылки не устраняют это ограничение. Controlled release fixture не принимает actual candidate с failed image/ML gates. Counters/public export не заменяют all-output privacy или full M13.

Reader не загружает отдельный intake source-snapshot envelope: источник удостоверен существующей signed curator lineage chain, не независимым повторным source-admission audit на serving boundary. Intake snapshot остаётся evidence первоначального import в своих controls; новый контекст не заявляет его проверки. Защита от согласованного переподписания всех материалов скомпрометированными доверенными curator/publisher keys не входит в эту гарантию. Source hash и approval hash сохраняются отдельно, поэтому разные разрешённые snapshots не смешиваются.

## План и критерии

1. Failure-first schema/type tests: source revision/hash bounds, exact v1/v2 shapes, frozen nested values, no approval on qualification, worst-case full JSONL record <=2048 bytes.
   Direct field validation выполняется до deepcopy/asdict, чтобы пользовательский __deepcopy__ не заменил изменяемый объект строкой лишь на время проверки.
2. Readers: primary source/run/evaluation/authorization linkage; negative signed-source mutations и mismatch; no writes, latest trust/expiry/head checks сохранены.
3. Engine/HTTP/journal: immutable generation snapshot, реальные v2 события, failure/abort semantics, legacy-read compatibility. Public export неизменен и исключает все новые nested private refs.
4. Independent probe: wrong graph/approval/context/schema/expected evidence must fail; distinct controlled-release vs actual-qualification scope; no raw private report output.
5. Disposable Linux CI: scoped suites без native skips, production context/schema >=95% mixed coverage, independent probe 100%, existing gates не ослабляются, actual candidate integration и source binding. Сохранить все terminal workflows и любые failed attempts.
6. RB-65/PB-39, evidence, STATUS/implementation/tasks. Полный M13 не закрывать до оставшихся all-output требований и отдельной приёмки; M07 reliability debt и image/ML blockers не скрывать.

## Основания и альтернативы

- [OpenLineage object model](https://openlineage.io/docs/spec/object-model/): различение job definition, runtime occurrence и dataset; объявленный design graph не равен наблюдению выполнения. Здесь используются существующие immutable refs, OpenLineage server/client не устанавливается.
- [SLSA v1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts): provenance проверяется против artifact digest, доверенных identities и ожидаемых параметров. Это guidance для связи уже существующих verifier boundaries, не заявление SLSA level или certification.
- Offline resolver потребовал бы отдельной historical-time/trust семантики и доступа к private storage во время расследования. Новый event-side snapshot использует результат уже выполненной проверки и не добавляет путь повторного разрешения expired release. Копирование raw signed packages в каждое событие нарушило бы minimization/bounds; одного нового opaque hash без доступной связи с chain недостаточно.

Источники прочитаны 2026-10-19. Введение новой схемы само по себе не доказывает достижение M13.
