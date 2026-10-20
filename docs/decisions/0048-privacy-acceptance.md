# ADR 0048: fresh M13 privacy acceptance

Дата: 2026-10-20. Статус: полный gate proposed; первый private receipt increment реализован, native validation ещё не завершена.
Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit».
[M13](../acceptance.md#m13), [карта каналов](../privacy-output-map.md), [предыдущий native increment](../evidence/serving-output-2a70ffc-native.md).

## Цель

Подключить воспроизводимую executable M13-приёмку к acceptance runner. Проверять свойства privacy/audit текущего synthetic local-cpu продукта на текущем candidate, а не считать исторические зелёные отчёты одним gate. Scope M13 не меняется; image/ML failures и остальные M-gates независимо запрещают release.

## Предлагаемые границы и компоненты

| Компонент | Обязанность | Зависимость |
| --- | --- | --- |
| privacy-contract | Строгая проверка fresh receipts, source/candidate bindings, наблюдаемых каналов, обязательных отрицательных controls и cross-report invariants | Existing canonical/decode, inventory, проверенные native receipt schemas |
| privacy-campaign | Собственные fresh child runs, frozen command arguments, deadlines, private intermediate evidence, constant diagnostics | privacy-contract, existing output observer и release-reader native harness |
| acceptance M13 | pass/fail/inconclusive, digests методов и материалов, только утверждённая public projection | privacy-campaign |
| CI и эксплуатация | Воспроизведение clean checkout, сохранение первого отказа, полный terminal CI, runbook/playbook | acceptance M13 |

Без новых зависимостей, платформ, credentials или ослабления policy. Не менять пользовательские AGENTS.md/GOAL.md. Не запускать локальные Docker/WSL/Kubernetes/SQL; native validation только в существующем disposable hosted CI.

## Доказательства одной campaign

1. В начале и конце проверить clean source revision, runtime fingerprint, exact image ID и digest проверяющих scripts. Gate создаёт новый campaign ID и начальную inconclusive запись; старый report не является входом с правом pass.
2. Выполнить фиксированный набор executable contracts в отдельном bounded child: auth/per-client quotas, strict event/context, retention/close ownership, metrics cardinality и permissions, public export, correlation, private CLI/core policy, late captures/report snapshot. Report перечисляет конкретные test IDs и исход каждого; skips/errors/failures не становятся pass. Список модулей и минимальное покрытие задаются gate contract, а не произвольным JSON от child. Raw unittest diagnostics не публикуются.
3. Запустить fresh actual-candidate output qualification через ADR0047. Нужны current source/image, verified unchanged signed proposal, exact required case set, full child exit, zero FD stderr, six actual input needles, strict HTTP/metrics/private audit/public evidence checks. Candidate/subject/model/evaluation refs должны соответствовать одному current proposal, а не только совпадать между недоверенными report fields.
4. Проверить release-context production Reader path отдельным fresh controlled native campaign. Controlled approval и actual qualification permit принципиально разделены; fixture не разрешает actual release. Gate должен явно проверить, достаточно ли этого контроля для approval/release части M13, и не выдавать разные model subjects за одну цепочку. Если это покрытие недостаточно, M13 остаётся inconclusive до исправления, а не объявляется полным по одному candidate path.
5. Наблюдаемые serving channels: HTTP body/headers; Python stdout/stderr/logging; native/inherited FD и interpreter exit; отключённые ambient traces/log exporters; approved metrics; closed owned audit; public export; final evidence. Проверить private worker IPC/no-container-logs и отсутствие forwarding request features в SQL/tracking/controller paths. Не обозначать отсутствие проверки как отсутствие канала.
6. Сверить private journal correlation с первичными signed materials, counts с public closed-window export, required auth/quota outcomes, retention policy, canary coverage и непустое число реальных запросов. Нельзя принять один status=pass, длину списка cases или только declared config вместо этих проверок.
7. Сохранить exact scanned snapshots, digests и source bindings. Public M13 summary содержит только фиксированные approved fields; request/client IDs, raw payload, private URLs и hashes чувствительных значений в него не попадают. Private receipt остаётся private. Synthetic artifact digests, необходимые acceptance envelope, отделены от public serving export.

## Правила результата

- pass допустим только при полном подтверждении M13 для указанного synthetic profile, текущих source/candidate и всех обязательных каналов.
- fail: доказанное нарушение contract/privacy/correlation, подмена source/digest/schema/case set, uncontrolled output или ошибочный negative control.
- inconclusive: отсутствующая native среда/обязательное evidence, неподтверждённая cleanup/freshness/coverage, skipped native check. Этот статус не разрешает promotion.
- Ошибка child/timeout/cancellation не оставляет текущий pass. Не печатать exception text с private values; внешние diagnostics фиксированы.
- Нет claim об устранении membership inference, differential privacy или защите от privileged host owner. Реальный пилот требует отдельной purpose/retention/privacy specification.
- CI-only guard ADR0047 и недоказанный shared/local forced-stop recovery сохраняются как открытое ограничение R1, а не исчезают после подключения M13.

## Отрицательная приёмка

Сначала RED: replay report до campaign start; будущие/naive timestamps; wrong commit/image/contract digest; dirty source; разные subjects в receipt и первичных материалах; duplicate/missing/unknown mandatory cases; skipped test; non-integer counters; inconsistent private/public counts; незакрытый audit; неправильные auth/quota outcomes; unexpected metric labels; утечка nested canary/private URL; потерянный producer после deadline; legacy correlation v1; forged qualification-as-release; mutable post-scan report; unsafe path/symlink; interrupted publication со старым pass.

Unit tests не создают local infra. Linux native проверка должна запускать real current candidate и сохранить полные очищенные reports и все terminal CI outcomes. Сначала contracts/binding, затем runner, затем acceptance dispatch, без фиктивного pass между этапами.

## Открытые вопросы до реализации полного gate

- Approval/release coverage: как доказать production release-context privacy без циклического требования уже принятого M13 и без ложного одобрения actual candidate с failed ML/image gates.
- SQL/service log coverage: какие каналы фактически получают serving input и какое runtime evidence подтверждает отсутствие forwarding; одной декларации конфигурации недостаточно.
- Private/public report boundary: какие поля M13 envelope необходимы verifier, а какие должны оставаться только в private receipt.

Эти вопросы являются условиями проектирования и приёмки, не разрешением их пропустить. До их разрешения M13 dispatch не переводится в pass.

## Первый increment: независимый admission private receipt

Реализованы [privacy_evidence](../../mlsecops/privacy_evidence.py) и интеграция в [parent observer](../../scripts/serving_output_native.py). Это проверка структуры, свежести и привязок private synthetic receipt, не доказательство правдивости всех его полей и не публичная privacy projection.

1. Родитель читает current proposal из existing serving storage client до запуска child. Existing `release_bundle.load` и `bind_proposal` проверяют signatures, capsule/material semantics, exact image/source, digest модели и срок. Пять expected references выводятся из проверенного package/context, а не копируются из будущего отчёта child.
2. Родитель фиксирует начало, запускает прежний bounded fixed child, дожидается полного выхода/закрытия FDs и повторно проверяет source. Действуют прежние hosted-only ограничения ADR0047.
3. Новый checker принимает exact bytes: bounded JSON, обязательные root fields, 22 case IDs, шесть обязательных runtime components, UTC-aware campaign interval внутри интервала родителя и все пять expected references. Case IDs сохраняют регистр: фактические `ONNX`/`CPU` имена допустимы; обязательные имена не нормализуются.
4. Проверяются строгие counter types, quota outcomes, 12 privacy requests / 36 events / 69 metric series, zero native stderr и complete FD observation, одинаковые private/public totals, четыре события на завершённый запрос и отсутствие незавершённых/aborted requests.
5. Нижние границы выводятся из непересекающихся фаз, а не из исторического полного итога: privacy matrix 9 audited requests (3 successful / 6 without context), audit pair 2 successful, quota 4 audited (2 successful / 2 without context). Всего минимум 15 audited / 7 correlated / 8 without context / 13 predict / 2 ready. Общий итог может меняться с наблюдаемыми retry/readiness requests.
6. Только после admission родитель добавляет `current-private-receipt-admitted`. Child не может заранее включить этот reserved case. Неправильный primary запрещает запуск child; неправильный receipt запрещает публикацию pass. Старое evidence main заменяет inconclusive до работы.

Возвращаемый checker summary с `receipt_sha256` остаётся **private**: digest может зависеть от sensitive identifiers. Он не добавляется в native report и не является self-referential receipt. Existing synthetic native report тоже не считается публично безопасным для настоящих данных. `release_ready=false`, `full_M12=inconclusive` и M13 dispatch `inconclusive` сохраняются.

## Разбор review и незакрытые обязательства

Design review выявил пять actionable пробелов полного gate. Они **не исправлены одним checker**:

- Actual candidate и controlled production-release fixture имеют разные subjects. Нужен явный compositional acceptance contract, либо M13 остаётся inconclusive; нельзя подделывать actual approval при failed ML/image gates.
- Требуется privacy-наблюдение production `configured()/audit_path` lifecycle, а не только injected journal, включая canaries в 429/503 и shutdown.
- SQL/service logs требуют inventory реально задействованных sinks, runtime readback, bounded closed snapshots и positive/negative controls. Config `log_statement=none` или отсутствие bytes в child stderr этого не доказывает.
- Closed journal сейчас проверяется до удаления, но независимому gate нужны сохраняемые exact private snapshots, HTTP-outcome linkage, signed materials/immutable refs и exact public export bytes, а не только согласованные summaries.
- Нужны отдельные строгие private verifier и public projection schemas. Не публиковать private graph, URLs, request/client IDs и hashes чувствительных значений; контролировать также failure/timeout outputs.

Второй review выявил четыре ошибки самого checker: lowercase-only cases, недостаточные cross-component minima, непроверенный тип limitations и `OverflowError` для большого JSON integer. Все воспроизведены failure-first и исправлены. Добавлен также RED control reserved parent case. Третий review нашёл недостаточный signature-negative test: unknown field давал schema rejection вместо invalid signature. RED assertion подтвердил проблему; тест исправлен на byte mutation настоящей подписи и exact rejection. Внешняя модель не использовалась по решению владельца. Три цикла завершены, четвёртый не запускался.

Проверки и границы: [local evidence](../evidence/privacy-evidence-2026-10-20.md), [RB-67/PB-41](../operations/privacy-evidence-troubleshooting.md).

## Основания

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): исключать секреты из logs, проверять logging failure modes и учитывать недоверенные источники событий.
- [SLSA verifying artifacts v1.1](https://slsa.dev/spec/v1.1/verifying-artifacts): проверять provenance относительно ожидаемого producer/subject и доверенной policy, не принимать произвольный self-asserted metadata. Здесь это принцип привязки evidence, не заявление соответствия SLSA.

Официальные источники просмотрены 2026-10-20. Конкретный gate contract определяется требованиями проекта, а не названием стандарта.
