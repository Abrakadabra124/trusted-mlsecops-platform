# M11: недоступность и смена policy на actual candidate

Реализация подготовлена; native CI результат пока отсутствует. Это продолжение [проверенного key revocation](evidence/runtime-bootstrap-replay-2026-10-29.md) на настоящем обученном candidate. Полный M11 и R1 остаются открыты.

## Сценарий и границы

[Hosted coordinator](../scripts/kube_candidate_faults.py) последовательно выполняет outage, TCP blackhole, policy change, затем необратимый key revocation. Все probes используют один подписанный proposal, model/subject, qualification permit, source и image. Permit ограничен прежними 600 s; он не продлевается автоматически. До каждого fault требуется минимум 180 s его остатка, иначе qualification отказывает до изменения authority. Максимум Job остаётся 240 s; истечение permit в самом probe также не принимается за ожидаемый trust fault.

Production release остаётся запрещён без настоящей общей assurance. Используется purpose-bound candidate qualification, а не искусственный all-pass approval. Actual model revocation, clocks, rotation и разрешённый rollback этим increment не закрываются.

Outage останавливает owned trust StatefulSet; blackhole добавляет принадлежащую прогону ingress deny policy и проверяет настоящий TCP timeout; policy change публикует новый подписанный несовместимый policy hash. После подтверждённого отказа coordinator восстанавливает доступность/совместимость с сохранением PVC и всей истории отзыва. Последним отзывается publisher key; этот отзыв не отменяется.

В candidate probe HTTP работает в потоке того же процесса. На время ready/checkpoint injection [общая lifecycle probe](../mlsecops/kube_serving_lifecycle.py) использует существующий `Engine.exclusive`, чтобы heartbeat не обновил lease во время внесения сбоя. Lock всегда освобождается, в том числе при ошибке coordinator. Часы и deadline не меняются; после injection запросы и heartbeat работают обычным образом. Это тестовая синхронизация, отсутствующая в конфигурации production CLI. У отдельного ordinary CLI child сохраняется прежний SIGSTOP/SIGCONT протокол.

[Candidate verifier](../mlsecops/kube_candidate_trust.py) требует настоящий успешный HTTP prediction до fault, допустимые ответы и первый полный 503 не позднее 60 s от консервативной нижней границы последнего trust read. До восстановления выполняется fresh cold load: outage/blackhole требуют именно `Unavailable(trust_service_unavailable)`, policy change - `trust_policy_changed`. Произвольная ошибка или отказ из-за permit expiry не принимаются. После восстановления старый Engine остаётся fenced, новый Reader обязан заново проверить тот же model/subject.

Для каждого сценария сравнивается полный [CAS + promotion journal snapshot](promotion-snapshot.md) до и после fault. Отчёт хранит его SHA256 и отдельный typed probe; файлы `outage.json`, `blackhole.json`, `policy-change.json`, `key-revocation.json` связаны через artifact_hashes. Raw snapshots, credentials и logs остаются в приватной `.runtime`.

## Ранбук

1. На Windows разрешены только pure/mocked tests. Infrastructure run - существующий configured-serving workflow на disposable GitHub-hosted runner. Проверить commit и отсутствие другого активного run перед dispatch.
2. Требовать stages `actual-candidate-outage`, `actual-candidate-blackhole`, `actual-candidate-policy-change`, затем `actual-candidate-key-revocation`. Controlled stages с похожими именами не заменяют actual evidence.
3. В `actual_inference.trust_lifecycle` проверить все три сценария, точные model/subject, cold denial/recovery cases, HTTP trace, no-auto-reactivation и snapshot hash. Отдельно проверить финальный key report, source/image и hashes каждого primary report.
4. Если `candidate_trust_window` - сохранить фактические времена и закончить qualification. Не удлинять signed permit сверх контракта и не принимать expiry вместо fault. Если `candidate_trust_binding_changed` - сохранить приватные snapshots, не исправлять journal вручную.
5. При сбое coordinator lock освобождается, внешний context восстанавливает принадлежащий прогону nonterminal fault. Незавершённая последовательность остаётся fail/inconclusive. Отзыв ключа сохраняется даже при последующем отказе.
6. Подтвердить worker absence после каждого probe, source SQL stopped и cluster absence в cleanup. При неподтверждённой очистке не объявлять результат успешным. Не выполнять global reset/prune.

Локально: `python -m unittest scripts.kube_candidate_trust_qualification scripts.kube_serving_lifecycle_qualification scripts.kube_candidate_faults_qualification` - 19 methods, три изменённых модуля 142/142 statements и 48/48 branches. Ещё 70 adjacent methods pass. RED tests до реализации показали отсутствие pause/cold-denial интерфейса. Это pure/mocked evidence; реальная SQL/network проверка требуется отдельно.
