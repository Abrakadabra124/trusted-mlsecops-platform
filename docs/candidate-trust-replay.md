# M11: старый подписанный trust-документ на actual candidate

Статус: [native dba0f75 / 40922974146](evidence/candidate-trust-replay-2026-10-29.md) success. Версия 5 с действующей подписью и остатком срока 3361.69 s точно отказана после получения версии 7; HTTP 503, cache invalidation, no-late-ML и новый working Engine подтверждены. Полные M11/CP3/R1 остаются открыты. Это in-process signed-response replay qualification, не защита от rollback доверенного DB administrator и не разрешение production release.

## Сценарий

В существующем actual policy-change Job [probe](../mlsecops/kube_candidate_probe.py) сохраняет canonical bytes настоящего signed trust response до изменения policy. [Capture verifier](../mlsecops/kube_candidate_replay.py) проверяет подпись, environment, wall/server timestamps и точное соответствие документу, payload и version floor, которые уже проверил действующий Lease. Высокая версия не присваивается вручную.

Внешний coordinator выполняет прежние два SQL updates: несовместимая policy версии v+1, затем совместимая v+2. Root private key остаётся вне Pod. После отказа старый Engine закрывается, отсутствие worker проверяется. Новый Engine загружает ту же модель и получает актуальный v+2 из настоящей authority; успешные predictions и golden parity обязательны до replay.

Только затем транспортная зависимость Reader возвращает сохранённый v вместо текущего документа. Server timestamp берётся из нового настоящего SELECT. До подстановки оба документа заново проверяются: signature, environment, срок по wall/server clocks, та же policy и те же revocation sets. Current document обязан совпасть с payload/observed digest/high-water mark загруженного Lease и иметь версию ровно v+2. Документы не переподписываются, version floor и часы не меняются, старый документ в authority не публикуется.

Настоящий `Lease.refresh` должен вернуть именно `trust_version_replay`. HTTP - 503, cache и Reader.current очищены, прежняя generation fenced. Проверяются zero Worker.predict после injection, два дальнейших predict и readiness после возврата нормального transport. Старый Engine не активируется автоматически. Fresh Reader проверяет тот же model/subject, затем отдельный новый Engine проходит полный HTTP contract и golden predictions.

## Evidence и границы

`actual_inference.trust_lifecycle.policy-change.probe.version_replay` содержит trace, точную причину, исходный/current document hashes, версии, expiry и время проверки старого документа, положительный остаток его срока и golden error до/после отказа. Primary policy-change report связан SHA256 через artifact_hashes; полный CAS + promotion snapshot до/после Job должен совпасть. Raw signed envelopes остаются в памяти private probe и не включаются в публичный report.

Replay использует существующий [denial harness](../mlsecops/kube_candidate_clock.py), но не входит в цикл пяти clock cases и не повторяется в других fault Jobs. Сохраняются максимум Job 240 s, permit 600 s, fresh-source/image/model/subject bindings и прежний minimum remaining permit перед каждым fault. Нет автоматического продления срока или смягчения admission.

Это дополнение к [actual clock/cache](candidate-clock-cache.md) и [actual outage/policy lifecycle](candidate-trust-lifecycle.md). Не смешивать его с [отказом старому release sequence](promotion-replay.md): trust-policy version и promotion sequence защищают разные состояния. Также оно не заменяет независимый model revoke, root rotation, whole-bundle rollback, M22 review и общую M18 приёмку.

## Ранбук и плейбук

Владелец операции - maintainer disposable qualification. Требуются чистый checkout, доступ к существующему configured-serving workflow и отсутствие другого активного run. Локальные Docker/WSL/Kubernetes/SQL не запускать.

1. Read-only: `gh run view RUN_ID --json status,conclusion,headSha,jobs`. При timeout повторить запрос того же run. Не создавать новый run только из-за ошибки наблюдения.
2. Компонентная проверка: `python -m unittest scripts.kube_candidate_replay_qualification scripts.kube_candidate_clock_qualification scripts.kube_candidate_qualification scripts.candidate_serving_reader_qualification scripts.trust_qualification scripts.serving_core_qualification`. Локальные worker/transport - doubles; это отдельно от native evidence.
3. Публикация code commit в `codex/cp3-m11-trust` запускает один hosted workflow. Изменяющий этап создаёт только disposable owned resources; policy coordinator уже выполняет v+1/v+2. Не добавлять ручной SQL update для получения нужного результата.
4. Проверить отсутствие worker перед replay, успешный pre-replay inference, still-valid старый документ с настоящей подписью, current=prior+2 и точный `trust_version_replay`. Далее должны быть пять 503 observations, очищенный cache, no-late-worker-call, no-auto-reactivation, fresh Reader и новый serving Engine с прежними model/subject.
5. `candidate_replay_capture_binding` означает несовпадение fresh ответа с уже наблюдаемым Lease; `candidate_replay_binding` означает нарушение preconditions. `candidate_replay_server_clock` означает skew, а не доказательство replay rejection. Сохранить primary JSON/raw logs приватно, прекратить qualification, проверить источник и chronology. Не исправлять floor/cache/revocations вручную и не выдавать произвольный 503 за pass.
6. При expiry, другой подписи/policy/revocation set считать run fail/inconclusive. После исправления причины повторить весь source-bound run с новым явным qualification permit в его прежних пределах. Не восстанавливать доверие удалением revocations или публикацией старого документа.
7. В finally возвращается исходный transport; owned Engines и workers закрываются. Для успеха необходимы worker absence после replay/recovery, source SQL stopped и cluster absence. При неподтверждённой очистке эскалировать владельцу run с finite phase/cause, без secrets/raw payload.

Отрицательные локальные tests покрывают expired/corrupt/noncanonical/mutable capture, unsigned current response, одинаковую версию, искусственный floor, несовпадение payload/digest, другой policy/revocations и clock skew. Локально 85 methods pass; в Linux CI 277 method executions без skipped. Replay verifier и общий denial harness: 118/118 statements и 24/24 branches. В actual policy-change Job 131 typed assertion, в общей actual группе 757 с повторами. Native [primary evidence](evidence/candidate-trust-replay-2026-10-29.md) проверено по source/report hashes, timestamped trace и cleanup.
