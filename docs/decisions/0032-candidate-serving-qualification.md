# ADR 0032: Испытание настоящего candidate без фиктивной release acceptance

Дата: 2026-10-15 (Europe/Moscow). Статус: реализован и проверен в scoped qualification. На `0a47b7b` 39 native cases pass, [evidence](../evidence/candidate-serving-2026-10-15.md). Scope: T15, отдельная qualification phase перед final approval. Полный M12/R1 ещё не принят. UTC campaign timestamps сохраняются отдельно.

## Проблема

Первый API replay использовал test lineage и искусственные all-pass contract reports. Это полезно для проверки production Reader, но не доказывает работу API на модели из настоящего training/evaluation pipeline. Перенос этих all-pass reports на реальный candidate создал бы фиктивные утверждения о непройденных gates. Такой подход запрещён.

Final promotion требует M01-M23, включая HTTP qualification; для получения этого evidence candidate необходимо сначала испытать. Решение - отдельное разрешение **испытать**, а не ослабление разрешения **выпустить**.

## Решение и границы

1. Qualification runner читает уже опубликованный unapproved proposal через serving-only TLS SQL role. Проверяются исходные publisher/curator/evaluator signatures, capsule, source/image/policy bindings и exact bytes. Candidate, evaluation, provenance и release descriptor не переписываются и не переподписываются.
2. Отдельный ephemeral qualification signer выдаёт короткий permit в signature domain `candidate-serving-qualification`, с purpose, campaign, environment, proposal/subject/model/source/image digests и expiry. В permit нет pass assertions для M-gates и нет release approval.
3. Qualification-only Reader находится в `scripts/`, не выбирается production CLI/config и не меняет `mlsecops.release_reader.Reader`. Его immutable handoff передаётся тому же Engine/HTTP/isolated worker. Ready в этом отдельном loopback test означает verified candidate load, не trusted production release.
4. Текущий trust обслуживается отдельной disposable SQL authority с собственным root и permit pin. Fresh load, before/after inference, expiry и model revocation проверяются. Source CAS, holdout budget и production promotion head не меняются.
5. Golden reference получается отдельным existing one-shot worker на фиксированных synthetic features и exact model bytes, с nonce/row/digest validation. Это transport/runtime consistency, не новая независимая sklearn parity или бизнес-оценка; прежние M06/M07 evidence сохраняют собственный scope.
6. HTTP checks и fault injection работают только на owned test resources. Итог связывается с настоящим proposal/model/source, но `release_ready=false`, полный M12 пока inconclusive. Final promotion всё ещё требует реальные reports всех gates и отдельный release approval.

Production signature verifier обязан отвергать qualification permit как `release-approval`; missing/failed assurance не превращается в pass. Test root не записывается в рабочую trust configuration. Ручная модификация trusted host/Python-кода остаётся за границей этой reference threat model.

## Проверка

- Negative-first: missing/wrong-domain signature, subject/model/source/environment/campaign mismatch, extra fields, expiry, stale permit, wrong SQL role, changed capsule/material bytes, revoked key/model, old immutable handoff.
- Native: настоящий signed proposal после Docker training и independent evaluation; read-only CAS; отдельные reference и persistent workers; API readiness/digest/score/abstain, malformed input, overload, stopped worker, verified reload, model revoke и подтверждённая cleanup.
- Report/permit не содержат all-pass gate fixtures; actual release без assurance остаётся запрещённым. Source snapshot и original envelope digest должны совпасть до/после campaign.
- Не считать успех этого компонента закрытием M11 HTTP outage, M13 privacy/quotas/audit, M14 load, M18 или R1. Не обходить текущие image/poisoning/evasion/robustness failures.

## Основание

[SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts) рекомендует внешний trust root, signature/subject binding и проверку ожидаемых параметров. Здесь эти принципы используются для lab permit, без заявления SLSA compliance или уровня. [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) рассматривает оценку и управление рисками на протяжении lifecycle; разделение qualification/release - проектное решение, не требование сертификации. Источники проверены 2026-10-14.

[ADR 0031](0031-isolated-serving-api.md) описывает реальный runtime/API; [acceptance](../acceptance.md) сохраняет полный контракт результата.
