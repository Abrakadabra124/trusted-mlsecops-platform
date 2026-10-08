# ADR 0011: одноразовый ordered prediction protocol

Дата: 2026-10-08. Статус: **Implemented component, локально проверен**. Компонент T26/M20 после scoped controllers. 164 contract checks, 74 developer checks и 136 controller checks прошли; [результаты/CI](../../STATUS.md), [runbook](../prediction-protocol.md). Это не изменение SQL schema, dataset policy или ключей; существующие artifacts и receipts не удаляются. Полный M20 ещё не принят.

## Проверенный пробел

In-memory reproduction на `0bb0e68` показал: `evaluate_verified_candidate` принимал `schema_version=999` и произвольный объект `scan`, если batch/model binding и scores совпадали. Report не подписывался в этом reproducer. Текущий список scores не имеет row identifiers, поэтому контракт не различает переставленные response records. Это незавершённое требование M20, не основание ослабить gate.

## Решение

Prediction protocol v2 задаёт точные request/response fields. Trusted caller создаёт свежий случайный batch nonce, позиционные opaque row IDs и неизменяемую копию исходного request. Worker возвращает model digest, digest канонического request, тот же nonce и ordered records `row_id/score`. Caller сравнивает порядок без сортировки, проверяет число/тип/диапазон/конечность probabilities, version и ограниченный scan contract. Raw text и неизвестные fields не попадают в подписанный report.

Один pending batch допускает ровно одну попытку consume. После успешного или ошибочного ответа повторный consume отказывает. После transport failure caller не переиспользует batch; следующий run получает новый nonce. Ответ от другого batch не подходит даже той же модели и тем же features. В evidence входят request/response digests и worker execution metadata, но не features или labels.

Это защита корреляции и single-use обработки, не доказательство правильного вычисления: malicious worker способен вернуть ложные, но корректно оформленные scores. Их проверка относится к независимой evaluation, challenge/intake и threat model. Перестановку самих значений с подделанными правильными IDs нельзя объявлять обнаруженной. Query budget и долговременная защита от повторной оценки candidate принадлежат M07; in-memory consume не заменяет persistent budget или release replay prevention M11.

## Совместимость и реализация

- Сначала постоянные отрицательные tests, затем общий protocol helper без ONNX parser imports.
- Перевести scorer, worker и golden recovery/migration probes на один контракт. Training request не меняется.
- Не добавлять silent fallback на v1. Worker image и source fingerprint должны обновляться вместе; scoped admission pin меняется только через explicit idle `controller_bootstrap --replace-profile`.
- Старые подписанные evaluations остаются историей v1. Их bytes не переписываются и v2 evidence им не приписывается. Для нового evaluation требуется актуальная image-bound модель либо отдельный совместимый run по существующей policy.
- Повторить native Docker training/evaluation, controller suite, M03 и storage recovery. Одноразовую migration не запускать заново на populated private target; её новый golden verifier проверяется в fresh CI.

## Приёмка компонента

Positive roundtrip; unknown/bool version; wrong action/model/request/batch; duplicate/missing/extra/reordered rows; boolean/NaN/Inf/out-of-range scores; arbitrary text/fields; oversized request/response; invalid scan shape/count/version; repeated consume и cross-batch replay. Отдельная интеграционная проверка должна подтвердить отсутствие вызова signer и SQL publication на malformed output. Реальный worker и оба storage paths сохраняют качество и проверяемую подпись.

Полный M20 также требует live попыток чтения labels, signer, DB, tokens, `/proc` соседнего controller и admin API под worker identity. Этот protocol slice не объявляется завершением всего M20 или R1.
