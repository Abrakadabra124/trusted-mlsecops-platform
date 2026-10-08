# Prediction protocol v2

Компонент [T26/M20](acceptance.md#m20) связывает response недоверенного model worker с конкретным запросом scorer. Решение и границы: [ADR 0011](decisions/0011-prediction-protocol.md). Текущие результаты и CI находятся в [STATUS](../STATUS.md); protocol pass не закрывает весь M20.

## Как работает

1. Scorer создаёт новый `PredictionBatch` с bytes модели и ordered features, без holdout labels. Случайный 128-bit nonce обозначает batch; IDs имеют вид `nonce:position`, не содержат исходные entity IDs и не используются между runs.
2. Request v2 имеет ровно шесть полей: `schema_version`, `action`, `model`, `features`, `batch_id`, `row_ids`. Канонический JSON фиксируется внутри pending object; внешнее изменение копии request не меняет ожидаемый digest. SHA-256 связывает байты, но не является подписью или доказательством правильного вычисления.
3. Offline worker проверяет request, загружает ONNX только в своём процессе и возвращает version/action/batch, request/model digests, ordered `predictions` и ограниченный `scan`. Каждый prediction содержит ровно `row_id` и `score`.
4. Scorer проверяет version как integer, точные поля, nonce/digests, число и порядок IDs. Он не сортирует response, чтобы не скрыть ошибочную перестановку. Probability должен быть числом, но не boolean, находиться в [0, 1]; NaN, Inf и неизвестные fields отвергаются.
5. Даже неуспешная попытка consume делает pending object использованным. Повтор того же ответа или поздний «исправленный» ответ не принимается. Новый run создаёт новый nonce. Transport failure прекращает run, без автоматического переиспользования request.
6. Только после этих проверок scorer считает метрики и вызывает signer. Signed report содержит request/response digests, число rows, protocol version и фактические execution metadata отдельного prediction worker. Features/labels и raw worker logs в него не включаются.

## Что ограничивается

JSON request и response ограничены 16 MiB. Это верхняя граница protocol, а не обещание принять любой payload такого размера: Kubernetes transport имеет дополнительный compressed ConfigMap limit, native model parser и admission задают другие ограничения. Features ограничены действующей схемой и максимумом 20 000 rows.

`scan` принимает только фиксированный ONNX/linear profile, установленную pinned ONNX version, положительное bounded число inspected nodes и нулевые unsupported/skipped/errors. Эти проверки не позволяют публиковать произвольный текст вместо scan, но **не превращают self-report worker в независимый security audit**. Full M21 coverage-aware intake остаётся отдельным требованием.

Протокол обнаруживает переставленные или продублированные response records. Он не доказывает, что злонамеренный worker действительно вычислил правильные scores или не прикрепил ложное значение к правильному ID. Для этого нужны остальные evaluation/challenge controls; cryptographic digest не проверяет семантику модели.

Single-use state действует внутри одного последовательного controller run. После crash объект не восстанавливается для повторного consume. Это не persistent holdout query budget, не блокировка повторного обучения/оценки candidate и не release replay prevention. M07 и M11 должны реализовать собственные долговременные ограничения.

## Проверка и обновление

Для unit/controlled integration suite нужен уже инициализированный workspace:

```bash
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops.prediction_protocol_qualification
```

Report: `.runtime/evidence/prediction-protocol-qualification.json`. Suite использует искусственные model bytes без parser, mutations response/request и spies на signer/SQL writer. Она доказывает отказы до этих вызовов в проверенном кодовом пути, не настоящий SQL authorization и не сетевую изоляцию. Native Docker и Kubernetes paths проверяются отдельно:

Локально unit/controlled integration suite содержит 164 проверки. Coverage для одного `mlsecops.prediction_protocol` составил 100% statements/branches (71 statements, 28 branches); CI требует этот результат отдельно. Это не coverage всех security branches платформы, не native parser coverage и не закрытие M18. Повторяемый замер:

```bash
uv run --locked coverage run --source=mlsecops.prediction_protocol --data-file=.runtime/evidence/protocol.coverage -m mlsecops.prediction_protocol_qualification
uv run --locked coverage report --data-file=.runtime/evidence/protocol.coverage --fail-under=100
```

Реальное исполнение:

```bash
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.qualification
uv run --locked python -m mlsecops.controller_bootstrap --replace-profile
uv run --locked python -m mlsecops.controller_qualification
```

Последние две команды требуют готового [scoped controller lab](scoped-controllers.md) и отсутствия активных Jobs при replace. Worker и controller обновляются вместе, fallback на prediction v1 отсутствует. Training protocol не меняется. Старые подписанные evaluation artifacts не переписываются и не получают задним числом v2 evidence.

Recovery и migration golden verifiers используют тот же helper. Полную migration suite нельзя повторно запускать со сбросом populated target: новый verifier проверяется на чистом target в CI. После protocol change заново выполняются M03, storage recovery, controller suite и clean-checkout CI, а прежние зелёные reports сохраняются как история, не доказательство нового кода.

Код: [protocol](../mlsecops/prediction_protocol.py), [negative suite](../mlsecops/prediction_protocol_qualification.py), [scorer](../mlsecops/pipeline.py), [worker](../mlsecops/worker.py).
