# PB-12 / RB-25 / RB-26: отказ модели и повторная квалификация

Сфера: [linear-onnx-v2](../model-contract.md), owned synthetic lab. Ответственные: ML engineer за export/parity, platform operator за worker/source, security reviewer за неподдерживаемые или изменённые artifacts. Не production recovery и не разрешение promotion.

## PB-12: диагностика до изменения состояния

Prerequisites: корень этого репозитория, pinned uv/Python environment, для native шага Docker Linux. Не передавать неизвестную модель в host Python/ORT вручную. Suite ниже использует только созданные им synthetic fixtures, ничего не скачивает и не читает production holdout.

Read-only относительно сервисов, SQL и release state (coverage пишет локальный diagnostic file):

```powershell
git status --short
git rev-parse HEAD
docker image inspect trusted-mlsecops:dev --format '{{.Id}} {{json .Config.Labels}}'
uv run --locked coverage run --source=mlsecops.model --data-file=.coverage-model-contract -m scripts.model_contract_qualification
if ($LASTEXITCODE -ne 0) { throw 'model contract failed' }
uv run --locked coverage report --data-file=.coverage-model-contract --fail-under=100
if ($LASTEXITCODE -ne 0) { throw 'model coverage failed' }
```

Expected: 18 methods pass; 89 statements/26 branches, 100%; реальный экспорт и 1000-row parity <=1e-5. Наличие image label не доказывает соответствие source само по себе: штатный runner также проверяет fingerprint. При отсутствии image первый docker command неуспешен; это prerequisite, не отказ модели.

**Изменяющий этап**, только в новой явно принадлежащей этому эксперименту папке. Build обновляет local dev image tag, не перезапускает работающие сервисы. Qualification создаёт keys, datasets, candidates/evaluations и ограниченные временные workers в новом lab state. Не выполнять поверх рабочего state и не выдавать новую лабораторию за reset доступного holdout budget:

```powershell
$state = '.runtime/model-contract-recheck-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
if (Test-Path -LiteralPath $state) { throw 'fresh state required' }
uv run --locked python -m mlsecops build
if ($LASTEXITCODE -ne 0) { throw 'worker build failed' }
uv run --locked python -m mlsecops.qualification --state $state
if ($LASTEXITCODE -ne 0) { throw 'native qualification failed' }
```

Сверить свежий `evidence/developer-qualification.json`, три runs, source/image, probability difference и parity. Его full_acceptance остаётся inconclusive. Private state содержит ключи/данные и не попадает в Git. SQL permissions, tracking service и cluster этой процедурой не меняются. Временные workers убирает штатный runner; если остался контейнер, сначала установить его ownership, не применять global prune.

## RB-25: scanner/loader отвергает artifact

| Симптом | Проверка | Безопасное действие |
| --- | --- | --- |
| model_size_rejected / model_parse_rejected | Тип, размер, upstream receipt/hash без загрузки на host | Quarantine; исправить bounded transport/export, не переименовывать pickle в ONNX |
| model_structure_rejected / model_topology_rejected | Exporter version, IR/opsets, точная заявленная архитектура | Воспроизвести штатный export; другой model family требует reviewed profile |
| model_tensor_interface_rejected / model_interface_rejected | Число features, динамический batch, output shape/type | Исправить exporter/schema, не переставлять столбцы при serving |
| model_attribute_contract_rejected / model_parameter_rejected | Attributes, lengths, finite bounds, positive scale | Проверить preprocessing и параметры training; сохранить rejected artifact digest |
| model_binary_classifier_rejected | Class labels [0,1], LOGISTIC, бинарная parameter symmetry | Исправить согласованный exporter, не ослаблять смысл положительного класса |
| model_unknown_fields_rejected | Совместимость pinned schema/exporter; возможная неподдерживаемая подмена | Не очищать поля и не продолжать; ML/security review и повторная qualification |
| model_check_rejected / model_runtime_rejected | Версии locked environment и isolated worker exit | Сохранить закрытые logs; не выводить raw exception/модель в public issue |
| Отказ scan receipt | Policy v2, ровно 2 nodes, image/source binding | Новый штатный evaluation, не правка signed v1 report |

Установленная причина этого increment: operator allowlist не проверяла весь application contract, а protobuf сохранял неизвестное поле. Это воспроизведено synthetic negative tests. Не утверждать, что наблюдалась атака на production. После исправления каждый неподдерживаемый fixture отвергается до вызова ORT constructor; реальный clean export продолжает исполняться.

**Rollback:** не возвращать v1 guard как способ пропустить отказ. Сохранить последний действительно approved и не отозванный release только если его совместимость и trust подтверждены полным release controller. Такой serving rollback ещё не реализован в текущем increment: здесь безопасный исход - оставить candidate unapproved и сохранить evidence. Если clean pinned export стабильно не проходит, остановить выпуск и передать owner/exporter версии, source/image digests и fixed reason code; секреты/байты остаются приватными.

## RB-26: неверные outputs или несовпадение Python/ONNX

1. Прекратить использование результата при prediction_shape_rejected, prediction_range_rejected, prediction_label_rejected или prediction_runtime_rejected. Не нормализовать ошибочный output постфактум и не подставлять probability=0.
2. Сверить feature schema, порядок шести features, положительный class label, фактические candidate bytes и pinned environment. Различать wrong artifact, неподдерживаемый export и обычную погрешность вычислений.
3. Повторить PB-12 на собственном synthetic state. Проверить оба столбца probability, сумму строк и labels. Parity сравнивает те же 1000 golden rows с sklearn, не новый удобный набор после неудачи.
4. Если отличие превышает 1e-5, зафиксировать failure и ML review; не увеличивать epsilon после результата. Runtime fault test использует контролируемую инъекцию, не доказывает recovery от segfault/OOM.
5. Финальный критерий исправления: отрицательные fixtures остаются rejected, clean export/1000-row parity проходит, native свежие runs дают проверяемый report, regression CI завершён. Даже тогда M09/M21/M18 не получают автоматический pass.

Остаточные ограничения: полноценные timeout/crash/path/conversion scenarios и OOD abstain ещё запланированы. Generic worker_failed не позволяет отличить корректное отклонение модели от native crash; нельзя считать любой ненулевой exit достаточным evidence security pass.
