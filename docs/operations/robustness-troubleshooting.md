# PB-18 / RB-36: evasion failure и abstain

Владелец: MLSecOps lab operator/model reviewer. Область: synthetic CPU research, отдельная campaign в owned workspace. [Протокол](../robustness-protocol.md) фиксирует данные, budget, признаки и thresholds до измерения. Это не production-инцидент и не независимый reviewer challenge.

## Встретившаяся проблема

Первый native replay 2026-10-13 завершил все восемь worker executions и primary material reconciliation, но recall упал с 0.8383673469387755 до 0.7665306122448979: 88 потерянных true positives из 1225 positives, падение 0.07183673469387755 при лимите 0.05. Это **статистическое нарушение**, не зависший процесс или ошибка Docker. Fail остаётся fail; увеличение допустимого падения или уменьшение attacker budget не является исправлением модели.

Domain-support guard отдельно подтвердил 12 abstentions без inference и корректный порядок mixed batch. Его успех не устраняет evasion внутри допустимой области. Full M09 остаётся не принятым; image/poisoning gates не отменяются.

## Технологии и границы

Evasion означает изменение признаков на этапе предсказания, а poisoning - изменение обучения. Этот probe меняет только две заранее выбранные нормализованные координаты, не labels и не training data. Четыре corner queries выполняются штатным ONNX worker без сети, ключей, mounts и SQL credentials.

Abstain - явный отказ от ML-ответа, здесь `score=null` для конечных чисел вне synthetic support. Это не JSON validation error и не доказательство обнаружения всех необычных данных. NaN/Inf, неправильная форма и bool отвергаются до predictor; runtime failure не маскируется abstain. Core ещё не предоставляет публичный HTTP endpoint или обход signed loader.

## RB-36: сначала read-only диагностика

1. Прочитать только агрегаты `.runtime/evidence/robustness.json`: `execution_status`, `status`, `reason`, `campaign_id`, source/image/protocol, metrics, parity и `primary_reconciliation`.
2. `execution_status=complete`, `primary_reconciliation=pass`, `metrics.status=fail` означают завершённый эксперимент с нарушением policy. Не повторять его в надежде получить лучший seed.
3. При `reason=robustness_persisted_material_changed`, `selection_binding` или `metrics_binding` проверить исходные private files и hashes. Не переписывать summary или expected hash ради pass. При утрате материалов считать evidence неполным.
4. При `image_source_fingerprint_mismatch_rebuild_required` собрать новый source-bound image; старый report остаётся историческим. При `worker_deadline/worker_failed` проверить доступный CPU/RAM и наличие своего terminal container; не выполнять global prune и не менять resource/security limits для ложного pass.
5. При mixed-batch mismatch проверить позиции supported/abstain и tolerance. Разные batch sizes могут давать небольшой floating-point error; применяется заранее существующий `repeat_tolerance=1e-6`, а не произвольное округление до совпадения.

Пример безопасного просмотра агрегатов PowerShell:

```powershell
$report = Get-Content .runtime/evidence/robustness.json -Raw | ConvertFrom-Json
$report | Select-Object status,execution_status,campaign_id,metrics,parity,outside_support_abstentions,primary_reconciliation | ConvertTo-Json -Depth 5
```

Не публиковать train/probes/scores/request-response files или keys. Вывод aggregate metrics разрешён для этой synthetic campaign, но не автоматически для будущих приватных данных.

## PB-18: воспроизведение

Prerequisites: pinned uv/Python, Docker Linux amd64, достаточный ресурсный headroom. Source image и host scripts должны оставаться неизменными до завершения. В рамках теста ничего не устанавливается в training containers.

```powershell
uv sync --locked --python 3.12.15
uv run --locked python -m unittest scripts.robustness_qualification scripts.robustness_native_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops bootstrap --state .runtime/robustness-replay
uv run --locked python -m scripts.robustness_native --state .runtime/robustness-replay
```

Последние три команды изменяют локальное состояние: собирают image, создают новый owned lab workspace/keys и сохраняют свежую research campaign. Не указывать чужой nonempty directory. `workspace_id` проверяется; рабочий SQL ledger не подключается. Полный локальный replay выполнялся на существующем owned `.runtime`; fresh workspace sequence также проверяется CI, фактические результаты указаны в STATUS. Exit 1 при наблюдаемом threshold violation ожидаем, но его нельзя подавлять в CI. Exit 2 означает inconclusive, не approval.

## Восстановление, rollback и эскалация

Сначала сохранить fail evidence. Для functional regression откатить код к reviewed compatible version и повторить на новом source-bound image, не подменяя прошлые artifacts. Для измеренной уязвимости модели нужен новый заранее описанный mitigation experiment: feature provenance, обоснованная adversarial training/decision policy и проверка utility/false positives на новых независимых probes. Нельзя выбирать параметры по опубликованным probes и затем называть их untouched holdout. До подтверждения mitigations выпуск блокируется, безопасный operational fallback - manual review без ML.

Escalate model reviewer при превышении recall drop, неизвестной возможности управлять признаками или необходимости менять policy. Escalate platform operator при mismatch source/image/ownership или утрате evidence. Это инструкция дальнейших действий, не заявление, что mitigations или production recovery уже выполнены.
