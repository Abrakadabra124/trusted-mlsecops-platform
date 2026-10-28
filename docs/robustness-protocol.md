# Ограниченная evasion-проверка и abstain

Протокол synthetic-lab-v1, зафиксирован 2026-10-13 **до первого измерения этой campaign**. T12/M09, не production и не общий adversarial robustness certificate. Результаты добавляются отдельно, параметры по ним не подбираются.

[Проверенный результат local/clean-checkout CI](evidence/robustness-2026-10-13.md): guard и исполнение работают, но recall drop=0.07183673469387755 >0.05. Это statistical fail; неизменённый протокол и negative outcome остаются опубликованными.

## Предварительный контракт

- Тренировка: неизменные первые 14 000 строк pinned data.lock, seed=17, прежний StandardScaler + LogisticRegression. Validation: следующие 3 000 строк, только parity. Final holdout не оценивается, SQL budget не сбрасывается.
- Research probes: 3 000 synthetic entities, seed=73041, IDs от 2 000 000. Проверяется отсутствие совпадающих IDs/feature vectors с исходным dataset. Эти probes станут известными после публикации; они не независимый reviewer challenge и не замена M07.
- Attacker меняет только `change_size` и `change_entropy` на inference, без изменения labels/остальных признаков. Это гипотеза laboratory feature-space attacker, не утверждение о реально управляемых production-признаках.
- Бюджет L-infinity=0.05 в нормализованных единицах для каждой из двух координат, максимум L1=0.10. Область каждой координаты [0,1]. Четыре corner queries на строку, плюс ранее полученный clean response; retain-noop, если ни одна атака не уменьшила score. Цель - минимизировать вероятность label 1. Labels не передаются атакующему selector или prediction worker.
- Clean/attacked recall на одном полном наборе positives, threshold=0.5; допустимое падение <=0.05 по M09. Минимум 200 positives и ровно 3 000 probes. Ни abstain, ни потерянные ответы не исключают строки из знаменателя ради pass. Неверный protocol - reject, недостаточная выборка - inconclusive, нарушение порога - fail.
- Четыре corners покрывают экстремумы выбранных двух координат для текущей монотонной линейной модели. Это не общая стратегия для нелинейных моделей, categorical features или другого attacker budget.

## Исполняемый M09 для существующего кандидата

С 2026-10-29 [gate](../mlsecops/robustness_gate.py) подключён к `mlsecops.acceptance --gate M09`. Он требует уже evaluated candidate в owned storage и текущий source-bound image. Общий [candidate reader](../mlsecops/candidate_subject.py), используемый также M08, проверяет подписанную lineage, policy, identities, source/image, dataset/run/model digests и повторное SQL чтение.

Контрактные fixtures безопасного формата выполняются отдельным Python subprocess: реальные ONNX bytes, forbidden pickle, custom domain/operator, external tensor path, oversized/extra graph и guard до вызова runtime constructor. Проверяются точные 35 case IDs и отсутствие skips; controller получает только итог, без импорта ONNX parser. Это controlled проверка настоящего parser, не доказательство невозможности любых parser exploits.

Далее fresh reference campaign повторяет исходный training request на закреплённых train/validation и frozen probes. M09 перечитывает 28 primary files, проверяет train/validation/probes и exact training request против текущих материалов. Отдельный prediction worker получает **bytes существующего candidate**: 3 000 golden cases + 3 000 clean probes + 4 x 3 000 corners. В отчёт входят actual-candidate Python/ONNX parity, label equality вне epsilon-зоны, replay против reference, заново выбранные adversarial scores и recall drop. Model digest reference явно отделён от model_digest кандидата.

12 outside-support fixtures должны abstain без вызова predictor; mixed batch проверяет позиции и одно фактическое предсказание. Повторный subject/source/material readback завершает проверку. Proof request/response остаётся в `.runtime`; публично выводятся aggregates, case outcomes и digests. **Native проверка нового gate ещё требуется**; реализация dispatch не означает passing M09. Порог recall drop <=0.05, frozen probes и остальные M01-M23 не изменены. [Evidence](evidence/m09-candidate-2026-10-29.md), [ранбук](operations/robustness-troubleshooting.md#исполняемый-m09-на-текущем-candidate).

## Контракт abstain для будущего serving

Не более 100 строк по шесть конечных чисел. Ошибка shape/type, bool, NaN/Inf или переполнение - reject до исполнения. Конечная строка вне известного synthetic support [0,1]^6 получает `abstain`, `score=null`, `reason=outside-support`, без передачи в predictor. Поддерживаемые строки смешанного batch сохраняют порядок. Ошибка predictor не маскируется abstain.

Это только **domain-support guard**, не статистический novelty detector: совместный distribution shift внутри [0,1]^6 не обнаруживается. Нельзя обучить произвольный detector и объявить его надёжным на данных без реального calibration corpus. [scikit-learn различает novelty и outlier detection](https://scikit-learn.org/stable/modules/outlier_detection.html); выбор зависит от предположений о training/reference data. [Рекомендации по leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage) требуют отделять данные обучения от оценки. Источники проверены 2026-10-13; здесь выбран явный ограниченный guard, а не неподтверждённая статистическая гарантия.

## Границы реализации

У core-функции нет HTTP endpoint, release approval или обхода trusted loader. Native research использует штатные network-none workers и независимый intake до prediction. Материалы и scores сохраняются приватно; публичный отчёт содержит aggregate metrics и digests. Полный M09 потребует включения этого поведения в release/serving contract и проверенного общего acceptance runner. M08, image audit и остальные release blockers остаются обязательными.
