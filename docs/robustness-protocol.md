# Ограниченная evasion-проверка и abstain

Протокол synthetic-lab-v1, зафиксирован 2026-10-13 **до первого измерения этой campaign**. T12/M09, не production и не общий adversarial robustness certificate. Результаты добавляются отдельно, параметры по ним не подбираются.

## Предварительный контракт

- Тренировка: неизменные первые 14 000 строк pinned data.lock, seed=17, прежний StandardScaler + LogisticRegression. Validation: следующие 3 000 строк, только parity. Final holdout не оценивается, SQL budget не сбрасывается.
- Research probes: 3 000 synthetic entities, seed=73041, IDs от 2 000 000. Проверяется отсутствие совпадающих IDs/feature vectors с исходным dataset. Эти probes станут известными после публикации; они не независимый reviewer challenge и не замена M07.
- Attacker меняет только `change_size` и `change_entropy` на inference, без изменения labels/остальных признаков. Это гипотеза laboratory feature-space attacker, не утверждение о реально управляемых production-признаках.
- Бюджет L-infinity=0.05 в нормализованных единицах для каждой из двух координат, максимум L1=0.10. Область каждой координаты [0,1]. Четыре corner queries на строку, плюс ранее полученный clean response; retain-noop, если ни одна атака не уменьшила score. Цель - минимизировать вероятность label 1. Labels не передаются атакующему selector или prediction worker.
- Clean/attacked recall на одном полном наборе positives, threshold=0.5; допустимое падение <=0.05 по M09. Минимум 200 positives и ровно 3 000 probes. Ни abstain, ни потерянные ответы не исключают строки из знаменателя ради pass. Неверный protocol - reject, недостаточная выборка - inconclusive, нарушение порога - fail.
- Четыре corners покрывают экстремумы выбранных двух координат для текущей монотонной линейной модели. Это не общая стратегия для нелинейных моделей, categorical features или другого attacker budget.

## Контракт abstain для будущего serving

Не более 100 строк по шесть конечных чисел. Ошибка shape/type, bool, NaN/Inf или переполнение - reject до исполнения. Конечная строка вне известного synthetic support [0,1]^6 получает `abstain`, `score=null`, `reason=outside-support`, без передачи в predictor. Поддерживаемые строки смешанного batch сохраняют порядок. Ошибка predictor не маскируется abstain.

Это только **domain-support guard**, не статистический novelty detector: совместный distribution shift внутри [0,1]^6 не обнаруживается. Нельзя обучить произвольный detector и объявить его надёжным на данных без реального calibration corpus. [scikit-learn различает novelty и outlier detection](https://scikit-learn.org/stable/modules/outlier_detection.html); выбор зависит от предположений о training/reference data. [Рекомендации по leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage) требуют отделять данные обучения от оценки. Источники проверены 2026-10-13; здесь выбран явный ограниченный guard, а не неподтверждённая статистическая гарантия.

## Границы реализации

У core-функции нет HTTP endpoint, release approval или обхода trusted loader. Native research использует штатные network-none workers и независимый intake до prediction. Материалы и scores сохраняются приватно; публичный отчёт содержит aggregate metrics и digests. Полный M09 потребует включения этого поведения в release/serving contract и проверенного общего acceptance runner. M08, image audit и остальные release blockers остаются обязательными.
