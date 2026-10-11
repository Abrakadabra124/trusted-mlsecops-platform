# ADR 0019: замороженная оценка и проверка подписанного report

Дата: 2026-10-11. Scope: T09/T10 и M07; реализованный компонент, пока не принятый полный gate. [Контракт и воспроизведение](../frozen-evaluation.md), [эксплуатация](../operations/evaluation-troubleshooting.md).

## Проблема

Прежняя функция смешивала нехватку данных и низкое качество в одном `fail`. Recall с нулевым denominator мог выглядеть как обычное числовое значение. Подпись подтверждала автора/целостность, но отдельного consumer API для сверки report с ожидаемым candidate и проверенным budget receipt не было. Это риск неверного решения downstream, даже если криптография работает.

## Решение

- Определение оценки в `evaluation_quality.definition` включено в source fingerprint worker/controller image. До чтения holdout SQL scorer сверяет профиль через `freeze`: только synthetic source, фиксированные label horizon, feature order и исходные пороги. Запрос не может ослабить пороги или добавить реальный immature dataset под именем lab.
- Политика содержит AP metric, baseline, slices, threshold 0.5, 95% paired IID percentile bootstrap, seed 73021 и 1 000 resamples. Её полное определение и digest входят в подписанный report. Definition возвращается новой копией; изменение переданных rules отвергается. Это code-bound frozen lab policy и self-review, не независимый production approval.
- Slices определяются по исходному проверенному JSON `change_size < 0.5` и `>= 0.5`. Нельзя сначала округлить вход до float32: значение 0.499999999 иначе оказалось бы на другой стороне границы. Float32 остаётся вычислительным типом обучения, но не меняет определение среза.
- AP baseline равен доле positive labels: все постоянные scores имеют одинаковый ranking. Это математический эквивалент AP для `DummyClassifier(strategy='prior')`, а не fit модели по holdout. Контракт проверяется настоящим DummyClassifier, обученным на двух отдельных train priors. Калибровка/precision/cost такой эквивалентностью не доказываются.
- `inconclusive`: <200 positive labels, <100 rows в любом заявленном slice, один класс или неопределённый slice recall. `fail`: достаточные данные, но AP <0.80 либо gain <0.10. `pass`: исходные lab thresholds выполнены. Undefined metric передаётся как JSON null, не ноль/NaN. Любой non-pass не является основанием для promotion.
- Интервалы используют одинаковые sampled indices для model AP и baseline prevalence. Это неопределённость фиксированной модели на IID synthetic entities, не variability retraining, не temporal/group bootstrap и не переносимость на бизнес. Если resample имеет один класс, он учитывается как undefined, а не незаметно удаляется из расчёта: интервалы inconclusive/null. В lab интервалы диагностические; первоначальные point thresholds не заменяются новыми CI thresholds.
- `read_evaluation` требует явно ожидаемый candidate reference. Он читает подписанный report и candidate из SQL, сверяет run/model/dataset/lineage/policy/image, полноту и согласованность метрик, scan/protocol, parity, frozen policy и существующий immutable holdout reservation. Promoter не получает права на labels, новые оценки или изменение истории. Проверка выполняется и после записи самим scorer.

## Почему так

Не добавлены orchestrator, новая БД, monitoring SDK или статистическая зависимость. Используются уже зафиксированные NumPy/scikit-learn и существующие SQL identities. Выбор policy code-bound сохраняет `data.lock` и не меняет approved dataset bytes; будущий production policy authority требует отдельного approval/migration design.

Подпись не заменяет семантическую валидацию и не доказывает честность скомпрометированного signer. Reader проверяет согласованность заявлений, но не пересчитывает AP из подписанного отчёта без vectors/labels. Истинность расчёта обеспечивается проверяемым trusted scorer, authenticated storage и текущим кодом; сохранение независимого полного evidence для итогового release остаётся обязанностью M07/M18/M23.

## Первичные основания

- [scikit-learn AP](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html): среднее precision, взвешенное приращениями recall. Не подменяем его трапецеидальной площадью PR curve.
- [DummyClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.dummy.DummyClassifier.html): prior возвращает постоянные probabilities по train distribution. Равенство его AP prevalence на evaluation set - математический вывод, дополнительно проверенный контрактом.
- [scikit-learn: data leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage): preprocessing fit только по train. Контракт вызывает настоящие fit/export и фиксирует аргументы StandardScaler при изменении validation features.
- [SciPy bootstrap](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.bootstrap.html): paired resampling, percentile intervals и ограничения вырожденных выборок. Использована та же базовая схема с NumPy RNG без добавления новой прямой зависимости.

Источники проверены 2026-10-11. Bootstrap не является гарантией устойчивости к poisoning, fairness или production utility.
