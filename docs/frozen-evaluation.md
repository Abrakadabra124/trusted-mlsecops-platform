# Независимая оценка: frozen policy и signed report

Статус: работающий компонент T09/T10. Полный M07 пока `inconclusive` через общий acceptance CLI; компонентный pass не заменяет его реализацию. [ADR 0019](decisions/0019-frozen-evaluation.md), [ранбуки](operations/evaluation-troubleshooting.md).

## Как устроен путь

1. Curator подписывает source/dataset/lineage. SQL отделяет train/validation от holdout. Источник остаётся synthetic-only, реальный label horizon не согласован.
2. Publisher запускает отдельный training worker. StandardScaler нормирует признаки, Logistic Regression обучает линейный классификатор, skl2onnx экспортирует его в ONNX. ONNX Runtime выполняет prediction; labels и signing key worker не получает.
3. Scorer проверяет frozen profile и signed dataset, занимает постоянный holdout slot, затем читает labels и передаёт worker только features. Typed prediction protocol проверяет порядок строк, model/request binding и числа до расчёта метрик.
4. `evaluation_quality` рассчитывает AP, постоянный baseline, gain, размеры срезов, TP/precision/recall и состояния pass/fail/inconclusive. TP - true positives, количество правильно предсказанных положительных случаев; explicit counts позволяют проверить согласованность ratios.
5. NumPy строит 1 000 paired IID resamples с seed 73021. Для каждого resample повторно вычисляются AP и baseline; сохраняются двухсторонние 95% percentile intervals. IID означает предположение независимых одинаково распределённых entities, выполняемое генератором лаборатории, но не произвольными production-релизами.
6. Ed25519/DSSE-подпись связывает политику, candidate и результаты. DSSE связывает тип документа с точными подписанными bytes. Новый `read_evaluation` проверяет не только подпись, но и ожидаемый subject, metric schema, арифметику, execution/protocol и постоянную резервацию из PostgreSQL. Результат остаётся `unapproved`, не разрешением на выпуск.

## Точный контракт

| Ситуация | Результат |
| --- | --- |
| AP >=0.80, gain >=0.10, достаточная выборка | quality pass только для lab |
| <200 positives или <100 rows в любом slice | inconclusive |
| Один класс, отсутствуют positives в заявленном slice | inconclusive; неопределённые metrics null |
| Данных достаточно, пороги не пройдены | fail |
| Неправильные labels, bool/NaN probabilities, wrong shape | reject до подписания |
| Ослабленная policy, другой источник или immature horizon | reject до SQL чтения candidate/holdout и budget spend |
| Чужой candidate, model, dataset, lineage, run или image | reader reject, даже при действительной подписи evaluator |
| Не хватает metric, нарушена арифметика/CI policy или нет reservation | reader reject |

AP в поле `auprc` - scikit-learn average precision, не trapezoidal area. Baseline не обучается на holdout; его AP вычисляется аналитически и проверен против настоящего train-fitted DummyClassifier. Версия библиотеки зафиксирована lockfile. Slices по `change_size` не являются группами fairness и не имеют гарантированной бизнес-интерпретации.

## Повторение с чистого checkout

Требования: uv, Python 3.12.15, Docker Linux amd64 и ресурсы из README. Новый локальный state, свободный loopback port, без paid cloud. Команды ниже создают отдельный стенд; не направлять qualification на рабочую БД.

```text
uv sync --locked --python 3.12.15
uv run --locked python -m unittest scripts.evaluation_quality_qualification scripts.evaluation_binding_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops bootstrap --state .runtime/evaluation-lab
uv run --locked python -m mlsecops.storage_bootstrap --state .runtime/evaluation-lab --port 15450
uv run --locked python -m mlsecops.evaluation_qualification --state .runtime/evaluation-lab
```

Report: `.runtime/evaluation-lab/evidence/evaluation-qualification.json`. Повторный запуск обучает свежий candidate и тратит новый holdout slot. Native negative fixtures намеренно сохраняются в append-only истории как отвергнутые объекты. Нельзя считать любую строку evaluations approved report или очищать историю для получения pass. Для exhausted budget действуют [PB-05/RB-08](operations/holdout-budget.md).

CI Storage выполняет contracts, coverage, настоящую SQL evaluation, recovery и budget campaign. Kubernetes/M20 отдельно проверяет scoped-controller путь; Docker host qualification сама по себе не доказывает Kubernetes isolation. Изменения frozen rules требуют нового source fingerprint/image и повторной проверки, а не редактирования подписанного report.

## Локальные измерения

На 2026-10-11: 31 unittest methods с положительными и отрицательными subcases; 24 native SQL/model checks. Actual preprocessing contract вызывает настоящие fit/export дважды с неизменным train и разными validation features и проверяет, что scaler видит только train. Это controlled host execution того же кода, не новый native training provenance sink.

Coverage модуля quality: 135/135 statements и 76/76 branches. Также прошли 74 developer regression checks, 164 prediction protocol checks и 16 budget contracts. Последний native report: 2026-10-11T12:50:42.963622Z, source fingerprint `d040d8fe9810eda1dcb76dff712d8d339c2028ce54c42ed8cdce023ef3ccfb95`, image `sha256:a375b3f8afbce0e3d05d58f780210de8d88bce321f72e789baebf568d10ce574`, report digest `f486b0823bfcdd294ac7a2892ddb9bac25521015c7a7cd7952b94a37dce10022`. Это dirty local checkout; clean-checkout CI учитывается отдельно в STATUS.

Реальная модель: 3 000 holdout rows, 1 222 positives; AP **0.9323007296445032**, baseline **0.4073333333333333**, gain **0.5249673963111698**. 95% IID diagnostic interval AP: **[0.9218861146500273, 0.9421175400584901]**, gain: **[0.5088475540872814, 0.5421550041037284]**, 1 000 valid resamples, 0 undefined.

Low-change: 1 533 rows/306 positives, precision 0.7971014492753623, recall 0.7189542483660131. High-change: 1 467 rows/916 positives, precision 0.8637803590285111, recall 0.8930131004366813. Эти числа не выбирают пороги задним числом и не доказывают пользу на настоящих релизах.

## Что остаётся для полной приёмки

Следующий increment подключил [executable M07](evaluation-gate.md): свежая campaign связывает проверки с текущими inputs и не принимает старый component report за итоговый pass. Проверенные результаты находятся в STATUS. T09/T10 сохраняют зависимости от полного T08 lifecycle. Реальный пилот отдельно требует утверждённых labels/horizon, temporal/group split, cost/precision/recall target, бизнес-baseline и соответствующих confidence intervals. Полный release/M18, protected audit и scanner blockers не закрываются хорошим AP.
