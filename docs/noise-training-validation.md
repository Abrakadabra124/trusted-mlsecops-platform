# CP2: validation перед исправлением обучения

Протокол зафиксирован 2026-10-29 до первого результата нового варианта. Причина: R1-B02, измеренные отказы M08 (5% poisoning) и M09 (recall drop >0.05). Это разработка исправления обязательного блокера, не новый release gate.

Один вариант: generalized cross entropy, `q=0.7`, на worst-case signed margin линейного классификатора. Функция потерь `(1-sigmoid(margin)^q)/q` ограничивает вклад сильно противоречащей метки. Идея взята из [Zhang и Sabuncu, NeurIPS 2018](https://proceedings.neurips.cc/paper_files/paper/2018/file/f2925f97bc13ad2852a7a551802feea0-Paper.pdf). Перенос на adversarial linear CPU profile является нашей гипотезой: результаты статьи на image classification не доказывают устойчивость нашего candidate к targeted poisoning.

Для обучения используется box radius 0.10 только для change_size/change_entropy с clipping [0,1]. Более консервативный training radius не меняет evaluation attacker radius 0.05/L1 0.10. Все шесть признаков сохранены. L2 `C=1`, StandardScaler обучается только на train, инициализация обычной logistic regression, L-BFGS-B/maxiter 500/ftol 1e-12/gtol 1e-8. Это невыпуклая задача; numerical stationarity <=1e-5 не доказывает глобальный минимум. При ошибке solver или ухудшении objective результат отвергается, silent fallback отсутствует.

Данные: воспроизвести data.lock, использовать только первые 14 000 train и следующие 3 000 validation. Генератор создаёт исходные bytes целиком для проверки lock, но final holdout не передаётся fit/scoring, его labels не оцениваются. Публичные frozen M08/M09 probes и paired research probes не вызываются. Неизменный baseline и вариант проходят clean training и по две label-flip/backdoor train-only мутации 700 строк с development seeds 619/631. Это 10 fits, не замена 35 M08 trainings или независимых M22 challenges.

До просмотра результата фиксируются условия перехода к native проверке: clean validation AP >=0.80, gain >=0.10, loss к clean baseline <=0.03; evasion recall drop <=0.05 при threshold 0.5; для всех четырёх poisoned variants исходные M08 AP/ASR/denominator thresholds. Все случаи сохраняются. Неуспех любого условия оставляет вариант непринятым. Brier score, recall и false-positive rate сообщаются отдельно, без утверждения калибровки или бизнес-utility. После результата нельзя менять параметры и выдавать повтор за исходный эксперимент.

Локальный запуск допускает только Python CPU development на синтетике. Он не загружает существующие ONNX, не запускает Docker/WSL/SQL/Kubernetes, не обращается к GitHub или сервисам и не меняет подписанный candidate. Публикуются только код, агрегаты и digests; сырые scores/rows остаются вне Git. До отдельного source-bound hosted CI, ONNX parity, M07/M08/M09/M22 и общего M18 нет принятия алгоритма в основной worker или разрешения release.

## Первый результат и решение

2026-10-29, Windows/Python 3.12.15, numpy 2.5.3/scipy 1.18.1/scikit-learn 1.9.1: завершены 10 fits. Clean baseline AP 0.931912, вариант 0.911508 (loss 0.020404). Evasion drop снизился с 0.066990 до 0.043584. Но все четыре poisoning cases остались fail: upper ASR 0.145337-0.146433 >0.10. Вариант **не принят**, основной worker не меняется.

Дополнительная цена: clean recall 0.834544 ->0.786118, FPR 0.097672 ->0.105622, Brier 0.090079 ->0.110714. Улучшение одной robustness-метрики не скрывает ухудшение других. Первое исполнение остановилось на передаче numpy array вместо list в существующий строгий prediction protocol; это исправлено преобразованием на границе, а не ослаблением валидации. Первая попытка не содержала завершённого candidate result.

## Диагностика и воспроизведение

### Вариант v2, до первого результата

Следующая гипотеза фиксируется отдельно после отказа v1: при том же `q=0.7`, training radius 0.10 и неизменных validation/attack thresholds применить balanced weights `N/(2*n_class)` к bounded loss. Вес определяется только наблюдаемыми train labels, без clean-reference labels, validation fitting, знания poisoned indices или final holdout. Формула соответствует [scikit-learn compute_sample_weight](https://scikit-learn.org/stable/modules/generated/sklearn.utils.class_weight.compute_sample_weight.html). Проверяются те же два development seeds; это повторная разработка на известной validation, не независимый challenge.

Веса меняют обучаемую функцию риска и границу решения, поэтому вероятность от sigmoid нельзя объявлять откалиброванной вероятностью инцидента. Threshold остаётся 0.5; recall/FPR/Brier и AP loss сообщаются вместе с результатом, все прежние условия допуска сохраняются. Это гипотеза о компенсации class imbalance, не доказанная коррекция class-conditional poisoning. V1 доступен без флага, v2 запускается явным `--balanced`; результаты хранятся раздельно.

### V2: validation pass и следующая native проверка

Второй результат, 2026-10-29: 10 fits, validation **pass**. AP 0.9116318703419971 (baseline 0.9319120498018768, loss 0.0202801794598797), evasion drop 0.043583535108958835, 1 239 positives. Все четыре poisoning cases: upper ASR 0.016913306348599885, eligible 1 083, max AP loss 0.0054459769173361705. Чистый recall 0.87409200968523, FPR **0.1635434412265758** против baseline 0.097671777399205, Brier **0.11304204755637928** против 0.09007855163491003. Эти издержки не скрываются. Данные/thresholds не менялись, final holdout и frozen probes не оценивались этим script.

После validation variant вынесен в [noise_training](../mlsecops/noise_training.py) и подключён как versioned `train` на ветке candidate trial. Прежнее обычное обучение доступно только как `reference-logistic-train` для исторического paired experiment; scoped controllers запрещают эту action. Worker протокол сохранён, recipe/source/image связаны существующим provenance; параметры release descriptor теперь явно называют новый алгоритм. Recipe не является approval. Автоматического переноса старого pass на новый source нет.

[Отдельный hosted workflow](../.github/workflows/model-candidate.yml) повторяет validation, создаёт одно evaluated SQL candidate и выполняет полные M08/M09 на его bytes. Проверяются actual ONNX parity, frozen probes, poisoned trainings, primary readback и cleanup. До terminal результатов это **не native pass** и не принятие CP2. M07 полная приёмка, M06, image audit, M22 и CP3-CP5 также остаются обязательными.

Ответственный: разработчик модели. Prerequisites: locked Python environment, разрешённая synthetic-only CPU development, сохранённые data.lock и protocol. Команда:

```text
uv run --locked python -m unittest scripts.noise_training_qualification scripts.robust_training_qualification
uv run --locked python -m scripts.noise_training_validation
uv run --locked python -m scripts.noise_training_validation --balanced
```

Каждый validation запуск сохраняет private primary scores/coefficients и report в новом `.runtime/noise-validation/<uuid>/`; последнее завершённое evidence находится в `.runtime/evidence/noise-validation.json` или `noise-validation-balanced.json`. Exit 1 при плохих метриках ожидаем и не означает сбой runtime. Ошибка до завершения оставляет campaign inconclusive; нельзя брать старый summary за новый результат. Сверить время/source digests и все десять cases.

При source lock mismatch остановиться и проверить изменённые inputs; не переписывать lock ради зелёного запуска. При solver failure не подставлять baseline. При statistical fail сохранить все результаты, зафиксировать новую гипотезу до нового fit и не запускать frozen acceptance до готовности. Validation script не меняет SQL candidate. Native workflow создаёт только disposable owned storage и в конце проверяет State.Running=false; production promotion отсутствует. При native failure сохранять отказ и не переносить trial в main как принятый candidate. Следующее изменение алгоритма требует отдельного versioned протокола и полной приёмки.
