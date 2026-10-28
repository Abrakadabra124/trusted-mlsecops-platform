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

### Подтверждённый native результат 2026-10-29 МСК

Исправленный [run 40784079343](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40784079343), job `123152789443`, commit `e7d166e98b28b2a9e2264c079f6efeb0940c1660`, завершился **success**, source_dirty=false. M08 выполнялся 02:00:43-02:05:37 МСК, M09 02:05:37-02:05:57 МСК. Owned SQL остановлен с проверкой `State.Running=false`.

| Проверка | Фактический результат |
| --- | --- |
| M08 | **pass**, 68 checks, 35 trainings / 35 predictions, 30 poisoned + 5 controls, 35 nonviolating / 0 violating / 0 inconclusive |
| M08 primary | 251 files reconciled, actual-candidate replay error 0.0 |
| M08 thresholds | max upper ASR **0.01535139014528554** <=0.10, max AP drop **0.004749635293563759** <=0.03, min eligible **1 109** >=500 |
| M09 | **pass**, 42 checks, 18 001 actual-candidate predictions, 28 primary files, 12 outside-support abstentions |
| M09 parity | 3 000 golden rows, max absolute error **2.5171979389781995e-07** <=1e-5, 0 label mismatches, reference replay 0.0 |
| M09 evasion | 1 225 positives, clean TP 1 056 -> attacked TP 1 017, recall drop **0.03183673469387755** <=0.05 |
| Signed evaluation component | Holdout AP **0.9132159424391436**, gain **0.5058826091058103**; 1 000 valid diagnostic bootstrap resamples. Это component evaluation, не вся M07 negative suite |

Общие привязки **обоих gates**:

- Candidate: `9e2a2271b2fe4ad3852c8c1031a3bcbe54a463b3833ea6a4d5c012e52afcb4f4`.
- Evaluation: `d0f3ffa864eec6a11c26058ff30db47b6e191728e1e7d52c45b7439f26195fa6`.
- Model: `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`.
- Image config: `sha256:b5b667b93d15717564a60060199d94a5c51a8c57289e6d95296d84fa02df24e6`.
- Source fingerprint: `197f845e8fb67b0a92273beb4bad99d70c571c5a13b987bddc4b95ba2c5f9849`.
- Training input: `09732aa22f7b0a672c790ef63bb25494d7496ca858e70d591e5a1fdbbef8495d`.

Protocol и host_scripts hashes M08/M09 ожидаемо различаются: это разные проверки, а не разные models. Оба report сохраняют release_ready=false. Общая M18 не выполнена, независимые M22 challenges и system-image blockers не сняты.

[Paired v2 run 40784734008](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40784734008), job `123154973738`, commit `2d3e43ed383255dc8212b7823b4fabc3a96dd808`: **success**, 14 actual worker executions, primary reconciliation pass, source_dirty=false. На каждом из трёх прежних наборов кандидат прошёл quality, evasion и AP-loss guard:

| Probe | Candidate AP | AP loss к fresh original | Recall drop |
| --- | --- | --- | --- |
| 73041 | 0.9150660733 | 0.0207132911 | 0.0318367347 |
| 73043 | 0.9159978144 | 0.0192364949 | 0.0232365145 |
| 73047 | 0.9135283297 | 0.0173413778 | 0.0435153584 |

Три прежних baseline drops 0.07184/0.07386/0.07594 остаются fail. У нового варианта FPR 0.14989-0.16732 против baseline 0.09248-0.10310. Это известные regression probes, несмотря на исторические ключи `new-73043/new-73047`; они не независимые reviewer challenges. Candidate model bytes совпали с M08/M09, но image config другого build `sha256:13dbd148d8216b1f35c7e861fb8d6c40f4f0e0fd522176c2f62d32d9062edc53` и revision отличаются. Эти campaigns нельзя склеить в одну M18-приёмку.

До native прошли 47 numerical/model methods; coverage `noise_training`+`robust_training`: 123/123 statements, 28/28 branches. Gate contracts M08/M09 отдельно: 20 methods pass. Совместный запуск gate tests после format/release tests в одном Python process закономерно получил controller-parser rejection из-за ранее импортированного ONNX; отдельный process, как в CI, прошёл. Проверка boundary не отключалась. Release/evaluation/intake regression methods также прошли, кроме указанного нарушения порядка test isolation; это не покрытие всего проекта.

Ответственный: разработчик модели. Prerequisites: locked Python environment, разрешённая synthetic-only CPU development, сохранённые data.lock и protocol. Команда:

```text
uv run --locked python -m unittest scripts.noise_training_qualification scripts.robust_training_qualification
uv run --locked python -m scripts.noise_training_validation
uv run --locked python -m scripts.noise_training_validation --balanced
```

Каждый validation запуск сохраняет private primary scores/coefficients и report в новом `tmp/noise-validation/<uuid>/`; последнее завершённое evidence находится в `tmp/evidence/noise-validation.json` или `noise-validation-balanced.json`. `tmp/` исключён из Git. Каталог `.runtime` принадлежит platform bootstrap и не создаётся diagnostic script. Exit 1 при плохих метриках ожидаем и не означает сбой runtime. Ошибка до завершения оставляет campaign inconclusive; нельзя брать старый summary за новый результат. Сверить время/source digests и все десять cases.

Первая native попытка [40783732315](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40783732315), `9f50e23`: 47 contracts/100% двух training modules и Linux validation pass, но bootstrap отказал `refusing_nonempty_unowned_workspace`. Причина: прежняя версия diagnostic script создавала `.runtime/evidence` до ownership marker. M08/M09 не выполнялись; это не statistical failure. Исправление: development outputs в отдельном ignored `tmp/`, без отключения ownership check и без удаления существующих данных/keys. Исторические локальные результаты до исправления остаются в `.runtime` как private evidence. Нужен новый clean hosted run после исправления.

При source lock mismatch остановиться и проверить изменённые inputs; не переписывать lock ради зелёного запуска. При solver failure не подставлять baseline. При statistical fail сохранить все результаты, зафиксировать новую гипотезу до нового fit и не запускать frozen acceptance до готовности. Validation script не меняет SQL candidate. Native workflow создаёт только disposable owned storage и в конце проверяет State.Running=false; production promotion отсутствует. При native failure сохранять отказ и не переносить trial в main как принятый candidate. Следующее изменение алгоритма требует отдельного versioned протокола и полной приёмки.
