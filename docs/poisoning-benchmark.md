# Native poisoning benchmark: фиксированная матрица

## Что проверяется

[ADR 0020](decisions/0020-poisoning-benchmark.md) и [protocol](../scripts/poisoning.py) зафиксированы в commit `ad7196702542087150e57b1c7c54ebe6631128dc` до первого native результата. [Runner](../scripts/poisoning_native.py) сохранён следующим commit `b525362` до запуска. Это реализация 30 poisoned trainings + 5 controls из M08, не автоматическая приёмка всего M08 и не 36+6 M22.

Training использует первые 14 000 строк воспроизведённого data.lock source, validation - следующие 3 000. У каждого seed собственное свежее clean обучение и шесть poisoned обучений. Seed влияет на выбор повреждённых строк и передаётся classifier, но используемый `lbfgs` может дать одинаковые clean models: не заявляется пять независимых datasets или популяционная неопределённость между seeds.

Label flipping меняет positive label с 1 на 0. Backdoor family дополнительно ставит `change_entropy=1.0` на тех же выбранных train rows. До 5% всех train rows - это не 5% positive subset: в receipt сохраняются count, fraction, IDs и before/after digests. Остальные признаки, строки и validation не меняются. Контракт проверяет точное число изменений, reproducibility и input immutability.

Worker - прежний CPU Linux image: `StandardScaler` и `LogisticRegression`, ONNX export и отдельный prediction process без сети, host mounts, SQL credentials, keys и evaluation labels. Доверенный исследовательский controller сохраняет модели и считает метрики. Он не подписывает release и не публикует poisoned datasets как approved platform data.

## Почему отдельные security probes

3 000 probes генерируются заранее фиксированным seed в другом пространстве entity IDs. Проверяются отсутствие пересечения IDs и точных feature vectors со всем исходным source. Один и тот же probe существует в clean и trigger view; его label не меняется, предполагается манипуляция наблюдаемой telemetry. Для label-flip ASR используется clean view, для backdoor - trigger view с matched clean model на таком же входе.

Final holdout M07 не используется для этих 35 оценок. Рабочая БД, её cap 32, signing keys и ledger остаются неизменными. Возможность генерировать публичную синтетику и видеть source не означает секретность этой research suite. Известные probes нельзя многократно использовать для tuning и затем представлять как новую независимую приёмку.

## Что означает результат

- AP (average precision) измеряется на clean security samples; сравнивается падение относительно clean control того же seed.
- ASR (attack success rate) - false-negative fraction на positive probes, которые clean model на том же view определила корректно. Denominator >=500, иначе inconclusive.
- Пороги исходного M08: AP drop <=0.03 и upper ASR increase <=0.10. Считаются paired 2 000-resample 95% percentile bootstrap и Wilson interval. Решение использует больший upper bound, как заморожено в ADR, включая zero-event uncertainty.
- Все 35 scenarios сохраняются, даже если ранний case fail. Aggregate fail не прекращает сбор evidence и не превращается в exit 0; CLI returns 1. Если нет fail, но есть insufficient evidence, exit 2. Только все nonviolating дают component pass/exit 0.
- `pass` сценария не означает «атака обнаружена». Возможны слабая атака или отсутствие измеренного нарушения в заданном budget. Clean self-controls - sanity check и счётчик false rejection относительно самих себя, не оценка real-world false-positive rate.
- Native matrix не доказывает integrity enforcement: poisoned samples здесь намеренно обучаются в research пути для измерения. Production intake по-прежнему требует отдельно approved source. Общая M08 subject/material reconciliation и independent M22 challenges остаются работой следующих этапов.

## Воспроизведение

Prerequisites: locked Python/uv environment, Linux/amd64 Docker и current source-bound worker image. Платное облако/GPU не нужны. Этот command не read-only: выполняет 35 trainings и 35 predictions в disposable offline контейнерах, сохраняет экспериментальные артефакты локально.

```text
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.poisoning_qualification scripts.poisoning_native_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.poisoning_native
```

Частичная матрица, переиспользование run ID, неправильные counts/types или перестановка случаев не принимаются за полный результат. Нельзя указать subset seeds или resume с готовой моделью. При повторе создаётся новый campaign ID и выполняется вся фиксированная suite; это проверка воспроизведения, не новый независимый statistical sample.

Итог: `.runtime/evidence/poisoning.json`; campaign и per-case model/metadata/vectors/receipts: `.runtime/poisoning/<campaign-id>/`. В Git попадают только код, инструкции и очищенные выводы. [CI](../.github/workflows/poisoning.yml) не использует continue-on-error для плохих метрик, но всегда печатает очищенные результаты всех завершённых cases.

## Ранбуки и доказательства

### Проверка первичных материалов

[Verifier](../scripts/poisoning_evidence.py) повторно проверяет все 35 cases, а не доверяет полям `status` и summary counts. Восстанавливает train-only mutation и training request из source lock, сверяет model bytes, dataset/lineage/policy/input digests, versions, времена, worker image и заявленные ограничения execution. Из сохранённых scores восстанавливает prediction response и его digest, проверяет batch/row binding; затем заново считает все AP/ASR/CI и общий outcome. Все прочитанные 251 файла сверяются ещё раз перед возвратом результата. Это обнаруживает изменение во время чтения, но не исключает malicious host или transient replace-and-restore race.

```text
uv run --locked python -m scripts.poisoning_evidence
```

Команда не обучает модель, не загружает ONNX в host process, не запускает inference и не меняет SQL, сервисы или campaign. Docker используется только для inspect текущего source-bound image. Единственная запись - отдельный `.runtime/evidence/poisoning-reconciliation.json`; исходный report и директории campaign нельзя выбрать выходом. Input report по умолчанию `.runtime/evidence/poisoning.json`. Допустимая output location ограничена `evidence/` выбранного state.

`evidence_integrity=pass` означает согласованность материалов, **не устойчивость модели**. Если заново вычисленные метрики дают `fail`, verifier сохраняет `status=fail` и exit 1. Insufficient evidence даёт inconclusive/exit 2; ошибка binding - integrity fail/exit 1. `release_ready=false` и `full_M08=inconclusive` сохраняются: связи с approved release candidate и независимых challenges пока нет. В CI verifier запускается и после statistical failure, без `continue-on-error`.

Предположение: локальный controller/host доверен. Unsigned receipts нельзя считать защитой от полного согласованного подлога этим host; verifier не переизмеряет container isolation, parity или model predictions. Сохранённый ONNX здесь только хешируется, его scan receipt проверяется по схеме. Настоящие worker/format/isolation проверки выполняются другими компонентами. Старый commit или другая locked среда отвергаются как текущая приёмка, но историческое evidence не удаляется. Протокол, seeds, probes, бюджеты и thresholds ADR 0020 не изменены.

См. [RB-17](operations/poisoning-troubleshooting.md) для расхождения evidence, безопасной повторной проверки и ограничений. Native результаты нового verifier фиксируются в STATUS только после фактического исполнения.

Первый local native run `5b8dc6bf08934f6896c4184fd4bee8ee` завершён 2026-10-11T13:50:58Z: 35 trainings/predictions, 10 threshold failures, все при 5% poisoning. Label-flip ASR increase 0.10644-0.11578, backdoor 0.22345-0.23280; максимальный clean AP drop лишь 0.01063. Все 35 cases сохранены, minimum eligible 1 071, incomplete/inconclusive scenarios отсутствуют. Полный M08 остаётся непринятым; хороший общий AP не компенсирует targeted failures. Эти наблюдения получены после фиксации protocol, его thresholds/seeds не менялись.

[Clean-checkout CI 38144935449](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38144935449) на `e1a1831` повторил 35 trainings и 35 predictions, 10 violations и status fail в 2026-10-11T13:57:05Z. Воспроизведены input/protocol/probe digests, 12 contract tests и 100% protocol statements/branches. Job failure вызван шагом native matrix после полного исполнения, а не отсутствующим Docker или ошибкой contracts. Seed 17 backdoor: AP 0.92613 при clean AP 0.93660, но targeted ASR 0.23195 и upper 0.25691; именно targeted policy блокирует такой результат.

[PB-08/RB-15/16](operations/poisoning-troubleshooting.md) описывают threshold failures, частичные campaigns и ошибки схемы. Точные local/CI результаты публикуются в STATUS после завершения, а не выводятся из наличия кода.
