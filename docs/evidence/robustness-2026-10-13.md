# Evasion/domain-support: clean-checkout evidence

## Итог

Code commit `5e3bb21313f9bf95a492d708df97b868157d528c`, [CI 38454451985](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454451985): **workflow failure вследствие измеренного robustness violation**, не runtime error. `execution_status=complete`, `primary_reconciliation=pass`, `source_dirty=false`, `release_ready=false`. Полный M09 не принят.

Campaign `8ecf23cf3e324a938b197c4de7c53d95`, `2026-10-13T19:23:57.858408Z` - `19:24:11.643880Z` (UTC). Восемь настоящих network-none worker executions: training, independent intake, clean prediction, четыре corner batches и один mixed-batch prediction. Host не загружал ONNX/ONNX Runtime. Working SQL/cluster владельца не использовались.

## Зафиксированный эксперимент

[Протокол](../robustness-protocol.md) определён до первого измерения. На inference меняются только change_size/change_entropy в пределах L-infinity=0.05, L1=0.10. Остальные признаки и labels неизменны. Четыре дополнительных queries на строку, clean response сохраняется как noop candidate. Training seed=17, probe seed=73041, 3000 новых synthetic entities, проверена disjointness от исходного dataset.

Final holdout не оценивается; research probes не заменяют SQL query budget, M07 или независимый challenge. На этих опубликованных probes нельзя подбирать mitigation, а затем выдавать их за untouched test set.

| Метрика | Значение |
| --- | --- |
| Research rows / positives | 3000 / 1225 |
| Clean true positives / recall | 1027 / 0.8383673469387755 |
| Attacked true positives / recall | 939 / 0.7665306122448979 |
| Потерянные true positives | 88 |
| Recall drop | **0.07183673469387755 > 0.05: fail** |
| Conditional attack success на clean TP | 0.08568646543330087 |
| Python/ONNX parity, 3000 validation rows | max error 2.086162567138672e-07; label mismatches 0 |
| Outside-support fixtures | 12 abstentions, 0 prediction calls для этих строк |
| Mixed-batch score error | 5.960464477539063e-08, в прежнем repeat tolerance 1e-6 |

Это conditional point estimates на заданных synthetic probes, не production false-positive rate, business utility или универсальная adversarial guarantee. Native CI повторил численные local outcomes; это не обещание побитовой воспроизводимости любого image/build.

## Что действительно делает guard

`mlsecops.advisory.decide` возвращает score только для строк внутри [0,1]^6. Конечные числа вне support получают `abstain`, `score=null`; shape/type/NaN/Inf/bool ошибки отвергаются до predictor. Mixed batch сохраняет позиции. Runtime error не маскируется успешным abstain.

Guard **не обнаруживает joint distribution shift внутри support** и не устраняет показанную evasion-атаку. Сейчас это core для дальнейшего serving integration, не HTTP API, signed release loader или обход approval. Исполнение успешно проверено, но модель остаётся неприемлемой по этому robustness threshold.

## Привязка к материалам

| Материал | SHA-256/reference |
| --- | --- |
| Source fingerprint | `edb07dbce7b3fdcadc9fb06dad3a88e18235d71fb0d6a28be2ba312764420a3f` |
| Host scripts | `d518c5c818dd72d63acf890b808643abae8db44c7f03dfb1399cbfa4c3f57817` |
| Protocol | `aabc4c258e9f6a0b066f7e639426b10b75c94017642c842cce5e96d2b5059376` |
| Exact CI image | `sha256:d69a809a1c01cbc6321ef00178afbea2c2360b43f6b59b08eb35939be8586c08` |
| Model | `09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f` |
| Training materials | `c775e1d7310fec55b1fc8025d0d6cf9d184fcf1c15e5f7f93c9c17d41880bb6a` |
| Probes | `df1458768a6f47e5e8462fb2255341b70daaabc5d48efb3def6e9ba54481f390` |

Во время campaign перечитаны hashes всех 28 private material files, пересчитаны выбор атакованных строк и итоговые metrics. PredictionBatch отдельно проверял nonce/rows/request/model binding каждого фактического ответа. Это проверка на доверенном research host, не внешняя аттестация. Публичный summary не является offline архивом всех исходных request-response bytes; raw materials/models/keys не добавлены в Git.

## Тесты и регрессия

17 controlled methods прошли в CI. Для advisory + attack core: **98 statements и 42 branches, 100%**. Native orchestrator этим coverage percentage не покрывается целиком. Дополнительно локально прошли 83 adjacent tests и fresh developer qualification: 74 component checks, три обучения, probability difference 0.0.

Все девять workflows на code commit terminal:

| Workflow | Результат |
| --- | --- |
| [Evasion/domain guard 38454451985](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454451985) | failure: завершённый эксперимент, превышен recall-drop threshold |
| [Kubernetes 38454451948](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454451948) | success: M20 723 cases и M21 122 cases pass |
| [Developer 38454451909](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454451909) | success: 74 component checks |
| [Storage 38454451824](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454451824) | success: M03 431, M07 97, SQL denial 25 |
| [Tracking 38454451978](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454451978) | success: M06 pass |
| [Intake contracts 38454452090](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454452090) | success |
| [Documentation 38454452070](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454452070) | success |
| [Image audit 38454451963](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454451963) | failure: все scans выполнены; Critical/High/Unknown: worker 0/56/0, storage 9/115/19, worker candidate 0/55/0, storage candidate 1/85/0 |
| [Poisoning 38454451921](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38454451921) | failure: integrity pass, 35 cases/251 files, 10 violations |

Image audit run `05d6c617e7e546008b7053126324b0de`, source_dirty=false. Poisoning campaign `f3d71695fd9340398bf0539ee7be3ed3`, report digest `67b246ba74921dc85bc7e3e69ed98332c703ba5facf2bad16bb9d1298f08cdc1`, materials digest `488e83b74f7ea6987577cf3f3b921a9004dd021acf9dac674824bb0acc3c2d9c`. Новая проверка не делает прежние blockers безопасными.

## Дальнейшие действия

[PB-18/RB-36](../operations/robustness-troubleshooting.md) задаёт диагностику и безопасное повторение. Для устранения измеренного риска нужен предварительно описанный mitigation с проверкой utility/false positives на новых независимых probes. До этого не изменять thresholds задним числом, не выбирать удобные seeds и не объявлять M09/T12 завершёнными. R1 сохраняет полный scope; никакой acceptance waiver не добавлен.
