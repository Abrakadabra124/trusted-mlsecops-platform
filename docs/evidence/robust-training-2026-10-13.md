# Paired robust training: evidence

## Решение

**Не принимать candidate:** новый способ обучения уменьшил vulnerability, но recall drop остаётся выше frozen 0.05 на всех трёх probes. Clean utility guards прошли. Никаких thresholds, seed search или attacker-budget исключений после измерения не введено. Full M09/T12 и R1 открыты; poisoning/image findings не устраняются этим экспериментом.

[Протокол](../robust-training-protocol.md) зафиксирован до full training и просмотра новых outcomes. Seeds 73043/73047 были новыми для этого эксперимента, 73041 - известный regression. Это same-agent research, не независимый human challenge M22/T23. Следующие эксперименты не могут называть эти опубликованные probes untouched.

## Local execution

Campaign `f58729ab50fc45fb973826b2866ef282`, UTC `2026-10-13T20:02:55.297459Z` - `20:03:41.959020Z`, dirty checkout на parent `a25d3d4a184348063a1d696a0d8a3d3d3ccec4f3`. Owned workspace `.runtime/robust-training-replay-20261013`; 14 workers: два trainings, два independent intake и десять prediction batches. Worker network=none, non-root/read-only, no credentials; privileged host не загружал ONNX/ORT. SQL/final holdout budget и working cluster не использовались.

`execution_status=complete`, `primary_reconciliation=pass`, `status=fail`, `release_ready=false`. Перечитаны 47 primary files, exact model bytes, protocol-bound raw prediction responses, corners/selection и пересчитанные summaries. Эти hash checks предполагают доверенный research host, не независимую attestation.

## Метрики на каждом наборе

По 3000 rows, threshold 0.5. AP означает sklearn average precision, не трапецеидальную площадь под PR-кривой. Во всех шести clean measurements quality component pass; candidate AP loss <0.004 при guard 0.03. Confidence intervals и slices остаются в private structured report.

| Probe / positives | Model | Clean AP | Clean TP | Attacked TP | Lost TP | Recall drop |
| --- | --- | --- | --- | --- | --- | --- |
| known 73041 / 1225 | baseline | 0.935779364413 | 1027 | 939 | 88 | 0.071836734694 |
| known 73041 / 1225 | candidate | 0.931794067874 | 1006 | 942 | 64 | 0.052244897959 |
| new 73043 / 1205 | baseline | 0.935234309328 | 1027 | 938 | 89 | 0.073858921162 |
| new 73043 / 1205 | candidate | 0.931563161778 | 1010 | 935 | 75 | 0.062240663900 |
| new 73047 / 1172 | baseline | 0.930869707453 | 1000 | 911 | 89 | 0.075938566553 |
| new 73047 / 1172 | candidate | 0.928822476657 | 991 | 919 | 72 | 0.061433447099 |

Recall drop меньше не означает, что attacked recall обязательно стал лучше: на 73043 candidate TP=935 против baseline 938. Поэтому публикуются оба счётчика, не только относительное улучшение drop. Порог не округляется до pass.

| Probe | Baseline clean / attacked FPR | Candidate clean / attacked FPR |
| --- | --- | --- |
| 73041 | 0.103099 / 0.059155 | 0.100282 / 0.065915 |
| 73043 | 0.092479 / 0.059610 | 0.089694 / 0.062953 |
| 73047 | 0.100109 / 0.065098 | 0.097374 / 0.062910 |

FPR - false-positive rate на synthetic negatives; атака целится в уменьшение score, поэтому её FPR не является оценкой attacker, который повышает score. Непокрытые направления и joint shifts внутри support не сертифицированы.

## Numerical / boundary checks

- 18 controlled methods pass; math module 63 statements/12 branches, 100%. Native orchestrator этим coverage не объявляется полностью покрытым.
- Candidate solver: 11 iterations, initial objective `0.3891451041374769`, final `0.3727768909385837`, recomputed projected-gradient infinity norm `5.142995372159559e-09` <=1e-5. Solver success сам по себе недостаточен; worker делает повторную numerical проверку, host проверяет receipt/profile. Это не независимый optimization certificate.
- 3000 validation rows каждой модели: baseline ONNX max error `2.086162567138672e-07`, candidate `1.6235808830700194e-07`; вне threshold epsilon label mismatches=0.
- По 12 finite outside-support fixtures вернули abstain/score=null без prediction calls. Это не novelty detector внутри support.
- Первый запуск остановлен на source lock до обучения. Увеличился только metadata uv.lock для direct SciPy dependency. Generated dataset остался `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`, 1 915 576 bytes; package versions не менялись. Ошибка не подавлена, provenance обновлена явно.

## Local digests

Adjacent regression и новые contracts вместе: **121 tests pass** в Linux non-root/read-only/network-none container. Предшествующий Windows запуск 103 adjacent tests завершился 102 pass/1 error: WinError 1314 при setup symlink fixture, не обход безопасности модели. Проверка реально исполнена в Linux, не skipped. Fresh developer workspace `.runtime/robust-training-developer-20261013`: **74 checks, три trainings**, AUPRC=0.9323007296445032, max probability difference=0.0, max parity error=2.086162567138672e-07. Full acceptance остаётся inconclusive.

| Материал | SHA-256 |
| --- | --- |
| Runtime source fingerprint | `20db5ec7ac9ffc84492b428462790a20c68dda3340e5d93ff945efc632bd2a11` |
| Host scripts | `ea1e9b9ee75242d3bec73ccd80f1ef5458e355156fad18a7552d3e6ab1546c56` |
| Protocol | `faadb177335d547b5cfc7e54a3873a8869a2d13f070b2461508eac33bad18a66` |
| Data lock | `240ffe6a7c1ea637d3f592ce5c1defe993e6602559e5ea327df30f4092c9c622` |
| Local image | `sha256:66f4b1da871e1bb3183c3969ad70b2b1dcbf78fa2c78e440f3641ae6c58f88f3` |
| Baseline model | `09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f` |
| Candidate model | `ec61af11e7b6534a8ef1ae1e088f0ae13265781cd67c00bc956d81b4ef5dfe2b` |
| Train / 14000 rows | `0198f703686e091cf42957c32d1c1af686d59d1b9923af7f3f24d6e56ea54bc8` |
| Validation / 3000 rows | `b0f7c5821172f53ee323caa276d1ea6d9c04d008e8efe03515a14ea343fffaa4` |
| Known 73041 | `df1458768a6f47e5e8462fb2255341b70daaabc5d48efb3def6e9ba54481f390` |
| New 73043 | `3adbd1fe05c0555c1159d92df25180b82a2a62f6bd5846b403e3da1d7f204f87` |
| New 73047 | `05b2bc6d60900899998859652936a6ca7d0bbd12e9f9dde90ce9610c1e3bc020` |

## CI и ограничения

До публикации отдельный reviewer-agent обнаружил четыре gaps: incomplete abstention count, отсутствие semantic training/intake readback, необработанный cleanup timeout и binary-float boundary false fail. Исправления подтверждены read-only review и четырьмя новыми methods; **итог 22 controlled tests / 125 combined Linux tests pass**, math-core coverage 100%. Это не независимая human M22-приёмка.

Второй native replay `98a8244c7aba42beb53eca84c8b2dd1f`, UTC `2026-10-13T20:09:37.252367Z` - `20:10:28.091595Z`, также execution complete / reconciliation pass / statistical fail. Проверены 14 workers, 47 primary files, по 12 фактических abstentions. Summaries, parity, optimization и model bytes побайтно/структурно совпали с первым replay. Новый host scripts digest `80df0322f5a97077757f00cebb08f7d7dcfd8688576b6b040a7fcdf4344ab445`, остальные input digests прежние. Чисто численное сравнение AP использует Decimal, без изменения 0.03; training, seeds и budgets не менялись.

Code commit `a252f6feb161fe852213e0d0b55f58ab18b60f8c`, [Paired robust training research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873351): **failure из-за frozen recall-drop violations**, execution complete, primary reconciliation pass, source_dirty=false. Campaign `c3db3d38980d4b858a6e1dc7517d2280`, UTC `2026-10-13T20:12:11.847320Z` - `20:13:02.181392Z`. Все summaries, модели, protocol и host scripts совпали с reviewed local replay. Optimization и parity также прежние. CI image `sha256:0ad3713e5470ebe24f94406e92682335befc417d23664b156591a0bdbb869269`; другой build image не выдаётся за bit-for-bit воспроизведение container image.

| Workflow | Run | Результат |
| --- | --- | --- |
| Paired robust training research | [38460873351](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873351) | failure: candidate не прошёл recall drop; 14 workers завершены |
| Frozen evasion and domain guard | [38460873381](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873381) | failure: прежние 88 lost TP, drop 0.071836734694 |
| Developer runtime qualification | [38460873329](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873329) | success: 74 checks, три runs, probability difference=0.0 |
| Storage role and TLS qualification | [38460873443](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873443) | success: M03 431, M07 97 cases pass |
| MLflow tracking compatibility and private service | [38460873291](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873291) | success: M06 18 cases pass |
| Intake evidence contracts | [38460873405](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873405) | success: controlled contracts, не самостоятельный full M21 |
| Documentation integrity | [38460873483](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873483) | success |
| Worker and storage image audit | [38460873463](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873463) | failure: все четыре scans исполнены, findings сохранены |
| Frozen poisoning research matrix | [38460873386](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873386) | failure: primary integrity pass, 10 statistical violations |
| Kubernetes isolation qualification | [38460873478](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38460873478) | success: M20 723, M21 122 cases pass |

Все десять workflows terminal: шесть success, четыре failure. M20 завершён UTC `2026-10-13T20:25:48.067625Z`, M21 `20:28:09.893747Z`, source revision тот же; M21 явно source_dirty=false. Kubernetes worker image `sha256:0909506d353ac3bb2112c818a1dfb4faf38bb57fb3de65656ab149c641eea3f9`, source fingerprint прежний `20db5ec7...`. M21 повторно проверил пять Docker native, 25 SQL cases и scoped-controller matrix. Это regression принятых synthetic gates, не общий M18 release pass. GitHub job-log API проверен после завершения, raw logs остаются только локально.

Poisoning campaign `bddfc5751d0a4e018a4922dd378e1f1e`, execution complete/source_dirty=false, reconciliation проверил 35 cases/251 files. Report digest `6937213bc3fa47391043b6bccd2a4903c7846d4297e2c3e1d1fccbbcbc0a5c24`, materials `ec0018352622e402845a46ed7951625eef6cea21d2280071049d9f571a1e2080`. Улучшение evasion другой research-модели не отменяет эти baseline poisoning результаты.

Image audit `e26c4e37cb2e4831b60219f81fd30f12`, source_dirty=false: Critical/High/Unknown counts worker 0/56/0, storage 9/115/19, worker candidate 0/55/0, storage candidate 1/85/0. Это package finding counts, не число доказанных exploit paths. Candidate compatibility pass не разрешает security adoption.

Workflow не использует continue-on-error. Baseline evasion workflow сохранён отдельно. Нельзя считать результатом релиза ни exit 0 unit tests, ни улучшение loss, ни полную таблицу research metrics. Adoption потребует отдельного решения, повторения poisoning/M07 и release/serving integration.

Воспроизведение и ветви диагностики: [PB-19/RB-37](../operations/robust-training-troubleshooting.md). Raw train/probes/models/requests/keys остаются private; здесь только synthetic aggregates/digests.
