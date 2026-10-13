# M21: проверенная приёмка intake

## Результат и область

На code commit `04b5e788a774ccc9101d6b1888f993c5178f200a` [Kubernetes CI 38449516744](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516744) завершился success. **M21: 122/122 cases pass**, `source_dirty=false`; перед ним M20 повторил 723 cases pass. Это synthetic CPU lab acceptance, не M18 one-release acceptance, production readiness или универсальное обнаружение вредоносных моделей. `release_ready=false` сохранён.

M21 acceptance: `2026-10-13T18:58:54.854663Z` - `19:00:47.304730Z`. Campaign `d40cd473da6e44d5861507c749eabc9b`. Scoped component: `18:59:20.445553Z` - `19:00:47.064656Z`. Все времена UTC.

| Часть | Проверено | Метод |
| --- | --- | --- |
| Controlled contracts | 66 methods | ONNX profile, paths, intake protocol, signed denial, scoped observation/reconciliation |
| Docker intake | 5 cases | Настоящие isolated workers, unsafe bytes, replacement-process crash/deadline, clean-after |
| SQL denial | 25 checks | Настоящая отдельная TLS-БД, signed negative objects, permissions, readback |
| Scoped Kubernetes | 24 checks | 12 inspection cases, fresh evaluation/denials, отдельный reader, boundary/history/cleanup |
| Интеграция | 2 checks | Primary signed-material reconciliation и обязательный scoped replay |

Это смешанный controlled/native набор, а не 122 отдельных production-инцидента или эксплойта. Подробная [карта покрытия](../intake-gate.md) разделяет fault mechanisms и ограничения.

## Что подтверждено в Kubernetes

- 12 различных worker Pod UIDs и 12 cleanup confirmations. Scorer и promoter работают в отдельных Pods, не совпадающих с worker identities.
- Реальный unschedulable Job завершился `Failed/DeadlineExceeded`. Pod к terminal read уже был удалён; использован UID, наблюдённый ранее с правильным owner. `inspected=0`, `approved_outputs=[]`, итог scan `inconclusive/scanner_timeout`. Pass относится к правильной блокировке отрицательного теста, не к успешному scan.
- Настоящий worker process failure получен некорректным digest запроса. Остальные protocol mutations вводятся после выполненного scanner; это не доказательство защиты от полностью согласованного ложного ответа скомпрометированного scanner.
- Сама inspection matrix не изменила holdout ledger. Fresh clean evaluation заняла slot 24, две signed denials - slots 25 и 26. Проверены ровно шесть новых evaluation-table objects; protected tables не изменились. Рабочий локальный cluster/SQL владельца не использовался и не сбрасывался.
- Scorer: UID 65532, peak memory 153504 KiB, parser/runtime не загружены, host socket отсутствует. SQL role=scorer, signer и scoped API token присутствуют только там, где положено controller profile.
- Promoter заново прочитал и проверил positive/negative signed objects без evaluator key/API token. `persisted_readback_digest=e3146f6b7abc0d798242934139563a404b12e5e1d3ee3c371463cad978fce2f5`.

## Привязка материалов

| Поле | Digest/reference |
| --- | --- |
| Source fingerprint | `59aab518888eb458f5964e90f9ad46ea31b6adaa94bd0dc373f2e83c02fca653` |
| Exact CI worker image | `sha256:f5788dc9eed81f4a9577f50a8e1f1b3330d1ed8acf920033783d289dffbb3072` |
| Model bytes | `b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634` |
| Docker SQL candidate | `aa4fba213b9550ca3b34120dfdfd1fd9091307f4697c28d077f2c27d25c8f7f1` |
| Kubernetes SQL candidate | `7fc77be7cfa91b15dae8d27fb6c72cd0940449d65f3a979442d814bdfe79aaec` |
| Docker signed evaluation | `f73bdc11c2f62586bdad790326b3062a036669232b7f22f40bca4e9c3b50832e` |
| Policy | `9a78ff344304e12e52c54652d8750aae69038e2a1ae2fb2c375a752e67fedb24` |
| Host contract sources | `7f221372a38d80aaec19dc64027afeb7bfd406418b03ef7a7da104cc4205b83f` |

Две БД имеют разные CAS candidate identities. Проверено совпадение exact model bytes и split materials, а не один общий storage record. Новый CI image не объявляется побитово равным локальному image. Коммиты документации после code commit не меняют историческую привязку этого результата.

| Evidence file | SHA-256 |
| --- | --- |
| intake-gate | `15502de75506ba8867ef807015ed33e1eb71e44feb7b929a5f432c4c73027546` |
| contracts | `a37a343c31a1b4f5c07aa8fdc1703578c1a19a8440a48f55aa83236f2d03fea3` |
| native Docker | `84416f8cb31334641581449da9b3a7611ef45198d3086841c7c8bdaec33756ad` |
| SQL denials | `145e58e6ebab2017ea65953554539302a616cdd67e5a4b43d06fe236cae39675` |
| scoped Kubernetes | `22b9c27f9d3e732905942c0157893b38792fff97d720d8437ff738443fb3b3a5` |

Primary readers выполнились во время campaign. Этот очищенный документ и публичные summaries не заменяют полный offline archive signed objects. Raw logs, keys, модели и datasets не добавлены в Git.

## Регрессия и остающиеся blockers

На том же code commit все восемь workflows завершены:

| Workflow | Итог |
| --- | --- |
| [Kubernetes 38449516744](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516744) | success: M20 723, M21 122 |
| [Intake contracts 38449516919](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516919) | success: 66 methods; отдельно 16 runner methods, 177 statements/54 branches, 100% |
| [Developer 38449516685](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516685) | success: 74 component checks, три fresh runs, probability difference 0.0, parity error 2.086162567138672e-07 |
| [Storage 38449516988](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516988) | success: M03 431, M07 97, SQL denial 25; recovery 433 остаётся компонентом, не full M17 |
| [Tracking 38449516901](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516901) | success: M06 pass |
| [Documentation 38449516809](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516809) | success |
| [Image audit 38449516762](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516762) | failure: все четыре scans выполнены; Critical/High/Unknown: worker 0/56/0, storage 9/115/19, worker candidate 0/55/0, storage candidate 1/85/0 |
| [Poisoning 38449516753](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38449516753) | failure: integrity pass, 35 cases/251 files, 10 statistical violations |

Image audit run `cbf757acb52d4691956bc23c929fd6d8`, `source_dirty=false`. Poisoning campaign `d0541cebac224e49b5e936a2c13c04ff`, report `56f3ac13528de3eaa7ed26f741200acda57928127283255999927cdd1a2a61a4`, materials `8b5e93336712379830465ee903bcbd9975c576132ef460ce91e11e4aa442ae01`. Уязвимости и threshold violations не waived. T27 остаётся открытой для lifecycle-зависимостей T12 и release/serving integration; проверенный M21 не закрывает весь R1.

## Повторение и диагностика

Следовать [PB-17/RB-35](../operations/scoped-intake-troubleshooting.md): fresh disposable owned cluster, актуальные source/image/profile, M20 prerequisites, затем acceptance M21. Нельзя повторять migration/reset на рабочей БД или считать старый report текущим pass. Missing backend, incomplete evidence, чужие UIDs или отказ cleanup блокируют приёмку.

При получении CI logs сразу после completion была замечена неполная копия `gh run view --log`: строки M21 pass уже присутствовали, но последние JSON summaries отсутствовали. Read-only jobs/logs endpoint вернул полный terminal job log, после чего проверены все 122 outcomes и bindings. Это проблема получения evidence, не ошибка выполненного gate. Процедура описана в RB-35; raw logs остаются приватными.
