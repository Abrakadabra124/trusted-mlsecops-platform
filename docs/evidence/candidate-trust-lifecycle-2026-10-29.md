# Actual candidate: outage, blackhole, policy change и key revocation

Неделя 8, T14, CP3. Код `0485996edd2333a236e2c4d7e0f7e15145c33125`, [CI 40911041271](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40911041271), job `123578761460`: **success** за 13m32s. Полный native interval UTC: 2026-10-29 16:25:49.308687 - 16:36:36.813226. Actual-candidate interval: 16:32:42.930666 - 16:36:36.812792.

Проверены три новых fault-сценария и последующий необратимый key revocation на одном обученном candidate, proposal, model/subject, pinned image/source и qualification permit. Это не production promotion: actual запрос по-прежнему отказан с `release_assurance_required`, `release_ready=false`. Полные M11/CP3/R1 не завершены.

## Результаты actual-candidate probes

| Сценарий | Typed cases pass | Первый полный HTTP 503, s | HTTP trace observations | HTTP 200 / 503 в trace |
| --- | ---: | ---: | ---: | ---: |
| Authority outage | 198 | 59.797690113 | 44 | 39 / 5 |
| TCP blackhole | 215 | 12.733832126 | 49 | 0 / 49 |
| Policy change | 72 | 4.250479163 | 2 | 0 / 2 |
| Publisher key revocation | 70 | 4.251475865 | 2 | 0 / 2 |

Перед каждым fault выполнен настоящий успешный prediction, связанный с model/subject и эталонными scores. Этот начальный запрос не включён в число последующих trace observations. Отсчёт - от начала этого успешного запроса, консервативной нижней границы последнего trust read. Это не точный timestamp SQL SELECT. После первого 503 успешных ML-ответов в trace нет; outage и blackhole дополнительно наблюдались после 60 s.

Базовая actual-candidate HTTP-матрица дала ещё **60 typed cases pass**. Всего выполнено 615 typed case assertions, включая повторяющиеся проверки ответов, а не 615 уникальных сценариев. Во всех пяти probes максимальное расхождение с golden scores равно **0.0** на трёх фиксированных синтетических feature rows. Это проверка parity, не бизнес-качества модели.

До восстановления fresh cold Reader получил точные причины: outage/blackhole - `Unavailable(trust_service_unavailable)`, policy change - `trust_policy_changed`. После восстановления старый Engine не активировался автоматически; новый Reader заново проверил тот же model и subject. TCP blackhole подтверждён connect timeout и последующим успешным соединением. Outage восстановил owned authority с прежним PVC. После key revocation cold Reader получил `trust_key_revoked`; отзыв не отменялся.

После каждого probe подтверждено отсутствие worker. Полные CAS + promotion authorities/events/heads snapshots до и после каждого fault совпадают; общий hash одинаков для всех четырёх случаев. Source SQL остановлен, disposable cluster удалён и отсутствие проверено. Local Docker/WSL/SQL не запускались.

## Проверки кода и регрессии

Linux: **251 method execution**, группы 143 + 31 + 30 + 5 + 14 + 28, без skips. Это сумма запусков групп, не число уникальных методов. Combined fault/snapshot scope: **274/274 statements, 104/104 branches**. Bootstrap: 41/41 statements и 12/12 branches; promotion/replay: 230/230 и 72/72; expiry: 50/50 и 12/12. Attach/runtime: 257/258 statements и 91/92 branches.

Ordinary controlled serving/expiry/recovery, unexpired sequence refusal и прежние controlled faults также прошли на этом code revision. Первый expiry 503 за 0.908014774 s до срока; прежний sequence 1 при отказе оставался valid ещё 1635 s. Это controlled contract evidence; оно не заменяет actual-candidate checks и не переносит фиктивные gate reports в acceptance.

Локально до CI проверены failure paths pause/cold-denial, освобождение настоящего Engine lock при ошибке coordinator, неверные причины отказа, чужой recovered model, изменившийся journal и недостаточный остаток permit. Объединённые 30 tests полностью покрывают fault/snapshot scope; ещё 70 adjacent methods pass. Подготовлены [ранбук и описание механизма](../candidate-trust-lifecycle.md).

## Независимая сверка отчёта

Fingerprint пересчитан из **134 Git blobs**, обе копии полного JSON в CI log совпадают. Для всех actual cases проверены и значения, и типы `actual/expected`; проверены cold/recovery/final-worker labels. Trace проверен на порядок времени, запрет 200 после первого 503 и после 60 s, совпадение first-denial metric с фактической строкой. Model/subject/source/image и hashes отдельных primary reports совпадают. Приватные raw logs/credentials не публикуются в репозиторий.

| Поле | Значение |
| --- | --- |
| Source fingerprint | `e9368f79e509b653f49bba1e691ac0cd7fe8cf3c5b80199cd3dcece855fa6f13` |
| Image | `sha256:923bbbdbdfc2a6212b517d8c7a2ab360c34383edf7de34a2afeb47cbf37f1786` |
| Candidate | `8d707fcfea81e8f2f5a1a16a5ded7ad996b12af1ce6f6ac066025977e4339770` |
| Proposal | `a5ece1d33423f71b2771641b957287b926c6a7bd74e8de2c98307aee928c7c16` |
| Model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Subject | `ef5b3552ca7eaec66e47af284188c2a8ee856aff044e19f3e481271d6f87f169` |
| Qualification permit | `fcfa4ad10504b92e3a6f442e18aaa079a5e1d4f7acdd63e83273beb13a0e2dac` |
| Unchanged CAS + promotion snapshot | `2eeeb1bc0fe122cc96effa8bbc36533a07f8a94eea50cb4809e0bd83f62e1d19` |
| Full report SHA256 | `715396bd782d420945d8eba65b6e3cb1b0bf4ae1203a15992d9787004a414359` |
| outage.json SHA256 | `09fff20bc17438b9fd3b1d39576cc74bbbece02e6f823d8ad25f1d7f758bfa7b` |
| blackhole.json SHA256 | `3c87caa0e96b015fe5fdc362845892726ae941d2e0945bcc2363d69d50ed564e` |
| policy-change.json SHA256 | `702948c49d7a76f39332aa6455fb67f5930d227dbfbfd2667d4d1ce1b37f2faa` |
| key-revocation.json SHA256 | `56595b28bb869403b8ac8e80bb7c8b69362009d5d76e5622192b097413341454` |

Report hashes относятся к canonical JSON + LF. Snapshot hash - к canonical JSON без LF.

## Оставшиеся требования

Следующий обязательный increment - actual-candidate negative clock/cache behavior. Actual model revocation требует независимого owned authority state: нельзя отменить ранее сделанный key revoke. Root/key rotation, разрешённый whole-bundle rollback, общий M11 gate и остальные CP3-CP5 остаются открытыми. Independent M22 challenges всё ещё 0/2; system-image findings сохраняются. Этот run не объявляет новый общий M12/M18 pass и не снимает production refusal.
