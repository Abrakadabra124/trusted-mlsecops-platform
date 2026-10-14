# Evidence: HTTP qualification неизменённого actual candidate

Дата: 2026-10-15 Europe/Moscow. Реализация после `afdc05c`; UTC timestamps native campaign фиксируются отдельно. [ADR 0032](../decisions/0032-candidate-serving-qualification.md), [PB-26/RB-50/RB-51](../operations/candidate-serving-troubleshooting.md). Это T15 increment, не полная M12/M18/R1-приёмка.

## Проверено локально

- `scripts.candidate_serving_reader_qualification`: 17 methods pass, branch-aware coverage 94% (111 statements, 26 branches). Исходные signed fixtures контролируемые; это не настоящее обучение.
- `scripts.candidate_serving_native_qualification`: семь methods pass, включая реальный loopback HTTP с подставным worker, 14 input/lock-pressure checks, CLI confirmation/error redaction, configurable port, invalidation старого отчёта до Docker preflight и fresh-subprocess import boundary.
- Итоговый объединённый regression: 129 distinct methods pass за 13.316 s. Это 17 qualification Reader и 112 adjacent/harness methods; harness не считается дважды. Покрыты serving core/HTTP/runtime/native helpers, release reader/bundle/policy/authorization и trust.
- Review обнаружил expiry-after-refresh и Base64 key alias defects. Новые тесты сначала воспроизвели четыре expiry failures, три source-key alias bypasses, неправильный тип campaign и нежелательные parser/fixture imports. После исправления 21 method новой suite проходит.
- Второй read-only reviewer обнаружил конфликт 15445 с tracking-service, отсутствие cleanup после частичного bootstrap и stale pass при раннем preflight failure. Добавлены failure-first regressions, configurable default 15446, проверка local workspace перед invalidation и cleanup/readback по подтверждённой identity. Если marker ещё не создан, ресурсы не удаляются вслепую: unconfirmed cleanup с сохранением state. Native partial-bootstrap fault injection не выполнен.
- Reviewers - агенты, не независимый человек и не внешняя security certification. Отдельно повторены 50 serving methods, 94% coverage (523 statements, 156 branches).
- Ruff check/format: pass, 322 files formatted. Documentation check: 351 files, 126 Markdown documents, 915 local links; внешние URLs/runtime эта проверка не подтверждает. `git diff --check` pass.

## Что именно реализовано

Serving-only TLS SQL reader получает неизменённый proposal настоящего upstream training/evaluation. Отдельный ephemeral signer выдаёт permit только на испытание, без M-gate reports. Отдельная authority проверяет текущий trust; same Engine/HTTP/Docker worker принимает exact verified bytes. Production Reader/config не изменены, исходный release без assurance по-прежнему отвергается.

Reference predictions получаются отдельным one-shot ONNX worker на тех же bytes и трёх фиксированных synthetic rows. Это проверяет consistency persistent runtime и протокола, не независимую sklearn parity. Report явно хранит release_ready false и full_M12 inconclusive.

## Native / CI

[Storage run 38638879034](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879034), job `116108993633`, **success** на commit `0a47b7bf0f3fe02b2c49487c8da2f9defdee8557`. **39/39 actual-candidate cases pass**, source_dirty false. Это новый native replay, не перенос прежнего 34-case fixture evidence. Docker/WSL и существующая платформа на компьютере владельца не запускались и не изменялись; реальные контейнеры работали на disposable GitHub runner.

Campaign `2702a381a5c84b4d9a1dd4a2f73f884b`: `2026-10-14T21:20:49.611499+00:00` - `2026-10-14T21:21:00.508134+00:00` UTC. По Europe/Moscow это 2026-10-15. Source/model bindings:

| Материал | SHA-256 / reference |
| --- | --- |
| Worker image ID | `sha256:d2452e8882518409aaa58ab664eaa80c6ec3ba391b93e5323c6e415aa7610c23` |
| Worker source fingerprint | `30bbfd3cf753f64c39fdd867982083d6db81f1e4bffedae206b7bb3e425e5cfd` |
| Original proposal envelope | `f3e8cb460ca341fa3ba12357ee8ab0302d927903f079b5d4e8389d11f0b184c9` |
| Original release subject | `6100c0d95f09e372bcf6492a778b7d7e180214388459a11ff0cee4a4e1ae08d1` |
| Model | `b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634` |
| Candidate | `5c3177068356e20eb31571b85ace89076bb854f54be23f71b38c2556fd215bab` |
| Evaluation | `7f36aa39db73526afbf84ad3e7ad0b8fdb6d29e254ac542f4174c03eb3a80d8b` |
| Qualification permit payload | `c15301663165798b42ae9abc7cba17748b0afa43b6ad84bbf84df0a2d97bdcaf` |

Fingerprint здесь покрывает worker/runtime sources, lock, Dockerfile и policy; scripts отдельно связаны clean Git commit. Совпадение worker fingerprint с предыдущей ревизией не означает, что новый controller уже был испытан раньше.

Проверенные результаты:

- Три golden rows, maximum error **0.0** между one-shot и persistent ONNX worker. Same-model consistency, не независимая оценка качества.
- Настоящие HTTP 401/413/422/429/503; NaN/Inf, boolean/unknown version/features, missing fields, empty/101-row batch; valid 100-row boundary. 429 получен реальным ожиданием занятого Engine lock, не throughput benchmark.
- Malformed ONNX не становится ready. После STOP своего worker HTTP отказ через **2.089667247 s**, удаление именно owned worker и explicit verified reload подтверждены. Это наблюдение одной controlled fault campaign, не M14 latency SLO.
- Подписанный отзыв actual model запрещает predict и readiness. Qualification authority/private key удалены; исходные CAS, budget, envelopes, model bytes и checkout совпадают до/после.
- Отсутствующий permit запрещает startup/predict. Qualification signature не принимается как release approval; actual proposal без assurance по-прежнему denied. В итоговом report release_ready false, full_M12 inconclusive.

В том же CI отдельно прошли 17 permit Reader methods / 94% coverage, семь harness methods, восемь reader diagnostic/cleanup methods и 50 serving methods / 94%. Native regression: M03 431, M07 97, promotion journal 108, journal recovery 36, reader-only 18, прежний HTTP fixture path 34, trust component 45 cases. Trust component first denial **59.993632902 s** не является HTTP outage trace нового candidate.

## Все CI workflow этой ревизии завершены

Commit `0a47b7bf0f3fe02b2c49487c8da2f9defdee8557`: **6 success / 4 failure**, без cancelled или незавершённых runs. Проверен terminal state каждого run; raw logs остаются приватными. Job-specific images и scopes не объединяются в фиктивную общую M18 acceptance одного release.

| Workflow | Run | Итог |
| --- | --- | --- |
| Storage role and TLS qualification | [38638879034](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879034) | success, actual-candidate 39 cases |
| Developer runtime qualification | [38638879060](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879060) | success, 74 checks, три training runs |
| MLflow tracking compatibility and private service | [38638879097](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879097) | success, M06 18 cases |
| Kubernetes isolation qualification | [38638879277](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879277) | success, M20 723 / M21 122 cases |
| Intake evidence contracts | [38638879235](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879235) | success |
| Documentation integrity | [38638879177](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879177) | success |
| Worker and storage image audit | [38638879223](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879223) | failure, все четыре scans выполнены |
| Frozen poisoning research matrix | [38638878919](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638878919) | failure, 10 threshold violations |
| Frozen evasion and domain guard | [38638879126](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879126) | failure, recall drop выше 0.05 |
| Paired robust training research | [38638879271](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38638879271) | failure, candidate не принят |

Дополнительные проверенные факты:

- Developer: maximum probability difference 0.0, independent export parity maximum error `2.086162567138672e-07`. Это отдельный replay, не reference calculation новой serving campaign.
- Kubernetes job `116108996741`: M20 закончился `2026-10-14T21:27:47.582092+00:00`, M21 `2026-10-14T21:29:32.840041+00:00`, source revision тот же, M21 source_dirty false. Owned CI cluster удалён отдельным successful step.
- Image job `116108995390`: worker 0 Critical / 56 High, storage 9 Critical / 115 High, worker-candidate 0 Critical / 55 High, storage-candidate 1 Critical / 85 High. Для четырёх targets scan_executed true, SBOM validated, scanner exit 2. Успешная candidate compatibility/restore не отменяет эти findings; severity policy и exceptions не ослаблялись.
- Poisoning campaign `ab65072edfdb4a0399738d02f7fb22e9`: evidence integrity pass, 35 verified cases / 251 files, 10 violating scenarios, 0 inconclusive. Контроль целостности не объявляется semantic poisoning detector.
- Evasion campaign `dfba75e1da114818842805962a0f68db`: execution complete / primary reconciliation pass; recall drop `0.07183673469387755` при maximum `0.05`.
- Paired campaign `bbb0a97748f643e39182ada639edf333`: execution complete / primary reconciliation pass; candidate drops `0.052244897959183675`, `0.06224066390041494`, `0.06143344709897611`, каждый выше `0.05`. Qualification не подменяет эти результаты pass и не принимает candidate.

## Остаётся

Полная M12 acceptance с production release Reader, timestamped HTTP trust-outage trace M11, privacy/audit/quotas M13, нагрузка M14 и остальные R1 gates. Текущие image/poisoning/evasion/paired robustness failures не обходятся квалификационным permit. Это разрешение получить проверочные данные, не разрешение выпустить модель.
