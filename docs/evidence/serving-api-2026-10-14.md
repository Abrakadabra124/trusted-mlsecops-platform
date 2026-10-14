# Persistent isolated serving и API: 2026-10-14

Parent: `a711ffa99b7cfa8594c7cf0832e4fc3dda66f3f6`. Первый runtime commit: `d0d4423e62489b956405fdd72890859c247d57e8`. Scope: T15 implementation component. Полные M12/M13/M14/R1 остаются открытыми. Ниже отдельно указаны native evidence этого commit и последующие исправления, требующие своего CI.

## Локальные проверки

Negative-first suites сначала падали на отсутствующих модулях. Текущая suite: **41 methods pass**, controlled Python branch coverage **94%** (502 statements / 150 branches). Это не 100% и не доказательство Docker isolation. Проверены настоящая ONNX InferenceSession на synthetic bytes, real OS pipe timeout/EOF/oversize, loopback Uvicorn HTTP, crypto rebinding fixture и controlled Docker config/lifecycle cases. Объединённая adjacent suite: **138 methods pass за 10.920 s**. Ruff check/format pass, 315 files; docs check 344 files / 123 Markdown / 885 local links pass.

Проверены schema/version/extra fields, row/nonce/model/request digest mismatch, malformed model, repeated load, scanner/runtime version, retained process/session, exact bytes, mixed score/abstain, load failure/expiry/revoke, 401/413/422/429/503 contract, eight-slot overload и cancellation. После ошибки request features модель остаётся работоспособной; после worker/trust failure - нет. Полная M13 privacy campaign, реальные per-client quotas и audit ещё не выполнены.

Отдельный failing regression воспроизвёл освобождение admission slot до завершения отменённого HTTP inference thread: ожидалось 7 свободных слотов при одном ещё работающем запросе, фактически стало 8. После deferred release test проходит, включая late exception без private canary в response. Это controlled defect, не production incident.

Fresh-context reviewer проверил `serving.py` и `serving_http.py` и нашёл P2: при отказе `Thread.start()` сохранялся незапущенный heartbeat, последующий `close()` выбрасывал необработанный `RuntimeError`, а retry мог получить ready без работающего heartbeat. Два новых regression tests воспроизвели fail/error до исправления. Теперь handle публикуется только после успешного start под Engine lock; проверены безопасный повторный close и активация после transient failure. Это один scoped automated review, не независимая human challenge или полный security audit. Внешние модели/CLI не запускались.

## Native CI

[Storage CI 38630228220](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228220) на `d0d4423` завершён success. Новый этап подтвердил **34 native checks**, настоящий Docker worker, две disposable TLS SQL authority/storage, current Reader, loopback HTTP и одноразовые test roots. Positive reports являются contract fixtures, **не настоящими passed gates**. Новый source candidate с failed image/poisoning/evasion/robustness не принимается. Local working Docker/WSL не изменялся.

Runner проверил actual ready/load, real CPU golden parity, persistent session reuse, wrong-input errors, stopped worker deadline/cleanup, explicit verified reload и actual signed revocation -> prediction/readiness 503. В отчёте `release_ready=false`, `full_M12=inconclusive`, `source_dirty=false`.

- Campaign: `3d5db82530cd493083e19a60fa34c221`, UTC `20:18:32.801076` - `20:18:47.986090`.
- Source fingerprint: `b797213c40425c53e4e5ce6331abb78872d5a0048105eda29cd44db2d9377ee2`.
- Golden: 3 rows, maximum error `3.166496753692627e-08` при допуске `1e-5`.
- STOP-injected worker: отказ через `2.104486554999994 s`, затем подтверждённое удаление собственного контейнера и verified reload. Это fault-case duration, не M14 latency SLO.
- Отдельный reader-only campaign `61a781700e024f31be2cf88748fdf8c9`: 18 checks pass.
- Regression в том же job: M03 431 / M07 97, SQL journal 108, recovery 36 / 1 000 golden rows / error=0, online trust 45 checks. Trust-component outage впервые отказал через `59.99161243599997 s`; это не HTTP outage trace.
- CI serving contracts: 41 methods за 3.690 s, coverage 94% на 502 statements / 150 branches.

### Остальные workflows d0d4423

| Workflow | Run | Результат |
| --- | --- | --- |
| Developer runtime | [38630228462](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228462) | success, 74 component checks / 3 trainings |
| Storage/TLS/serving | [38630228220](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228220) | success, результаты выше |
| Tracking | [38630228499](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228499) | success, M06 18 cases |
| Intake contracts | [38630228230](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228230) | success |
| Docs | [38630228470](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228470) | success |
| Kubernetes | [38630228139](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228139) | success, M20 723 / M21 122 cases |
| Image audit | [38630228354](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228354) | failure, четыре scans действительно выполнены |
| Poisoning | [38630228408](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228408) | failure, 10 statistical violations |
| Baseline evasion | [38630228112](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228112) | failure по recall drop |
| Paired robust | [38630228142](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38630228142) | failure на всех трёх probes |

Все десять workflows terminal: **6 success / 4 failure**. M20 завершён UTC `20:27:23.871086`, M21 `20:29:41.292148`, оба на `d0d4423`; M21 source_dirty=false. Developer probability difference=0.0, parity error=`2.086162567138672e-07`. Image matches: worker 56 High; storage 9 Critical / 115 High; worker candidate 55 High; storage candidate 1 Critical / 85 High. Это scanner matches, не число независимо подтверждённых exploitable vulnerabilities. Thresholds не изменены, candidates не приняты.

Poisoning campaign `a02edb628f4948b1bc77041bdd1fdf5c`: primary integrity pass, 35 cases / 251 files, 10 violations / 0 inconclusive scenarios. Evasion `9d52bbad90c4409ea6c26b1fc644aa2b`: complete, primary reconciliation pass, recall drop=`0.07183673469387755` >0.05. Paired `9dcbca91035c4a13bbd11171d0cbdc12`: complete; candidate drops `0.052244897959183675`, `0.06224066390041494`, `0.06143344709897611`, каждый >0.05. Successful runtime не отменяет эти fail. Raw logs, models, keys и tokens не публикуются.

## Исправления после native d0d4423

Source review обнаружил resource mismatch: acceptance требует serving <=1 vCPU / 1 GiB, worker запрашивал 2 vCPU / 1 GiB, а подписанный runtime-profile описывал 2 vCPU / 4 GiB. Два отрицательных tests сначала получили `2 != 1` и `(2000,4096) != (1000,1024)`. Исправлены Docker request/readback и release document на 1 vCPU / 1 GiB. Старый профиль отвергается даже с пересчитанным digest и корректной подписью; existing releases не редактируются и не переподписываются автоматически. Требуется новый proposal и штатный approval.

Проверка соседнего пути обнаружила тот же класс ошибок в Channel: failing `Thread.start()` выбрасывал raw exception, не завершив уже созданный child. Отдельный real OS process regression подтвердил отказ до исправления; теперь child reaped и pipes закрыты. Worker constructor больше не создаёт контейнер: Engine сохраняет ownership до отдельного one-shot `start()`. Controlled initial-load/removal failure сохраняет full container ID для cleanup retry, не ready=true. Новые tests проверяют отсутствие изменяющих calls до ownership, повторный start и retry cleanup.

Второй scoped reviewer указал, что первая попытка исправления Channel всё ещё теряла handle, если после thread-start failure одновременно отказывал kill. Основной агент воспроизвёл на реальном Python child: `OSError PRIVATE-CLEANUP`, child_alive=True; test cleanup затем безопасно завершил его. Channel теперь тоже имеет отдельный start и заранее сохранён у Worker; cleanup errors обезличены, handle удерживается до подтверждения. Дополнительные failing tests обнаружили чтение queue после close и ошибочное подтверждение cleanup живого IO thread. Closed loop больше не зависит от успешного enqueue sentinel в полную queue; живой thread означает cleanup_unconfirmed.

После всех corrections: **50 local serving methods pass за 4.812 s**, coverage **94% на 523 statements / 156 branches**. Release contracts: 22 methods pass, 229 statements / 94 branches, 100% для трёх Python modules, не SQL/Docker. Объединённая adjacent suite: **137 methods за 10.639 s**. Это перечисленная release/reader/promotion/trust/serving suite, не весь репозиторий; предыдущие 138 включали другой набор adjacent modules. Native результаты `d0d4423` не выдаются за проверку этих новых исправлений; новый clean-checkout CI ещё обязателен. Подозрение на несовпадение policy digest опровергнуто source check: `release_native` и acceptance используют один полный `policies/local-cpu.json`; scoring-only policy ошибочно не подставляется.

## Оставшаяся работа

Заключительный fresh-context review scoped lifecycle corrections не обнаружил новых actionable findings. Reviewer выполнил 28 профильных tests и четыре in-memory fault probes; основной агент независимо выполнил полный перечисленный набор 137 методов. Это автоматический review ограниченного diff, не human M22 challenge, penetration test или гарантия отсутствия всех ошибок. Локальный Docker не запускался.

Candidate-bound full M12 qualification без фиктивных gates, настоящий HTTP trust outage deadline trace, root rotation/rollback protocol, scoped serving permissions, M13 logs/metrics/traces privacy and audit, per-client quotas, M14 load profile, monitoring/recovery и общая M18/R1 приёмка. Loopback bearer token и owned Docker subprocess не объявляются production identity/TLS ingress или multi-node HA.

[ADR 0031](../decisions/0031-isolated-serving-api.md), [API](../serving-api.md), [PB-25/RB-48/RB-49](../operations/serving-troubleshooting.md).
