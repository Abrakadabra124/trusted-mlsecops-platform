# T16: существующие serving outputs и privacy boundary

Дата: 2026-10-19. Статус: implemented, local и native actual-candidate qualification pass на `621d355`. Scope: неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Полный M13/R1 не принят. [ADR 0041](../decisions/0041-serving-output-privacy.md), [RB-60/PB-34](../operations/serving-privacy-troubleshooting.md).

## Источник и окружение

Изменения поверх `4624af1b53b14928dfdb70b7abcdfddfd308425b`. Windows, Python 3.12.15, FastAPI 0.142.2, Uvicorn 0.54.0; зависимости не обновлены. Локальные production services, Docker, WSL и SQL не запускались/не менялись. Только synthetic fixtures, owned tempfiles и loopback HTTP. User-owned AGENTS.md/GOAL.md не входят в implementation commit.

## Failure-first результаты

| Проверка | До исправления | После исправления |
| --- | --- | --- |
| Native telemetry + slash redirects | 4 methods, 9 failures; positive default-provider control сработал | Explicit flags/strict routes проходят; настоящий lifespan проверяет environment override |
| Raw headers helper | TypeError: новый headers argument не поддержан | Настоящий loopback raw request/response работает |
| Candidate privacy integration | AttributeError отсутствующего privacy_matrix | Controlled HTTP matrix использует тот же probe, callback ownership сохранён |
| Review: full feature object и truncated response | 2 methods, 3 failures: compact/pretty features не отклонены, oversized HTTP prefix принят | 27 combined privacy/native/candidate methods pass, 0 skips, 16.299 s |
| Credential-wrapper callback regression | 15 adjacent methods, 1 error: scanner partial попал в credential-only interceptor | Исправлен тестовый interceptor, оба callbacks проверены |
| Неполный audit scan receipt | 1 method: 8 failures + 2 errors на 10 invalid receipts | Все invalid receipts дают constant rejection, public summary получает только bounded counts |
| Review 2: действующий bearer и flattened/vector features | 1 method, 4 failures: оба leaks и обе структуры получали false pass | Actual credential включён в private needles; exact response schema; настоящие loopback header/log negative controls |
| Review 3: feature JSON в HTTP header | 1 method, 1 failure на настоящем loopback: escaping скрывал object | Raw header scan и bounded allowlist names/formats, negatives для duplicates/invalid/oversized headers |

Controlled default-provider span с marker доказывает чувствительность recorder, но не внешнюю передачу. Telemetry SDK/exporter не устанавливались. Противоположный контроль deliberately leaking output/response/capture подтверждает отказ checker, а не безопасность production.

## Локальная верификация

Privacy suite: **17 methods / 0 skips, 1.981 s**. Probe: **179 statements, 82 branch exits, 100%**, отдельный обязательный CI gate. Проверены stdout/stderr/logging/HTTP canaries, full feature object, active bearer, response schema/headers, capture overflow, missing prediction, incorrect status, incomplete accounting/receipt, audit filename/bytes, hardlinks, invalid needles, empty/missing/nested/oversized source и 67-file rejection. Отдельные adjacent HTTP/audit/native/access suites: 90 methods, 87 pass, 3 platform skips, 24.782 s. Skips не считаются выполненной Linux qualification.

Настоящий локальный loopback с controlled Engine выполняет 12 requests и подтверждает 36 audit events; сам этот тест не является actual ONNX/container candidate. Raw transport regression покрывает oversized loopback response и incomplete Content-Length через настоящий HTTPResponse parser с controlled input. Последующая native candidate проверка описана отдельно ниже. Процент покрытия относится только к новому probe, не ко всей системе и не к доказательству всех security properties.

После review 2 отдельно повторены изменённые native/candidate harness contracts: **16 methods / 0 skips, 15.845 s**. Три platform skips предыдущей adjacent suite: POSIX directory identity, retained concurrency/real fsync и owned retained lifecycle. Linux CI обязан выполнить их, а не сохранить skips. Ruff и docs checker проходят; проверка документации не подтверждает внешние URLs или runtime acceptance.

## Review и ограничения

Same-model adversarial review cycle 1 нашёл три actionable defects: тихое усечение response, пропущенный full feature object и неверный partial interception. Cycle 2 выявил непроверяемый active bearer и обход сравнения object через flatten/vector. Final cycle 3 нашёл escaping в header capture. Все шесть замечаний воспроизведены и исправлены. Последнее исправление проверено regression/coverage автором, но повторного независимого review не было: лимит трёх циклов соблюдён. Внешняя модель не использовалась по выбору владельца.

Scope summary: `existing-serving-output-privacy-not-full-M13`. Только owned temporary audit и controller outputs во время 12 cases. Worker subprocess outputs, approved metrics/trace policy/cardinality, public export всей платформы и полная correlation chain остаются открытыми. Нельзя принимать M13 по отключённой telemetry или одному counter. Исторические image/poisoning/evasion/paired failures и M07 reliability debt не устранены этим изменением. Полный R1 и release approval остаются запрещены.

## Native verification code commit 621d355

[Storage run 39276391635](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391635), job **118141671532**, attempt 1, success. Code commit `621d3550495220199087a64ed31067e9ac67952f`; actual candidate finished **2026-10-19T15:23:58.372600+00:00**. [Полный сохранённый sanitized report](serving-privacy-621d355-native.md).

| Проверка | Подтверждённый результат |
| --- | --- |
| Privacy contracts | 17 methods / 0 skips, 1.289 s; probe 179 statements / 82 branch exits, 100% |
| Existing HTTP audit | 48 methods / 0 skips, 4.619 s; middleware 101 statements / 34 branches, 100% |
| Journal/retention | 77 methods / 0 skips, 3.744 s; core 94/98 branches = 95.9184%, retention 102/102 = 100% |
| Serving/access regression | 81 serving methods / 0 skips, 15.828 s; 32 access methods / 0 skips, 2.046 s |
| Actual candidate | 77 unique cases pass, source dirty=false, release_ready=false |
| New privacy matrix | 12 requests, 36 accepted/durable events confirmed, 3 owned audit files scanned, ambient_signals_used=false |
| Prior audit pair | accepted/durable deltas 8/8, verified qualification context preserved |
| ONNX golden / stopped worker | 3 rows, maximum error 0; stopped worker gives 503 in 2.014582001 s |
| Client quotas | 422/429/422/429, refill 200/200, admitted deltas 2/2/4; boundary window 0.005949042 s |
| Trust outage | 43 client observations; first completed 503 at 59.788612656 s; saved assessment independently recomputed |
| Paused SQL | 503 in 10.002683416 s; ACTIVE observed before denial, query still pending, generation fenced |
| Signed expiry | 503 in 6.686168822 s before signed expiry; renewal and fresh readback version 3 |
| Earlier scoped gates | M03 431/M07 97 cases pass; prior M07 connection failure root cause remains unknown |

Source fingerprint: `f89b7b371d241bd5e6a0dfd9716e8ec071d0efe607e734dfddf7ff5d6029ecc7`. Runtime image: `sha256:9661a1bc0891fdb54bee4cf952e8c14834b0771e4244a01633c479e813b9f6d9`. SHA-256 canonical JSON saved report: **`921cf87f9ad16ab1f9982383b5f29b33d06ba57b2ac4e51eb2de4bb5e8f4c93a`**.

Сохранённый Markdown report перечитан отдельной командой: проверены revision, dirty/release flags, unique cases, exact privacy summary, audit deltas, outage reassessment, pending SQL/fencing и expiry renewal. Это проверка финального артефакта, не только exit code. Windows concurrent real-fsync headroom остаётся inconclusive; Linux pass не объясняет его причину.

## Полная CI matrix

Все 10 workflows `621d355`, attempt 1, terminal: **6 success / 4 failure**. Rerun/cancel не выполнялись. Kubernetes job **118141671684**: M20 **723 cases pass**, finished **2026-10-19T15:29:31.702201+00:00**; M21 **122 cases pass**, finished **2026-10-19T15:31:48.763911+00:00**. Оба reports привязаны к code commit, M21 source dirty=false. API некоторое время продолжал возвращать in_progress; terminal success наблюдался в 15:53:51 UTC. Причина задержки наблюдаемого статуса не установлена; время ожидания API не выдаётся за измерение длительности тестов или исправление CI reliability.

| Workflow | Run | Conclusion / наблюдение |
| --- | --- | --- |
| Documentation | [39276391294](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391294) | success |
| Intake | [39276391447](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391447) | success |
| Developer runtime | [39276391615](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391615) | success; 3 fresh trainings, max probability difference 0, parity 2.086162567138672e-7 |
| Storage | [39276391635](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391635) | success; native privacy/candidate results выше |
| Tracking | [39276391525](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391525) | success; M06 18 cases |
| Kubernetes | [39276391522](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391522) | success; M20 723 / M21 122 cases pass |
| Image audit | [39276391298](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391298) | failure; 4 scans executed, SBOM validated, scanner exit 2 |
| Poisoning | [39276391313](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391313) | failure; 10 violating / 0 inconclusive scenarios, evidence integrity pass |
| Evasion | [39276391111](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391111) | failure; recall drop 0.07183673469387755 > 0.05 |
| Paired training | [39276391120](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391120) | failure; candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05 |

Image Critical/High: worker **0/56**, storage **9/132**, worker-candidate **0/55**, storage-candidate **1/85**. Privacy increment не устраняет image findings и не меняет ML/security thresholds. Successful infrastructure/HTTP checks не разрешают release failed candidate.
