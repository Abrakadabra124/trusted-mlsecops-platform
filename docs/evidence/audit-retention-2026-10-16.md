# Audit retention: qualification, 2026-10-16

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». База `09b535f`, [ADR 0037](../decisions/0037-audit-retention.md), [RB-56/PB-30](../operations/audit-retention-troubleshooting.md). Статус: corrected native component qualification пройдена на `b2b3bf6`, **51 tests pass / 0 skips**. Полная задача T16/M13/R1 и M18 branch-coverage acceptance остаются открытыми. Локальные checkpoints ниже сохраняются как история, не заменяют этот native результат.

## Реализованный scope

Explicit `Journal(..., retention=Policy(...))`: fd-relative Linux spool, bounded segments и metadata, exclusive ownership до snapshot, per-record sync, byte/age rotation, maintenance без новых requests, минимальная retention и clean same-boot restart без reset sequence/age/budget. Queue admission по-прежнему не делает I/O. Legacy single-file contract сохранён.

Повторный запуск после crash/reboot не объявляется автоматическим recovery; unknown/stale lease требует reconciliation. Windows native retained mode отвергается, не имитируется через permissive paths. Нет HTTP integration, новой release authority или обхода failed/inconclusive gates.

## Failure-first и review

Отсутствие модуля и retention keyword дали первые RED tests. Затем tests воспроизвели leaked cleanup exception и отсутствие явного closed guard. Исправления возвращают bounded error и запрещают вызовы после освобождения directory FD. Design review выявил два уточнения: lease-before-snapshot и точка handoff до завершающего fsync/close. Порядок подтверждается отдельными interleaving scenarios в native suite; внешний reviewer/model не используется по решению владельца.

## Локальная проверка

Windows после первого implementation review: **45 methods, 29 pass / 16 explicit POSIX skips**, 2.136 s. Из них 21 прежний core contract и 24 retention contracts; 15 новых native filesystem cases ещё требуют Linux. До добавления cursor regression смежная suite дала 229 methods, 214 pass / 15 skips за 26.566 s. Предыдущий coverage checkpoint: serving_audit **98%**; audit_retention **27%** на Windows не достигает native threshold и не принимается за доказательство filesystem поведения. Ruff lint/format проходят. Native Linux результаты, exact revision и CI matrix добавляются только после фактического прогона.

Implementation review выявил shared directory cursor у повторного `scandir(fd)`. Controlled regression сначала получил пустой второй inventory вместо `.lease`. Теперь каждый bounded scan открывает независимый `.` относительно owned directory FD; отдельный native regression добавлен для Linux. Это исправление подтверждено controlled test, но исходный дефект не воспроизводился в локальном Linux runtime, который не запускался.

## Корректирующий review после первого CI

На `e67223996ddfa7be5d4ae6d19f81c179fe0134c4` [storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38926452268), job `117059112163`, завершён success: **45 tests pass**, serving_audit coverage **97%**, audit_retention **92%**, actual-candidate regression **67 cases pass**, release_ready=false. Это исторический первый прогон, не qualification исправлений ниже. Candidate campaign `636ff75401b54c08b1d6c71704a0dabc`.

Второй review нашёл два новых validation defects: null clock принимался как новый anchor; manifest head мог отставать от фактических records и повторно выдать sequence. Controlled RED cases воспроизвели clock bypass, duplicate head, duplicate/gapped records. Исправления требуют persisted clock и проверяют bounded canonical lines, непрерывность sequences и exact head. Дополнительно проверен O_NONBLOCK при чтении: FIFO не должен блокировать до fstat. Native FIFO и real-clock idle-expiry tests добавлены, но ещё не выполнены в corrected Linux CI.

Заключительный review 3/3 завершён без новых конкретных воспроизводимых дефектов в заявленном контракте. Внешняя модель не использовалась. Три bounded implementation review cycles закончены; это не независимый человеческий security audit.

Corrected local Windows checkpoint: **51 methods, 33 pass / 18 explicit native skips**, 2.194 s. Смежная suite перед добавлением последнего Linux-only timer test: **236 methods, 219 pass / 17 skips**, 34.286 s. Coverage checkpoint на 50 methods: serving_audit **98%**, audit_retention **44%**; native threshold по-прежнему не считается пройденным на Windows. Ruff и docs checker проходят: 383 files, 148 Markdown documents, 1069 local links, включая локальные пользовательские instructions. Native corrected qualification pending.

Рабочие Docker/WSL/Kubernetes и enterprise foundation не изменялись. В `AGENTS.md` и `GOAL.md` обнаружены отдельные пользовательские изменения правил отчётности: они соблюдаются, но не включаются автоматически в code commit этого increment.

## Corrected native component: b2b3bf6

[Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710730), job `117066845457`, exact code `b2b3bf65b7b740318c5f5d0086fa380a14b834b1`, Ubuntu 24.04 / Python 3.12.15: **51 tests pass без skips за 2.927 s**. Core 21 + retention 30 methods включают controlled failures и реальные Linux filesystem cases. FIFO startup, same-boot restart, independent inventory cursor, minimum retention с реальными часами/idle maintenance, fd-relative parent replacement, ownership/handoff и отказ fsync проверены в disposable runner. Это не испытание физического power loss или storage firmware.

Coverage.py с branch measurement: serving_audit **97% Cover**, 211 statements / 80 branches / 5 missing statements / 3 partial branches; audit_retention **93% Cover**, 266 statements / 102 branches / 13 missing statements / 14 partial branches. Отдельные component thresholds >=95% и >=90% пройдены, прежний core threshold не ослаблен. Итоговая колонка Cover смешивает statements и branches: **93% не означает 93% branch coverage**. Обязательные >=95% branch coverage новой security-critical логики по M18 этим не доказаны; требуется отдельное закрытие непокрытых ветвей до финальной приёмки.

Повторная локальная regression после публикации code: **182 methods, 164 pass / 18 explicit POSIX skips за 27.933 s**. Это отдельная более узкая suite из 12 модулей, не повтор исторического набора 236 methods. Команда: `uv run --locked python -m unittest scripts.serving_audit_qualification scripts.audit_retention_qualification scripts.serving_access_qualification scripts.serving_session_qualification scripts.serving_runtime_qualification scripts.serving_core_qualification scripts.serving_http_qualification scripts.serving_native_qualification scripts.candidate_serving_reader_qualification scripts.candidate_serving_native_qualification scripts.serving_outage_qualification scripts.serving_pause_qualification`. Ruff check и format проходят, 204 Python files unchanged by formatter.

## Actual-candidate regression, не HTTP audit acceptance

В том же storage job: **67 cases pass**, source_dirty=false, release_ready=false. [Полный sanitized report](audit-retention-b2b3bf6.md), canonical SHA-256 `1e3c18a6cf0f542c2d3b1efe80138fc883878a13892ca4fa38de3e7efe570279`, campaign `7c11f550be1c4c75b70ec795bb3161e1`. Source fingerprint `9eac6f96db4e55438097b792903abee05ae8f3cc10369a8789129a1eef16de18`, runtime image `sha256:faf7129cd5e77d916a4f39c7b3fcd349cf61f77071199ec475ff53515b3baf51`.

- Golden consistency error 0.0; stopped-worker denial 2.013518621 s.
- Quotas: statuses 422/429/422/429, refill 200/200, admitted deltas [2,2,4]. Это существующая client admission, не новое audit подключение.
- Trust outage: первый client-completed HTTP 503 через 59.761295788 s от last verified read; 54 observations. Assessment повторно вычислен из сохранённого report, не только скопирован status.
- Paused SQL: HTTP 503 за 10.001781662 s, query всё ещё ACTIVE, read не завершён, поколение fenced. ACTIVE timestamp находится внутри request interval.
- Настоящая короткая signed policy: HTTP 503 за 6.705806780 s до lease deadline и policy expiry; после expiry повторный 503 при pending query. Renewal/recovery version 3 и сохранность исходного candidate подтверждены.

Сохранённый JSON повторно прочитан: canonical hash, уникальность 67 case IDs, exact revision, source_dirty/release_ready, outage assessment, ACTIVE ordering, pre/post-expiry и quota invariants проверены assertions. Журнал не подключён к HTTP; эта регрессия доказывает сохранность прежнего serving поведения, а не новые M13 correlation/privacy controls.

## Terminal CI matrix: b2b3bf6

Все **10 workflows terminal: 6 success / 4 failure**. Проверено после завершения Kubernetes, до docs-only публикации; запущенные jobs не прерывались новым push. Это не all-green release и не принятие full M18.

| Workflow | Результат |
| --- | --- |
| [Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710730) | success; audit 51, M03 431, M07 97 и actual-candidate 67 cases pass |
| [Developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710807) | success; три fresh trainings, maximum probability difference 0.0, sklearn/ONNX parity error 2.086162567138672e-7 |
| [Tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710720) | success; M06 18 cases pass |
| [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710715) | success; M20 723 / M21 122 cases pass; M21 finished 2026-10-16T16:18:23.736830 UTC |
| [Intake contracts](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710746) | success |
| [Documentation](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710817) | success; documentation integrity, не runtime acceptance |
| [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710849) | failure; Critical/High: worker 0/56, storage 9/132, worker-candidate 0/55, storage-candidate 1/85. Все четыре scans executed, SBOM validated, scanner exit 2 |
| [Poisoning](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710842) | failure; execution complete, primary evidence integrity pass, 35 verified cases / 251 files, 10 violating scenarios, 0 inconclusive scenarios; full M08 inconclusive |
| [Evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710811) | failure; execution complete / primary reconciliation pass, recall drop 0.07183673469387755 > 0.05 |
| [Paired robustness](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710771) | failure; execution complete / primary reconciliation pass. Candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05 |

Campaign IDs: poisoning `9639c9a4efe44d3b8708f2d649b32bfb`, evasion `ef63a25c239a4131a70bee47fe4af23d`, paired `fe6f8cf9fe9c49db98ce1b40ec9ce117`. Values получены из текущих primary reports, не перенесены из прошлого дня: в частности, storage High count сейчас 132, а не прежние 131. Успешная reconciliation доказывает согласованность evidence, не устойчивость модели. Никакой security/ML threshold, failure exit или scanner finding не отключён ради зелёного CI.

## Следующая граница и ограничения

[План T16](../../tasks/plan.md) сохраняет следующий scope: versioned immutable release/qualification contexts, ASGI actual-send transitions, explicit sink-failure/admission policy, all-output canaries и bounded cardinality. Нельзя выдавать permit/proposal hash за promotion selection, а transport completion за доказанную доставку клиенту. Crash/reboot reconciliation и M18 branch coverage остаются отдельной обязательной работой. До full acceptance `release_ready=false`; успешный storage job не отменяет image/ML failures.
