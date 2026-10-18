# T16: audit admission и event schema 2

Дата: 2026-10-18. Base revision `032171796ed6a297e8f19725079da83145f132fd`. Scope: [ADR 0039](../decisions/0039-audit-admission.md), component API, не HTTP/M13 acceptance. Release ready: **false**.

## Native CI: завершённая проверка 01ec902

Code revision `01ec9021cfa8e5a356ca6361ac9b94f0e0744562`. Все 10 workflows terminal, **6 success / 4 failure**, без повторного запуска или отмены. Storage attempt 1: **77 audit methods / 0 skips / 3.795 s**. Event schema 35 statements / 16 branches / 100%; journal **94/98 branches = 95.9184%**, retention **102/102 = 100%**. Per-module >=95% gate pass; aggregate Cover journal 98% не подменяет branch percentage. Новый retained reopen case выполнен на Linux, а не mock.

| Workflow / run | Итог | Проверенное evidence |
|---|---|---|
| [Storage 39129029564](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029564) | success | Job 117680175876; 77 audit tests, M03 431 / M07 97 cases, 72 actual-candidate regression cases pass |
| [Kubernetes 39129029606](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029606) | success | Job 117680176053; M20 723 / M21 122 pass; M21 finished 2026-10-18T13:07:37.682788Z |
| [Developer 39129029664](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029664) | success | Три fresh trainings, max probability difference 0, ONNX parity 2.086162567138672e-7 |
| [Tracking 39129029584](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029584) | success | M06 18 cases pass |
| [Intake 39129029671](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029671) | success | Contracts workflow completed |
| [Docs 39129029559](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029559) | success | Documentation checks, не runtime acceptance |
| [Image audit 39129029649](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029649) | failure | Все четыре scans выполнены, SBOM validated, scanner exit 2; Critical/High: worker 0/56, storage 9/132, worker candidate 0/55, storage candidate 1/85 |
| [Poisoning 39129029639](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029639) | failure | Completed matrix: 10 violating scenarios, 0 inconclusive scenarios; M08 не принят |
| [Evasion 39129029591](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029591) | failure | Recall drop 0.07183673469387755 > 0.05 |
| [Paired 39129029641](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029641) | failure | Candidate recall drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05 |

[Полный sanitized candidate report](audit-admission-01ec902-native.md) перечитан после сохранения: 72 unique case labels, source revision совпадает, source_dirty=false, release_ready=false. Canonical report SHA-256 `9d02dfbbb99600fc09a266ab32c7b2dc223820dd07d90206d84de018965b4218`. Source fingerprint `877bdb7cf3b9030130b8cd0bb2ef55d9636c9a0660a717cf203bebd5b605514d`; runtime image `sha256:9bcfa72f1169556fa2b94a3f3851a5e1d82c65c79cfccc1d3fe20bae1241f216`.

Report assessment пересчитан из 51 outage observation: первый client-completed 503 через 59.745691567 s; paused SQL 503 через 10.001975617 s с ACTIVE до completion; signed expiry 503 через 6.692173955 s до expiry, post-expiry denial при pending SQL и renewal/recovery version 3. Golden error 0; quotas 422/429/422/429, refill 200/200, admissions 2/2/4. Это regression существующего serving, не доказательство HTTP audit emission. Прежний M07 connection failure на 503b68b не считается исправленным новым pass.

## Failure-first и исправление

- До реализации восемь admission methods завершились errors: Journal не имел reserve API. Один test cleanup дополнительно выявил незакрытый descriptor в самой fixture; cleanup переведён в finally.
- До event schema 2 positive cases были rejected, два methods завершились errors. Строгая allowlist реализована без подмены qualification context selection-ом.
- Независимое same-model review нашло normal overload window после расходования всех четырёх holds. Добавленный test воспроизвёл два failures: queue_full и capacity_exhausted вместо штатного admission_full. Guard теперь учитывает все live reservations, не только unused holds. Повторный review новых admission/event изменений не сообщил новых actionable нарушений. Внешняя модель по выбору владельца не использовалась.

## Локальные результаты

Windows, Python 3.12.15, pinned uv environment. Команда:

```text
uv run --locked coverage run --data-file=.coverage-audit-admission --source=mlsecops.serving_audit,mlsecops.audit_event,mlsecops.audit_retention -m unittest scripts.audit_event_qualification scripts.audit_admission_qualification scripts.serving_audit_qualification scripts.audit_retention_qualification
```

Результат: **77 methods, 53 выполнены, 24 skips, 0 failures/errors, 3.229 s**. Skips включают Linux retained restart и прежние platform tests. Это не 77 native passes.

- `audit_event`: 35 statements, 16 branch exits, 100% aggregate Cover, все branches covered.
- `serving_audit`: 250 statements, 2 missed; 96/98 branch exits = 97.9592%. Aggregate Cover округляется до 99%; это не branch percentage.
- `audit_retention`: Windows run не подтверждает native coverage. Существующий Linux >=95% per-module branch gate сохранён без ослабления.
- 169 adjacent methods прошли за 21.679 s, 0 skips: serving context/session/runtime/core/HTTP/native/access, candidate reader/native, release reader/native, outage/pause. Исходный запуск с ошибочным module name не учитывается; окончательная команда и exit 0 сохранены в private `.runtime/audit-admission-adjacent.txt`/`.exit`.
- CI workflow включает обе новые suites в настоящий audit run и отдельный 100% schema coverage gate. Native результат приведён отдельно выше; Windows числа не заменены Linux числами.

Tests проверяют одновременные reservations, bounded metadata после расходования holds, byte/queue budget, отсутствие credit возврата pending data, foreign/old ack rejection, failed sink, abandoned shutdown, mixed legacy/v2 records и недопустимые fields/contexts. Linux-only test делает fresh same-boot retained reopen и проверяет новый sequence 3 после prefix 1-2; локально он skipped.

## Дополнительная проверка после публикации кода

Code revision: `01ec9021cfa8e5a356ca6361ac9b94f0e0744562`, local HEAD и remote main сверены. Шесть in-memory mutations обнаружены assertions, без изменения production files: отключение reservation overload guard (2 failures), ack до fsync (1), over-release pending capacity (1), отсутствие owned sequence check (3), разрешение release_ready true/0 (2), возврат mutable context alias (1). Во всех случаях 0 test errors. Это чувствительность выбранных negative tests, не exhaustive proof.

Промежуточное наблюдение Storage run `39129029564`, job `117680175876` подтвердило success audit step при ещё выполнявшемся полном job. Затем terminal logs проверены, итоговая матрица зафиксирована выше. Следующий push выполняется только после завершения всех 10 workflows, без cancel-in-progress.

## Незавершённые требования

HTTP create_app в code revision 01ec902 пока не использует reserve/confirmed. Нет доказательства durable intent перед actual 200, cancellation/send lifecycle, liveness при stalled sink или all-output canaries/cardinality. Новые 72 serving regression cases относятся к 01ec902; старый report 503b68b сохранён отдельно. Известные image/ML failures и ранее необъяснённый M07 connection failure не исправлены этим кодом. R1 и M13 остаются открытыми.

Эксплуатация и воспроизведение: [RB-58/PB-32](../operations/audit-admission-troubleshooting.md).
