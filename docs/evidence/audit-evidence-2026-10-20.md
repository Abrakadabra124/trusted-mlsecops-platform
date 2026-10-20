# T16: private primary audit evidence, 2026-10-20

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0049](../decisions/0049-private-audit-evidence.md), [RB-68/PB-42](../operations/audit-evidence-troubleshooting.md).

## Scope

Текущий increment сохраняет exact closed manifest/segments/public stdout и bounded independent HTTP outcomes; родитель после child exit повторно проверяет packet против signed primary materials и своего campaign nonce. Это primary-evidence компонент, не полный M13. Production lifecycle/429/503 privacy matrix, service-log observation, actual/controlled subject composition и отдельная public gate projection остаются открыты.

Предыдущая native точка - [b0df48e](privacy-evidence-b0df48e-native.md). Её 83 cases и CI 6 success / 4 failure не являются результатом нового кода.

## Failure-first и review

- Missing packet module, capture/store/load API, HTTP ledger и parent verifier сначала воспроизведены failing tests.
- Review 1/3 выявил три actionable design issue: реальные 404 без request ID; replay старой campaign с новыми unsigned timestamps; невозможность отличить pre/post-admission 429/503 по status. Добавлены ordinal exchange/null ID, parent nonce в signed permit и наблюдение успешного admission ack.
- Replay RED: прежний parent принял свежедатированный receipt с чужой campaign. Regression теперь требует отказ до packet admission.
- Попытка заменить Journal wrapper-объектом сломала `http_audit_configuration`: production требует exact Journal type. Исправление ограничено методом принадлежащего harness экземпляра; production guard не ослаблен.
- Review 2/3 воспроизвёл false pass после перехваченной ошибки ledger. Собственные RED tests дали 6 failures: duplicate, invalid/oversized/missing-ID response и ошибка HTTP read не блокировали последующий snapshot. Введён постоянный failed state, включая transport exceptions.
- Дополнительный RED: отсутствовал fsync parent directory для новой записи каталога. Добавлены parent fsync, finally-close и controlled fault/readback checks. Это не испытание физического power loss.
- Пользователь отказался от внешней модели. Review выполняет same-model subagent; Antigravity/внешняя модель не использовались.
- Final review 3/3: новых actionable correctness/security issues в согласованном scope не найдено. Reviewer отдельно выполнил 33 local methods без skips и 20-method coverage run 100%; Linux IO проверен только по коду, четвёртый цикл не выполнялся.

## Локальная проверка

Windows, project `.venv`, без Docker/WSL/Kubernetes/SQL. Разрешённые loopback fixtures используют mock worker, не actual ONNX container.

- Focused run: 41 methods, 5 Linux-only skips, 6.718 s. Skips относятся к native packet IO и source-cleanup integration, не выдаются за pass.
- Branch-aware coverage: packet verifier 100%, HTTP observer 100%, retention probe 100%, parent output module 99% (CLI entrypoint).
- Native parent test использует реальные signatures и independently bound proposal/permit; storage IO заменён controlled fixture. Это не native SQL readback.
- Broader regression: 155 methods / 7 Linux-only skips / 37.065 s, включая private packet, parent signatures, public export, FD observer, lifecycle, HTTP и transport ownership. Ruff: 254 files formatted, lint pass. Documentation check: 488 files / 203 Markdown / 1478 local links (до обновления индексов).
- Final changed-suite verification: 20 methods / 0 skips / 0.873 s и 100% statement/branch coverage трёх новых модулей; отдельно 21 parent/output/IO methods / 5 Linux skips / 3.166 s. Documentation: 488 files / 203 Markdown / 1487 local links после обновления индексов.
- **[Native a7a09c8 verified](audit-evidence-a7a09c8-native.md)**: 85 candidate cases, Linux packet 20 / parent-output 26 / export-IO 56 tests без skips. Exact retained packet проверен родителем после child/source cleanup. Все 10 CI terminal, attempt 1: 6 success / 4 failure. Подробные counts, source/image/packet digests, полный synthetic receipt и failed gates сохранены отдельно.

Private `.runtime` хранит локальные RED/GREEN logs и coverage, но они не коммитятся. Public evidence не содержит packet, request/principal IDs, credentials, сырые журналы или private keys.
