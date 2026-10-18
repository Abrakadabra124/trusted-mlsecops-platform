# T16: audit admission и event schema 2

Дата: 2026-10-18. Base revision `032171796ed6a297e8f19725079da83145f132fd`. Scope: [ADR 0039](../decisions/0039-audit-admission.md), component API, не HTTP/M13 acceptance. Release ready: **false**.

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
- CI workflow включает обе новые suites в настоящий audit run и отдельный 100% schema coverage gate. Native результат пока отсутствует.

Tests проверяют одновременные reservations, bounded metadata после расходования holds, byte/queue budget, отсутствие credit возврата pending data, foreign/old ack rejection, failed sink, abandoned shutdown, mixed legacy/v2 records и недопустимые fields/contexts. Linux-only test делает fresh same-boot retained reopen и проверяет новый sequence 3 после prefix 1-2; локально он skipped.

## Границы

HTTP create_app пока не использует reserve/confirmed. Нет доказательства durable intent перед actual 200, cancellation/send lifecycle, liveness при stalled sink или all-output canaries/cardinality. Старые 72 native serving cases относятся к `503b68b`, а не этому increment. Известные image/ML failures и ранее необъяснённый M07 connection failure не исправлены этим кодом. R1 и M13 остаются открытыми.

Эксплуатация и воспроизведение: [RB-58/PB-32](../operations/audit-admission-troubleshooting.md).
