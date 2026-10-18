# RB-58 / PB-32: audit admission, pending durability и versioned events

Этот runbook описывает backend на исходном component increment `01ec902`. Подключённый позднее HTTP lifecycle и его текущие ограничения описаны отдельно в [RB-59/PB-33](serving-http-audit-troubleshooting.md).

Scope: [ADR 0039](../decisions/0039-audit-admission.md), journal component. HTTP producer пока не подключён. Не интерпретировать этот runbook как подтверждение живого service audit или полной M13 privacy acceptance.

## RB-58: диагностика

Ответственный - оператор disposable lab и владелец serving/audit controller. Prerequisites: известны checkout revision, isolated Python 3.12 environment и owner private journal directory. Linux retained state требует прежних private permissions и same-boot ownership. Не запускать Docker/WSL и не трогать working SQL ради этих tests.

Read-only сначала:

```powershell
git rev-parse HEAD
git status --short
uv run --locked python -m unittest scripts.audit_admission_qualification scripts.audit_event_qualification
```

Tests создают и удаляют только собственные temporary files. Linux restart case на Windows имеет явный skip; это не native pass. Не передавать production journal path в test fixture. Не печатать содержимое private JSONL: identifiers, correlation refs и credentials не нужны для диагностики admission.

Для уже имеющегося Journal использовать его bounded `status()` внутри owner process, не открывать второй writer. Разбирать только числовые счётчики и фиксированный failure code:

| Симптом | Проверка и действие |
|---|---|
| `audit_admission_full`, healthy true | Проверить `pending + held_slots`, количество reservations и `reserved_bytes + held_bytes` против настроенных caps. Не повышать лимиты и не сбрасывать tickets. Дать принятым operations завершиться; новый admission может быть отклонён штатно. |
| `held_slots=0`, reservations > 0 | Все четыре события ticket приняты, но producer ещё не вызвал release. Metadata остаётся ограниченной. Проверить owner finally; не освобождать неизвестные чужие tickets. |
| `confirmed` false | Запись принята, но fsync ещё не подтверждён. Не объявлять её durable, не продолжать защищённый ответ за trust deadline. Сохранить intended/actual distinction в будущем HTTP producer. |
| `audit_reservation_invalid` | Проверить, что ticket и sequence получены от того же Journal и ещё активны. Не подставлять старый persisted sequence или чужой request ID. |
| `audit_unavailable`, `sink_failed`, unconfirmed > 0 | Остановить новые protected admissions, сохранить evidence gap. Диагностировать storage по [RB-56](audit-retention-troubleshooting.md). Не выдумывать terminal event и не удалять guard/segment. |
| `reservations_open` при close | Shutdown произошёл до producer finally. Это не clean close. Найти незавершённый owner request; release возвращает лишь unused holds, не исправляет уже зафиксированный failure и не переписывает history. |
| `audit_event_invalid` | Проверить exact schema/version и context kind, не логируя raw offending value. Qualification permit не переименовывается в selection. Убрать payload/custom fields из producer; malformed event даёт sticky failure. |

## Проблема, найденная при реализации

Controlled review выявил: после четырёх accepted events held count становится нулевым, но ticket ещё ждёт durability. Ранний вариант проверял overload только при ненулевом hold; чужой unticketed emit мог установить sticky queue/disk failure и лишить request подтверждения. Это лабораторный воспроизводимый дефект, не production incident.

Исправление учитывает наличие live reservations, включая полностью consumed. Negative test сначала воспроизвёл оба отказа (`audit_queue_full` и `audit_capacity_exhausted`), затем проверил normal rejection, healthy status, ложный ack до fsync и настоящий ack после возобновления writer. Storage caps и legacy-only failure policy не ослаблены.

## PB-32: проверяемая последовательность

1. Зафиксировать revision/status read-only командами. Не включать пользовательские изменения AGENTS/GOAL в commits.
2. Выполнить две новые suites, затем смежные `scripts.serving_audit_qualification` и `scripts.audit_retention_qualification`. Expected: нет failure/error; skip отражает платформенное ограничение, не выполненный тест.
3. В disposable Linux CI выполнить те же suites без native skips, schema coverage 100% и прежний per-module audit branch gate >=95%. Сохранить CI run/job/attempt и результаты, включая failed attempts.
4. При sink fault сохранить private spool и ownership. Recovery/restart только по RB-56, без удаления единственной копии, stale guard reset или отключения permissions. При unknown ownership/crash state эскалировать оператору; автоматическое восстановление не заявлено.
5. Критерий закрытия component incident: negative reproduction проходит, pending/durable/hold accounting согласованы, clean close после всех release проверен. Это не закрывает HTTP admission, actual send/cancel, canaries или M13.

Rollback нового API: остановить его producer, дождаться bounded close и сохранить private spool. Не запускать старый event exporter на новых records без проверки версии. Нельзя объявить восстановление законченно успешной командой Git: отдельно проверить owner process, journal health и конечное состояние. Production rollout этого component ещё не выполнен.
