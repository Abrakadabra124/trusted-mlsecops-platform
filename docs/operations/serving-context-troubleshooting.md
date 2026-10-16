# RB-57 / PB-31: serving context binding

Неделя 9, T16. Owner: инженер serving/control plane. Scope: [ADR 0038](../decisions/0038-serving-audit-context.md), private context handoff, не audit sink recovery. Prerequisites: checkout точной revision, locked Python environment; native runtime только собственный disposable CI. Локальный Docker/WSL/cluster пользователя не трогать.

## Симптомы и установленный дефект

- Readiness/inference возвращает 503 при работающем worker: возможны отсутствие typed result, другая модель/generation или истекший budget. Сам 503 не устанавливает причину.
- Candidate размечен как release-selection: нарушение provenance, не подтверждение promotion; остановить публикацию такого evidence.
- Success заменяется на 503 после serialization: проверить deadline/fence, не отключать fail-closed проверку.

При реализации unit fixtures возвращали старые dictionaries без model/context. После перехода HTTP на typed result пять harness cases перестали получать 200. Исправлены fixtures без ослабления production boundary. Это тестовый integration defect, не production incident. После исправления 168 adjacent tests pass.

## PB-31: диагностика

Из корня проекта, сначала read-only:

```powershell
git status --short
git rev-parse HEAD
gh run list --commit (git rev-parse HEAD) --limit 20 --json databaseId,name,status,conclusion
```

Проверять code commit, не последующий docs-only checkpoint. Не публиковать credentials, permit, reader object или private exceptions. Conclusion без report/source binding не доказывает конкретный сценарий.

Следующие команды создают только controlled temporary test resources и coverage file. Loopback HTTP helper не равен production validation:

```powershell
uv run --locked python -m unittest scripts.serving_context_qualification scripts.release_reader_qualification scripts.candidate_serving_reader_qualification scripts.serving_core_qualification scripts.serving_http_qualification scripts.candidate_serving_native_qualification scripts.serving_native_qualification
uv run --locked coverage run --data-file=.coverage-serving-context --source=mlsecops.serving_context -m unittest scripts.serving_context_qualification
uv run --locked coverage report --data-file=.coverage-serving-context --fail-under=100
uv run --locked python scripts/check_docs.py
```

Expected: методы pass, отдельный context module 100%, docs pass. Не подставлять старую coverage DB: run создаёт свежую. Команды не принимают M13 и не проверяют native model isolation.

## Ветви отказа и recovery

1. **Plain result:** сопоставить caller/callee одной revision; исправить fixture/adapter. Не добавлять fallback, читающий глобальный engine после ответа.
2. **Permit/selection:** использовать qualification тип и verified permit payload digest. Не синтезировать approval и не редактировать signed artifacts.
3. **Model/bundle mismatch:** сохранить bounded private incident record, запретить success. Повторить проверку материалов и worker binding на новом disposable стенде, не менять digest вручную.
4. **Old generation / expired lease:** старый ответ нельзя перепривязать к новой модели. Завершить 503, восстановить доверие по [RB-53](serving-deadline-troubleshooting.md), явно activate и отправить новый запрос. Автоматический restart здесь не реализован.
5. **HTTP pass, audit file пуст:** increment не пишет HTTP events. Не создавать фиктивные записи и не выдавать handoff за end-to-end audit.

Rollback: не выполнять reset/prune или удаление spool. При регрессии запретить promotion, исправить commit, повторить scoped CI. Развёртывание предыдущей revision требует обычной release/trust проверки; эта процедура не разрешает live rollback на компьютере пользователя. Recovery против реального deployment здесь не выполнялся.

## Конечное состояние и эскалация

Проверить exact revision, local contracts, пять native context cases и соседние quota/deadline/outage сценарии. Public JSON сохраняет прежние поля без permit/proposal/selection. Native report должен быть clean-source и `release_ready=false` для qualification. M13 открыт до ASGI events, sink admission policy и all-output canaries. Escalate при неизвестном verified reference, повторном mismatch или утечке refs; передавать очищенные case labels/status, не payload.
