# RB-60 / PB-34: serving privacy и полнота диагностического capture

Scope: неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Владелец процедуры - оператор qualification; изменение production policy требует владельца сервиса и security review. Это synthetic qualification, не отчёт о production-инциденте. [ADR 0041](../decisions/0041-serving-output-privacy.md), [evidence](../evidence/serving-privacy-2026-10-19.md).

## RB-60: предварительные условия и read-only диагностика

Использовать checkout trusted-mlsecops-platform, закреплённый `uv.lock` и Python 3.12. Не запускать локальные Docker/WSL/Kubernetes/SQL: native integration разрешена только в disposable CI. Команды тестов ниже создают собственные tempfiles, threads и loopback listener, но не меняют действующий сервис.

```powershell
git status --short
git rev-parse HEAD
uv run --locked python -c "import importlib.metadata as m; print({n:m.version(n) for n in ('fastapi','uvicorn','opentelemetry-api')})"
```

Зафиксировать revision и dirty state. Не печатать environment целиком, Authorization, raw request, приватный audit, URL хранилищ или exporter headers. Git HEAD без проверки dirty state не доказывает источник запуска.

## Диагностические ветви

| Симптом | Причина/проверка | Безопасное действие |
| --- | --- | --- |
| `privacy_ambient_signals_used` | Native provider был использован; проверить пять explicit flags и positive control | Остановить qualification/promotion, проверить version/diff; не отключать detector |
| 307 или `privacy_response_canary` | Slash redirect либо отражённый marker/full feature object | Проверить canonical route и response producer; не маскировать готовый evidence |
| `privacy_response_headers` / `privacy_response_schema` | Неизвестное поле, дубликат или неверный формат публичного output | Проверить API producer/версию; не разрешать произвольные debug fields |
| `privacy_output_canary` | Marker/credential/feature найден в captured stdout/stderr/logging | Локализовать producer в private evidence, не копировать значение в issue |
| `privacy_private_audit_canary` | Marker в owned journal bytes или filename | Остановить pass, проверить event schema/producer; не удалять журнал для зелёного результата |
| `serving_native_response_overflow` / `privacy_capture_overflow` | Capture неполон из-за ограничения | Fail/inconclusive, устранить неожиданный объём; не принять обрезанный prefix |
| `serving_native_response_incomplete` | HTTP body короче объявленного Content-Length | Проверить framing/transport failure; не анализировать prefix как полный ответ |
| `privacy_audit_source_invalid` / `privacy_audit_receipt_invalid` | Missing/empty source, links, bounds или неверный receipt | Проверить ownership собственного fixture; не расширять scanner на реальные каталоги |
| `privacy_audit_accounting` / `privacy_audit_pending` | Не подтверждены 36 events или остались reservations | Использовать [RB-59](serving-http-audit-troubleshooting.md); не сбрасывать counters |
| `privacy_http_status` | Матрица нарушена: auth, rate limit, trust, model или audit | Сохранить failure; проверить предыдущие native steps и trust renewal, не менять ожидаемый статус ради pass |

## Встреченные проблемы и исправления

1. Default FastAPI instrumentation записала synthetic path/query в controlled span. Явные telemetry flags закрывают native channel; положительный контроль оставлен. Внешний exporter не запускался, реальная утечка данных не заявляется.
2. Default slash redirect отразил query в Location. Точные routes теперь не перенаправляют: 404 без marker, в том числе с произвольным Host.
3. Raw HTTP helper возвращал первые 65537 bytes, скрывая canary в хвосте большого ответа. Проверка теперь отклоняет overflow и неполный framing; regression использует настоящий loopback для overflow и настоящий HTTPResponse parser с controlled bytes для truncated body.
4. Response checker исключал вместе с одиночным numeric score весь feature object. Теперь полный object ищется и в normalized JSON; compact/pretty payload воспроизводили false pass до исправления.
5. Scanner callback использует `partial`, который перехватчик credential-wrapper теста ошибочно принимал за свой вызов. Тест теперь перехватывает только `credential=` binding и проверяет перенос обоих callbacks: audit status и scan. Runtime auth не изменён.
6. Повторный review показал ещё два false pass: действующий bearer отсутствовал в canaries, а full feature object обходил поиск через flatten/vector. Теперь используется также фактический credential теста, а публичные JSON responses проходят exact schema. Настоящие loopback negative controls отражают действующий Authorization в header/log и обязаны отклоняться; это тест детектора, не оставленная runtime instrumentation.
7. Final review воспроизвёл feature JSON в HTTP header: сериализация списка headers экранировала кавычки и скрывала совпадение. Raw header scan и allowlist имён/форматов закрывают этот обход. Regression сначала failed на реальном loopback, затем прошёл; четвёртый review не выполнялся.

## PB-34: воспроизводимая последовательность

1. Выполнить read-only команды выше, подтвердить repository/ownership и synthetic-only scope.
2. Проверить детектор и существующую обвязку:

```powershell
uv run --locked coverage run --data-file=.coverage-privacy --source=scripts.serving_privacy_probe -m unittest scripts.serving_privacy_qualification
uv run --locked coverage report --data-file=.coverage-privacy --fail-under=100
uv run --locked python -m unittest scripts.serving_native_qualification scripts.candidate_serving_native_qualification
uv run --locked python scripts/check_docs.py
```

Expected: privacy 17 methods / 0 skips, probe 100% statements/branches, native harness contracts без failures. Это локальные contract/loopback tests, не native candidate. Не повторять чистый прогон без изменения кода или нового основания.

3. После approved commit/push дождаться всех 10 CI terminal. В Storage проверить именно новую revision и attempt: privacy step, actual candidate `http_privacy`, 12 requests, 36 confirmed events, nonzero audit files, no ambient signals, `release_ready=false`. Ожидаются три новых case IDs сверх прежних 74, но 77 не считается доказанным до actual run.
4. Проверить вместе с privacy прежние auth/quota/expiry/outage/correlation результаты. Один успешный privacy command не заменяет все M-gates. Не rerun/cancel вслепую, не скрывать failed image/ML workflows.
5. Публиковать только очищенный finite summary, версии/digests и ссылки на точные CI runs. Проверить сохранённый файл evidence, а не только stdout команды. Raw capture и journal остаются private.

## Восстановление, rollback и эскалация

При ошибке детектора остановить acceptance и исправить/перепроверить сам detector, затем повторить соответствующий ограниченный тест. При runtime regression запретить promotion и восстановить только заранее проверенный immutable artifact по существующим процедурам release/recovery. Не включать native telemetry или access logging для «временной диагностики» с реальным input, не удалять audit directory и не создавать fictitious approval.

Если требуется rollback к версии до этого исправления, privacy boundary той версии не доказана: в лаборатории безопаснее остановить protected serving, чем объявить её пригодной для реальных данных. Общий production rollback этой процедурой не проверен. Эскалация обязательна при неполном capture, unknown source ownership, повторной недоступности writer, изменении framework semantics или необходимости использовать реальные данные/внешний exporter.
