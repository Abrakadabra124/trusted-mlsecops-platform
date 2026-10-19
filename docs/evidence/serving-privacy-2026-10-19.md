# T16: существующие serving outputs и privacy boundary

Дата: 2026-10-19. Статус: implemented, local tests pass; native actual-candidate verification pending. Scope: неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0041](../decisions/0041-serving-output-privacy.md), [RB-60/PB-34](../operations/serving-privacy-troubleshooting.md).

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

Настоящий loopback с controlled Engine выполняет 12 requests и подтверждает 36 audit events; это не actual ONNX/container candidate. Raw transport regression покрывает oversized loopback response и incomplete Content-Length через настоящий HTTPResponse parser с controlled input. Полный native pipeline пока не запускался для этой revision. Процент покрытия относится только к новому probe, не ко всей системе и не к доказательству всех security properties.

После review 2 отдельно повторены изменённые native/candidate harness contracts: **16 methods / 0 skips, 15.845 s**. Три platform skips предыдущей adjacent suite: POSIX directory identity, retained concurrency/real fsync и owned retained lifecycle. Linux CI обязан выполнить их, а не сохранить skips. Ruff и docs checker проходят; проверка документации не подтверждает внешние URLs или runtime acceptance.

## Review и ограничения

Same-model adversarial review cycle 1 нашёл три actionable defects: тихое усечение response, пропущенный full feature object и неверный partial interception. Cycle 2 выявил непроверяемый active bearer и обход сравнения object через flatten/vector. Final cycle 3 нашёл escaping в header capture. Все шесть замечаний воспроизведены и исправлены. Последнее исправление проверено regression/coverage автором, но повторного независимого review не было: лимит трёх циклов соблюдён. Внешняя модель не использовалась по выбору владельца.

Scope summary: `existing-serving-output-privacy-not-full-M13`. Только owned temporary audit и controller outputs во время 12 cases. Worker subprocess outputs, approved metrics/trace policy/cardinality, public export всей платформы и полная correlation chain остаются открытыми. Нельзя принимать M13 по отключённой telemetry или одному counter. Исторические image/poisoning/evasion/paired failures и M07 reliability debt не устранены этим изменением. Полный R1 и release approval остаются запрещены.
