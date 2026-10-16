# Private serving context: qualification, 2026-10-16

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Code commit `71518643b65c946784f3c614069457511a4ca1a7`, [ADR 0038](../decisions/0038-serving-audit-context.md), [RB-57/PB-31](../operations/serving-context-troubleshooting.md). Local contracts pass; native results ещё не записаны. Это не full M13/M18/R1 acceptance.

## Реализованный контракт

Verified readers передают versioned context: release-selection с настоящим selection digest или candidate-qualification с permit payload/proposal digests. Kind не заменяет авторизацию; оба результата сохраняют `release_ready=false`. Engine фиксирует context после проверки модели под lock и возвращает его отдельно от public payload с fence того же поколения. HTTP отвергает неизвестный result type, foreign generation, missing context и model/bundle mismatch. Private refs не входят в JSON; финальный deadline fallback снимает context с response.

Новый increment не изменяет audit storage backend и ещё не пишет HTTP events. Наличие private context не доказывает durable audit или ASGI send completion. Scope: код передачи проверенной идентичности, а не полная privacy qualification.

## Failure-first и review

- До реализации HTTP boundary одна negative test дала 10 assertion failures: по пять вариантов на ready/predict (plain dictionary, missing context, old generation, wrong model, wrong bundle) ошибочно получили 200. После реализации ожидаемый 503 подтверждён.
- Старые harness fixtures не содержали identity/context; обнаружены 4 failures и 1 error, затем fixtures исправлены без fallback в production коде. Финальная regression прошла целиком.
- Same-model design review и отдельный implementation review не нашли конкретных дефектов в своих scoped artifacts. Это не внешний человеческий audit; другая модель не привлекалась по решению владельца.
- Controlled in-memory mutation, отключающая context binding, обнаруживается 6 assertion failures HTTP test. Mutation, заменяющая activation snapshot поздним чтением loaded context, обнаруживается 1 assertion failure. Production files не менялись; это чувствительность tests, не production incidents.

## Local Windows / Python 3.12.15

Основная команда: `uv run --locked python -m unittest scripts.serving_context_qualification scripts.serving_session_qualification scripts.serving_runtime_qualification scripts.serving_core_qualification scripts.serving_http_qualification scripts.serving_native_qualification scripts.serving_access_qualification scripts.candidate_serving_reader_qualification scripts.candidate_serving_native_qualification scripts.release_reader_qualification scripts.release_reader_native_qualification scripts.serving_outage_qualification scripts.serving_pause_qualification`.

**168 methods pass, 0 skips, 28.566 s**. Loopback HTTP tests работают с controlled worker fixtures; они не заменяют настоящие ONNX/SQL/container checks.

Отдельные измерения Coverage.py:

| Scope | Tests | Statements | Branch exits | Cover |
| --- | --- | --- | --- | --- |
| serving_context | 7 pass | 31, no misses | 4, no misses | 100% |
| release_reader | 19 pass | 132, no misses | 38, no misses | 100% |
| candidate_serving_reader | 17 pass | 116, 4 misses | 26, 4 partial | 94% |
| serving protocol/worker/runtime/core/HTTP | 80 pass | 729, 34 misses | 206, 23 partial | 94% |

Последняя колонка - агрегированный Cover, не отдельный branch percentage. Для context нет ни statement, ни branch misses, поэтому оба показателя 100%. Для остальных из Cover нельзя вывести достижение общего M18 branch threshold. Existing per-module core/retention branch gate не изменён.

Ruff check/format pass, 208 files. Docs checker перед code commit: 392 files, 153 Markdown documents, 1108 local links с локальными пользовательскими instructions. Native runtime пользователя не запускался и не менялся; AGENTS.md/GOAL.md остались вне commit.

## Native CI

Первый [Storage CI 7151864](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38937731842), job 117097348863, **failure** на context unit tests: `test_failed_recheck_does_not_return_or_retain_success_context` повторно активировал engine до завершения asynchronous retirement. Реальная защита вернула `serving_cleanup_pending`. Actual-candidate HTTP step не выполнялся, его pass не заявляется.

Исправлен test lifecycle: после каждой rejected operation вызывается `engine.drain()` и проверяется отсутствие cleanup/retiring. Production code неизменен. Controlled Worker.close delay 0.05 s воспроизводит исходную ошибку; исправленный test проходит 20 повторений. Context suite повторно 7 pass, 31 statements / 4 branch exits, 100%. Требуется fresh CI исправленного commit, не простой rerun flaky test.

Пять context cases добавлены к actual-candidate matrix; наличие кода пока не считается native evidence. Исторические результаты `42ce792` не подменяют новый прогон.

## Следующий scope

Совместимая версия event schema для qualification, ограниченная admission/reservation policy и реальные ASGI start/body/disconnect события. Нельзя объявлять queue acceptance durability, записывать completed до успешного send или продлевать trust deadline ожиданием fsync. Затем all-output canaries/cardinality и full M13. Image/ML blockers сохраняются до нового измеренного результата, не скрываются успешной компонентной проверкой.
