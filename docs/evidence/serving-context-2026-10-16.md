# Private serving context: qualification, 2026-10-16

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Initial implementation `7151864`, corrected code **`503b68bbde0fb619132a0e1d797b0173ec55d3f5`**, [ADR 0038](../decisions/0038-serving-audit-context.md), [RB-57/PB-31](../operations/serving-context-troubleshooting.md). **Native component qualification pass: 72 cases, Storage attempt 2.** Не full M13/M18/R1 acceptance. История failed attempts сохранена, нестабильность M07 не объявлена исправленной.

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

Исправление опубликовано как `9326fcde917c92a4a34aa06c2a21b8720a55e47f`. Повторная Windows regression: 168 methods pass без skips, 28.167 s. Scoped review drain/fence ordering замечаний не нашёл. Все десять workflows первой revision были terminal до следующего push: 5 success / 5 failure, включая дополнительный исправляемый Storage failure. [Kubernetes 7151864](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38937731827): M20 723 pass, M21 122 pass, завершение M21 2026-10-16T17:27:31.242179Z. Эти результаты не являются новым прогоном 9326fcd.

Пять context cases добавлены к actual-candidate matrix; наличие кода пока не считается native evidence. Исторические результаты `42ce792` не подменяют новый прогон.

### Вторая попытка: 9326fcd

[Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38939866993), job 117104507602: context/unit и controlled native HTTP/ONNX/TLS прошли. Пять новых context cases actual candidate pass, но полный workflow **failure**: paused SQL probe всё ещё оборачивал old `predict`, которого HTTP больше не вызывает. `connected_read_entered=false`, ACTIVE отсутствует, HTTP 200; qualification корректно завершилась отказом, а не фиктивным pass. [Очищенные excerpts](serving-context-9326fcd-partial.md) сохранены.

Hook исправлен на `predict_result`. Failure-first loopback HTTP test до исправления обнаружил ноль вызовов probe.run, после - ровно один и selected=true внутри reader. Тест использует настоящий HTTP/Engine dispatch, но controlled worker и не выполняет SQL/container pause: намеренно проверяет inconclusive, не выдаёт себя за native outage. Pause suite: 15 pass, Cover 94%; для полного actual-candidate результата требуется следующая fresh revision. Пороги ACTIVE/pending/deadline/fence не ослаблены.

Исправление опубликовано как `503b68bbde0fb619132a0e1d797b0173ec55d3f5`; локальная полная смежная regression теперь **169 methods pass, 0 skips, 30.081 s**. Третий и последний scoped implementation review подключения fault injection замечаний не нашёл. Перед push все workflows 9326fcd завершились: 5 success / 5 failure; [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38939866726) M20 723 / M21 122 pass, M21 finished 2026-10-16T17:43:43.880186Z.

### 503b68b: отдельный ранний отказ M07

[Storage attempt 1](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124426/attempts/1), job 117112099518, прервался до serving на M07. [Сохранённый report](serving-context-503b68b-attempt1.md): 32 attempts, 31 claimed slots, один `storage_connection_rejected` вместо ожидаемого `holdout_budget_exhausted`. Это реальный отказ qualification, не допустимый pass бюджетного контроля. Причина соединения остаётся неизвестной; ни connection/lock/resource contention, ни связь с context change не доказаны.

Запрошен один повтор того же commit на новом disposable runner, без debug/raw-secret logging и без изменения M07/SQL политики или порогов. Прежний отказ не удалён; возможный pass повторения не доказывает исправление причины. Runtime бюджет и данные пользователя не изменялись. Повтор такой нестабильности требует отдельной диагностики по [RB-27](../operations/qualification-environment-troubleshooting.md), не бесконечного rerun до зелёного.

## Итоговая native qualification: 503b68b

[Storage attempt 2](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124426/attempts/2), job `117113836984`, success. [Полный очищенный candidate report](serving-context-503b68b.md): campaign `80e96787fd4b4745b260893e277e525d`, 72 уникальных cases pass, source_dirty=false, release_ready=false. Finished 2026-10-16T17:57:41.271415Z. Source fingerprint `ba76619b9a6231b2d120ed117b711e3b0413bbe849fac6c593a6f75e82a98bbc`; runtime image `sha256:abcb339a52ccce3e3790118c51d60654ffcc814634a616f1bda4ff06728d1665`. Повторная сборка не объявляется bit-for-bit identical.

Пять новых cases: candidate не release-selection; readiness и prediction связаны с context/generation; private refs не входят в публичный ответ; public shape не изменён. Вместе с ними повторно прошли исходные 67 cases, а не только новый happy path.

- Golden error 0; остановленный worker получает HTTP denial за 2.014195480 s.
- Trust outage: первый завершённый клиентский 503 за 59.741860846 s, 52 observations, assessment pass. Trace пересчитан из сохранённого файла через `assess`, не только прочитан итоговый status.
- Настоящий paused SQL: 503 за 10.001544697 s; connected read вошёл, libpq ACTIVE наблюдался до завершения HTTP, чтение оставалось pending, generation fenced. Это исправленная проверка воздействия, а не mock исключение.
- Short signed policy: 503 за 6.698285174 s до expiry; после expiry ещё один 503 при ACTIVE/pending SQL. Подписанное renewal и recovery version 3 подтверждены.
- Quotas: boundary 422/429/422/429, refill 200/200, admitted deltas 2/2/4. Лимиты не ослаблены для прохождения context checks.

Сохранённый JSON заново прочитан и проверен: exact source revision, clean source, 72 unique cases, пять новых labels, outage recomputation, ACTIVE ordering, pre/post-expiry, renewal и quota invariants. SHA-256 canonical сохранённого report: **`4d201f8c0e0c65daec9f2996fc2379fc1b3eadc7fc5fe66c853fb078895c0af3`**. Это digest сохранённого canonical JSON, не hash transport logs.

Linux context suite: 7 pass, 0.012 s, 31 statements / 4 branch exits, 100%. Existing serving suites: 80 pass, 13.989 s; core Cover 91%, HTTP Cover 95%, не отдельные branch percentages. Pause suite 15 pass. Audit suites 61 pass без skips, 3.598 s; checker 10 pass, 0.162 s. Existing independent branch gate: core 76/80 = 95%, retention 102/102 = 100%. Это не full M18 для всех security-critical modules.

## CI matrix exact source revision

Все 10 workflows terminal: **6 success / 4 failure**, включая Storage **attempt 2**. Attempt 1 на M07 остаётся failed историей и reliability debt.

| Workflow | Run | Результат |
| --- | --- | --- |
| Storage role and TLS qualification | [38942124426, attempt 2](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124426/attempts/2) | success; M03 431, M07 97, candidate 72 cases pass |
| Kubernetes isolation qualification | [38942124193](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124193) | success; M20 723 / M21 122 pass |
| Developer runtime qualification | [38942124237](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124237) | success; 3 fresh trainings, max probability difference 0, parity 2.086162567138672e-7 |
| MLflow tracking compatibility and private service | [38942124224](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124224) | success; M06 18 cases pass |
| Intake evidence contracts | [38942124372](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124372) | success |
| Documentation integrity | [38942124197](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124197) | success |
| Worker and storage image audit | [38942124238](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124238) | failure; all four scans executed, SBOM validated, exit 2 |
| Frozen poisoning research matrix | [38942124213](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124213) | failure; 10 violations, 0 inconclusive scenarios |
| Frozen evasion and domain guard | [38942124221](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124221) | failure; recall drop 0.07183673469387755 > 0.05 |
| Paired robust training research | [38942124169](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124169) | failure; candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05 |

Kubernetes job `117112095515`: M20 finished 2026-10-16T17:59:46.335700Z, M21 finished **2026-10-16T18:02:07.852424Z**, M21 source_dirty=false. Poisoning primary integrity pass: 35 verified cases / 251 files; execution complete не превращает 10 violations в pass. Evasion/paired primary reconciliation pass, но метрики нарушают порог. Image Critical/High counts: worker 0/56, storage 9/132, worker-candidate 0/55, storage-candidate 1/85. Эти ограничения остаются запретами release, а нестабильность M07 требует отдельного выяснения причины.

## Следующий scope

Совместимая версия event schema для qualification, ограниченная admission/reservation policy и реальные ASGI start/body/disconnect события. Нельзя объявлять queue acceptance durability, записывать completed до успешного send или продлевать trust deadline ожиданием fsync. Затем all-output canaries/cardinality и full M13. Image/ML blockers сохраняются до нового измеренного результата, не скрываются успешной компонентной проверкой.
