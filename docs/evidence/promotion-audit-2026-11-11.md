# T29: свежий аудит перед фиксацией выпуска

Неделя11, Security events и потеря telemetry. ЗадачаT29, Security event contracts
и replay. Принят компонент audit admission; полный M23/R1 не принят.

## Актуальное дополнение: durable promotion.denied

Runtime `b9843045316905136c1f81c8d0180f2d60823397` подключает реальное решение
release_authorization/fresh trust/audit к producer outbox. Фиксированные reasons:
authorization/trust/audit_unavailable; asset и bundle равны proposal envelope
digest. Событие не содержит exception text, model bytes, credentials или input
rows. Перед network IO оно сохраняется; новая promotion сначала доставляет
pending outbox, затем получает свежий challenge. Повтор доставки сохраняет
event ID/sequence; новая отказавшая попытка promotion получает новую correlation.

Вложенный audit config теперь schema2 и требует state_directory/state_sha256.
Главный promotion config остаётся schema2. Legacy audit config без outbox
отвергается; [миграция и retry](../operations/security-events.md#аудит-на-границе-promotion)
описаны вместе с кодом. Missing assurance по-прежнему не пишет release CAS/SQL,
но теперь сохраняет событие отказа. Если доставка не подтверждена, наружу выходит
постоянный `promotion_denial_audit_unconfirmed`, не разрешение на выпуск.

[Run43064414379](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43064414379)
success на `b984304`: contracts job130675379769 **287Linux executions/0skips**,
группы21+25+47+10+1+24+85+65+9. Admission79/79statements,12/12branches.
Дополнительное локальное измерение promotion:97/97statements,27/28branches,
42tests success; это отдельная группа, не прибавляется к CI total.

Native job130675380338: **25cases pass** с настоящими SQL/collector/HTTP.
Четыре реальных отказа дали четыре durable события: один authorization и три
audit_unavailable. Проверены offline enqueue, flush перед новым challenge,
SQL rollback, точные route/subject/receipt, idempotent selection retry,
восстановление и конечная доставка всех четырёх событий. Collector PID/port/state
и owned SQL/network/volume очищены с проверкой. Fingerprint
`7816293810759a98699c8eb453f8e1cab860ec2f737b1b3bd46d04bc6a508f1e`.

[Run43064414458](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43064414458),
job130675392839: **success**,54unit executions(41+13) и45native cases. Настоящий
candidate отклонён с release_assurance_required в parent и отдельном CLI;
оба refusal event получены collector, проверены подписи и привязка к реальному
proposal. Отдельная controlled fixture прошла прежний положительный путь
CLI -> Reader -> HTTP. Положительной приёмки настоящей модели нет.

Чистый detached `b984304`, новая locked .venv Python3.12.15: **88tests/0skips**,
12.414s, `-W error`, import/interpreter из нового checkout, git clean. Повторить
команду ниже, добавив scripts.security_event_delivery_qualification и
scripts.security_event_wire_qualification. Локальная инфраструктура не запускалась.

Границы: trust.revoked/identity.denied/inventory.mismatch ещё требуют своих
actual sources. Этот increment не превращает trust check denial в событие
успешного изменения authority. Ранние malformed/config/SQL operational отказы
не выдаются за authorization findings. Crash до enqueue, producer heartbeat,
deployed audit enforcement, sequence elapsed и full M23 остаются открытыми.

## Исходная реализация audit admission и граница результата

Runtime: `1cd246655dfc696d7472874b455958098e9df2bd`.
Исправление изоляции CLI test: `d803b1c76f0aeec60c7578fb98ee6e318d41951f`.
Разница второго commit только в qualification test, не в production Python.

[`promotion.promote`](../../mlsecops/promotion.py) требует audit client. Collector
подписывает свежий nonce-bound ответ для digest конкретного selection после
durable health poll. Проверяются role/epoch/config pin, подписи, свежесть и
состояние telemetry. Client не использует прежний healthy ответ; roundtrip<=2s.
Проверки идут до SQL statement и после него перед transaction commit. При
втором отказе незавершённый selection откатывается. Конфигурация promotion CLI
теперь schema2 с обязательным absolute `security_audit_config`; request остаётся
schema1. На этом историческом revision отсутствующее ML assurance даёт отказ до
audit IO; дополнение b984304 выше добавило событие отказа.

Это не распределённый commit между SQL и collector. Сбой после последнего
подтверждения возможен; есть bounded freshness5s с общей wall-clock доверенной
границей. Доступ к SQL-функции принадлежит доверенному ml_promoter; компрометация
controller/его credentials этим механизмом не решается. Ответ collector не
означает разрешение модели, сохранение selection в incident journal или
активацию serving. [ADR0060](../decisions/0060-promotion-audit-admission.md).

## Авторитетные проверки

[Run43061060230](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43061060230)
на runtime `1cd2466`: оба job success.

- Contracts job130663437078:282 Linux test executions,0skips. Группы:
  21+25+47+10+1+24+85 существующих и смежных;60 promotion/controller/rollback/CLI
  и9 admission. Это число исполнений методов, не число независимых M-gates.
- Новый admission module:72/72 statements,8/8 branches. Coverage не заменяет
  native fault injection и проверку модели.
- Native job130663437551:14cases pass, реальные отдельные collector process,
  HTTP и PostgreSQL через существующий TLS client. Fingerprint
  `3185fc1e316dbabc68815dd84e99e3bf4f7ec23c2dd2527cb2d8636687b34bb1`.
- Native cases: offline отказ; неизменные head/events; незавершённая запись не
  видна другому SQL connection; collector stopped после SQL statement;
  вторая audit boundary reached; реальный rollback; восстановление; точный head
  и один event; идемпотентный retry; запрет cached-health retry; сохранение прежнего
  выпуска при отказе retry; cleanup collector; cleanup owned SQL/network/volume;
  неизменный runtime source.

Повтор на исправленном checkout `d803b1c`:
[Run43061595393](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43061595393)
success, contracts job130665330246 снова282tests/0skips, native job130665329719
снова14cases/cleanup pass. Runtime fingerprint остался тем же.

Проверка совместимости существующего promotion CLI:
[Run43061631970](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43061631970),
job130665745549, `d803b1c`, success.49unit executions(36+13) и44native cases:
настоящий candidate отказал с `release_assurance_required`, отдельная controlled
fixture прошла CLI exact retry -> Reader -> HTTP. Новая audit конфигурация реально
загружалась в CLI process; owned model/trust stores и source SQL cleanup прошли.
Это повторение прежней controlled integration, не full M10/actual ML approval.

Положительная authorization/trust fixture controlled. Эти14cases не являются
настоящим all-pass assurance модели, полным M10/M23 или доказательством того,
что все deployments уже имеют audit mounts/network. Живая ML dashboard в этом
SQL harness не запускается; полный сценарий M23 с healthy dashboard ещё нужен.

## Clean checkout и обнаруженная проблема теста

Чистый detached checkout `d803b1c`, новая `.venv`, Python3.12.15, locked deps:
74tests/0skips,11.720s, `python -W error -m unittest ...` success. Проверены
пути interpreter и imported mlsecops из этого checkout, `git status --porcelain`
пуст. Локальные SQL/Docker/WSL/Kubernetes не запускались.

Первый строгий clean run на `1cd2466` остановился на прежнем `runpy` test: CLI
module был уже в sys.modules, и Python выдавал RuntimeWarning. Причина повторно
воспроизведена отдельным тестом. `d803b1c` временно удаляет module entry внутри
восстанавливаемого patch context; global warning filter не менялся. После этого
тот же test и полный74-method набор прошли с `-W error`.

Команды воспроизведения без локальной инфраструктуры:

```powershell
uv sync --locked --no-build --python 3.12.15 --link-mode copy
uv run --locked python -W error -m unittest scripts.security_event_admission_qualification scripts.promotion_qualification scripts.promotion_controller_qualification scripts.rollback_admission_qualification scripts.promotion_entrypoint_qualification scripts.release_reader_native_qualification scripts.release_native_qualification scripts.release_key_serving_qualification scripts.release_signer_fixture_qualification
uv run --locked python scripts/check_docs.py
```

Для реального SQL campaign используется job `audit-promotion-sql` в
[security-events-contracts.yml](../../.github/workflows/security-events-contracts.yml).
Native script дополнительно проверяет Linux/GitHub-hosted до действий.
Raw logs остаются private; здесь только конечные результаты. Диагностика,
восстановление и безопасный retry: [ранбук](../operations/security-events.md#аудит-на-границе-promotion).

## Незавершённое

Остальные actual event sources, автоматический heartbeat producers, deployment
enforcement, measured sequence-gap campaign и полный M23 остаются открытыми.
Также сохраняются actual M10/M19, independent M22 challenges0/2, M16/M17,
image findings/R1-B08 и M18 последним на одном candidate. Этот компонент
не меняет эти критерии и не означает завершение недели11 или R1.
