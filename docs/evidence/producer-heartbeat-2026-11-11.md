# T29: durable producer heartbeat и обнаружение остановки

Runtime появился в `c313a8691681983dd6f3c68f38b6a821b5324dcf`.
Последующий qualification source: `8b0468465402d267cf94b94ff8778932276ea19b`.
Linux runtime fingerprint:
`e93c85e061e753333a3dce048459e24c2a8674b4f68b1e8f5617fa6ef32a0070`.
Между этими commits production modules/workflows не менялись; менялись harness,
его negative tests и описание readback. Общий M23/M18/R1 остаётся открыт.

## Реальные процессы и время

Окончательный [run43083688017](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43083688017)
на8b04684 завершился success. Job130742468651:46 identity/heartbeat assertions,
период **30.096s**, signed gap после остановки **90.412271147s**, max HTTP
0.079543227s. Также прошли25 promotion и37 trust assertions с owned cleanup.
Источник и fingerprint сверены с заголовком. Это финальная повторная проверка
с bounded readback и отдельным тестом реального POSIX lock.

Первый успешный [run43082799738](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43082799738)
на6774fc7 завершился success. Native job130739424109 проверил46 assertions,
включая повторные HTTP/receipt checks, а не46 независимых сценариев.
Measured heartbeat interval=30.135s, stopped producer signed notice=91.292231055s,
max HTTP=0.134918625s. Это измерение bounded synthetic lab, не production SLO.

- Настоящий serving процесс запускает owned scheduler и отдельные bounded Python
  source children. Collector работает отдельным процессом. Startup heartbeat
  создан самим producer, без ручного preseed, проверен через collector journal.
- Outbox schema2 сохраняет counter и latest signed heartbeat в том же atomic
  journal, что и event head. last_event_sequence включает pending. Сохранение
  произошло до сетевой отправки; HTTP echo не использовался как health grant.
- Пять authentic credential/role denials доставили события и heartbeat. Offline
  collector вызвал503 с сохранённым шестым pending event; live/metrics остались
  доступны. Startup с pending и offline collector отказал до engine activation.
- После restart с прежним outbox доставлен исходный шестой envelope/receipt,
  heartbeat counter вырос, head=6. Event retry=0, подписи/subjects/routes/privacy
  проверены прежним способом. Ни один event timestamp не был переписан ради retry.
- После успешных HTTP checks процесс оставлен без новых запросов. Настоящий
  scheduler отправил следующий heartbeat через30s; independent collector
  readback подтвердил envelope. Проверка не ускоряет clocks/таймеры.
- После остановки serving heartbeat counter перестал меняться. Collector сам
  создал signed telemetry.gap reason=heartbeat с receipt в пределах120s.
  До остановки fresh signed audit challenge проходил; после gap был отклонён.
  Это actual audit boundary, не отдельная полная SQL promotion/M23 campaign.
- Все3 server lifecycles подтвердили остановку ticker/child; закрыты owned ports,
  collector/private files удалены. Source/fingerprint/checkout не изменились.

Engine в harness controlled unready. Этот report не доказывает inference,
M13/M14 или outage при действительно здоровой ML dashboard.

## Contracts, crash и чистое воспроизведение

Финальный contracts job130742469034 прошёл571 Linux test executions без пропусков:
21+25+47+10+1+38+85+65+9+14+60+31+36+129. Native assertions учитываются отдельно.
Предыдущие contracts наc313a86 и6774fc7 проходили569 executions. Финальная coverage:

| Модуль | Statements | Branches |
|---|---:|---:|
| security_event_delivery | 137/139 | 48/50 (96%) |
| security_event_outbox | 139/141 | 46/48 (95.83%) |
| security_identity_events | 52/52 | 10/10 (100%) |
| security_identity_http | 134/134 | 39/40 (97.5%) |

Это per-module coverage, не доля готовности продукта. Новые tests проверяют
counter/head/reopen, v1 refusal без reset, state corruption/backlog/clock/overflow,
unknown send, wrong/stale echo, scheduler failure/recovery/busy/cancellation и
невозможность выдать неподтверждённый cleanup за success. POSIX crash test
вызывает отказ после реального atomic rename: reopen видит увеличенный counter,
следующая отправка использует следующий, а не повторно выделенный номер.

Clean c313a86: новая locked Python3.12.15 .venv,201tests24.698s с-Werror,
6Linux skips. Это новые producer tests плюс прежние HTTP/audit/metrics/monitoring/
privacy regression tests. Clean8b04684: новая locked .venv и74tests2.909s,
4Linux skips, включая новый readback regression. В обоих checkout проверены
фактические interpreter/import paths и пустой git status. Локальная
Docker/WSL/Kubernetes/SQL инфраструктура не запускалась.

```text
uv sync --locked --no-build --python 3.12.15 --link-mode copy
python -W error -m unittest scripts.security_producer_heartbeat_qualification scripts.security_event_outbox_qualification scripts.security_event_delivery_qualification scripts.security_event_wire_qualification scripts.security_event_source_qualification scripts.security_event_source_live_qualification scripts.security_identity_events_qualification scripts.security_identity_http_qualification
```

## Регрессия candidate

[Run43082185574](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43082185574),
job130737288043 наc313a86 завершились success:54unit,37inventory assertions,
45promotion CLI cases. Повторная печать45-case report не удваивает число проверок.
Fresh owned SQL pipeline подготовил данные, обучил и оценил synthetic candidate
`c64b79667cce715b9cdae5e3077715e20c2b734964a8ddce2e8b2e33ec58bdab`.
Actual candidate получает release_assurance_required; positive Reader/HTTP/ONNX
проверяется на отдельно обозначенных controlled reports. SQL stop проверяет
State.Running=false; удаление source volume здесь не заявляется.

## История отказа и границы

[Run43082184982](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43082184982)
сохраняет failed native result после36 assertions; остальные contracts успешны.
Первый diagnostic не сохранил тип/место исключения, поэтому его точная причина
не доказана. Диагностический6774fc7 прошёл без изменения runtime; это не основание
стирать исходный failure или объявлять его причину установленной.

При разборе отдельно воспроизведён дефект polling: общий filesystem parent
context превращает отказ exclusive flock в artifact_unavailable. Прежний polling
распознавал только security_store_unavailable. Новый harness повторяет оба кода
не более2s; pin/signature/state validation errors немедленно сохраняют отказ.
Тест проверяет реальное преобразование исключения parent context, ещё один Linux
тест удерживает настоящий exclusive lock. Locking/runtime checks не ослаблены.

[ADR0064](../decisions/0064-producer-heartbeat.md), [ранбук](../operations/producer-heartbeat.md),
[план](../../tasks/producer-heartbeat-plan.md). Raw logs/state/credentials private.
V1 outbox не имеет доказанного heartbeat counter: автоматической migration нет.
Безопасная процедура для утраты state/registry epoch остаётся отдельной работой;
нельзя создать новый counter с прежним использованным key/epoch.

Mandatory deployment, periodic trust observer, actual sequence-gap campaign,
audit outage с healthy ML dashboard, fresh M13/M14 и полный M23 обязательны.
Остальные M01-M23 и M18 последним на одном candidate не заменяются этим report.
