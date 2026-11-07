# M15: candidate-bound monitoring observation

Код: `2249f350f3befd1892c65fbc3566a9981d0a57cb`, ветка
`codex/cp4-m15-monitoring-20261107`. Полный M15 и R1 пока не приняты.

## Проверенный контрактный слой

[Monitoring CI42321850571](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42321850571),
job128248005488, **success**:

- 111 monitoring tests, 45.915s, без пропусков;
- 77 HTTP/audit/lifecycle tests, 7.546s, без пропусков;
- 52 candidate/material/release tests, 3.260s, без пропусков.

Покрытие14 modules:1113/1115 statements,380/382 branches. Каждый module
отдельно проходит >=95% statements и branches. Packet verifier62/63 и27/28,
probe122/123 и29/30; остальные12 modules полностью покрыты. Это исполнение
контрактных тестов, не процент готовности R1 или доказательство production.

Windows:111 tests/1 Linux-only skip,60.048s; смежный набор114/3 Linux-only skips,
11.905s. В отдельном чистом detached checkout того же commit выполнены33 tests,
0 skips,24.599s, импортированный module path проверен, `git status` остался
чистым. Использована существующая locked venv, новая установка зависимостей
на Windows в этом повторе не выполнялась.

Реальный loopback HTTP в controlled fixture проверяет12000 observations,
10 clean windows без alarm,2 shift windows, подписанные delayed labels и
3 подписанные receipt. Predictor в этом тесте контрольный, не ONNX candidate.
Проверены подмена HTTP identity/score/window/ledger, недостающие records,
неверная подпись/срок/epoch, неизвестное label window, повтор label batch,
замена probe UID, отсутствие/подмена retained packet, отказ transport,
незавершённый scheduler/worker cleanup и отсутствие operator ack.

## Native composition

[Hosted observation42321850663](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42321850663),
job128248005249: **failure** на этапе probe, cause=`unknown`. Source SQL cleanup и
удаление owned cluster прошли; post-cleanup packet verification закономерно
skipped. Успех контрактного CI не скрывает этот отказ.

При разборе найден пропущенный prerequisite: retained audit требует заранее
созданного приватного каталога, а probe передавал отсутствующий `audit`.
Контролируемый regression test воспроизвёл отсутствие каталога до открытия app.
Исправление создаёт его с mode0700 и добавляет Linux test с настоящим audit,
HTTP lifespan и scheduler. Исходный ограниченный diagnostic не сохранил точное
место исключения, поэтому связь с этим конкретным CI failure проверяется
повторным native запуском. Новая диагностика выводит только тип исключения и
строку публичного probe module, без exception text, stack locals и private paths.

Сценарий соединяет actual signed package, frozen validation reference, isolated
ONNX worker, HTTP collector, scheduler, operator-only signed-label intake,
loopback sink и retained primary packet. Reference вычисляется до короткого
qualification permit. Host сверяет immutable context, source/model/bundle,
SQL/promotion snapshots и packet, после owned cleanup перечитывает primary
records и пересчитывает окна/метрики/квитанции без инфраструктуры.

Workflow не публикует raw features, labels, request/response, ключи и логи.
Private evidence остаётся в `.runtime`; наружу выводится ограниченная проекция.
Ключи sink и label authority в этом lab принадлежат owned qualification probe.
Это функциональная проверка разделённых identities, не независимость
администраторов и не внешний security audit.

## Остаточные ограничения

- `release_ready=false`, `full_M15=inconclusive`: qualification не выдаёт
  production approval и не создаёт assurance.
- Feedback quarantine, безопасный durable restart, общая M15 acceptance и
  свежие M13/M14 после изменения HTTP остаются открытыми.
- Прошлые M13/M14 passes принадлежат своим commits. Здесь повторены component
  regressions, полные gates автоматически не переносятся.
- Независимые M22 cases остаются0/2. Sink receipts не заменяют human review.
- Single-node synthetic lab, общие административные полномочия, ограничения
  Windows файловой безопасности и ранее открытый shutdown debt сохраняются.

Ранбук и пошаговый запуск:
[model-monitoring](../operations/model-monitoring.md#приватный-пакет-сквозного-наблюдения-m15).
