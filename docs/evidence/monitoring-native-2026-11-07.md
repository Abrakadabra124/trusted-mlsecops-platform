# M15: candidate-bound monitoring observation

Проверенный native код: `acb5b18d8d45b5d329a8794ff49c9503800afc49`, ветка
`codex/cp4-m15-monitoring-20261107`. Native observation **pass**, полный M15 и R1
пока не приняты. Начальная композиция `2249f35` и её отказ сохранены ниже.

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

Исправление: `acb5b18d8d45b5d329a8794ff49c9503800afc49`.
[Contract CI42322768944](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42322768944),
job128250962526, **success**:113 monitoring tests/0 skips/49.276s,
77 HTTP tests/0 skips/7.718s,52 material tests/0 skips/4.751s. В том числе выполнен
новый Linux test с реальным retained audit и HTTP lifecycle. Покрытие14 modules:
1122/1124 statements,384/386 branches; каждый module >=95% по обеим метрикам.
Локальный targeted regression:25 tests/1 Linux-only skip/1.100s. Эти результаты
не заменяют отдельный повтор native observation.

Повтор [Native CI42322768934](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42322768934),
job128250962479, commit`acb5b18`: **success**. Workflow использовал чистый hosted
checkout и новую locked установку, собрал image, выполнил source pipeline и
actual-candidate composition. `source_dirty=false`; source revision, fingerprint,
image, model, subject, permit и reference связаны в
[публичной JSON-проекции](monitoring-native-2026-11-07-summary.md).

| Проверка | Подтверждённый результат |
| --- | --- |
| HTTP observations | 12000,120 batches |
| Контрольные окна | 10 окон по1000, без drift alarm |
| Shift fixture | 2 окна по1000, data и prediction drift |
| Delayed labels | 200 positives, отдельный quality alert, повтор принимает0 |
| Подписанные receipt | 3, максимальная доставка0.368848423s при пороге120s |
| Probe Job elapsed | 23.100061s, это не load benchmark |
| Worker cleanup | Проверено отсутствие worker pods |
| Source SQL cleanup | success, проверено stopped state |
| Disposable cluster cleanup | success, проверено отсутствие кластера |
| Primary packet после удаления инфраструктуры | Перечитан и пересчитан, pass |
| Release | `release_ready=false`, `full_M15=inconclusive` |

Packet SHA256`5043b3f57c115c81156b1754c0d6ad8a7854c5b9a1438589b736abc78a3b2530`
совпадает в live operator summary и post-cleanup пересчёте. Reference
SHA256`23746f54f7e86258b94cb38fb02d428d16cea12ca19178e5ca5120c2ee1e2b3c` также
совпадает. SQL/promotion snapshots проверены до и после inference существующим
candidate harness. Пропущенный audit prerequisite исправлен, повторный native
startup и teardown прошли; прежний R1-B08 shutdown debt этим не объявляется закрытым.

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
