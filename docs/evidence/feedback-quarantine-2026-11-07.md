# T18: карантин непроверенной обратной связи

Дата: 2026-11-07 МСК. Runtime source:
[`9162a2fe512be18537598a7f413543e15af3947a`](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/9162a2fe512be18537598a7f413543e15af3947a).
Scope: bounded CLI intake и существующий SQL quarantine, соединённые с actual
monitoring campaign. Полный M15 и R1 не приняты, `release_ready=false`.

## Реализованная граница

`mlsecops.feedback` принимает до 100 claims/16384 bytes: model/bundle digests,
request ID, row index и binary label. Неизвестные поля, features и free text
отклоняются. `ml_ingestor` пишет только в append-only quarantine; `ml_curator`
читает и проверяет запись. CLI возвращает ограниченную receipt без labels и
request IDs. CAS делает одинаковый canonical retry идемпотентным. Поля
`training_eligible`, `verified_labels`, `release_ready` остаются false.

Не добавлены HTTP endpoint, SQL role или grants. Существующий serving не получает
write credentials. Валидация формы claim не доказывает истинность метки или
существование запроса; противоречия между отдельными claims остаются предметом
curator review. Это не реализация автоматического data approval.

## Локальные controlled проверки

- 27 целевых тестов / 0 skips / 27.566s.
- Общий monitoring suite: 129 tests / 2 Linux-only skips / 60.324s на Windows.
- 16 modules: 1298/1300 statements и 430/432 branches; каждый отдельно >=95%.
- Два новых modules: 173/173 statements, 46/46 branches, 100%.
- Ruff и documentation checker прошли: 804 files, 290 Markdown, 2198 local links
  на runtime commit, до добавления этого evidence.

Проверены malformed input, roles, oversized content, duplicate observations,
CAS retry, readback tampering, постоянный текст CLI ошибок, SIGINT, отсутствие
authority, обязательность primary packet, изменения других tables/promotion,
неверный SQLSTATE, потерянный proof и несовпадение summary. Unit SQL transport
заменён контролируемым объектом; фактические grants он не доказывает.

## Hosted проверка

[Contracts 42325145891](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42325145891)
завершился success на том же runtime commit:

- 129 monitoring/feedback tests / 0 skips / 53.507s.
- 77 HTTP/audit/lifecycle tests / 0 skips / 8.151s.
- 52 material/lineage/release tests / 0 skips / 3.166s.
- 16 modules: 1298/1300 statements, 430/432 branches, каждый отдельно >=95%.
  Два новых modules покрыты на 100% по обеим метрикам.

[Native campaign 42325145874](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42325145874)
/ job128258582240 завершился **success**. Компонент карантина принят в этом lab
профиле. Checkout чистый (`source_dirty=false`), dependencies установлены по lock,
образ собран на hosted runner. [Публичный summary](feedback-quarantine-2026-11-07-summary.md)
содержит точные source/model/bundle/packet bindings и результат post-cleanup replay.

| Проверка | Фактический результат |
| --- | --- |
| HTTP observation campaign | 12000 observations, 10 clean windows, 2 shift windows, 3 signed receipts |
| Максимальная доставка alert | 0.398394584s, меньше 120s |
| Непроверенные synthetic claims | 10 records, добавлена ровно 1 quarantine row |
| Повтор и curator inspect | Идентичная receipt, retry не меняет ledger |
| SQL grants | 15/15 прямых forbidden operations вернули 42501 |
| Другие source tables | Не изменились |
| Cluster CAS/promotion snapshot | Не изменился |
| Verified labels / training eligibility / release readiness | false / false / false |
| Owned cleanup | Worker cleanup verified, source SQL stopped, cluster absent |
| Offline primary reconciliation после cleanup | pass для monitoring packet и feedback proof |

Feedback record SHA-256:
`630ac74560ecc6f25bfbfdf21452fbd17905b855c5feb3050ad6f613ab99e563`.
Feedback proof SHA-256:
`badfd15fb2e0b4eee34b0954c06c1cac01312a71cd48be020223ed79b4a48c8e`.
Monitoring packet SHA-256:
`f8a26f56331477a718eedc293a8591d0b6a9f9b2d13d19177df98d06eaac03e4`.
Probe elapsed23.029503s относится к observation Job, не является M14 benchmark
или замером полного CI/feedback transaction.

Прогон после фактических HTTP predictions берёт 10 row IDs первого ответа и
формирует synthetic claims. Последовательно запускаются CLI submit, exact retry
и curator inspect. Сверяются source SQL ledgers до/после, неизменность других
tables и отдельного cluster promotion snapshot. 15 прямых SQL-запросов должны
получить именно 42501: восемь forbidden INSERT для ingestor, четыре forbidden
SELECT quarantine, curator INSERT и ingestor UPDATE/DELETE. Connection failure
не засчитывается как permission denial. Непроверенная запись также отвергается
действующими dataset intake и signed-label verifier.

Private proof содержит input, readback, receipts, все ledgers, promotion
snapshots и denials. После удаления owned runtime он перечитывается без SQL и
сопоставляется с actual HTTP packet. Отсутствие proof не разрешает success.
Raw logs, credentials и claims не публикуются.

## Эксплуатация и оставшиеся критерии

[Ранбук и плейбук](../operations/feedback-quarantine.md) описывают absolute client
paths, роли, команды, повтор после потери ответа, TLS/SQL отказ, проверку конечного
состояния и отсутствие destructive rollback. Signed monitoring labels остаются
отдельным [каналом](../operations/model-monitoring.md).

Карантин не закрывает durable monitoring restart/recovery, свежие M13/M14 и
общую M15 acceptance. Независимые M22 challenge-кейсы по-прежнему 0/2; исторический
third-party unsafe API audit их не заменяет. M18 остаётся последней проверкой
единого release candidate, общий R1 остаётся открытым.
