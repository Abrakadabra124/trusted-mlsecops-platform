# R1: границы и конечный маршрут поставки

Обновление 2026-10-29: [M09 actual-candidate integration](evidence/m09-candidate-2026-10-29.md) проверена native на `0150f62`: 42 cases, 18 001 actual predictions, parity pass, evasion fail 0.07183673469387755 >0.05. Dispatch содержит 11 gates M01-M09/M20/M21; остаются 12 M10-M19/M22/M23. Это счётчик реализованных путей, не принятых критериев: system-image и model failures сохраняются, M18 на одном candidate не выполнен. [Node patch experiment](operations/node-candidate.md#native-результат-2026-10-29-мск) уменьшил findings, но candidate не принят.

Зафиксировано 2026-10-20 по решению владельца. Это порядок завершения существующей цели, не новая цель и не изменение критериев. Источники: [GOAL](../GOAL.md), [STATUS](../STATUS.md), [план](../tasks/plan.md), [задачи](../tasks/todo.md), [M01-M23](acceptance.md), [policy](../policies/local-cpu.json).

## Пользовательский результат

Release Risk Advisor - воспроизводимый CPU-reference продукт: инженер из чистого checkout готовит отдельное окружение, создаёт управляемые синтетические данные, обучает и независимо оценивает модель, получает проверяемое разрешение выпуска либо корректный отказ. Разрешённый bundle обслуживает inference; инженер наблюдает состояние, воспроизводит отказ и восстанавливает систему по инструкции.

При запрете выпуска production serving не должен выдавать ML-ответы этого candidate. Qualification inference остаётся отдельным диагностическим режимом, не обходом approval. Положительные controlled fixtures проверяют механизм, но не доказывают пригодность настоящего candidate. Корректный отказ - обязательная ветка продукта, а не автоматическое завершение R1 с красными gates.

## Замороженный scope

Обязательны **все M01-M23**, M18 выполняется последним. Сохраняются Linux x86_64, locked CPU environment, synthetic 20 000 rows / split 70/15/15, существующие роли и архитектура, подписи и запреты release. Численные thresholds, sample sizes, severity policy, независимые роли и отрицательные сценарии берутся из исходных контрактов без ослабления.

Входят данные/lineage, обучение и изоляция, reproducibility/evaluation, intake/robustness/assurance, promotion/revocation, inference/privacy/audit, нагрузка/мониторинг/security events, staged rollout/rollback/restore, inventory, инструкции и общая приёмка одного candidate. Lab retention/expiry/teardown и проверка ранбуков также обязательны.

Не входят production HA/offsite, реальные персональные данные и бизнес-utility пилота, GPU/ARM/distributed training, LLM/RAG/агенты, UI/новые оркестраторы, production KMS/OIDC, differential privacy и защита от host administrator. Очередь развития: [future improvements](future-improvements.md). Это не основание отложить требуемый lab restore, M14-нагрузку, M23-alerting или исправление действующих release blockers.

Локальные Docker/WSL/Kubernetes/SQL не запускать и не менять; infrastructure verification только на разрешённом disposable hosted CI. Другой проект, реальные данные, секреты и платные ресурсы не затрагивать.

## Что действительно подтверждено

| Требование | Основание | Граница |
| --- | --- | --- |
| M01, M04, M05 | Native `ab00a4e`: 10 / 764 / 58 cases, [run и статус](../STATUS.md); M20 725 / M21 122 также pass | Qualification synthetic lab, не release approval или общая M18 |
| M02, M03, M06, M07, M20, M21 | Executable dispatch в [acceptance.py](../mlsecops/acceptance.py), профильные evidence в STATUS | Отдельные synthetic campaigns; ещё не общий candidate/M18 |
| Последний интеграционный checkpoint a7a09c8 | [Полная CI-матрица](evidence/audit-evidence-a7a09c8-native.md): M03 431, M06 18, M07 97, M20 725, M21 122 cases pass | 6 success / 4 failure, release запрещён |
| Actual candidate inference/privacy/audit | Там же: 85 cases, 107 HTTP responses, retained primary bytes и parent recheck | Qualification, не approved release и не полный M12/M13 |
| Promotion/reader/revocation/backup/restore | Существующие native components и ранбуки из STATUS | Controlled approvals и component recovery не заменяют M10/M11/M16/M17 |

Для остальных полных gates нет общей приёмки: M08-M19, M22, M23. Наличие файлов или частичного зелёного теста не меняет этот статус.

### Финальная проверка исполнимости приёмки 2026-10-23

Обновление 2026-10-28: M08 получил исполняемый путь на существующем evaluated candidate. [Native run 40747492224](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40747492224) подтвердил 68 checks, 35 scenarios и readback/replay; результат fail из-за 10 robustness violations. Теперь реализован dispatch **10 gates**, placeholder остаётся у **13 gates: M09-M19, M22, M23**. Полной приёмки одного candidate по-прежнему нет; следующие строки сохраняют историческую проверку `21ae473`.

На опубликованном `21ae473` проверены ветки `report()` в [acceptance.py](../mlsecops/acceptance.py) и фактические ответы неподключённых gates. Это проверка готовности runner, не новый native campaign; локальные infrastructure services не запускались.

- Полный dispatch существует для **9 gates: M01-M07, M20, M21**. Это наличие исполняемого пути, не утверждение, что эти gates приняты на текущем общем candidate.
- Для **14 gates: M08-M19, M22, M23** вызов `report()` возвращает `status=inconclusive`, `exit_code=2`, `cases=[]`. Здесь недостаточно повторить CI или собрать старые отчёты: требуется закончить привязку существующих компонентов и недостающих сценариев к полному контракту каждой проверки. Простое переключение статуса запрещено.
- [Финальный native walkthrough](operations/r1-walkthrough.md#финальное-воспроизведение-в-зарезервированные-30-минут) остаётся рабочей диагностической цепочкой с отказом, а не заменой этих gates. Проверенный checkout `2f8072e` и опубликованный `21ae473` отличаются только Markdown; этот аудит также не меняет runtime, policy или thresholds.

Это конкретный блокер завершения R1 в пределах текущего дедлайна, сообщённый владельцу до 23:34 МСК. Нужны оставшиеся CP2-CP5 и независимые challenges M22; self-review их не заменяет. Во время зарезервированного окна 23:04-23:34 МСК выполняются только воспроизведение, инструкции и публикация. Новую разработку нельзя считать разрешённой лишь из-за автоматического продолжения активной цели.

## Обязательные блокеры R1

| ID | Что осталось | Критерии / доказательство закрытия |
| --- | --- | --- |
| R1-B01 | M01 принят (10 cases); native `51d0a77` и финальный clean checkout `2f8072e` подтвердили единый same-candidate refusal/inference/recovery path. Предыдущие failures сохранены. Это qualification, не полная R1 acceptance; остальные критерии CP5 остаются | M01/T01-T02: clean environment, два bootstrap без потери данных/ключей, baseline pin, tools/images/locks и P0 inventory, incompatible/missing prerequisites rejected |
| R1-B02 | [Adoption 2026-10-28](evidence/cp2-runtime-adoption-2026-10-28.md): новый PostgreSQL опубликован/readback pass; Developer/Storage/Kubernetes `1dc1f05`, исправленный Wolfi tracking/MLflow 3.17.2 и пятикомпонентный image audit `37fe32b` success. Все пять images: 0 Critical/High/Unknown. Полное observed system coverage, poisoning/evasion и paired failures остаются; исторические отказы сохранены | M08/M09/M18/M22: remediation на validation без подбора final holdout, исходные frozen suites/thresholds и полный runtime/controller image scope; не scanner exceptions |
| R1-B03 | **Закрыт:** native `ab00a4e`, M04 764 / M05 58 cases pass; 13 concurrent Running observations и неизменный inference | M04/M05: реальные identity/network/storage и deadline/OOM probes, сохранение работоспособности serving; существующие M20 proofs переиспользованы |
| R1-B04 | Approval -> production Reader -> inference -> revoke ещё не принят как единая цепочка; M13 не завершён | M10-M13/M19: actual subject binding, policy/rollback/replay, configured lifecycle, privacy 429/503, service-log coverage, public projection и inventory impact; не очередное усиление вне требований |
| R1-B05 | Нет полной quality/security monitoring acceptance | M15/M23: два окна drift, delayed labels, clean controls, 7 event types, authentic delivery/dedup/gaps/outage; без auto-promotion |
| R1-B06 | Финальный `2f8072e` подтвердил независимый same-candidate storage restore, 1 000 golden rows/error 0.0 и идемпотентный повтор. Полные load, staged rollout, compatible rollback и M17 RTO/RPO не приняты | M14/M16/M17: исходные duration/count/latency/error/RTO/RPO, новый storage, golden readback и запрет revoked fallback |
| R1-B07 | Расширенная assurance/challenge campaign не завершена | M22/T28: 36+6 runs, минимум 2 независимых challenges, заранее утверждённые метрики; независимость не имитируется self-review |
| R1-B08 | Нет M18 на одном frozen candidate и clean-checkout walkthrough всего продукта | M18/T21-T24: все reports current/bound, coverage >=95% branches новой security logic, карты, retention/expiry/teardown, review/game day, инструкции, публикация и remote verification |

Исторический intermittent M07 connection rejection остаётся reliability debt в R1-B08: успешный retry не устанавливает причину. До финальной приёмки требуется диагностика либо явная согласованная политика надёжности, а не стирание первого отказа.

CP1 gates приняты в native `ab00a4e`: M01/M04/M05/M20/M21 pass. Linux targeted tests: 31 foundation и 18 isolation, новые modules 100% statements/branches. Основной review и проверка конкретных fixes закончены. Первая матрица `61c6849`, M05 handoff defect/RED и отдельный storage refusal сохранены в [STATUS](../STATUS.md); targeted success не превращает её в полностью зелёную. [Foundation runbook](operations/artifact-intake-troubleshooting.md#r1-b01-неполная-identity-при-повторном-bootstrap), [M04/M05 runbook](kubernetes-lab.md#cp1-m04m05-и-отказ-training-при-настоящем-inference). R1-B03 закрыт; R1-B01 остаётся открыт в части общего продукта, зависящей от следующих checkpoints.

## Конечная последовательность и checkpoints

Уточнение владельца 2026-10-23: до **23:04 МСК** приоритет у [сквозного запуска существующих компонентов](operations/r1-walkthrough.md), **23:04-23:34 МСК** только чистое воспроизведение, инструкции и публикация. Это перестановка работ R1-B01, не снятие CP2-CP5 или M01-M23. Непройденный release остаётся отказом; qualification inference не заменяет production serving. Конкретные блокеры сообщаются до дедлайна.

1. **CP1 - foundation и изоляция:** M01-часть R1-B01 и весь R1-B03 приняты. Переиспользованы bootstrap, inventory и native probes, подключены полные M01/M04/M05. Пользователь получает проверенный старт окружения и изолированный training path. Общий entrypoint R1-B01 остаётся обязательным до CP5, не заменяется набором component tests.
2. **CP2 - admissible candidate:** R1-B02 + R1-B07. Устранить image/model release blockers, выполнить M08/M09/M22 с существующими M02/M03/M06/M07/M20/M21. При fail сохранить refusal и работать над причиной, не выпускать fixture как candidate.
3. **CP3 - выпуск и serving:** R1-B04. Закончить цепочку M10-M13/M19 целиком, включая отдельный production configuration path, audit и отзыв. Не создавать новый security slice, если он не нужен одному из этих критериев.
4. **CP4 - эксплуатация:** R1-B05 + R1-B06. Подключить M14-M17/M23, alerts, rollback/restore и исполнимые эксплуатационные процедуры.
5. **CP5 - заморозка и приёмка:** R1-B08. Один clean checkout, pinned candidate и все M01-M17/M19-M23; M18 последним. Опубликовать code/instructions/sanitized evidence и проверить удалённые артефакты.

Это конечные интеграционные порции, не оценка календарных сроков. Ближайшая работа - CP2/R1-B02/R1-B07; незаконченный M13 и отдельный storage privacy/output отказ остаются в CP3, дальнейшее необязательное усиление аудита не выполняется. Все исходные критерии действуют, незакрытый end-to-end entrypoint не исключён из R1.

## Правила расхода и изменений

- На порцию: targeted tests -> нужная integration -> один основной review и проверка его конкретных исправлений. Без внешних моделей и повторных прогонов неизменённого кода.
- Полная дорогая CI-матрица запускается на CP1-CP5, не после каждого микроизменения. Все обязательные workflows и thresholds сохраняются. До готовности checkpoint не делать промежуточных code pushes, автоматически запускающих матрицу; документационный checkpoint может использовать existing skip-ci convention и локальный docs check.
- Новая работа входит в R1 только со ссылкой на критерий/R1-Bxx, подтверждённую регрессию или блокирующий безопасность/выполнение дефект. Остальные идеи получают FI-ID и не реализуются автоматически.
- Отчёт: пользовательский результат; закрытый блокер и evidence; оставшиеся блокеры; только записанные FI. Не создавать большой evidence-файл на каждое небольшое изменение.
- Здесь **не предлагается пересмотр исходного контракта**. Если он понадобится, представить один конкретный пакет изменений и последствий владельцу; до его согласия действуют прежние требования.

## Критерий остановки

R1 завершён только когда R1-B01-R1-B08 закрыты проверяемым evidence, полный пользовательский путь воспроизведён из чистого checkout, все обязательные gates приняты на одном candidate, инструкции повторяемы и результаты опубликованы. Нужная независимость review/challenges явно подтверждена; self-review не переименован в независимый.

После этого завершить существующую цель, представить результат и приоритетную FI-очередь, **остановиться**. Future backlog выполнять только после команды владельца «продолжай по списку будущих улучшений».
