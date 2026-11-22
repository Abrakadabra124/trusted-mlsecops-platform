# Original serving primaries for M18

## Сборка приватного черновика M18 из подтверждённых M13, M14 и M15

В чистом checkout кандидата оператору нужны сохранённые объекты трёх проверок, внешний хеш исходной квитанции, хеши freeze и плана, ссылка на исходное предложение выпуска и хеши исходных reports и admissions. Файл `evidence/M18-plan.json` должен находиться в приватной области `.runtime`. Получите его хеш из заранее зафиксированного плана. Таблицы cases и artifacts охватывают 22 дочерних критерия. Для M13, M14 и M15 сборщик пересчитывает по отчётам хеши перечней проверок и артефактов и сверяет их с планом. При утрате квитанции или несовпадении источника сборка останавливается.

В том же доверенном задании, в котором доступен `GITHUB_OUTPUT`, выполните `python -m scripts.m18_serving_retention assemble-draft`. Передайте `M18_FREEZE_SHA256`, `M18_SERVING_PRIMARY_SHA256`, `M18_PROPOSAL_REFERENCE`, `M18_PLAN_SHA256` и по паре переменных `M13_REPORT`/`M13_ADMISSION`, `M14_REPORT`/`M14_ADMISSION`, `M15_REPORT`/`M15_ADMISSION`. Для локального офлайн-запуска укажите в `GITHUB_OUTPUT` путь к приватному файлу вне Git. Возвращённое поле `sha256` указывает на байты черновика в `.runtime/evidence/M18-objects/`. Передавайте его следующему сборщику только через приватный канал.

Команда заново проверяет исходные материалы и связывает три отчёта, две приватные ссылки, ревизию, образ, freeze, предложение и план. Если уже есть доверенный черновик, передайте его хеш в `M18_DRAFT_BASE_SHA256`. Совместимые записи других этапов сохраняются. При конфликте существующего хеша сохраните оба исходных набора для разбора и проверьте их принадлежность одному предложению. Повтор идентичной сборки выдаёт прежний SHA-256. Статус черновика всегда `inconclusive`, `release_ready=false`. Окончательное утверждение индекса и независимая проверка всех 22 дочерних критериев остаются отдельными этапами.

Статус: bounded collector M13/M14/M15 для T21, без полной приёмки M18/R1.
Ответственный за подключение и native qualification: владелец parent integration.
Модуль: [m18_serving_retention.py](../../scripts/m18_serving_retention.py).
Проверки: [qualification](../../scripts/m18_serving_retention_qualification.py).

## Исходный пробел и границы

В baseline `8f01750` [m18_delivery_freeze.py](../../scripts/m18_delivery_freeze.py)
сохраняет package и primaries других gates, включая оригинальный M05.
[performance_delivery.capture](../../mlsecops/performance_delivery.py) сохраняет
подписанный package и policy, но не переносит все исходные serving observations
и packets в M18-objects. Обычный replay trio читает их по исходным путям.
Успешный replay сам по себе поэтому не доказывает автономность M18 primary store.

Новый collector копирует точные исходные байты в content-addressed storage
(CAS, файлы с именами SHA-256) `.runtime/evidence/M18-objects` и проверяет
восстановленное представление обычными offline verifiers. Он не выпускает
proposal, permit, gate report или acceptance. Исходные файлы не переписываются.
Canonical preimages для method materials, controlled contracts и вложенного
monitoring proof разрешены только при совпадении с уже опубликованными хешами.
Это не повторное вычисление результатов gate.

## Preconditions и порядок интеграции

1. Чистый source checkout должен совпадать с revision/fingerprint оригинального
   freeze. Нужны исходные четыре frozen files и уже сохранённый signed package.
2. Parent получает hashes непосредственно от первоначальных producer steps:
   `M18_FREEZE_SHA256`, `M13_REPORT`, `M14_REPORT`, `M15_REPORT`,
   `M13_ADMISSION`, `M14_ADMISSION`, `M15_ADMISSION`.
   M13 admission относится к `privacy-gate-private.json`; M14/M15 admissions
   относятся к соответствующим `M14-frozen-private.json` и
   `M15-frozen-private.json`. Не получать новые owner pins из непроверенных копий.
3. Сначала выполнить существующую последовательность native trio и её проверки
   cleanup: source SQL доступен во время live capture; transitions изолируют
   кампании; shared M11/M12 и остановка source следуют установленному parent
   порядку. Этот collector не меняет порядок, не восстанавливает инфраструктуру
   и не подменяет existing cleanup/transition receipt.
4. Вызвать capture после существующего успешного offline replay trio, пока
   оригинальные serving файлы ещё доступны. Допустимо после native teardown:
   collector читает файлы и подписанный package, без SQL/контейнеров/кластера.
5. Сохранить отдельный owner pin возвращённого private receipt. Перед включением
   fragment в M18 выполнить replay с теми же первоначальными owner pins.
   Интеграция workflow и общего index остаётся отдельной задачей parent.

В hosted step с указанными environment variables:

```bash
python -B -m scripts.m18_serving_retention capture
```

Capture записывает masked `sha256` в `GITHUB_OUTPUT`. Для replay parent передаёт
этот output как `M18_SERVING_PRIMARY_SHA256`, сохраняя все семь owner variables:

```bash
python -B -m scripts.m18_serving_retention replay
```

Library API: `capture(root, state, freeze_pin=..., reports=..., admissions=...)`
возвращает SHA-256 receipt; `replay(root, state, receipt_pin, freeze_pin=...,
reports=..., admissions=...)` возвращает проверенный fragment. Оба gate maps
содержат строго M13/M14/M15. CLI replay публикует только public report hashes,
source/proposal identity и `release_ready: false`, без private packet references.

## Что сохраняется и как проверяется

- Оригинальные M13/M14/M15 reports, component reports, controlled files,
  frozen inputs, admissions и private observations; шесть candidate-inference
  artifacts каждой кампании, включая оригинальный подписанный permit.
- M13: actual audit, controlled CLI audit/context, service windows, feedback
  privacy proof и source-service packet; canonical embedded monitoring proof.
- M14: start/finish request packets и resources. Public artifact references
  проверяются непосредственно через CAS.
- M15: monitoring binding, native packet, feedback proof, public observation
  и оригинальный `monitoring-gate-private.json`. Последний должен точно
  соответствовать private observation/packets из pinned frozen admission.

Private receipt `.runtime/evidence/M18-serving-primary-private.json` содержит
явный allowlist путей и pins. Рекурсивного копирования runtime/keys/logs нет.
Для [final_evidence.retained](../../mlsecops/final_evidence.py) fragment
`retained` содержит строго M13 и M15: M13 указывает на ORIGINAL privacy
admission, M15 на ORIGINAL native monitoring admission, не на его frozen wrapper.
M14 сохраняет свои private references через public report artifacts.
Parent переносит эти проверенные ссылки и исходные report hashes в общий M18
index, сохраняя остальные gates, включая независимый M23 collector.

Replay использует только receipt и objects, owner pins и тот же clean source.
Он восстанавливает allowlist во временный private каталог, запускает
`serving_campaign.privacy`, `performance_delivery.replay` и неизменённый
`final_evidence.retained`, затем удаляет временное представление. Подписи,
source/candidate/model/subject, signed package и исторический permit window
проверяют обычные readers. Expired сегодня permit не обновляется: историческое
выполнение обязано укладываться в оригинальное окно. Promotion требует своих
актуальных проверок и этим fragment не разрешается.

## Отказы и безопасное восстановление

Missing/corrupt/swapped objects, другой candidate даже после пересчёта outer
hashes, изменённый source, просроченное на момент исполнения окно permit,
расхождение native/frozen admission или ошибка обычного verifier запрещают
успешный capture/replay. Существующий повреждённый CAS object не перезаписывается.
Повторный capture с теми же байтами идемпотентен; отличный receipt не заменяется.
Неудачный capture может оставить отдельные objects, но не успешный новый receipt.

Диагностика начинается с exit status, producer step outputs и сохранности
оригинальных pins. Не печатать private receipt, packets или raw exception payloads.
При утрате материала восстановить только аутентичную копию с тем же исходным
хешем либо признать campaign inconclusive. Не reseal/refreeze/renew для обхода
отказа. Collector не удаляет единственные копии и не выполняет автоматический
rollback. Parent может исключить новый fragment из сборки, сохранив original
evidence для диагностики; это не разрешает пропустить обязательный gate.

Предел object остаётся 16 MiB, как у `final_evidence.blob`; allowlist ограничен
256 файлами. Некоторые native producers допускают больший packet. Если реальный
packet превышает inherited limit, сборка откажет: расширение лимитов не входит
в этот patch и требует отдельного совместимого решения parent.

## Проверка и ограничения доказательств

```bash
python -B -W error -m unittest scripts.m18_serving_retention_qualification
python -B scripts/check_docs.py
```

Qualification проверяет исходные bytes, неизменность owner pins, missing/corrupt/
swapped/resealed inputs, ordinary verifier failures, исходный permit window,
неизменность receipt и replay после удаления всех собранных исходных файлов
в контролируемом temporary fixture. CAS и source остаются доступными.
Эта destructive fixture-проверка не является командой очистки реального runtime.

Локальный результат на pinned Python 3.12.15: 12 tests pass, 0 skips;
coverage collector 183/183 statements, 46/46 branches (100%). Это coverage
bounded helper, а не измерение всей security-critical логики платформы.

Windows qualification использует реальные подписи и frozen package readers,
но controlled substitutes для native measurement reconciliation, POSIX audit
reader и source cleanliness. Linux permissions, реальные packets, native
cleanup и end-to-end M18 assembly требуют hosted qualification после интеграции.
Локальные Docker/WSL/Kubernetes/SQL и hosted dispatch этим patch не выполнялись.
Strict 22 child criteria, M18 и независимый открытый M22 не изменены.
