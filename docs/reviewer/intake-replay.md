# Приём и воспроизведение M22

Статус на 14 ноября 2026 года: получено 0/2 независимых кейсов. Отдельный аудит unsafe API проверял другие свойства. Здесь описан исполняемый v1 для двух сопоставимых poisoning challenges. Личность человека, новизну гипотезы, конфликт интересов и сохранение тайны до reveal проверяют reviewer и владелец. Локальная подпись и часы оператора сами по себе этих фактов не устанавливают.

## Для оператора до раскрытия методов

Проверено локально: пять controlled unit-тестов используют временные ключи, управляемое чтение subject и ответы worker. Проверены путь до 44 исходов в тестовом workspace, отказы при подменах и блокировка подтверждённого bypass. Покрытие интерпретатора составило 35/35 исполняемых строк и 22/22 ветвей, intake/replay 289/296 и 59/66. Живой прогон нового пути с независимыми материалами остаётся открытым. [Controlled tests](../../scripts/m22_review_qualification.py).

На разрешённом стенде сохранить один owned workspace с evaluated candidate, подписанной lineage и полной матрицей M22. Нужен чистый checkout **этой версии адаптера**, worker image с тем же source fingerprint и 300 первичных файлов. Обычная команда M22 без intake создаёт исходную матрицу. Оператор передаёт reviewer публичный source snapshot и JSON, напечатанный второй командой. Идентификатор campaign берётся из `.runtime/evidence/absolute-poisoning-gate.json`.

```text
python -m mlsecops.acceptance --gate M22 --output .runtime/evidence/M22.json
python -m mlsecops.m22_review manifest CAMPAIGN_ID
```

Reviewer проверяет revision, candidate/evaluation, SHA-256 модели, image, policy и protocol в manifest. Обе стороны сохраняют оригиналы и точные байты. Архив исходников не содержит candidate, секреты или результаты обучения. Для другого private workspace параметр `--state PATH` указывается перед подкомандой. Первичное исполнение требует доступного owned storage и worker. Штатный disposable workflow очищает стенд в конце job: для ручных фаз нужна согласованная сессия с сохранением этого же состояния.

## Для reviewer до reveal

1. Выбрать по новой стратегии label-flip и backdoor. В приватном каталоге создать `label-flip.md` и `backdoor.md` по [шаблону спецификации](challenge-spec-template.md). Описать отбор, знания, отсутствие feedback, ресурсы, метрики и критерии severity. Оба метода исполняются в пределах фиксированного профиля ниже.
2. Записать рядом два JSON того же basename. Ровно три поля: `family` (строка из имени файла), `train_entity_ids` (отсортированные различные целые ID положительных строк locked train), `trigger` (объект). Число ID из absolute policy: 1, 5 или 25 на 14 000 строк. Код всегда меняет выбранные labels с 1 на 0. Для label-flip объект trigger пустой. Для backdoor он содержит присваивания чисел от 0 до 1 именованным признакам из [FEATURES](../../mlsecops/datasets.py), одинаковые на выбранных train rows и на отдельном trigger view probes. Известный одиночный trigger и точные опубликованные absolute label-flip выборки отклоняются. В JSON нет путей, выражений, команд или кода. Технические тесты в репозитории используют собственные контролируемые данные.
3. Зафиксировать исходные четыре файла до передачи методов. Посчитать SHA-256 **байтов каждого файла**, включая его переводы строк. Лимит каждого файла 65 536 байт. Составить JSON payload с ровно четырьмя полями: `binding` (полный JSON manifest), `reviewer` (согласованный строчный ASCII ID), `frozen_at` (UTC ISO 8601 с timezone), `files` (отображение четырёх точных имён в SHA-256). Поле rules в binding фиксирует capabilities и ресурсы. Подписывать только после согласования. Типы сообщений доменно разделены с помощью DSSE (Dead Simple Signing Envelope) и Ed25519.
4. На устройстве reviewer использовать собственный приватный Ed25519 PEM. Для нового ключа штатный `mlsecops.signing.create_key(path)` возвращает публичное значение base64. Публичный ключ и личность владелец подтверждает заранее по известному ему каналу. Приватный ключ остаётся у reviewer. Владелец подтверждает, что reviewer не участвовал в разработке или настройке защиты. Сначала передать **только** конверт freeze. Оператор передаёт в intake подтверждённый ключ и ID автора защиты.

```text
python -m mlsecops.m22_review sign m22-freeze freeze.json freeze.dsse.json --key REVIEWER_PRIVATE_PEM
python -m mlsecops.m22_review intake CAMPAIGN_ID freeze.dsse.json --reviewer-public VERIFIED_BASE64 --owner DEFENCE_OWNER_ID
```

Операторский approver подписывает квитанцию, привязанную к двум хешированным методам и двум описаниям, фиксирует время получения и выводит digest квитанции. Reviewer сохраняет и сверяет копию квитанции. На workspace отводится один intake и одна попытка исполнения. После этого reviewer раскрывает четыре файла и сверяет [интерпретатор](../../mlsecops/m22_methods.py) с согласованными методами. Для такой проверки достаточно source и разрешённых train данных. В v1 фиксированы seed кандидата, один poisoned fit и две prediction batches на кейс, до 600 секунд на каждый worker, нулевой feedback и нулевые запросы к final holdout. Иной эффект, бюджет, новый исполняемый алгоритм или дополнительное обучение требуют отдельной предварительной версии протокола.

## Исполнение и решение

Reviewer формирует payload `methods.json` с полями `intake_sha256`, `checked_at` и `matches_frozen_methods: true` после сверки реализации. Оператор принимает `methods.dsse.json` в каталоге PACKET вместе с четырьмя оригиналами.

```text
python -m mlsecops.m22_review sign m22-methods methods.json PACKET/methods.dsse.json --key REVIEWER_PRIVATE_PEM
python -m mlsecops.m22_review execute PACKET
```

В каждом случае кандидат из owned storage служит matched clean control на тех же двух представлениях probes, в том числе на новом trigger. Адаптер передаёт worker только утверждённые операции train/predict. Native verifier реконструирует train request, lineage, model и prediction bindings. Из scores заново считаются AP drop, eligible и верхняя граница ASR по прежней absolute policy. Один интервал относится к синтетическим entities одной обученной пары. Шесть чистых контролей матрицы и их исходы остаются в отчёте.

`execute` печатает SHA-256 **канонического payload** observations. Оператор передаёт reviewer подписанные observations, первичные материалы для проверки и доступные результаты матрицы. В `.runtime/m22-review/run/` остаются 23 первичных файла и отдельно `observations.json`. Reviewer сверяет подпись approver через `mlsecops.signing.verify(envelope, "m22-observations", verified_approver_public)`, считает `digest(canonical(payload))`, проверяет обе пары прогнозов и все исходы. Для каждого семейства заполняет отдельную копию [шаблона результата](review-results-template.md) под именем `label-flip-result.md` или `backdoor-result.md`. В finding фиксирует отказ, false alarm, bypass, ограничения и обоснование по подписанной спецификации.

Payload итогового решения содержит `observations_sha256`, `decided_at` и `findings`. Ключи findings ровно `label-flip` и `backdoor`. Каждое значение содержит `decision` (pass/fail/inconclusive), `hard_boundary_bypass` (JSON boolean) и `result_md_sha256` (хеш исходных байтов результата). Два Markdown-файла и подписанный `decision.json` входят в DECISION_PACKET.

```text
python -m mlsecops.m22_review sign m22-decision decision-payload.json DECISION_PACKET/decision.json --key REVIEWER_PRIVATE_PEM
python -m mlsecops.m22_review record-decision DECISION_PACKET
python -m mlsecops.acceptance --gate M22 --output .runtime/evidence/M22.json
```

Оператор принимает одно проверенное решение. Повторная команда acceptance читает сохранённые байты, заново сверяет subject и 42 случая исходной матрицы, затем проверяет оба challenge. Любое измеренное нарушение, reviewer fail или подтверждённый hard-boundary bypass даёт fail. Частичный результат или отсутствующее решение не разрешает pass. Для pass нужны 44 согласованных исхода, подписи и полные байты. Даже тогда M18 и общее разрешение выпуска требуют своих проверок.

При отказе сохранить приватную директорию целиком, включая незавершённую попытку, и идентификатор исходной campaign. Поменявшиеся файлы сверить с оригиналами у сторон. Сохранять предыдущие исходы и причины изменений. Не сбрасывать маркеры и не переподписывать результат ради pass. Утрата исходного workspace требует новой campaign и нового freeze. Граница доверия включает операторский контроллер, его закрытые ключи, часы, private storage и независимую проверку custody. Протокол не защищает от их согласованной компрометации.
