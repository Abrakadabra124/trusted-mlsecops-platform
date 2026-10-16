# ADR 0038: private generation-bound serving context

Дата: 2026-10-16. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Статус: implemented, local contracts pass; [native 503b68b attempt 2](../evidence/serving-context-2026-10-16.md) 72 cases pass. Продолжает [ADR 0037](0037-audit-retention.md), не закрывает M13.

## Требование и решение

Audit должен связывать ответ с проверенной моделью, не получать идентичность из HTTP headers или позднего чтения изменяемого reader. Qualification permit разрешает испытание candidate, а не production promotion. Нельзя назвать permit проверенным selection.

[serving_context.py](../../mlsecops/serving_context.py) определяет два frozen/slots типа версии 1. `ReleaseContext` содержит selection/bundle/model SHA-256, kind `release-selection`. `QualificationContext` содержит permit/proposal/bundle/model SHA-256, kind `candidate-qualification`; поля selection в нём нет. Оба имеют `release_ready=false`. Принимаются только lowercase hex strings, без mutable containers, payload или credentials. Repr не раскрывает refs.

`VerifiedRelease.audit_context` использует request digest уже проверенного promotion selection. `QualifiedCandidate` сохраняет digest canonical permit payload и proposal reference из результата проверки подписанного permit, не из позднего состояния reader. Это **payload digest**, не digest signed envelope. Existing bundle/model binding и trust checks сохраняются.

## Поток

1. Reader проверяет authorization/qualification, материалы и текущее доверие. Самостоятельное создание dataclass не является разрешением или такой проверкой.
2. `Engine.activate` сверяет байты модели, worker binding и reader, затем под lock фиксирует context с exact bundle/model. Некорректный context запрещает activation; clear/invalidate удаляют его.
3. `check_result/predict_result` выполняют существующие checks и внутри exclusive section возвращают `ServingResult`: public payload, private context и generation fence. Старые `check/predict` остаются совместимыми wrappers с прежними dictionaries.
4. HTTP принимает только typed result с тем же generation, что у response budget. Проверяет context/public bundle/model. Несовпадение даёт bounded 503 без private exception text.
5. `VerifiedResponse` хранит context отдельно от JSON. Финальная lease/deadline проверка сохраняется после serialization; при замене ответа на 503 context снимается. HTTP не перечитывает reader/engine identity для attribution.

Frozen защищает от обычного присваивания и разделяемых mutable refs, не от произвольного кода в том же Python process. `ServingResult.payload` остаётся mutable dictionary для совместимости, но не содержит private refs. Неизменяемым объявлен context, не весь object graph. Generation event намеренно изменяемый: он отзывает допустимость старого результата.

## Альтернативы и ограничения

Не добавляем private fields в public JSON, не переименовываем permit в selection, не используем неявное thread-local состояние вместо явного результата между executor thread и ASGI task. Новый framework не нужен. Публичный response schema не меняется.

Здесь **нет** подключения `Journal.emit` к HTTP, записи request/send events, подтверждённой durability, queue reservation, all-output privacy/cardinality qualification или full M13. Existing journal schema ещё release-only; qualification context нельзя молча записать в selection field. Следующий slice требует версии event schema и решения admission/overload/failure policy. Успешный ASGI send не доказывает чтение клиентом. Нельзя записать completed до окончания send или «отозвать» отправленный 200 после ошибки async writer.

## Проверка

- Failure-first: до HTTP integration десять subcases двух routes получили 200 вместо требуемого 503. После реализации проходят.
- Local Windows после исправлений: 169 adjacent methods pass без skips; context module 31 statements и 4 branch exits покрыты полностью. Это не общий M18.
- Проверены frozen refs, disjoint scope, malformed refs, reader mutation, activation mismatch, failed recheck, old generation, private fields/headers и финальный deadline fallback.
- `candidate_serving_native.context_matrix` добавляет пять actual-candidate проверок: distinct scope, ready/predict generation binding, отсутствие private refs и прежний public shape. Native 503b68b attempt 2 подтвердил их в matrix из 72 cases; полный report сохранён и перечитан.
- Scoped same-model design и implementation review завершены без замечаний; внешняя модель по решению владельца не использовалась. Backend retention не изменён.
- Диагностика: [RB-57/PB-31](../operations/serving-context-troubleshooting.md).
- Первый CI `7151864` выявил race test loop с async retirement; test теперь вызывает drain и проверяет завершение cleanup перед следующей activation. [Evidence](../evidence/serving-context-2026-10-16.md) сохраняет failed attempt. Production code не ослаблен; native исправленного commit ожидается.
- CI `9326fcd` выполнил пять context cases, но выявил старый fault-injection adapter на predict вместо predict_result. Исправлено wiring, добавлен настоящий loopback dispatch regression без имитации native pause pass. Полный native suite до следующего CI не принят.
- Итог: native 503b68b attempt 2 прошёл все 72 cases с действительным ACTIVE/pending SQL и deadline denial. Ранний M07 connection failure первого attempt сохранён как unexplained reliability debt, не исправление context code.

## Первичные источники

[Python 3.12 dataclasses](https://docs.python.org/3.12/library/dataclasses.html): frozen эмулирует read-only поля, annotations сами по себе не валидируют значения. Поэтому refs проверяются явно. [ASGI HTTP specification](https://asgi.readthedocs.io/en/latest/specs/www.html): границы response start/body/send определяют следующую интеграцию, не подтверждают её реализацию. Проверены 2026-10-16; конкретный контракт выше является решением проекта.
