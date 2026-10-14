# ADR 0026: отделить release descriptor от assurance и approval

Дата: 2026-10-14. Статус: принят для локального increment T13; полный promotion lifecycle ещё не реализован.

## Требование

Существующая candidate capsule подтверждает связи материалов, но не разрешение эксплуатации. Нужны полный immutable descriptor, независимая policy и отдельное одобрение именно этих байтов. Нельзя исправлять failed gates удалением их из списка или подписью publisher от собственного имени как approver.

## Источники и интерпретация

- [DSSE protocol 1.0.2](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md), проверен 2026-10-14: проверка подписанных payload bytes и purpose-bound type, ключ доверия вне keyid входного сообщения.
- [SLSA v1.2, verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts), проверен 2026-10-14: подпись и subject недостаточны без проверки ожидаемой identity и policy. Здесь используется этот принцип, не заявляется SLSA level или сертификация.

## Решение

Переиспользовать существующие Ed25519/DSSE primitives и неизменяемый SQL CAS. Добавить три узких модуля: release policy, bundle, authorization. Descriptor подписывает publisher; assessor связывает отчёты с hash descriptor; approver связывает approval с descriptor, assurance, environment и policy. Trust root задаётся проверяющему снаружи. Сравнение ролей по decoded bytes исключает обход разными Base64-представлениями.

Не помещать approval hash обратно в descriptor: это создало бы круговую зависимость. Не разрешать workflow success или model-card text заменять M18 evidence. Не вводить registry alias до durable sequence transition. SQL publication - отдельная идемпотентная операция, не activation.

Ужесточённый контракт reports требует subject/model/source bindings, временной порядок и согласованные case outcomes. Существующие gate generators ещё не дают общий candidate-bound bundle; адаптация вместе с M18 остаётся задачей, а не автоматическая упаковка исторических pass.

## Альтернативы и последствия

Один JSON с флагом approved прост, но не разделяет полномочия и не фиксирует, что именно одобрено. Сразу добавлять новый registry/KMS/service mesh не требуется для проверки контракта и увеличило бы эксплуатационный scope. Локальные private keys достаточны для криптографических тестов, но не дают независимость администраторов или защиту production KMS.

Положительные authorization tests используют явно controlled fixtures. Native SQL проверяет сохранение/readback и **реальный отказ** без общей assurance. До state machine/revocation/serving результат всегда release_ready=false. [Контракт](../release-authorization.md), [процедуры](../operations/release-authorization-troubleshooting.md).
