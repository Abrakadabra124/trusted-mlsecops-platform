# ADR 0024: отдельная инспекция до evaluation inference

- Дата: 2026-10-13.
- Статус: принято для R1 synthetic component, не полный M21.
- Контекст: [контракт ONNX](../model-contract.md), [M21](../acceptance.md#m21), [реализация](../artifact-intake.md).

## Решение

Перед prediction нужен отдельный inspect worker с неизменяемыми bytes, fresh nonce и закреплённым image. Привилегированный controller не импортирует ONNX/ORT, проверяет только protocol/evidence binding. Scorer включает receipt в подписанный evaluation report schema 2; offline/SQL reader требует её присутствия. Внешний stored-evaluation envelope schema 1 не меняется. Allowed output означает разрешение оценки конкретных bytes, а не production approval.

Используется существующий isolated execution backend и узкий linear-onnx-v2, без установки универсального scanner ради списка инструментов. Docker, lab Kubernetes и scoped-controller используют общий pipeline. Разрешение inspect добавлено только evaluator/scorer role. Holdout reservation остаётся до worker, поэтому failed intake не обходит лимит обращений к holdout.

## Альтернативы и последствия

- Доверять scan из train/predict: дешевле один запуск, но нет отдельной pre-inference проверки. Отклонено.
- Парсить ONNX в scorer: проще транспорт, но parser получает privileged address space/signing context. Отклонено.
- Произвольная конвертация pickle и разнообразных neural graph: не нужна для выбранного baseline; расширяет поверхность атаки и недоказанное покрытие. Отложено до отдельного профиля.
- Новый сторонний scanner без подтверждённой поддержки этого формата: не доказывает фактическое coverage. Его внедрение требует отдельного compatibility/negative spike.

Цена: дополнительный worker на evaluation и несовместимость с прежними evaluation records без intake. История не переподписывается, рабочий budget не сбрасывается; старые evidence действительны только для прежнего commit. Same-image parser compromise, image vulnerabilities и poisoning остаются остаточными рисками. Изоляция ограничивает воздействие, не доказывает безошибочность scanner. Release gates не ослаблены.

Проверка: [controlled contracts](../../scripts/artifact_intake_qualification.py), [native failure replay](../../scripts/artifact_intake_native.py), обязательная developer CI. [Runbook](../operations/artifact-intake-troubleshooting.md) разделяет environmental failure, model rejection, injected failure и восстановление.
