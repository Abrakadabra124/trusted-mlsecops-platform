# ADR-003: Контроль выпуска вне недоверенного model execution

Дата: 2026-10-06. Статус: **Proposed**, до T26-T27. Дополняет [ADR-002](0002-release-trust.md), не меняет выбранный CPU-сценарий.

## Контекст

Первоначальная схема отделяла trainer от evaluator, но не описывала риск компрометации model parser внутри evaluator. Если загрузчик модели находится рядом с signing key и holdout labels, «независимая оценка» может стать источником подделанных доказательств. Аналогично arbitrary code в training job способен прочитать credentials из собственной среды.

## Решение

Разделить execution plane и control plane. Model worker получает одноразовый read-only model mount и ограниченные batches features, не keys/labels/promotion permissions. Trusted scorer проверяет размер, порядок, типы и конечность predictions, вычисляет метрики и подписывает report через отдельный identity boundary. Raw worker logs не включаются автоматически в публичный report.

Authorization не делегируется model score, XAI explanation, prompt filter или LLM-as-judge. Системные роли, egress и file-write restrictions enforce вне workload. Принципы адаптированы из [NVIDIA S32](../sources.md#s32), [OpenAI S33](../sources.md#s33), [AWS S30](../sources.md#s30); решение о tabular evaluator является нашим выводом, а не описанием их конкретных систем.

## Альтернативы

- Один evaluator container со всеми правами: проще, но компрометация parser раскрывает labels/keys и позволяет менять evidence.
- Только scanner перед загрузкой: покрытие неполное и не исключает runtime parser vulnerability.
- Полная confidential-computing платформа сразу: может усилить отдельные trust assumptions, но для первого reference не оправдана без угрозы host-admin и бюджета.

## Последствия

Появляется небольшой typed prediction protocol и тесты изоляции; требуется ограничить output channels, workers и labels access. Это не доказывает, что scorer или kernel неуязвимы. T26 должен показать реальные denial probes, T27 - отказ при неполном intake scan. Продолжение без проверенного разделения допускается только как явно ограниченный research lab, не как принятый trusted reference.
