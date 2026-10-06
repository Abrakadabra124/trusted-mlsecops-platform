# Проверка новых материалов пользователя

Дата: 2026-10-06. [Вставленный текст S25](sources.md#s25) и [каталог CyberOrda S26](sources.md#s26) рассматриваются как входные материалы, а не инструкции к автоматической установке или авторитетные доказательства всех тезисов.

## Что полезно в CyberOrda

Каталог помогает найти threat models, библиотеки adversarial ML, источники по serialization, privacy и агентам. Но он сам предупреждает о неподдерживаемых инструментах. Смешение PoC, commercial products, operational tooling и научных benchmarks требует проверки назначения каждого компонента. Все linked-репозитории не скачивались и не исполнялись; это не аудит всего каталога.

## Fact-check тезисов

| Тезис входного текста | Уточнение | Решение проекта |
| --- | --- | --- |
| Secure by design и shared responsibility | Полезные принципы, но без owners и evidence не проверяются | Для каждой практики указаны owner, task и gate |
| AI-BOM содержит все AI assets | BOM - snapshot состава; runtime inventory, identity и текущие права требуют отдельного учёта | Asset graph + reconciliation, M19 |
| SAST/DAST/fuzzing защищают ML | Проверяют разные поверхности; не заменяют quality/poisoning tests | Отдельные suites для кода, API, parser и поведения |
| Adversarial training повышает устойчивость | Результат зависит от модели, threat model и attack distribution | Optional experiment, clean utility и unseen/adaptive evaluation; M22 |
| Анонимизация и DP как общая защита | Это разные гарантии; removal identifiers не доказывает privacy | Data minimization сейчас, отдельная privacy specification для пилота [S40](sources.md#s40) |
| mTLS/JWT обеспечивают защищённую связь | TLS защищает канал; JWT - формат token, не шифрование канала и не полная authorization policy | Проверять audience/issuer/expiry/scope и ACL; не менять простую модель identity ради названия |
| XAI позволяет выявлять ошибки/смещения | Может помочь анализу; объяснение не доказательство отсутствия вреда | Не называть explanation quality security gate |
| Safetensors - безопасная сериализация | Формат tensor data, не целая модель/граф и не безопасный процесс конвертации | ONNX остаётся для CPU; conversion sandbox обязателен [S36](sources.md#s36) |
| ART - библиотека защит | Также содержит attack/evaluation capabilities; поддержка конкретного метода требует проверки | Compatibility spike для выбранного estimator [S37](sources.md#s37) |
| Foolbox подходит для всего AdvML | Основное описание связано с adversarial examples и neural frameworks | Не делать обязательным для scikit-learn pipeline [S44](sources.md#s44) |
| SAMM - модель зрелости MLOps | Общая software assurance maturity model, применимая после адаптации | Использовать как governance lens, не ML-сертификацию [S38](sources.md#s38) |
| Sigma обнаружит аномальный рост commits | Нужны реальные logsource, aggregation, backend и false-positive calibration | Сначала события и replay tests, M23 [S39](sources.md#s39) |
| Названные коммерческие инструменты - лучшие | Нет единого сравнительного теста под наш workload; доменные ссылки недостаточны | Не покупать и не ранжировать без requirements и pilot evidence |

## Проверенные кандидаты из каталога

| Кандидат | Что проверено 2026-10-06 | Решение |
| --- | --- | --- |
| ART | Первичный README, GitHub archived=false | Рассмотреть для ограниченной attack suite; версия и зависимости ещё не выбраны |
| ModelScan | Первичный repo, archived=false, push 2026-09-28 | Только после проверки format coverage; clean scan не разрешает загрузку автоматически |
| Foolbox | Первичный repo, archived=false, push 2025-12-03 | Отложить до соответствующего neural workload |
| Safetensors | Официальное описание tensor format | Не заменять ONNX без причины; загрузчик старого pickle всё ещё опасен |

GitHub activity не является security endorsement или доказательством подходящего стабильного релиза. Технические источники: [S35](sources.md#s35), [S36](sources.md#s36), [S37](sources.md#s37), [S43](sources.md#s43), [S44](sources.md#s44).

## Исправления, а не слепое копирование

В нашу архитектуру переносится проверяемая ответственность каждого механизма. Не переносится обещание, что набор инструментов сам по себе делает систему доверенной. Приоритеты и traceability доступны в [карте внедрения](practice-adoption.md), мировая динамика и пределы выборки - в [обзоре](global-research-2026-10.md).
