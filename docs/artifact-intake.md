# Независимый приём ML-артефакта

Компонент T27/M21 от 2026-10-13. [ADR 0024](decisions/0024-independent-artifact-intake.md), [PB-14/RB-29/RB-30/RB-31](operations/artifact-intake-troubleshooting.md). Полный M21 ещё не подключён к acceptance runner. Этот компонент не разрешает release.

## Что и зачем

ONNX (Open Neural Network Exchange) описывает вычислительный граф модели. Его checker проверяет структуру, но не доказывает происхождение, отсутствие poisoning или безопасность произвольного выполнения. Даже валидная модель может расходовать слишком много ресурсов. Поэтому используется узкий [linear-onnx-v2](model-contract.md) и изолированный процесс, а не загрузка неизвестного объекта в privileged scorer. Основание: [ONNX checker](https://onnx.ai/onnx/api/checker.html), [ONNX Runtime: Model Validation](https://onnxruntime.ai/docs/). Проверено 2026-10-13; текущая online ONNX documentation показывает 1.24.0, проект использует locked 1.23.2, поведение проверяется именно с ней.

До этого scan приходил вместе с predictions. Теперь отдельный worker сначала инспектирует immutable bytes без inference, labels, features или signing key. Это независимость от trainer и prediction execution, но не независимый разработчик/поставщик scanner: image, код и ONNX parser общие. Компрометация самого pinned scanner остаётся риском. Подпись фиксирует решение scorer, не превращает ненадёжный parser в доказательство абсолютной безопасности.

## Цепочка

1. SQL orchestration проверяет candidate/manifest/lineage и резервирует попытку holdout. Лимит не увеличен, не сбрасывается и не возвращается при отказе intake. Labels уже могут быть прочитаны доверенным scorer; этот этап не заявляется pre-holdout-read gate.
2. `evaluate_verified_candidate` до создания prediction batch формирует `inspect` request: model bytes, SHA-256, случайный 128-bit inspection ID и schema. Никаких полей labels/features/credentials.
3. Backend запускает отдельный worker в закреплённом image. Docker: network none, non-root, read-only root, capabilities dropped, CPU/RAM/PID/deadline limits. Scoped Kubernetes: роль scorer запускает job только в ml-eval; publisher не получает inspect action.
4. Worker вызывает `inspect_model`, не создаёт ONNX Runtime session. Проверяет точные graph, tensors, attributes и unknown fields, затем checker. Это allowlist конкретной binary linear model, а не общий malware detector.
5. Controller сверяет request ID/digest, модель, image, tool/policy, coverage counts, точный approved set и bounded response. Старый ответ или ответ для других bytes отклоняется. Если backend предоставляет input digest, он тоже проверяется.
6. Только pass с одним проверенным объектом разрешает отдельный prediction worker. Он повторно проверяет graph перед runtime load. Scorer вычисляет качество по своим labels и включает receipt в подписанный evaluation.
7. Evaluation report имеет schema 2; внешний stored-evaluation envelope остаётся schema 1. SQL reader повторно связывает receipt с сохранёнными bytes и image. Старый report schema 1 или report без `intake` больше не принимается. Его не дописывают задним числом: требуется новая evaluation в рамках доступного budget. Candidate materials bundle наследует эту проверку через общий reader.

Файловый helper `inspect_file` проверяет относительный путь, symlink, digest и неизменность после сканирования. Он возвращает проверенные bytes; нельзя заменять их последующим открытием изменяемого path. Root должен принадлежать контроллеру. Это не доказательство отсутствия всех filesystem races при атакующем владельце каталога. В SQL основном пути передаются bytes из content-addressed storage, а не ссылка на mutable файл.

## Support matrix

| Input / ситуация | Действие | Approved outputs |
|---|---|---|
| Exact Scaler -> binary LinearClassifier, профиль v2 | Полная структурная проверка, 2 nodes, затем evaluation | Только SHA-256 проверенных bytes |
| Произвольный ONNX, custom ops/functions, external tensors, unknown fields | Fail, модель не допускается | Пусто |
| Pickle/joblib/произвольные bytes под именем .onnx | Parser/profile fail; Python deserialization отсутствует | Пусто |
| Empty / oversized request | Reject до worker | Не создаётся pass receipt |
| Zero inspected, skipped/error/unsupported counts, лишний output | Protocol fail | Пусто |
| Stale nonce, чужой model/request digest, другой image/tool/policy | Binding fail | Пусто |
| Scanner crash/deadline/недоступная среда | Inconclusive, не разрешает prediction | Пусто |
| Traversal/symlink или изменение файла во время scan | Reject | Возвращаемого approval нет |
| Conversion из произвольного формата | Не поддерживается; тест изменяет файл, а не запускает converter service | Нет |

Размер protocol request ограничен 16 MiB, включая base64 и JSON, поэтому фактический raw model limit ниже 16 MiB. Response ограничен 64 KiB. Это строже 50 MiB внутреннего inspector. Источником истины служит наименьший применимый limit, не расширение его ради большого файла.

## Receipt и ошибки

Receipt schema 1: input digest/bytes, inspection ID, request/response hashes, tool name/version/policy, image ID, UTC timestamps, inspected/unsupported/skipped/errors, scan и approved outputs. Успех: inspected=1, остальные counts=0, approved=[model digest]. Отказ parser/profile: inspected=0/errors=1; scanner не пытается угадать исходный формат по расширению и не объявляет непроверенные bytes поддержанными.

`IntakeFailure.report` содержит очищенный fail/inconclusive. Transport failure отмечен `origin=controller`, response hash отсутствует; это не вымышленный ответ worker. Ответ настоящего worker имеет origin=worker. Непроверенные stdout, stderr и exception bodies не переносятся в report. По [ADR 0025](decisions/0025-signed-intake-denial.md) SQL/scoped-controller path сохраняет такой отказ как отдельный подписанный `intake-denial`, проверяет readback и всё равно заканчивается nonzero. [RB-32/RB-33](operations/intake-denial-troubleshooting.md) объясняют проверку и persistence failure. Filesystem preview и ранние preflight rejections пока не получают такой durable SQL record.

Исторический подписанный receipt проверяет subject и структуру, но не заменяет живое повторное сканирование или release freshness/revocation policy. Nonce защищает текущий запрос от подстановки другого ответа, а не превращает stored report в одноразовый release token.

## Проверки и оставшаяся работа

Controlled suite: 21 метод, реальный небольшой экспорт для parser tests, подделки protocol и role/path tests, ownership-before-evidence regression. Linux выполняет настоящий symlink case. Windows host без CreateSymbolicLinkPrivilege не может создать такой fixture; это не исправляется отключением теста или запуском Codex администратором. Все 21 выполняются в Linux/CI, 20 остальных отдельно проверяются на Windows.

Native Docker suite: настоящее обучение, чистый intake, renamed pickle, deadline/crash injection, повторный clean scan после сбоев. Fault injection заменяет только процесс в собственном network-none контейнере на sleep или exit 19. Это настоящие отказ процесса/дедлайн и проверка cleanup, но не воспроизведение уязвимости ONNX и не native Kubernetes failure test. Developer qualification проверяет путь training -> intake -> prediction -> signed evaluation в трёх fresh runs.

Очищенные результаты и commits: [STATUS](../STATUS.md). SQL denial persistence реализован отдельно от quality report; приёмка его native path фиксируется там. [M21 runner](intake-gate.md) теперь сверяет fresh Docker/SQL evidence, но оставляет gate inconclusive до отдельной scoped-controller negative matrix. Integration с будущим release/serving и preflight outcomes тоже остаются открытыми. M08 poisoning и image CVE blockers не устраняются структурным scanner; T27 остаётся открытой.
