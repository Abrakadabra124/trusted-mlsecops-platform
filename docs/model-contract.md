# Контракт ONNX-модели до загрузки

Дата: 2026-10-11. Компонент T12/T27, **не полный M09/M21**. Реализация: [model.py](../mlsecops/model.py), [protocol](../mlsecops/prediction_protocol.py), [tests](../scripts/model_contract_qualification.py). Решение: [ADR 0023](decisions/0023-linear-onnx-contract.md). Эксплуатация: [PB-12/RB-25/RB-26](operations/model-contract-troubleshooting.md).

## Требование и технологии

ONNX (Open Neural Network Exchange) хранит вычислительный граф и параметры модели. ONNX Runtime исполняет этот граф; sklearn обучает выбранный StandardScaler + LogisticRegression, а skl2onnx переводит его в ONNX. Разрешённое имя оператора само по себе не подтверждает правильную связность, смысл labels или полноту проверки параметров.

Protocol Buffers сериализует ONNX. Неизвестное текущему parser поле может пережить обычный parse/serialize. Проверка ищет такие поля рекурсивно и отклоняет весь input, а не незаметно удаляет поля и исполняет оставшееся.

## Что именно допускает linear-onnx-v2

Это ограниченный **профиль приложения**, не универсальное определение безопасного ONNX:

| Объект | Обязательное условие |
| --- | --- |
| Bytes | Непустой bytes, максимум 50 MiB внутри inspector; worker transport имеет отдельный, меньший лимит |
| Версии | IR 8, standard opset 18 и ai.onnx.ml opset 1; 2-3 declarations без других domain/version |
| Граф | Ровно Scaler -> LinearClassifier, один вход, два выхода; цепочка полностью связана, четыре разных непустых value names |
| Interface | FLOAT [dynamic batch, 6] -> INT64 [dynamic batch], FLOAT [dynamic batch, 2] |
| Scaler | Только offset/scale типа FLOATS, по 6 конечных чисел; scale строго положительный |
| Classifier | Только classlabels_ints, coefficients, intercepts, multi_class, post_transform; точные типы и длины |
| Смысл бинарного выхода | Labels [0,1], multi_class=0, LOGISTIC; противоположные две строки coefficients и два intercepts |
| Параметры | Абсолютное значение не больше 1e6; NaN/Infinity не допускаются |
| Дополнительные структуры | Нет initializers, sparse tensors, external data, functions, training info, quantization annotations, device configs, overloads или неизвестных protobuf-полей |
| После исполнения | Два outputs; integer labels 0/1, конечная матрица probabilities Nx2 в [0,1], сумма строки 1 с atol=1e-6 |
| Согласованность | Вне epsilon=1e-5 вокруг 0.5 label соответствует probability положительного класса; внутри epsilon допускается любой бинарный label |

Pinned exporter действительно пишет повторную идентичную standard-opset declaration. Она допустима; конфликтующая версия или дополнительный domain отвергаются. Не привязываемся к косметическим именам узлов, но проверяем связи. Cast, иной классификатор или inline unused tensor требуют отдельно рассмотренного изменения профиля, а не тихого расширения allowlist.

Последовательность: bounded bytes -> parser -> структура/interface/параметры/unknown fields -> ONNX checker full_check -> ORT CPU session -> bounded features -> проверка обоих outputs. Inspector не загружает external tensor files. ORT получает исходные проверенные bytes, а не повторно прочитанный путь или автоматически исправленную модель. Ошибка runtime превращается в фиксированный Rejected без приватного exception text.

## Проверки и границы evidence

Новый suite сначала выявил 31 failure и 5 errors в 14 test methods. Это controlled assertions на отсутствующие проверки и обработку ошибок, **не 31 обнаруженная production-уязвимость**. Отдельный regression показал, что добавленное неизвестное protobuf-поле принималось; теперь оно отвергается. Итоговый suite: 18 methods, 89 statements и 26 branches model.py, 100% coverage.

Положительный тест реально обучает baseline, экспортирует модель и исполняет её в CPU ORT на 1000 фиксированных synthetic golden rows. Проверяет max absolute Python/ONNX difference <=1e-5 и совпадение classes вне epsilon. Negative tests подменяют ORT constructor spy и подтверждают, что неподдерживаемый graph не доходит до создания session. Это доказательство порядка вызовов в Python, не доказательство отсутствия ошибок native parser.

Runtime-error/output-error случаи инъецированы контролируемо. Native developer qualification отдельно выполняет три свежих обучения в ограниченных workers. Результаты, source fingerprint, image digest и проверенный CI фиксируются в [STATUS](../STATUS.md); один exit 0 не заменяет сверку report/subject. [Workflow](../.github/workflows/runtime.yml) запускает suite и требует 100% coverage именно этого модуля.

`prediction_protocol.validate_scan` требует v2 и ровно два inspected nodes. Старые подписанные v1 reports не редактируются и не признаются свежими v2 reports. После source change нужно пересобрать worker и штатно получить новый candidate/evaluation. Нельзя переподписывать старый JSON вручную ради pass.

## Что остаётся незавершённым

- Full M09: отдельная frozen evasion campaign, заданный budget и recall-drop threshold, OOD/abstain и полная gate orchestration.
- Full M21: полный intake/conversion coverage, path/symlink/mutation cases, привязанные timeout/crash diagnostics и support matrix. Текущий scan receipt не является самостоятельным security approval.
- Модель с корректной структурой может быть poisoned. Положительный structural scan не отменяет обнаруженные robustness failures или image CVEs.
- 100% coverage не доказывает отсутствие уязвимостей; parser/native runtime остаются внутри изолированного worker и входят в threat model. Этот increment не добавляет serving activation или production release.

## Основания

Сверено 2026-10-11: [ONNX checker](https://onnx.ai/onnx/api/checker.html) проверяет consistency, full_check включает shape inference, но не наш бизнес-контракт labels. [LinearClassifier](https://onnx.ai/onnx/operators/onnx_aionnxml_LinearClassifier.html) задаёт типы attributes и варианты преобразования scores; выбранный LOGISTIC и противоположные coefficients - ограничение нашего exporter profile. [Scaler](https://onnx.ai/onnx/operators/onnx_aionnxml_Scaler.html) задаёт offset/scale; точная длина 6 здесь application policy. [External Data](https://onnx.ai/onnx/repo-docs/ExternalData.html) описывает внешний storage, который этот профиль запрещает. [Protobuf Message](https://googleapis.dev/python/protobuf/latest/google/protobuf/message.html) определяет рекурсивное DiscardUnknownFields; мы сравниваем deterministic serialization до/после и отклоняем различие.

Онлайн ONNX docs сейчас помечены 1.24.0, protobuf docs - 4.21.1. Это не версии нашего runtime: установленный ONNX 1.23.2, ORT 1.30.0, skl2onnx 1.20.0 и зависимости зафиксированы в uv.lock. Реальные schemas установленного ONNX и поведение установленного protobuf проверены локально; автоматического обновления пакетов не было.
