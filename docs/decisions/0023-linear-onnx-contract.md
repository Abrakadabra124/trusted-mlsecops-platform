# ADR-0023: Явный контракт выбранного ONNX baseline

Дата: 2026-10-11. Статус: **Accepted для компонента T12/T27**, не приёмка M09/M21.

## Контекст

R1 уже выбрал StandardScaler + бинарную LogisticRegression. Старый scanner ограничивал operator names и число узлов, но не доказывал соответствие этой архитектуре. Controlled tests воспроизвели принятие поменянных labels, неконечных параметров и графа, обходящего Scaler. Проверка одного столбца probabilities не замечала противоречивый второй столбец/labels.

## Решение

Ввести linear-onnx-v2: точная связность двух узлов, shapes/types, versions, attributes, finite bounded parameters и semantics binary output. ONNX checker сохраняется как дополнительная проверка стандарта, не заменяет application policy. Отклонять неизвестные protobuf-поля, а не очищать модель с последующим исполнением. Runtime использует те же immutable bytes.

Подробный [контракт и primary sources](../model-contract.md) определяют границы. Код остаётся в существующем model worker. Не добавляем сторонний универсальный scanner, ещё один сервис, pickle loader или новый формат для текущих двух узлов.

## Альтернативы

- Только ONNX checker не фиксирует смысл positive label и нашу выбранную архитектуру.
- Общая operator allowlist допускает нерассмотренные композиции и параметры. Для других model families понадобится versioned profile с собственными отрицательными tests.
- Автоматически исправлять граф, удалять поля или менять output order опасно: scanned и executed artifact перестают совпадать по смыслу/bytes.
- Полностью собственный ONNX parser увеличивает неподдерживаемый код; применяем штатный parser в уже изолированном worker и сохраняем остаточный native-parser риск.

## Последствия и пересмотр

Прежние v1 scan reports не подходят новой policy. Нужны fresh worker/candidate/evaluation, старое evidence сохраняется неизменным. Точный pinned exporter даёт 2-3 opset declarations с допустимым идентичным повтором; dependency upgrade требует повторной проверки этого контракта и parity.

Ограничение профиля соответствует уже выбранному baseline и не сокращает GOAL/M01-M23. Structural validity не заменяет poisoning/evasion testing, release approval или scanner timeout/crash coverage. [PB-12/RB-25/RB-26](../operations/model-contract-troubleshooting.md) запрещает отключать policy ради восстановления.
