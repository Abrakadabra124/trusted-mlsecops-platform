# Приватный шифрованный перенос между заданиями

Неделя 13, T21: обязательная предпосылка параллельной CI-проверки одного
кандидата. CI (continuous integration) здесь означает автоматические проверки
изменений. Этот компонент предоставляет только операции над байтами в памяти.
Workflow, M23 integration, frozen-candidate exporter и публичную классификацию
подключают их владельцы отдельно. Общая T21/M18-приёмка этим не закрыта.

## Контракт

[Модуль](../../mlsecops/ci_transfer.py) использует закрепленный
`cryptography==50.0.2`, AES-256-GCM: стандартное шифрование с проверкой
аутентичности. Вызывающий код передает 32-байтовый ключ. Каждый `seal` берет
новый 12-байтовый nonce из генератора ОС; аргумента для повторного nonce нет.
Самодельной криптографии, создания ключей, файлового или сетевого ввода-вывода,
командного интерфейса переноса и публикации в модуле нет.

```python
envelope = seal(payload, key=key, context=trusted_context)
payload = open(
    envelope,
    key=key,
    expected_context=independently_expected_context,
    expected_ciphertext_sha256=trusted_envelope_sha256,
)
```

`seal` и `open` возвращают `bytes`. SHA-256 вычисляется по **всему** конверту,
включая magic/version, nonce, ciphertext и tag. Внешний pin обязателен даже
при верных ключе и контексте. Получатель не должен брать pin или ожидаемый
контекст из скачанного конверта либо неконтролируемого соседнего manifest.

Контекст - обычный `dict` ровно с этими 13 полями. Подклассы типов, `bool`
вместо `int`, дополнительные/отсутствующие поля и неканонические значения
отклоняются. Вызывающий код выбирает ожидаемый phase до чтения конверта.

| Поля | Требование |
| --- | --- |
| `repository` | Фактический execution repo: ровно `Abrakadabra124/trusted-mlsecops-platform` или `Abrakadabra124/trusted-mlsecops-ci-private`, с указанным регистром |
| `run_id`, `run_attempt` | Исходные run/attempt, целые от 1 до `2**53-1` |
| `source_revision` | Полный commit SHA, 40 lowercase hex символов |
| `source_fingerprint` | 64 lowercase hex символа |
| `image_id` | Ровно `sha256:` и 64 lowercase hex символа; не tag |
| `candidate_sha256`, `proposal_sha256`, `payload_sha256` | По 64 lowercase hex символа; последний хеширует переданные plaintext bytes |
| `phase` | 1-64 ASCII символа; первый alphanumeric, остальные alphanumeric, `.`, `_`, `-` |
| `purpose` | Только `candidate` или `evidence` |
| `issued_at`, `expires_at` | UTC Unix seconds, целые от 0 до `2**53-1` |

AAD (additional authenticated data) - аутентифицируемый контекст, который не
шифруется вместе с payload. Здесь он вообще не помещается в конверт:
`b"MLSCIT\x01\x00" + canonical(context)`. Canonical JSON сортирует ключи,
использует separators `(',', ':')`, ASCII escaping и запрещает NaN.
Формат конверта: `b"MLSCIT\x01" | nonce[12] | ciphertext | tag[16]`.
Любой другой header/version отклоняется. Контекст получатель передает независимо.

## Source identity и execution repository

`REPOSITORY` сохраняет прежнее публичное имя для совместимости существующих
callers. `PRIVATE_REPOSITORY` задает точное приватное имя, а неизменяемая
`EXECUTION_REPOSITORIES` содержит только эти два значения. Принимается только
обычный `str`: подклассы, другие repositories, иной регистр и пробелы отклоняются.
Членство в allowlist не делает repositories взаимозаменяемыми: точное имя входит
в AAD. Public ciphertext с private expectation и обратная подмена дают
`ci_transfer_authentication` даже при правильных ключе и внешнем ciphertext pin.
Схема контекста, canonical AAD и wire format не изменены.

Публичный source origin остается `Abrakadabra124/trusted-mlsecops-platform`.
`repository` обозначает владельца фактического запуска, а `source_revision` и
`source_fingerprint` связывают исходники. Для будущего private canary требуется
точное зеркало публичного Git DAG с тем же commit SHA. Перед шифрованием будущий
hosted driver должен проверить live GitHub metadata: private visibility,
repository ID `1465012664`, точное имя, публикацию утвержденного source commit
в публичном origin и совпадение текущего checkout с фактическим `GITHUB_SHA`.
Подмена `GITHUB_REPOSITORY` или `GITHUB_SHA` недопустима. Core не обращается к
GitHub и сам не удостоверяет эти свойства.

Этот срез добавляет только core-предпосылку private AES canary. Workflow,
live guard, secrets, cross-job upload/download и cleanup здесь не реализованы;
candidate/M18 acceptance не заявляется. Пять original-candidate callers пока
сохраняют public-only ограничения. Их отдельная будущая интеграция затрагивает:

- [ci_candidate_transfer._authority](../../scripts/ci_candidate_transfer.py);
- [ci_consumer_native.run_owner](../../scripts/ci_consumer_native.py);
- [ci_serving_recovery.binding](../../scripts/ci_serving_recovery.py);
- [ci_validation_transfer.retain](../../scripts/ci_validation_transfer.py);
- [consumer_candidate_storage.import_candidate](../../scripts/consumer_candidate_storage.py).

## Сроки, лимиты и обязательные внутренние проверки

- `issued_at <= now < expires_at` проверяется до криптооперации и перед
  возвратом результата. TTL (time to live) положителен: максимум 1800 секунд
  для `candidate`, 86400 секунд для `evidence`; grace period нет.
- Production-вызовы опускают `clock` и используют фактическое UTC-время ОС.
  `clock` предназначен только для автономных тестов; это доверенная функция,
  возвращающая целые Unix seconds. Ее отказ или неверный тип блокируют операцию.
- Plaintext ограничен 256 MiB. Конверт ограничен 256 MiB + 35 байт. Слишком
  большой вход отклоняется до хеширования/криптооперации. API принимает уже
  выделенные bytes; будущий downloader обязан ограничивать чтение до выделения
  памяти. AESGCM обрабатывает вход целиком, поэтому peak memory выше размера payload.
- После `open` обязателен frozen-package reader с исходными лимитами внутренних
  пакетов, проверками signatures, candidate/proposal/source/image binding и
  настоящего исходного proposal expiry. Транспорт эти лимиты не увеличивает,
  proposal не переподписывает и не продлевает. `evidence` TTL не оживляет
  истекший proposal. Успешная расшифровка не дает release/promotion permission.
- Контекст изолирует разные runs, attempts, phases и candidates. Повторный
  `open` тех же байтов в том же допустимом окне возможен: это не журнал
  одноразового использования. Replay/idempotency policy остается у интегратора.

## Приватность и действия при отказе

**Весь конверт остается private**, включая header, nonce и ciphertext. Сам
факт шифрования не разрешает публичный artifact/upload. Ожидаемый контекст,
plaintext и его hashes также не становятся разрешенным публичным evidence.
Ключи никогда не помещаются в репозиторий, logs, job outputs или artifacts.
Shared symmetric key подтверждает владение ключом, не независимую identity
издателя. Его доставка, доступ, ротация и lifetime остаются обязанностью
интегратора; случайный nonce не заменяет управление ключами.

Ответственный за handoff останавливает потребителя при любом `Rejected`.
Разрешены только фиксированные диагностические labels:
`ci_transfer_key`, `ci_transfer_context`, `ci_transfer_payload`,
`ci_transfer_envelope`, `ci_transfer_pin`, `ci_transfer_payload_digest`,
`ci_transfer_authentication`, `ci_transfer_clock`, `ci_transfer_time`,
`ci_transfer_random`. `InvalidTag` преобразуется в фиксированный отказ без
отображения исходной причины. Не логировать аргументы, locals traceback,
ключи, контекст, plaintext или конверт при диагностике.

При pin/context/authentication mismatch сверить независимо доверенные
ожидания и owned source; не принимать новые ожидания из отказавшего пакета.
При expiry проверить фактическое время и исходное разрешение, затем остановить
истекшую попытку. Не сдвигать timestamps ради повторного запуска. Для безопасного
отката отключить потребителя до исправления, сохранив приватные материалы в
разрешенном контуре. Не переходить к незашифрованному handoff. Ошибки clock,
источника случайности или доверенного pin требуют эскалации владельцу pipeline.

## Локальная квалификация и границы результата

[Тесты](../../scripts/ci_transfer_qualification.py) используют только публичный
детерминированный fixture key и синтетические bytes, не создают реальных ключей
и не записывают payload на диск. В окружении Python 3.12 с закрепленными зависимостями:

```text
python -B -m unittest scripts.ci_transfer_qualification
python -B -m ruff check --no-cache mlsecops/ci_transfer.py scripts/ci_transfer_qualification.py
python -B scripts/check_docs.py
```

Проверяются отказы по каждому binding, закрытая схема, tamper каждого байта
nonce/ciphertext/tag, внешний pin, неверный ключ, будущие/истекшие timestamps,
отказ clock/random, повторная проверка времени, размеры и свежие nonce.
Отдельная проверка стандартным AESGCM читает wire format и canonical AAD.
Порог покрытия production-модуля: минимум 95% statements и 95% branches
**отдельно**, не общий комбинированный процент.

Проверка 2026-11-14: 32 tests, 0 skips; модуль 100/100 statements и 42/42
branches, оба показателя 100%, без coverage exclusions. Python 3.12.15,
cryptography 50.0.2, coverage 7.16.2. Coverage собирался в памяти без файлов
payload/report. Родительский `.venv` launcher указывал на отсутствующий старый
путь Python; использован существующий Python 3.12.15 с библиотеками этой `.venv`
через process-local `PYTHONPATH`, без установки или изменения окружения проекта.

Проверка allowlist 2026-11-20: прежние 32 и 5 новых tests, всего 37 pass,
0 skips. Private roundtrip, подмена public/private в обоих направлениях с
ожидаемым authentication failure, чужие имена, case drift и подклассы `str`
проверены реальными `seal`/`open`. До правки core новые private сценарии дали
RED: 1 failure и 2 errors с `ci_transfer_context`. После правки coverage в памяти:
102/102 statements и 42/42 branches, оба 100%, exclusions 0; те же версии
Python/cryptography/coverage. Ruff check и format check прошли. Hosted canary
и original-candidate callers в этот результат не входят.

Это только offline component qualification. GitHub configuration, доставка
ключей, live encrypted handoff, CI-запуск и приватная передача между jobs здесь
**еще не доказаны**. Пока эти предпосылки не реализованы и проверены владельцем
pipeline, private evidence не должен пересекать задания.
