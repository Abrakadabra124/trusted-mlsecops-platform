# ADR 0036: bounded private audit journal

Дата: 2026-10-15. Статус: core implementation, HTTP integration pending. Scope: T16, не полный M13/M23. [RB-55/PB-29](../operations/serving-audit-troubleshooting.md), [evidence](../evidence/serving-audit-2026-10-15.md).

## Вопросы оператора и границы

Нужно различать: событие принято в очередь или подтверждено записью; закрыт writer или ещё выполняет I/O; был ли потерян audit; к какому проверенному release относится запрос. Этот increment реализует storage/lifecycle первых трёх вопросов. Четвёртый требует последующей привязки к настоящему Engine и ASGI (Asynchronous Server Gateway Interface), не только проверки формы hash.

Один процесс и доверенный host administrator. Worker не получает journal API, файловый дескриптор или путь. Сам модуль ещё не подключён к HTTP endpoints. Поэтому `healthy=false` сейчас является контрактом компонента, а не уже действующим отказом serving. M13 остаётся inconclusive, существующие release gates не обходятся.

## Событие и приватность

Доверенный producer передаёт ровно `request_id`, `principal_id`, `route`, `stage`, `status`, `release`. IDs имеют bounded hex-формат; route только predict/ready/live/other. Stage различает request_started, response_started, response_completed и aborted; status отсутствует до response start. Для успешного predict/ready требуется principal и release context. Private release context содержит selection/bundle/model SHA-256; он предназначен для разрешения цепочки в trusted metadata, но модуль не проверяет криптографическую подлинность этих ссылок.

Producer обязан генерировать request ID на стороне сервера и брать principal только из проверенной allowlist. Нельзя передавать client-supplied trace IDs. В файле нет полей для URL, IP, headers, token, body, features, scores, traceback или hash входных значений. Валидатор создаёт собственные fixed-field snapshots и проверяет их значения; мутация исходного объекта не добавляет поле при сериализации. Это data minimization, не differential privacy и не защита от злонамеренного доверенного producer, способного закодировать данные в разрешённом поле.

Envelope добавляет schema_version=1, sequence и recorded_at_ns. Sequence назначается вместе с enqueue под admission lock. Clock rollback/некорректный sample и переполнение sequence дают sticky failure. Временная отметка относится к приёму события, не доказывает время сетевой доставки.

## Ресурсы, durability и lifecycle

- Один новый абсолютный путь, existing file не перезаписывается и не дополняется. POSIX: parent открывается с O_DIRECTORY/O_NOFOLLOW, owner/mode проверяются через fstat, файл создаётся относительно того же dir_fd с O_EXCL/0600; parent fsync фиксирует создание. Windows: binary mode, ACL приватного каталога проверяет оператор.
- Event <=2 KiB; максимум 64 pending, включая выполняющийся write; максимум 16 MiB суммарно зарезервированных bytes. Значения можно уменьшить, но не увеличить выше этих границ. При достижении cap запись не считается принятой.
- `emit` не выполняет disk I/O. Он возвращает sequence принятой записи, **не durable acknowledgment**. Единственный writer завершает short writes и вызывает fsync для каждой строки. Только затем растут durable/durable_bytes.
- Очередь, invalid trusted event, clock или filesystem failure переводят health в sticky failed. Уже принятые записи при producer-side failure дренируются, если диск исправен; после sink failure остаток становится unconfirmed. Неизвестные exception messages не попадают в status или файл.
- `start` сохраняет thread handle до dispatch. Start/construction failure не допускает повторного запуска объекта; pending worker остаётся owned. `close` закрывает admission до join, timeout 0-5 s не освобождает ресурсы живого writer. Успех разрешён только после подтверждённого закрытия и accepted==durable, без прежнего failure.
- Неверный close timeout также делает failure sticky. Большие integers проверяются без float conversion; исправленный аргумент позволяет drain/close, но не превращает прежний failure в успешную qualification.
- Queue.Empty не доказывает пустую очередь к моменту закрытия: stop decision повторно проверяет pending под тем же lock. Иначе возможна потеря только что принятой записи с ложным успешным close.

fsync подтверждает ответ ОС, не multi-node replication или честность дискового контроллера. Сбой fsync может оставить полную строку на диске, но durable count не увеличивается; такая запись остаётся unconfirmed. Не следует автоматически replay-ить или считать её отсутствующей. Файл не подписан и не защищён от trusted host-admin modification. Нельзя называть его non-repudiation ledger.

На Windows `healthy=true` не является доказательством приватного ACL: это только здоровье writer при выполненном операторском prerequisite. Неприватный inherited ACL делает использование недопустимым, даже если все writes успешны. Машинная проверка ACL и native privacy qualification остаются отдельной незакрытой работой; POSIX enforcement не переносится на Windows по аналогии.

## Retention и последующая интеграция

Hard byte cap уже действует; **time-based retention, rotation, purge и restart resume не реализованы**. Journal сохраняет файл после close/failure и никогда сам его не удаляет. Это намеренный промежуточный предел, не готовая политика круглосуточного serving. При высокой нагрузке 16 MiB быстро исчерпываются; безопасную ротацию и общий storage budget нужно квалифицировать до включения журнала как обязательной production-подобной зависимости endpoint.

Следующий обязательный slice: owned segment lifecycle/retention, ASGI observer фактического response start/completion/abort, immutable verified release correlation, ограниченный overload/sink-failure отказ без продления trust deadline и минимальная безопасная export schema. Нельзя писать 200 в audit до последней проверки generation/lease. `response_completed` означает завершение server-side send, не подтверждение получения клиентом. Anonymous flood не должен превращать глобальную telemetry queue в неограниченный DoS механизм; это отдельный admission/retention тест перед M13.

Canaries должны пройти настоящие headers/query/path/body/exception paths и все подключённые logs/metrics/traces, не только этот валидатор. Private IDs/release refs не экспортируются как metric labels. Audit core tests не принимают M13 и не закрывают T16.

## Альтернативы и источники

Выбраны стандартные queue/thread/file primitives без нового сетевого сервиса. Прямой fsync в HTTP handler может задержать отказ у истечения trust lease. Обычный асинхронный logging handler сам по себе не предоставляет нужный контракт accepted/durable/unconfirmed и sticky failure. Удаление старых файлов по glob без ownership/retention evidence исключено.

- [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): минимизация sensitive fields, ограниченные события и проверки logging failures. OWASP отдельно предупреждает о DoS через logging; окончательная endpoint failure policy не выводится из одного filesystem test.
- [OpenTelemetry sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/): не собирать лишнее; hash угадываемого идентификатора не означает анонимизацию. Collector здесь не установлен.
- [Python os](https://docs.python.org/3.12/library/os.html): fd-relative operations, explicit binary flags, write/fsync. [QueueHandler](https://docs.python.org/3.12/library/logging.handlers.html#logging.handlers.QueueHandler) описывает очереди обычного logging, не приёмку этого журнала.

Первичные источники проверены 2026-10-15. Конкретные bounds являются политикой этого lab, не отраслевым нормативом.
