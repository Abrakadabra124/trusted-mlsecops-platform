# PostgreSQL: проверяемые identities и append-only objects

## Результат и границы

Четвёртый increment R1 добавляет PostgreSQL 18.6, взаимную TLS-аутентификацию, шесть SQL identities, девять классов объектов, versioned migration и 367 component checks. Следующий slice подключает реальные training/evaluation reads/writes через ограниченные credentials и добавляет 26 integration checks. [M03](integrity-gate.md) объединяет их с integrity fixtures и сквозным сравнением hashes. Это не полная приёмка M04/M20: оркестратор пока сохраняет host-admin доступ. Старый developer demo хранит артефакты в host filesystem и остаётся отдельным preview path.

PostgreSQL - реляционная база данных. Здесь она хранит небольшие lab artifacts как `bytea` и проверяет размер и SHA-256 непосредственно при записи. mTLS (mutual Transport Layer Security) проверяет сертификат сервера и клиента; сервер дополнительно сопоставляет Common Name сертификата с SQL login. Psycopg 3.3.6 - Python-драйвер, который передаёт значения через SQL parameters, а не вставляет входные bytes в текст запроса.

Решение и ограничения выбора: [ADR 0006](decisions/0006-role-isolated-storage.md). Это не S3-платформа для больших datasets и не WORM storage, защищённое от администратора.

## Воспроизведение

Требуются Docker Linux/amd64, uv, Python 3.12.15, минимум 8 GiB свободного диска и свободный loopback port 15439. PostgreSQL получает 1 CPU, 512 MiB RAM, 64 PID; при повторном запуске сохраняет volume, container identity и сертификаты. Для собственного bootstrap создаются только ресурсы с workspace labels.

```bash
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops.storage_bootstrap
uv run --locked python -m mlsecops.storage_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.storage_pipeline
uv run --locked python -m mlsecops.storage_pipeline_qualification
```

Повтор bootstrap без изменения идентичности входит в qualification. `--port` задаётся только при первоначальном создании. Порт проверяется настоящим bind, затем проверяются фактический Docker port mapping и SQL connection; одного успешного `docker create` недостаточно.

Отчёты самостоятельных component CLIs: `.runtime/evidence/storage-bootstrap.json`, `.runtime/evidence/storage-qualification.json`, `.runtime/evidence/storage-pipeline-qualification.json`, demo refs - `.runtime/storage-demo.json`. CI [storage.yml](../.github/workflows/storage.yml) теперь вызывает весь M03 и сохраняет `.runtime/evidence/M03.json` с component hashes. Private keys, certificates, DB bytes и raw connection errors в Git/CI output не публикуются.

## Права и данные

| Table | INSERT + SELECT | Дополнительный SELECT |
| --- | --- | --- |
| quarantine | ingestor | curator |
| train, validation | curator | publisher |
| holdout | curator | scorer |
| manifests, lineage | curator | publisher, scorer |
| candidates | publisher | scorer, promoter |
| evaluations | scorer | promoter |
| releases | promoter | serving |

Таблицами владеет `ml_owner` с NOLOGIN. Runtime identities не входят в owner/admin roles, не могут создавать schema/role, читать server files или выполнять OS commands. INSERT ограничен столбцами `sha256` и `payload`, timestamp задаёт сервер. UPDATE, DELETE и TRUNCATE запрещены всем runtime identities. Повтор одинаковой вставки не заменяет объект; клиент повторно читает и сравнивает bytes. SHA-256 constraint и предел 50 MiB действуют и при обходе Python API прямым SQL.

Разные таблицы не означают разные tenants: это single-workspace lab, без row-level tenant isolation. Hash доказывает согласованность bytes, но не полезность модели, отсутствие poisoning или право на release. Для каждого артефакта по-прежнему необходимы отдельная подпись, policy и проверка provenance.

## Bootstrap и trust

1. Проверяется workspace marker; для новой установки создаётся отдельный CA, не переиспользуются DSSE signing keys.
2. CA имеет срок 365 дней, server/client certificates - 90 дней. Ключи ECDSA P-256 создаёт cryptography. Существующая PKI проверяется, незаметная rotation запрещена; частично записанное состояние требует явного recovery.
3. Пин official PostgreSQL image: `sha256:9551dd5bf356409a21b31248f49b33bba9bb1877365f3a7e933aecd9af3cf52d`. Offline helper с единственной дополнительной capability CHOWN подготавливает **только новый собственный volume**. Runtime работает как UID/GID 999, readonly root, без capabilities и privilege escalation. Docker socket в него не передаётся.
4. Сервер принимает только TLS 1.3 и сертификаты разрешённых runtime roles. Административный доступ возможен только через Unix peer внутри owned container. CA private key и client keys в БД не копируются.
5. Migration 1 создаёт ACL и CHECK constraints в transaction. Её checksum сохраняется в самой БД; повтор с несовпадающей историей отклоняется. Изменение SQL требует новой миграции, а не редактирования применённой версии.
6. Каждый runtime получает отдельный credential directory `.runtime/storage-clients/<role>` с одним client key, двумя public certificates и connection descriptor. Сам Python storage client не вызывает Docker и не читает остальные role keys. Host bootstrap всё ещё управляет всеми identities, поэтому это не независимые администраторы.

Контейнер публикует только `127.0.0.1:15439`. Его отдельная bridge network не запрещает исходящий трафик БД. Worker network isolation этим не заменяется. В production нужны reviewed network policies, внешний lifecycle сертификатов/ключей и независимые операционные роли. На Windows POSIX mode 0600 не доказывает NTFS isolation; private files остаются в доверенном user workspace.

## Что проверяет qualification

367 сценариев проверены локально: повтор bootstrap; identity и TLS у каждой роли; вся матрица SELECT/INSERT/UPDATE/DELETE/TRUNCATE; owner/admin impersonation, DDL, чтение server files и OS execution; неправильный digest, пустой/слишком большой payload, invalid ID и попытка подделать timestamp. TLS negatives включают plaintext, другой hostname, чужой CA сервера/клиента, отсутствие client certificate, истёкший certificate, чужую роль, admin TCP login и доступ к другой БД.

SQL denials принимаются только с ожидаемым SQLSTATE `42501`, CHECK denials - `23514`. Timeout или недоступный сервер не считаются успешным authentication negative. После отказов повторяется positive control и проверяются исходные bytes. Потенциально изменяющие SQL probes выполняются в rollback-only transactions. Временные fixture objects удаляются bootstrap-admin только по точному случайному run ID/content digest, не через очистку таблиц. Не запускать qualification параллельно с обслуживанием пользователей: TRUNCATE probe при ошибочно выданном праве мог бы кратковременно удержать lock до rollback.

## Ограничения и следующий этап

- Новый SQL path использует ограниченные credentials, но curator staging, CA и orchestration остаются под общим host administrator. Это ещё не раздельные OS identities controllers. Старый filesystem path не получает SQL ACL автоматически.
- Нет автоматической rotation/CRL, HA, внешнего KMS или независимого reviewer. [SQL backup/restore](storage-recovery.md) проверен компонентно; полный release/serving recovery M17 ещё не принят.
- Предел bytes на один объект не ограничивает суммарное заполнение volume. Container memory/CPU/PID limits не доказывают доступность БД при злоупотреблении SQL. Statement timeout - default для trusted clients, не неотменяемая квота атакующего SQL role.
- Dependency audit после добавления Psycopg не нашёл известных Python vulnerabilities. Это не image/OS scan и не доказательство отсутствия всех уязвимостей. Binary Psycopg выбран для одинаковой установки Windows/Linux; его bundled libpq/OpenSSL требуют отдельного контроля обновлений. Production может предпочесть C build с системными libraries.
- Не удалять volume или PKI для «починки» startup. При missing/foreign ресурсе bootstrap отказывает; восстановление должно сохранять ownership и проверять evidence, не переиспользовать чужую БД.

Следующий проверяемый этап - убрать широкие credentials у controllers, добавить независимый scorer/query budget, persistent audit и полный release recovery. M03 проверяет integrity и SQL roles; полнота M04/M20 ещё не достигнута.

## Реальный SQL pipeline

Curator сначала проверяет M02 data path, подписанный manifest и полную lineage, затем ingestor сохраняет synthetic source в quarantine. Curator читает эти bytes через свою SQL identity, проверяет связь с source digest, публикует split objects, подписанные metadata и последним - signed dataset index. Hash index служит точкой входа; произвольный SQL object сам по себе не считается approved dataset.

Publisher читает только signed manifests/lineage и train/validation, проверяет pinned curator public key, актуальный source approval digest, expiry и policy. Он передаёт train и validation features в offline worker, проверяет bounded output и сохраняет модель/run metadata/scores в candidates. Scorer читает candidate и holdout, но не train; prediction worker получает только features, без holdout labels и SQL credentials. Scorer подписывает report, дополнительно связанный с точными candidate reference, dataset reference и lineage ID, и записывает его в evaluations.

Publisher и scorer больше не вызывают full-dataset verifier, который открывал все три split. Общая проверка подписи/schema отделена от чтения bytes; curator сохраняет ответственность за полную cross-split проверку. Подпись curator - явная доверительная граница, не обещание, что consumer без holdout может независимо пересчитать весь исходный dataset.

26 integration checks подтверждают actual read-table scopes, AUPRC/parity, signed report bindings, stale source, missing objects, неверного signer, подмену подписанного index, перепутанные dataset/lineage/source ссылки, SQL denials и single-byte mutation модели. Подмена candidate metadata останавливается до запуска prediction worker. Локальный результат: AUPRC `0.9323007296445032`, baseline `0.4073333333333333`, parity max error `2.086162567138672e-7`, release остаётся `unapproved`. Known synthetic generator не обеспечивает секретности labels и не доказывает бизнес-utility.

При уже поднятом собственном kind можно выбрать `python -m mlsecops.storage_pipeline --backend kubernetes`. Этот SQL demo также выполнен локально, training/prediction Jobs завершились успешно с теми же AUPRC/parity; qualification CLI из 26 checks измеряет Docker profile. Это не межпрофильное сравнение всех probability vectors. Ни одному worker не передаются DB certificates или signing keys.

## Первоисточники

[PostgreSQL certificate authentication](https://www.postgresql.org/docs/18/auth-cert.html), [TLS configuration](https://www.postgresql.org/docs/18/ssl-tcp.html) и [privileges](https://www.postgresql.org/docs/18/ddl-priv.html) обосновывают CN matching, проверку сервера и разделение владельца/доступов. [Psycopg installation](https://www.psycopg.org/psycopg3/docs/basic/install.html) описывает trade-off binary/C builds. [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/) обосновывает loopback bind; фактическую доступность всё равно проверяет runtime probe.
