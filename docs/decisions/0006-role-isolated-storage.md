# ADR 0006: PostgreSQL как локальное role-isolated storage

Дата: 2026-10-07. Статус: storage component реализован, 367 локальных checks прошли; интеграция с pipeline и полный M03/M04 ещё не выполнены. [Runbook](../storage-lab.md).

## Требование и ресурсы

M03/M04 требуют реального запрета записи approved objects и чтения чужих datasets, а не разных имён directories. T08 также требует отдельной metadata DB. Read-only inventory: Docker располагает 31.3 GiB RAM, собственный kind занимает примерно 1.44 GiB при лимите 12 GiB, на C: около 33 GiB свободно. Новый PostgreSQL ограничивается 1 CPU/512 MiB, без платного сервиса и без изменения чужих PostgreSQL containers.

## Решение

Использовать отдельный PostgreSQL 18.6, official image с immutable linux/amd64 digest. Не обновлять и не переиспользовать базы других проектов. Persistent Docker volume и отдельная bridge network имеют workspace ownership labels; TCP публикуется только на loopback. Production-подобные свойства - mTLS, реальные SQL identities/GRANT, append-only objects для runtime ролей, versioned migrations, backup/restore - важнее переноса ещё одного metadata control plane в kind.

Маленькие lab artifacts допускается хранить в отдельных таблицах как bounded bytea с SHA-256 constraint. Для 2 MB synthetic source и малой ONNX модели это устраняет неподтверждённый S3 backend. Это не рекомендация хранить большие ML datasets в PostgreSQL: для production объёмов нужен object store с отдельными identities и проверкой retention/immutability. DB backups должны учитывать все blobs; размер и resource exhaustion проверяются отдельно.

Planned роли: ingestor пишет только quarantine; curator публикует approved train/holdout/manifests; publisher читает train/validation и пишет candidates; scorer читает holdout/candidates и пишет evaluations; promoter пишет releases; serving читает releases. Таблицами владеет NOLOGIN owner, обычные runtime роли не получают UPDATE/DELETE/TRUNCATE/DDL/role administration. Worker credentials не выдаются: approved input продолжает поступать через bounded protocol.

TLS использует отдельный локальный CA, server/client certificates, проверку hostname и client identity. Bootstrap administrator отделён от application roles, не передаётся worker. Сертификаты и приватные ключи остаются в ignored state. Это не внешний KMS и не защита от Docker/host administrator. Renewal требует явного контролируемого действия.

## Этапность и риски

1. Идемпотентный TLS bootstrap без потери keys/data, проверка чужого CA/hostname/client identity и запрета plaintext.
2. Schema/roles и реальные allow/deny операции, immutable content, повтор migrations, восстановление.
3. Переключение настоящих curator/publisher/scorer reads/writes на role-restricted backend. До этого отдельные storage probes не объявляются полным M03/M04 pass.
4. Отдельная MLflow metadata database и restricted publisher; никакого model autoload из registry.

Пока не измерены latency, restore, resource exhaustion и container vulnerabilities, соответствующие gates остаются inconclusive. Single host/volume не дают HA или offsite recovery. Перед каждым новым сервисом повторяется headroom inventory.

## Уточнение после runtime проверки

На Docker Desktop 4.91.0 / Engine 29.8.0 сеть `--internal` сохранила requested PortBindings, но фактический `NetworkSettings.Ports` содержал пустой список и host connection отклонялась. Нельзя считать CLI flag доказательством работающего loopback endpoint. Для этого increment выбрана отдельная обычная bridge network с bind `127.0.0.1:15439`, проверяемым mTLS и SQL ACL, без нового TCP proxy. Исходящий трафик DB container этим решением **не запрещён**. Untrusted workers по-прежнему offline; выдача им DB credentials запрещена. Это ограничение trusted control-plane storage, не ослабление worker policy и не полный M04 pass. При переносе controllers с host понадобятся отдельный reviewed network path и проверяемая egress policy.

Порт 54329 попал в Windows excluded range; добавлена настоящая проверка bind до создания ресурсов. При смене сети сохранены прежние database volume, CA и container identity; внешний PostgreSQL и глобальные настройки Docker не менялись.

## Основания

[PostgreSQL privileges](https://www.postgresql.org/docs/18/ddl-priv.html) позволяют отделить владение объектами от runtime grants. [Certificate authentication](https://www.postgresql.org/docs/18/auth-cert.html) связывает проверенный certificate с DB identity; клиент всё равно обязан проверить сервер. [Versioning policy](https://www.postgresql.org/support/versioning/) использована для выбора поддерживаемого minor release. Конкретное применение bytea в малом lab - проектный trade-off, не рекомендация PostgreSQL для любых ML datasets.
