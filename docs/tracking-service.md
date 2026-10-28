# Постоянный локальный MLflow с PostgreSQL и TLS

T07/T08 component, 2026-10-11. После [offline spike](tracking-spike.md) появился **реальный постоянный tracking service**. Он хранит три настоящих обучения, metadata и auth в PostgreSQL, artifacts в отдельном volume. Это ещё не полный M06, trusted release или production deployment.

Актуальное продолжение 2026-10-28: [MLflow 3.17.2 на Wolfi и новый pinned PostgreSQL](evidence/cp2-runtime-adoption-2026-10-28.md) прошли 70 native service checks; отдельный M06 прошёл 18 checks с шестью trainings/predictions/tracking runs и нулевой разницей вероятностей. Исторический component scope ниже не подменяет эту отдельную проверку. Recovery, observed system image scope и полный R1 по-прежнему требуют своей приёмки.

## Что работает

```text
offline training workers -> проверенная projection -> host publisher
                                                    |
                                      HTTPS + scoped Basic auth
                                                    |
                                       MLflow 3.17.2 / Uvicorn
                                         |                |
                              mTLS, verify-full       artifact volume
                                         |
                                PostgreSQL 18.6
                                 /             \
                       tracking_metadata    tracking_auth
                       отдельная роль       отдельная роль
```

- **MLflow** хранит runs, параметры, метрики и JSON lineage projections. Ни его tags, ни aliases не одобряют модель и не выбирают production artifact.
- **PostgreSQL** хранит metadata и права в двух databases с разными login roles. Роли не имеют SUPERUSER, CREATEDB, CREATEROLE или REPLICATION; `pg_hba.conf` разрешает каждой только свою БД и клиентский сертификат.
- **TLS** шифрует клиентский HTTP endpoint; CA и hostname проверяются. **mTLS** дополнительно проверяет клиентский сертификат при соединении MLflow с PostgreSQL; `sslmode=verify-full` исключает молчаливое понижение до plaintext или проверки только CA.
- **Uvicorn** обслуживает HTTPS внутри pinned MLflow image, без нового reverse proxy. Для этого lab достаточно native TLS; production edge, SSO и rate limiting не реализованы этим выбором.
- **Docker** разделяет БД, tracking service и offline ML workers. PostgreSQL находится только в internal network без host port. У MLflow есть также отдельная client bridge network, единственный опубликованный порт привязан к `127.0.0.1`. Это не доказательство запрета исходящей сети MLflow: client bridge допускает egress.

## Как устроен запуск

1. `tracking_config` создаёт уникальную lab identity, локальную CA, 30-дневные server/client certificates и случайные API credentials. Их байты и image ID связаны с host-side configuration digest. Секреты сохраняются только в ignored `.runtime/tracking-service/`; host administrator входит в trust boundary.
2. Bootstrap создаёт два owned networks и три volumes: PostgreSQL, read-only configuration для MLflow и writable artifacts. Одноразовый offline root helper с одной capability CHOWN готовит права; постоянные процессы запускаются с UID 999 и 65532, без capabilities и с read-only root filesystem.
3. PostgreSQL инициализируется с checksums. Через локальный peer-authenticated admin channel создаются две БД и две роли. В MLflow не передаётся PostgreSQL superuser credential. CA private key также не копируется в контейнеры.
4. Server читает только собственные TLS/DB certificates и bootstrap admin/CSRF secrets. `NO_PERMISSIONS` установлен явно. Assistant, telemetry и job execution выключены. Passwords не записаны в Docker command line или Docker Config.Env, однако доступны процессу MLflow и доверенному host-admin.
5. После verified HTTPS health bootstrap сравнивает фактические images, container/network identities, resource limits, mounts, port bindings и hashes конфигурации. Повтор `up` сохраняет identities, БД и runs. Подмена или несовместимое обновление image требует отдельной migration, а не автоматического пересоздания.
6. Внешний host harness выполняет три настоящих обучения. Worker не получает MLflow SDK, пароль, сеть или DB certificates. Отдельный HTTP client с identity publisher записывает только allowlisted digests и metrics; reader проверяет их и artifact bytes обратно. Admin client используется только для настройки grants.
7. Qualification останавливает оба сервиса, запускает прежние контейнеры/volumes и повторяет чтение и запреты. Это persistence после restart, **не disaster recovery** и не потеря metadata.

Host harness имеет доступ к нескольким test identities для негативных проверок. Это не независимые production administrators и не интеграция publisher с Kubernetes ServiceAccount. Постоянный MLflow не меняет существующий cluster SQL или исходную DevSecOps-платформу.

## Воспроизведение из checkout

Требуются Linux amd64 Docker Engine, uv 0.12.23 и Python 3.12.15. Docker Desktop с Linux containers поддержан локальной проверкой. Tracking и PostgreSQL ограничены суммарно 2.5 GiB RAM и двумя CPU; дополнительно нужны ресурсы для сборки и training worker. Сеть требуется для первой сборки и загрузки pinned images/dependencies.

```bash
uv sync --locked --python 3.12.15
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.tracking_spike build
uv run --locked python -m scripts.tracking_config_qualification
uv run --locked python -m scripts.tracking_client_qualification
uv run --locked python -m scripts.tracking_service up
uv run --locked python -m scripts.tracking_service_qualification
uv run --locked python -m scripts.tracking_service status
```

Qualification публикует новый experiment с тремя runs, не удаляет предыдущие. Endpoint: `https://127.0.0.1:15445`. `status` проверяет configuration/running state, не заменяет health или повторную qualification. Пользовательские `up --port` допустимы для нового bootstrap; qualification намеренно фиксирует порт 15445 для воспроизводимого профиля.

Проверить TLS без отключения проверки:

```bash
curl --cacert .runtime/tracking-service/ca.crt https://127.0.0.1:15445/health
```

В Windows PowerShell использовать `curl.exe`, чтобы не вызвать одноимённый alias. Для UI нужны доверие **своей** CA и user `reader`; пароль хранится в локальном `credentials.json`. Не импортировать CA автоматически в системное хранилище и не обходить предупреждение браузера. Скриптовый клиент использует scoped CA file, а не глобальные настройки TLS. Не публиковать файл с паролями, raw logs или весь `.runtime`.

Остановка без удаления истории:

```bash
uv run --locked python -m scripts.tracking_service stop
uv run --locked python -m scripts.tracking_service up
```

`stop` повторно проверяет ownership и точные container IDs, сохраняет volumes. Истёкший, но неизменённый certificate запрещает новый `up`, однако не блокирует безопасный `stop`. Автоматической ротации certificates, backup/restore и destructive `down` пока нет. При частичном bootstrap или ownership mismatch скрипт останавливается, не присваивает существующие ресурсы и не выполняет global prune. Для восстановления нужна проверка конкретных owned resources; не удалять рабочие БД ради зелёного теста.

## Проверено локально

Первый полный run: `2026-10-11T10:14:10.004003+00:00`, base commit `16eccf17a8f62bd45385802d06b0650c9bf0d0f6` с незакоммиченным increment. Не clean checkout.

- **70 component checks pass: 54 native и 16 controlled configuration mutation checks.** Native часть включает idempotent bootstrap, HTTPS/CA/hostname, 16 PostgreSQL role/TLS cases, реальные API/artifact запреты, три publications и restart обеих БД/service.
- **74 worker checks pass**, три независимых обучения: AUPRC 0.9323007296445032, max probability difference 0.0, ONNX parity error 2.086162567138672e-7. Это синтетические данные, не business utility.
- Отдельно проходят **13 configuration**, **19 HTTP client**, **27 projection** и **12 spike orchestration contracts**. Эти counts не означают coverage всей платформы или полного API MLflow.
- Tracking image: `sha256:6e55b45cf898b2f60aef1a9eebfb880b0e8b9d1d62c8be7e84fa3a0b0370e949`; recipe materials: `299119e5c4a64507894ef546d0daec96fe88461707d7370b55c9ccec7942ef13`.
- PostgreSQL image: `sha256:9551dd5bf356409a21b31248f49b33bba9bb1877365f3a7e933aecd9af3cf52d`; worker: `sha256:2931ffbe14f0b54d5d3722f8094c9cf18ae20d0c11eec63fa4df9626683081b0`.
- Runtime source fingerprint не изменён: `5c42a8f25bb59fde14446e9864b5c812a26893e9bf5527a2e3ae740c8e7f54e3`. Host scripts и tracking image отделены от worker dependencies.
- Полный private report: `.runtime/evidence/tracking-service.json`. Он сначала становится inconclusive; старый pass не сохраняется при новом незавершённом запуске.

Две ранние bootstrap ошибки не скрыты: chmod после CHOWN без FOWNER был исправлен изменением порядка; internal-only network не дала фактический host port. После этого добавлена отдельная client network и negative test на отсутствие фактического binding. Удалялись только новые owned bootstrap resources без опубликованных experiments; никаких действующих ML datasets/SQL или чужих containers.

## Проверенный clean-checkout CI

[Run 38131527513](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38131527513), job `114446677086`, commit `40d26dc09df7b8731f83e716e720cfd6ff995db2`: **success**. PostgreSQL/TLS qualification завершена `2026-10-11T10:22:34.863854+00:00`, `source_dirty=false`.

- Повторены **70 component checks: 54 native + 16 controlled**, **74 worker checks**, три свежих training runs и **13 + 19 + 27 + 12 contracts**. Hashed dependency audit не сообщил известных vulnerabilities. Отдельный SQLite regression также прошёл 53 HTTP checks с собственными тремя обучениями.
- AUPRC всех трёх PostgreSQL-published runs: 0.9323007296445032; max probability difference 0.0; ONNX parity error 2.086162567138672e-7.
- CI tracking image: `sha256:cdbe66cbfda5b2ff7ddc3236589ba8fdfbd9c62e862f3cb03b033a2d40b1c50c`; CI worker: `sha256:8653aafff31cc421d7e88cfdb194e3606ca7fe85360564710453b71aafcf6992`.
- Docker runtime PostgreSQL image ID в CI: `sha256:2e182ed2ff8f5d0835353864264437a26dffc542a9a6c677ec495aa54e491627`. Pinned pull reference остаётся `postgres:18.6-bookworm@sha256:9551dd5bf356409a21b31248f49b33bba9bb1877365f3a7e933aecd9af3cf52d`. Разные Docker image-store representations не скрываются; сравниваются фактические локальные IDs внутри каждого запуска, не заявляется bit-for-bit build identity между машинами.
- Проверенные record hashes: `ef6afe430ba1f93fa3ebfdd0de7d01043cf869edb4a4cfaa82afb8f4141d93f1`, `1dcf277a657ad6b5f4b71042a6957bc3225fea68d87aab9c2b0d41a92200cfd5`, `b561ec94e5f4e7709e150958c486b984927b30ae0b7e77db47ba22cd0817d8fc`. Они включают конкретные run IDs/materials, поэтому не обязаны совпадать с независимым локальным запуском.
- Остановка owned CI services завершилась success; проверено конечное stopped state без удаления volumes. На пользовательском компьютере local service оставлен работающим. [Workflow](../.github/workflows/tracking.yml).

На том же commit [image audit 38131527429](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38131527429) завершился **fail по findings**: scanner positive control и четыре scans выполнены, worker 56 High, storage 11 Critical/118 High, worker candidate 55 High, storage candidate 3 Critical/88 High. Это worker/storage scope, не полный OS scan нового MLflow image. Functional green не снимает release block.

Regression workflows того же `40d26dc` завершились success: [documentation](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38131527438), [developer runtime](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38131527523), [storage/TLS](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38131527611), [Kubernetes/M20](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38131527618). У Kubernetes подтверждены migration, M20 и cleanup steps; tracking не был интегрирован в этот кластер. Self-review не объявляется независимым человеческим review.

## Что ещё обязательно

- [M06 dispatcher с native campaign и material reconciliation](reproducibility-gate.md) подключён и проверен по исходному численному контракту. Полная lifecycle lineage и проверка потери tracking metadata без изменения реального release остаются обязательной незавершённой частью T07/T08; pass M06 её не заменяет.
- T08: Kubernetes scoped publisher integration и metadata recovery. Host publisher является рабочим local component, не новым привилегированным controller в кластере.
- Отдельный полный OS image audit MLflow и publisher provenance. Известные High/Critical findings baseline PostgreSQL/worker не устранены; `release_ready=false` независимо от успешных функциональных проверок.
- Basic auth MLflow отмечен upstream как experimental. EDIT позволяет изменять metrics/artifacts; это не WORM. Tested grants относятся к experiment/API routes, не ко всем функциям MLflow. Нельзя считать tracking источником разрешения выпуска.
- Нет SSO, production secrets manager, rate limits, volume quotas/retention, многопользовательского hardening, HA, автоматической ротации и восстановления в новой среде. TLS/loopback и resource limits не подменяют эти механизмы.

## Основания решения

Эксплуатация: [диагностический плейбук и ранбук](operations/tracking-troubleshooting.md) фиксируют реальные bootstrap-проблемы, ownership checks и безопасный restart. Проверенные команды отделены от ещё не реализованного disaster recovery.

- [MLflow auth](https://mlflow.org/docs/latest/self-hosting/security/basic-http-auth/): явно выбранные permissions, отдельный auth store и современные grant APIs. API paths дополнительно проверены по installed 3.17.0 source.
- [MLflow tracking server](https://mlflow.org/docs/latest/self-hosting/architecture/tracking-server/): tracking отделён от artifact storage. Метод запуска проверен по установленному `_run_server`, не угадан по старому tutorial.
- [Uvicorn HTTPS settings](https://uvicorn.dev/settings/#https): native certificate/key options, проверенные реальным TLS endpoint.
- [PostgreSQL verify-full](https://www.postgresql.org/docs/18/libpq-ssl.html) и [pg_hba.conf](https://www.postgresql.org/docs/18/auth-pg-hba-conf.html): certificate identity, hostname и database-specific rules.
- [Docker bridge networks](https://docs.docker.com/engine/network/drivers/bridge/): separate networks и явный loopback binding. Исходящий доступ frontend network не объявляется заблокированным.

Кратко для собеседования: «Я отделил tracking от release authority и от недоверенного обучения. Три настоящих offline training runs публикуются внешней identity в MLflow через проверяемый HTTPS; metadata/auth хранятся в раздельных PostgreSQL databases с mTLS. Негативные запросы проверяют права и доверие сертификатам, перезапуск проверяет сохранение истории. Это production-подобный local component, но ещё не production release».
