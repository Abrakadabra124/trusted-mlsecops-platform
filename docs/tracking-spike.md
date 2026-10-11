# MLflow: проверка совместимости и доступа до deployment

Scope T07/T08, [ADR 0017](decisions/0017-experiment-tracking.md). Это настоящий MLflow 3.17.0 с HTTP requests и тремя реальными обучениями, но пока **одноразовый offline SQLite spike**, не целевой PostgreSQL/TLS service и не выполненный M06. Production/release readiness остаётся false.

## Технологии и ответственность

MLflow хранит experiments, runs, параметры, метрики и артефакты. Он помогает сопоставить результат с исходными материалами, но не заменяет независимый evaluation, подпись артефактов и promotion verifier. Изменяемые tags/metrics/aliases не являются release approval.

В этом проверочном стенде SQLite хранит metadata и auth в двух отдельных файлах. Это позволяет сначала проверить меняющийся API и реальные права доступа без модификации существующей PostgreSQL. SQLite **не заменяет** запланированные отдельные metadata/auth PostgreSQL databases, identities, TLS, backup и network controls.

Docker запускает probe и tracking server внутри одного изолированного network namespace. HTTP доступен только на loopback внутри контейнера; host ports, host mounts, host network, Docker socket и signing keys ему не передаются. Basic auth поверх HTTP допустим только для этого временного внутреннего probe: будущий клиентский endpoint обязан использовать проверяемый TLS.

## Как работает

1. Отдельный hashed lock фиксирует **91 пакет**, включая `mlflow[auth]==3.17.0` и `psycopg[binary]==3.3.6`. Существующие `pyproject.toml`, `uv.lock` и worker image dependencies не изменяются. Native wheel install выполняется с `--require-hashes --only-binary :all:`; uv не копируется в final image.
2. Build label связывает Dockerfile, Docker-specific ignore, requirements input/lock и probe. Перед запуском проверяются digest label, immutable image ID, Linux amd64 и UID 65532. В контекст сборки не попадает `.runtime` или весь checkout.
3. Host runner создаёт новый UUID state и выполняет existing developer qualification: **74 проверки**, включая три fresh-process обучения и независимые оценки. Worker остаётся offline, не получает MLflow SDK, пароль или API.
4. Host projection выбирает только allowlisted IDs/digests, seeds и метрики. Проверяет разные run IDs, одинаковые input/image/materials/version/policy/source bindings, probability tolerance <=1e-6 и AUPRC difference <=1e-4. Модели, строки dataset, ключи и произвольные поля metadata в MLflow не экспортируются.
5. Настоящий MLflow запускается с `basic-auth`, `NO_PERMISSIONS`, случайными disposable credentials и отключённой telemetry. Admin создаёт experiment; publisher получает EDIT, reader READ, foreign не получает grant. Admin credentials существуют только внутри disposable probe, не в Git или training worker.
6. Publisher создаёт три отдельных tracking runs, записывает параметры, метрики и JSON projection artifact. Reader читает их обратно. Проверяются anonymous/foreign denial, запрет reader write, publisher delete и self-admin, отказ перезаписывать уже заданный input parameter.
7. MLflow process перезапускается с теми же SQLite files. Параметры, метрики, artifact bytes и foreign denial повторно проверяются. Это restart одного сервиса, не disaster recovery и не проверка потери metadata.
8. Runner связывает возвращённые artifact hashes с отправленными records и повторно проверяет image. Cleanup удаляет только контейнер с ожидаемыми image/ownership labels по фактическому ID и проверяет его отсутствие. Остальные контейнеры не затрагиваются.

Права EDIT не делают MLflow append-only: publisher может менять разрешённые metrics/artifacts. Поэтому release verification обязан опираться на независимые подписанные источники и hashes, не на доверие текущему значению в tracking UI. Встроенные права также не доказывают запрет всех операций за пределами tested experiment/API routes.

## Воспроизведение

Требования: Linux amd64 Docker Engine, uv 0.12.23, Python 3.12.15; достаточное место для отдельного MLflow image и worker. Ни облако, ни новые внешние credentials не нужны. Выполнять из корня checkout:

```bash
uv sync --locked --python 3.12.15
uv run --locked pip-audit -r images/tracking/requirements.lock --disable-pip --require-hashes --strict --progress-spinner off
uv run --locked python -m scripts.tracking_records_qualification
uv run --locked python -m scripts.tracking_spike_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.tracking_spike build
uv run --locked python -m scripts.tracking_spike qualify
```

Для уже проверенного source-compatible worker candidate можно явно добавить `--worker-image trusted-mlsecops:worker-candidate` к последней команде. Неверный source fingerprint требует rebuild, не обхода проверки. Tracking build не меняет baseline worker tag или рабочую SQL-БД.

Rebuild dependency lock выполняется осознанно, не автоматически в CI:

```bash
uv pip compile images/tracking/requirements.in --python-version 3.12 --python-platform x86_64-manylinux_2_28 --no-build --generate-hashes --output-file images/tracking/requirements.lock
```

Новый lock требует нового audit/build/native probe. Dependency audit без findings не является полной security приёмкой image или всей MLflow HTTP surface. Отдельная publisher provenance verification ещё требуется.

Reports находятся в ignored `.runtime/evidence/tracking-spike.json` и `.runtime/tracking/<uuid>/evidence/`. Последний запуск сначала записывает inconclusive, поэтому crash не оставляет старый pass. Не публиковать UUID directory целиком: host training state содержит private test keys. При cleanup identity mismatch ресурсы сохраняются для расследования; не применять global prune.

## Проверено локально 2026-10-11

- Python dependency audit: 91 пакет, 0 известных vulnerabilities, 0 skipped. Это snapshot результата PyPI audit, не гарантия безопасности и не OS scan.
- Первый native run завершён `2026-10-11T09:41:20.032777+00:00`: **53 HTTP checks pass**, три разных MLflow run IDs; **74 worker checks pass**. AUPRC каждого обучения 0.9323007296445032, max probability difference 0.0, max ONNX parity error 2.086162567138672e-7.
- Tracking image `sha256:6e423e846a98b7cdd4f7c3cde46615a3843a7c060308a508f019d7262e168362`, recipe materials digest `a4c25aebbd77160ba2f5db04e699a014930e9f068610535c73cdf18fc6130eff`.
- Worker `sha256:2931ffbe14f0b54d5d3722f8094c9cf18ae20d0c11eec63fa4df9626683081b0`; app fingerprint `5c42a8f25bb59fde14446e9864b5c812a26893e9bf5527a2e3ae740c8e7f54e3`. Локальный revision `bb6a5f4` с незакоммиченным increment, не clean checkout.
- 27 projection contracts прошли; `scripts/tracking_records.py` имеет 32/32 covered lines и 16/16 branches. Дополнительно 12 image/cleanup orchestration contracts. Это не coverage всей платформы, probe или runner; M18 не закрыт.
- Исходный test запуск projection был RED из-за отсутствующего implementation module. После реализации стал GREEN. Первая build попытка выявила запрещённый root Docker context; добавлен узкий Docker-specific ignore, не широкое включение workspace.

[CI workflow](../.github/workflows/tracking.yml) повторяет dependency audit, contracts, build, обучение и native probe из чистого checkout.

## Проверенный clean-checkout CI

[Run 38129646455](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38129646455), job `114441125148`, commit `a48a9dc970f6ffc0b16a6cbeb007326dec0bb101`: **success**. Native probe завершён `2026-10-11T09:50:46.167720+00:00`, `source_dirty=false`.

- Повторены **53 HTTP checks**, **74 worker checks**, три fresh training runs, **27 + 12 contracts** и dependency audit без известных vulnerabilities. Max probability difference 0.0, AUPRC всех runs 0.9323007296445032.
- Projection coverage: **32/32 executable lines, 16/16 branches**. Это узкий module coverage, не runner/probe/M18.
- Hashed lock SHA-256: `1022d73ac8bf084d0f23474dbe594060d85e3481314fde6cd11a7d872c171adf`; recipe materials digest совпал с локальным `a4c25aebbd77160ba2f5db04e699a014930e9f068610535c73cdf18fc6130eff`.
- Tracking image: `sha256:5ea5ed6f343479a888d957d1db127bd245f65bfa91e856833065aa1d35e0dc7c`; worker: `sha256:e8aad63e9097673f6f74bfb8302e7e8898652b13cf45d29db6c90d3ccec11e73`. Другие image IDs относительно локальной сборки не скрываются; bit-for-bit image воспроизводимость не доказана.
- Принятые tracking artifact digests: `2ba028aee9620171b59ac5c474be3ac97683e00a2d74fd4fbcfc21b10df4577c`, `8d1e27b1f559b3c197616085a2097b81d122f013edd3edc5ceebceb5b6b8773b`, `16d9860a7e17be5fc58367dd53db9967782c3226ec807a34aa0da366f924deb0`. Run IDs и images входят в records, поэтому hashes не обязаны совпадать между отдельными CI builds.
- Cleanup завершён с проверкой отсутствия своего container ID. Новый сервис не оставлен доступным на хосте, рабочий SQL не переключался.

Это самостоятельный tracking compatibility report, не перенос green status на PostgreSQL/TLS deployment или image OS security gate.

## До полного T08/M06

Отдельные PostgreSQL metadata/auth roles, постоянный private service с TLS и проверкой CA/hostname, scoped publisher integration, native seed/data/environment mutation runs, точная graph/lineage reconciliation и сценарий потери metadata без изменения runtime release. Нужны OS image scan, полный inventory, backup/restore, общая security coverage и независимый review. Известные baseline image vulnerabilities не исключены и продолжают блокировать выпуск.
