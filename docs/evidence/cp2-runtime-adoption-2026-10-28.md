# CP2: исправленные зависимости и storage artifact, 2026-10-28

Scope: неделя 1 «Контекст и foundation», T02 «Foundation P0 и совместимые зависимости», R1-B02. Это evidence компонентного исправления, не завершённый CP2/R1. Локальные Docker/WSL/Kubernetes/SQL не запускались и не менялись.

## Опубликованный PostgreSQL

[Prepare qualified storage artifact 40755338187](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40755338187), head `e4244d4bb1423ce56efcefca196617805ca75238`, attempt 1, job `123052637110`, success. Main-only guard и временные registry credentials сохранены. Publisher заново собрал и проверил оба candidates, сравнил их с прежними baseline и прочитал опубликованный image по immutable reference.

- Worker: 74 checks, три обучения, max probability difference 0.0, ONNX parity error `2.086162567138672e-07`.
- Storage: 435 checks, signed restore и 1 000 golden predictions, max error 0.0. SQL restore 3.416851 s, restore-to-golden 5.396002 s. Это компонентные времена, не полный M17 RTO.
- Manifest: `ghcr.io/abrakadabra124/trusted-mlsecops-platform-postgres@sha256:bd279118884568f35de40901ee9438f17af7c2e75a0623be89b36bbd69b68fe5`.
- Config/image ID: `sha256:ef426cb1343f72de96bcc72aade0ee57f552b806cdd7e93f80b98d41117fe059`.
- Storage recipe SHA-256: `b0241f538b523e637c95c51c27e8e7c950a0310868665ff75077f4c8ae99bbaa`.
- Source fingerprint: `a2427edf914351abf83a8db069f19aa2705fa366b4ba10b7d110c37da86c147a`.
- Evidence SHA-256: audit `156e18a4ddb82968234d294660cdb16f315098283d45441da4d463b86e8f2ac6`, storage `a1b6d6451e6d9784263d9172bffe2c3c14a45b2b84aa0295493a184df8d2fc4c`, worker `7e06b0232c8295389528e1d169b4a365da606ebf6e0606125c9e99b4c3719db4`.

`baseline_audit_status=fail`, `release_ready=false`: публикация разрешает использовать исправленный инфраструктурный artifact для следующих проверок, не выпуск модели. Прежние storage/tracking findings не исключены из comparison.

Отдельное anonymous чтение `2026-10-28T19:40:36Z` подтвердило SHA-256 manifest и config, Linux/amd64, USER `999:999`, OCI source label этого repository и 12 layers. GitHub credentials не использовались; временный anonymous registry token не сохранён. Это проверка metadata, не отдельный полный pull слоёв. Полный anonymous pull и работоспособность нового pin проверяют свежие hosted consumers без registry login.

Общий [storage pin](../../mlsecops/storage_bootstrap.py) обновлён только после этих проверок. Предыдущий manifest `9172aa68aa0790240cd4597707d8d8fda875dcd944e0155277e2347142585b7b` остаётся историческим rollback reference; его известные findings запрещают выпуск. Старые state markers и volumes не изменены. [Порядок adoption/rollback](../decisions/0050-runtime-image-adoption.md).

## Dependency blockers и неизменность данных

На том же `e4244d4` [Developer 40755338400](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40755338400) и [Storage 40755338237](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40755338237) отказали до инфраструктуры: filelock 4.0.12, CVE-2026-112940 / CVE-2026-112913 / CVE-2026-112907. [Tracking 40755338241](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40755338241) остановился до build: MLflow 3.17.0, CVE-2026-53995.

Scoped resolver update изменил только filelock до 4.2.1 в `uv.lock` и mlflow/mlflow-skinny/mlflow-tracing до 3.17.2 в hash-locked tracking requirements. Остальные версии зависимостей не изменены. `uv lock --check`, installed `pip-audit --strict` и tracking `pip-audit --disable-pip --require-hashes --strict` прошли, known findings отсутствуют на момент проверки. Это не аудит контейнера целиком.

До correction `data.lock` повторно сгенерированы исходные данные: 20 000 rows, 1 915 576 bytes, SHA-256 `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`, точно как раньше. Из inputs изменился только `uv.lock`: 113 874 bytes, SHA-256 `78563ff0a0999797844936271b7109174f46a9c7f7d896c3e0e8acdc79ccceeb`. Обновлена только эта запись provenance; output, generator, seeds, splits, model и thresholds сохранены. `validate_lock` прошёл; CI не получает автоматический update-lock.

Primary sources: [filelock 4.2.1](https://github.com/tox-dev/filelock/releases/tag/4.2.1), [MLflow advisory](https://github.com/advisories/GHSA-wqmh-qccw-pqwf), [MLflow 3.17.2](https://github.com/mlflow/mlflow/releases/tag/v3.17.2). FileStore-specific exploit не выдаётся за подтверждённую эксплуатацию нашего PostgreSQL profile; политика требует исправленной зависимости без advisory waiver.

## Tracking runtime и границы проверки

Обновление MLflow не устраняет системные пакеты Debian из прежнего tracking image. Новый recipe использует ту же закреплённую Wolfi runtime closure из 34 APK, которая прошла worker qualification: Python 3.12.15, glibc, исправленный Brotli. Builder и runtime имеют одинаковый Python path/ABI; uv остаётся только в build stage. Tracking dependencies устанавливаются по hashes и только из wheels. Сохраняются UID 65532, `/tmp` для разрешённой записи, TLS, authorization и прежние resource limits.

Audit ожидает Wolfi и проверяет наличие glibc, Python, mlflow, mlflow-skinny, mlflow-tracing, psycopg и uvicorn. OS-only inventory, отсутствие tracing и чужой distro не засчитываются. Existing High/Unknown, scanner crash, wrong image/materials и detection-control negative cases сохранены. Controlled RED подтвердил, что старый Debian profile не принимает новый tracking recipe; native build, auth/TLS/publication и full image scan ещё требуют завершённого hosted запуска.

M08 уже имеет фактический отказ на candidate, полный runtime inventory всё ещё непокрыт, M09/M22 и CP3-CP5 не приняты. Ни один результат этой страницы не закрывает эти blockers.
