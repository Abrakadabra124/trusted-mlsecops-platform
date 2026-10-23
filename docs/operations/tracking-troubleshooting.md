# Ранбук: private tracking service

Статус: локальный компонент, не production. Владелец действий - platform operator; неизвестная ownership или подмена требуют security reviewer. Эти роли пока выполняет владелец лаборатории, независимость администраторов не доказана.

MLflow хранит историю экспериментов, параметры и метрики. PostgreSQL хранит metadata и права в отдельных базах; TLS проверяет сервер, а mTLS также удостоверяет клиента PostgreSQL. Tracking не является источником разрешения выпуска модели.

## CP2: переход на non-root PostgreSQL image

Scope: только новые R1 states по [ADR 0050](../decisions/0050-runtime-image-adoption.md). Общий PostgreSQL reference импортируется из storage policy, а не дублируется отдельным pin.

Controlled RED воспроизвёл две ошибки: helper подготовки volume наследовал non-root USER образа, а существующий tracking state с прежним PostgreSQL reference принимался при неизменных application image/port. Это дефекты migration path, не подтверждённый production-инцидент. Исправление: explicit `--user 0:0` только для одноразового seed helper с network none, readonly rootfs, cap-drop ALL + CHOWN и no-new-privileges. Initdb/PostgreSQL остаются UID 999, MLflow UID 65532. Startup теперь требует совпадения PostgreSQL policy; old-state validation для read-only диагностики и owned stop остаётся доступной.

Диагностика: проверить `configuration.json` и текущий `PG_IMAGE`, не выводя `credentials.json`/private keys. `tracking_service_change_requires_explicit_migration` запрещает `up`, не разрешает удаление state. При проблеме seed посмотреть USER/CHOWN только собственного helper, не выдавать privileged и не запускать весь сервер root. Конечная проверка - native tracking workflow: успешный bootstrap, TLS/roles/publication и фактические runtime UIDs; 16 controlled config checks этого не заменяют. Старую историю сохранить с прежним checkout/image, переводить только отдельным согласованным recovery планом.

## CP2: dependency audit остановил сборку

На `883c262` Storage [40002307097](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40002307097) остановился до PostgreSQL из-за `certifi 2026.7.22`; Tracking [40002311281](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40002311281) остановился до сборки образа: 37 advisory matches в трёх пакетах. Это новые результаты dependency feed, не доказательство регрессии PostgreSQL или эксплуатации уязвимости.

Причины и scoped исправления:

- `certifi` предоставляет доверенные корневые сертификаты для Python TLS clients. [PYSEC-2026-4320](https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/certifi/PYSEC-2026-4320.yaml) требует удалить скомпрометированную цепочку emSign: версия `2026.10.19` в обоих locks, hashes сверены с [PyPI](https://pypi.org/project/certifi/2026.10.19/).
- `GitPython` даёт MLflow доступ к Git metadata. [Исправление 3.2.1](https://gitpython.readthedocs.io/en/latest/changes.html) закрывает `CVE-2026-114145`, запись в `.git` через submodule path. Версия `3.2.1` вместо `3.2.0` только в tracking lock.
- `Pillow` входит в зависимости MLflow для изображений. 35 scanner matches в `12.3.0` требуют `13.0.0`; [release notes](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html) описывают security fixes и несовместимые API. Наш профиль Python 3.12 сохраняется; этот bump требует нового tracking build и настоящих MLflow/TLS/publication checks, не только resolver success. Возможность обработки произвольных изображений не заявляется.

Плейбук для platform operator:

1. Сохранить run/commit и JSON `pip-audit` приватно; в публичный отчёт включить package/version/advisory/count, не огромные raw descriptions. Различать audit failure и недоступность feed. Не использовать `ignore-vuln`, TLS bypass или downgrade scanner.
2. Подтвердить fixed versions у издателей. Resolver `uv 0.12.23` генерирует кандидат locks отдельно от рабочих services: `uv lock --upgrade-package certifi==2026.10.19`; tracking использует прежние Python/platform/no-build/generate-hashes параметры из header с точечными `--upgrade-package certifi==2026.10.19 --upgrade-package gitpython==3.2.1 --upgrade-package pillow==13.0.0`. Проверить diff: другие package versions/graphs не меняются. Main lock revision 3 -> 5 является форматом pinned uv, не изменением Python.
3. Проверить `uv lock --check`, затем `uv sync --locked --python 3.12.15` в отдельном окружении. Выполнить `uv run --locked pip-audit --strict --progress-spinner off` и `uv run --locked pip-audit -r images/tracking/requirements.lock --disable-pip --require-hashes --strict --progress-spinner off`. Исправленные locks дали 0 findings для 63 installed / 91 tracking packages локально. Это package audit, не полный controller image scan.
4. Выполнить targeted developer/storage/tracking CI на новом commit. Конечное состояние: сборка нового tracking image, offline authorization, persistent SQL/TLS/publication, M06 и storage gates проходят. Source/materials digests меняются; старые evidence не перепривязывать к новому commit.
5. Не переключать существующую tracking БД автоматически и не переписывать `configuration.json`. При несовместимости сохранить отказ, старые volumes и logs; восстановление только по согласованному migration path. Возврат к уязвимому lock не разрешает выпуск. Если fixed version недоступна или новый audit fail, эскалировать как R1-B02, а не исключать finding.

## PB-01. Read-only диагностика

Условия: запуск из корня репозитория, окружение `uv sync --locked --python 3.12.15`, доступ к локальному Docker Linux daemon. Секреты и receipts находятся в `.runtime/tracking-service`; не копировать их в issue или чат. Docker-доступ сам по себе привилегирован; плейбук не является sandbox для оператора.

```text
uv run --locked python -m scripts.tracking_doctor
```

[Реализация](../../scripts/tracking_doctor.py) не вызывает bootstrap, restart, Docker exec или удаление ресурсов и не отправляет пароли. Последовательность:

1. Проверить локальную configuration, digest файлов и срок сертификатов.
2. Через Docker inspect сопоставить receipts и ownership labels, image IDs, networks, фактический loopback port, volumes, UID и ограничения ресурсов. Проверить, что оба контейнера работают.
3. Один GET `/health` через проверяемый HTTPS, без proxy, redirects и Authorization. Timeout 3 секунды, читается максимум 65 байт, разрешено не более 64. Каждый Docker inspect имеет собственный timeout; общего трёхсекундного deadline у всего плейбука нет.
4. Вернуть очищенный JSON в stdout. Исходные исключения, Docker inspect, тело ответа и credentials не печатаются. Коды процесса: 0 - pass, 1 - fail, 2 - inconclusive. Сохранение отчёта оператором допускается только в приватное хранилище.

| Check / reason | Что делать |
| --- | --- |
| `configuration_unavailable` | Проверить наличие и доступ к локальному state. Не создавать новые ключи поверх частичного state. |
| `configuration_invalid` | Проверить срок сертификатов, хеши и формат по доверенной копии. Не переписывать expected digests ради успеха. |
| `resources_unavailable` | Проверить выбранный Docker daemon и наличие receipts. Отсутствующий ресурс и недоступный daemon могут быть неразличимы; это inconclusive, не подтверждённая потеря данных. |
| `resources_invalid` | Проверить ownership/runtime policy и состояние контейнеров. Не рестартовать неизвестный ресурс. |
| `https_unavailable` | Проверить доверенный CA, срок/SAN сертификата, доступность порта. Не применять TLS bypass; причина может быть транспортной или TLS. |
| `https_invalid` | HTTP error, oversized response или redirect. Проверить endpoint и routing, не следовать неизвестному перенаправлению. |
| Все три pass | Конфигурация и HTTPS доступны. Это не проверка SQL queries, auth grants, сохранности runs, backup или полного M06. |

Для уточнения stopped state доступна существующая команда:

```text
uv run --locked python -m scripts.tracking_service status
```

Её `pass` означает только совпадение конфигурации; отдельно смотреть `running.pg` и `running.server`. Не смешивать этот результат с диагностикой доступности.

## RB-01. Volume initializer: chmod после chown

**Встреченный симптом:** bootstrap завершался ошибкой permissions до публикации экспериментов. **Причина:** initializer менял владельца каталога, затем пытался chmod с удалёнными capabilities, кроме CHOWN. Root без нужных capabilities не гарантирует право chmod чужого каталога.

**Исправлено:** `seed_volume` сначала задаёт mode 700, распаковывает mode 600 с `umask 077`, затем выполняет chown. Initializer временный, network none, readonly root, добавлен только CHOWN. Действующие PostgreSQL/MLflow запускаются без добавленных capabilities.

**Порядок действий при повторении:**

1. PB-01, затем локально определить, на каком owned bootstrap-ресурсе произошёл отказ. Не публиковать raw container logs: они могут содержать секреты.
2. Сверить initializer с [реализацией](../../scripts/tracking_service.py), не добавлять privileged/FOWNER ко всему сервису.
3. Если остался частичный state, перейти к RB-03, а не повторять setup на единственной копии данных.
4. Для нового изолированного стенда повторить qualification и проверить финальные ownership/mounts и реальную запись/read-back.

**Проверено:** исправление прошло native bootstrap и PostgreSQL/TLS qualification локально и в [CI на 40d26dc](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38131527513). Старую небезопасную последовательность на работающем volume повторно не запускали. Rollback ошибки не означает возврат к сломанному initializer; сохранять действующие volumes и остановить rollout.

## RB-02. Port указан в конфигурации, но реально не опубликован

**Встреченный симптом:** Docker HostConfig содержал port binding, но internal-only network не дала ожидаемый host endpoint. Успешное создание контейнера не доказало доступность MLflow.

**Исправлено:** PostgreSQL находится только в private internal network без host port. MLflow дополнительно подключён к client bridge с фактическим binding `127.0.0.1:15445`. Verifier проверяет не только HostConfig, но и NetworkSettings работающего контейнера; PB-01 делает реальный HTTPS-запрос.

**Диагностика:** PB-01 -> проверить ресурсы -> проверить HTTPS. Если изменены networks/port, остановить дальнейшую публикацию и сверить receipt; не подменять receipt фактическим состоянием без расследования. Не открывать порт на `0.0.0.0`, не публиковать PostgreSQL как обходной путь.

**Ограничение:** client bridge допускает исходящий доступ MLflow. Это не доказанная egress allowlist, и tracking не переносит свои сетевые права на offline training workers. Изменение topology рабочего стенда требует отдельной migration, не слепого пересоздания.

**Проверено:** actual binding + HTTPS положительный тест, controlled missing-binding отрицательный тест, PostgreSQL/TLS native qualification и указанный CI. Поведение проверено в данной Docker-среде, не заявляется одинаковым для всех network backends.

## RB-03. Частичный bootstrap или неизвестная ownership

**Сигнал:** `tracking_partial_resources_require_recovery`, `tracking_service_partial_state_requires_recovery`, `tracking_service_foreign_resource`, недостающий receipt. Это защитные ветви, не доказательство компрометации. Native ранние bootstrap-отказы действительно оставляли собственные незавершённые ресурсы; foreign-resource ветви проверялись controlled mutations.

1. Не выполнять повторный bootstrap/reset. Сохранить приватно state, identity, текущий commit и очищенный PB-01 report; проверить выбранный Docker context.
2. Сопоставить **каждый** container/network/volume с identity и config digest, а существующий receipt - с actual IDs/CreatedAt. Одного совпадения имени недостаточно.
3. Установить, были ли записаны experiments или другие полезные данные. Если это неизвестно, считать данные значимыми. Потеря receipt не разрешает автоматически присвоить ресурс себе.
4. Установленная foreign ownership или возможная подмена -> security review, без изменений. Подтверждённый пустой disposable bootstrap -> отдельное явно ограниченное решение на очистку конкретных IDs. Универсальная destructive-команда намеренно не предоставлена.
5. Есть данные -> остановить migration, сохранить исходные volumes, разработать restore в новое окружение. Проверенного автоматического tracking metadata-loss recovery пока нет; восстановление не объявляется успешным.

**Запрещено:** global prune, удаление всех `tml-*`, перезапись configuration/receipts, удаление `.runtime` или volumes ради зелёного теста. При Windows cleanup сначала проверить resolved absolute targets и использовать одну оболочку с LiteralPath.

## PB-02. Возобновление намеренно остановленного owned сервиса

Только если `tracking_service status` подтвердил неизменённую конфигурацию/ownership, stopped state ожидаем, сертификаты действуют, образ не заменён и нет признаков компрометации. Команда изменяет состояние обоих owned контейнеров, возможна краткая недоступность:

```text
uv run --locked python -m scripts.tracking_service up
uv run --locked python -m scripts.tracking_doctor
```

`up` не мигрирует неизвестную конфигурацию. Если она отвергнута, не изменять marker/ключи, вернуться к RB-03. При неуспешном запуске допустима безопасная остановка проверенных owned контейнеров командой `uv run --locked python -m scripts.tracking_service stop`: volumes сохраняются. Если ownership не подтверждена, stop также должен отказать; не обходить verifier.

Для проверки сохранности истории используется отдельная **изменяющая** qualification:

```text
uv run --locked python -m scripts.tracking_service_qualification
```

Она создаёт три training runs и эксперименты, выполняет negative probes и перезапускает PostgreSQL/MLflow. Запускать только на согласованной лаборатории без параллельной публикации, не как безвредный health-check. Критерий восстановления - read-back параметров, метрик и artifact bytes после restart, а не только HTTP 200. Этот restart проверен; disaster recovery после потери metadata не проверен.

## RB-04. Истёкший или недоверенный сертификат

Leaf certificates действуют 30 дней. PB-01 блокирует stale/изменённую конфигурацию. Проверять локальные часы, CA, SAN и срок; запрещено `verify=False`, `curl -k` или изменение trust roots на полученные с неизвестного endpoint.

Неизменённый, но истёкший сертификат допускает только существующую ownership-checked процедуру stop. Автоматической ротации нет: нужен отдельный migration/backup план, новые проверенные материалы и повторная qualification. Controlled expiry/unknown-CA/hostname negatives проверены; production rotation не заявляется.

## Доказательства и пределы

- [26 tests плейбука](../../scripts/tracking_doctor_qualification.py): 24 controlled cases и два реальных filesystem cases. Missing/tampered state, unavailable daemon, partial bootstrap, foreign/policy drift, stopped containers, transport/TLS/redirect, oversized/non-200 response, sanitized error и exit codes.
- Локальный PB-01 `2026-10-11T11:02:52Z` прошёл три live stages на уже работающем service. Отдельно совпали content hashes state-файлов, container IDs и StartedAt до/после диагностики; отсутствующий state не создаётся. Покрытие doctor при объединении tests + live CLI: 49/49 statements, 6/6 branches. Не изменяет release authority; всегда `release_ready=false`.
- [Clean-checkout CI 38134212049](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38134212049) на `44deac94528ccae45e426c01d354a81f5e225a76` завершился success: 26 doctor tests и три реальные diagnostic stages; doctor report `2026-10-11T11:08:33.034498Z`. После native reproducibility CI безопасно остановил свои owned tracking containers. Это не проверка backup/restore после потери данных.
- [Tracking implementation и точные исторические результаты](../tracking-service.md): 54 native + 16 controlled service checks, 74 worker checks, SQL roles, HTTPS и restart. Это отдельная, более широкая проверка, чем doctor.
- Полный M06, Kubernetes tracking integration, recovery и security image gate остаются открытыми. При неизвестном результате оставить fail/inconclusive и приложить [incident record](incident-template.md), не объявлять восстановление.

При разработке doctor найдено различие между mock и реальным filesystem: `read_json` оборачивает отсутствующий файл в `Rejected(artifact_unavailable)`, а не возвращает FileNotFoundError напрямую. Добавлен реальный отрицательный тест и исправлена классификация в inconclusive без создания state; malformed JSON по-прежнему fail. Это исправление диагностического статуса, не восстановление пропавших данных. Поэтому одни mock tests без native проверки недостаточны.
