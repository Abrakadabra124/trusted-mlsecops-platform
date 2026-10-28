# Аудит worker, PostgreSQL и MLflow images

Срез T01/T02, не полный M01. Порог политики: найденные High/Critical дают `fail`; недоступность DB, неизвестная severity, неполное покрытие или ошибка дают `inconclusive`. Оба исхода возвращают ненулевой exit code и не разрешают выпуск. Даже `pass` этого компонента не означает `release_ready`: полный R1 требует остальных gates.

Текущий переход: [ADR 0050](decisions/0050-runtime-image-adoption.md) и [STATUS](../STATUS.md). Wolfi candidates прошли compatibility/security и PostgreSQL опубликован по проверенному manifest digest. Исторический **fail** на `d4b5514` и прежние Debian findings остаются в [comparison evidence](evidence/image-candidates-2026-10-09.md) и [baseline audit](evidence/container-audit-2026-10-08.md). Ни publication, ни смена Dockerfile не доказывают безопасный release.

## Расширение CP2 на tracking

2026-10-28: policy `worker-storage-tracking-v2` включает отдельный образ MLflow, который раньше отсутствовал в package audit. Проверяются его Linux/amd64 identity, USER `65532:65532`, digest шести материалов `images/tracking/`, непустой Wolfi SBOM и обязательные `glibc-2.44`, `python-3.12`, `mlflow`, `mlflow-skinny`, `mlflow-tracing`, `psycopg`, `uvicorn`. Материалы повторно сверяются перед итогом. Исходник helper `tracking_spike.py` включён в runner materials. Missing/stale image, missing package, crash и Unknown дают inconclusive; High/Critical дают fail. Прежние severity thresholds и controls не изменены. [Native adoption evidence](evidence/cp2-runtime-adoption-2026-10-28.md): полный component audit на `37fe32b` pass, 0 Critical/High/Unknown во всех пяти images. Это не полное runtime/system coverage.

Обычный audit теперь требует три компонента; `--compare-candidates` требует пять. Сравнение remediation worker/storage остаётся отдельным четырёхкомпонентным расчётом, но общий итог учитывает MLflow. Успешное сравнение не скрывает failed/incomplete tracking. Scoped publication PostgreSQL также требует завершённого tracking scan; её прежний контракт позволяет публиковать исправленный storage artifact при failed baseline, сохраняя `release_ready=false`. Это не разрешение выпуска модели или adoption.

Локальные controlled проверки: **166 cases**, 378/383 statements, 109/112 branches (97.32% branches) пяти audit/candidate modules; отдельно **9 storage publication methods**, 97/98 statements и 27/28 branches. RED до исправления подтвердил отсутствие MLflow в успешном результате и несовместимость нового scope с прежним publication verifier. Это проверки логики, не реальный Syft/Grype scan MLflow. Native audit нового scope ещё не выполнен.

Publisher/scorer controllers используют образ worker по [controller bootstrap](../mlsecops/controller_bootstrap.py), однако этот audit не сверяет фактически работающие workloads. Полный deployed controller/system inventory, его соответствие image reports и остальные M18 criteria остаются обязательными. [Диагностика и плейбук](operations/image-audit-troubleshooting.md#cp2-отсутствующий-образ-tracking).

## Фактические образы среды CP2

Опция `--runtime-state .runtime` связывает audit с существующим owned lab через [image_scope.py](../scripts/image_scope.py). Сборщик проверяет workspace/cluster ownership, текущий controller profile и его source/config/manifest bindings, host storage и private tracking. Он включает kind node, все контейнеры workspace, tracking PostgreSQL/server и regular/init/ephemeral containers всех Pod кластера. Для Pod используются наблюдённые content/config digests; mutable tag не считается доказательством identity. Новая загрузка из registry допускается только по проверенному digest, а экспортированный config повторно сравнивается с наблюдённым.

Состав повторно собирается после scan. Изменение source, controller profile, контейнеров или наблюдённых Pod images делает результат inconclusive. Ограничения: не более 256 Pod, 256 host containers, 64 уникальных image targets; неоднозначная identity и недоступный образ не пропускаются. Raw before/after snapshots остаются в ignored `.runtime/image-audit/<run_id>/`; публичный summary содержит счётчики покрытия и immutable image/config IDs без raw Docker/Kubernetes objects.

Scope `observed-runtime-image-audit-only` с policy `observed-runtime-images-v1` дополняет обычные worker/storage/tracking проверки. Byte-identical runtime image наследует утверждённый package profile соответствующего базового образа. Для других system images доступный OS scan сохраняет findings, но даже без High/Critical остаётся `inconclusive`: `coverage_profile=unapproved-system`. Наличие libc не доказывает, что scanner распознал Go/application binaries. Неподдерживаемый distro также не получает pass. Профили системных приложений требуют native SBOM evidence и ещё не утверждены; это открытая часть M18, а не scanner exception.

[Workflow](../.github/workflows/runtime-image-audit.yml) создаёт полный временный lab на стандартном `ubuntu-24.04` runner. Он запускается вручную либо при push только в `codex/cp2-runtime-image-audit`; `main` этим workflow автоматически не запускается. Контракты выполняются до инфраструктуры, локальные секреты не загружаются, cleanup проверяет ownership. Снимки и volumes исчезнут с hosted VM; их внешнего backup этот job не создаёт. Запуск и разбор отказов описаны в [ранбуке](operations/image-audit-troubleshooting.md#cp2-сверка-фактических-образов).

Controlled evidence 2026-10-28: 176 audit cases, 430/437 statements и 143/146 branches audit modules; 11 collector methods, 107/107 statements и 46/46 branches; 16 publication regression methods. Эти результаты проверяют код на fixtures, не подтверждают native image coverage или M18. Реальный CI outcome фиксируется отдельно в STATUS.

## Что делают технологии

Для незакрытых system profiles audit сохраняет `package_observation`: предварительно сверяет Syft/source/config digest, затем выводит ограниченный список name/version/type/cataloguer и paths внутри образа. Поля metadata, environment, annotations и raw runtime snapshots не публикуются. Пустые или `(devel)` версии остаются такими, не выводятся из tag. Этот список позволяет проверить состав Go binaries и distroless images; его status всегда `inconclusive`, он не присваивает application coverage. Действующие required profiles и severity policy сохранены. [Официальное описание Syft Go cataloguer](https://oss.anchore.com/docs/capabilities/go/) объясняет main module и `stdlib`; [cataloguer documentation](https://oss.anchore.com/docs/guides/sbom/catalogers/) отделяет запущенный cataloguer от действительно обнаруженных packages.

Syft формирует SBOM (software bill of materials): перечень обнаруженных установленных пакетов и их версий. Grype сопоставляет этот перечень с базой известных уязвимостей. Это не malware scan модели, не доказательство отсутствия неизвестных уязвимостей и не оценка практической эксплуатируемости каждого finding.

Docker экспортирует образ, не запуская его приложение. SHA-256 связывает точные bytes архива, SBOM и report; digest pinning не заменяет проверку издателя. Отдельные scanner containers не получают Docker socket, kubeconfig, ML keys, БД проекта или весь checkout.

## Воспроизведение

Опциональный безопасный remediation flow: [сборка, квалификация и сравнение candidates](image-candidates.md). Флаг `--compare-candidates` добавляет два отдельные images к текущим baseline на том же DB snapshot; он не выполняет deployment.

Из корня чистого checkout на Linux amd64 или Windows с Linux Docker Engine:

```bash
uv sync --locked --python 3.12.15
uv run --locked python -m scripts.image_audit_qualification
uv run --locked python -m scripts.image_archive_qualification
uv run --locked python -m scripts.image_audit_runner_qualification
uv run --locked python -m scripts.image_audit_flow_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.tracking_spike build
uv run --locked python -m scripts.image_audit
```

Нужны 8 GiB свободного диска, доступ к официальным registries и DB endpoint, локальный Docker daemon. На Linux запускать от обычного пользователя с доступом к Docker, не через root. Доступ к Docker сам по себе даёт сильные host privileges; изоляция scanner не устраняет этот риск оператора. Выходные коды Python CLI: 0/pass, 1/fail, 2/inconclusive; wrapper может нормализовать ненулевой код, поэтому проверяйте также JSON.

Путь summary: `.runtime/evidence/image-audit.json`. Полный raw SBOM, диагностика и DB snapshot: `.runtime/image-audit/<run_id>/`, ignored. Не запускать параллельно несколько writers для общего summary. При начале нового запуска старый `pass` заменяется на `inconclusive`, при crash старый успех не восстанавливается. Raw SBOM содержит image metadata/config и не предназначен для публикации.

## Как работает проверка

1. Фиксируются source revision/fingerprint, digest policy и audit scripts. Worker label должен совпасть с текущим fingerprint; tracking label - с digest текущего recipe, lock и server/probe sources. PostgreSQL и scanner images указаны с immutable digests; ни один непроверенный latest tag не выбирается автоматически.
2. Каждый target экспортируется через `docker image save <resolved ID>` в новый owned run. Из tar без распаковки в host filesystem читаются bounded regular manifest/config entries. Несколько images, duplicate members, symlink metadata, traversal и несоответствие platform/layers/labels отклоняются.
3. В Docker Engine с containerd runtime `.Id` может быть manifest ID, а `source.metadata.imageID` Syft - hash image config. Поэтому сохраняются оба: `runtime_image_id` и `image_config_id`. SHA-256 вычисляется над конфигурацией из свежего экспорта, а не над произвольным старым SBOM.
4. Syft 1.54.1 без сети каталогизирует squashed filesystem. Проверяются version/source/image/distro, непустой уникальный inventory, обязательные packages и `foundBy`. Worker/storage/tracking требуют Wolfi `20230201` и APK cataloguer; tracking также требует Python application packages. Debian SBOM не допускается вместо этих Wolfi profiles. Наличие SBOM не означает завершённый vulnerability audit.
5. Grype 0.120.1 отдельным контейнером обновляет официальную DB. Сохраняются TLS, hash validation и максимальный возраст 120 часов. После обновления cache монтируется read-only, сеть scanner выключена, auto-update выключен только для использования того же snapshot. Файлы DB хешируются до и после проверок.
6. Положительный контроль сопоставляет PURL `pkg:pypi/urllib3@1.26.7` с DB. Этот package не устанавливается и не исполняется. Ожидаются High/Critical `GHSA-v845-jxx5-vc9f` и native threshold exit 2. Для Wolfi также обязателен APK control `openssl@3.0.7-r0`, `CVE-2023-0286`, тот же snapshot и High/Critical/exit 2, в том числе без candidate comparison. Пустая или неправильная выдача любого обязательного control запрещает pass.
7. Проверяются Grype reports всех обязательных images: version, valid свежая DB, тот же DB snapshot, config ID, distro, связь каждого finding с SBOM package. Непустые ignored matches и coverage alerts не скрываются. High/Critical блокируют независимо от доступности fix; Unknown не становится Low.
8. Публикуются только выбранные поля findings, counts, hashes, версии и ограничения. Timeout/overflow останавливает CLI и удаляет только scanner по его собственному CID. Временные image archives удаляются после каталогизации; raw reports и DB остаются локально для разбора. Глобальные Docker prune и удаление чужих volumes не используются.

Контейнеры scanner работают non-root, с read-only rootfs, без capabilities, с no-new-privileges, 2 CPU/2 GiB RAM, 256 PIDs и tmpfs 1 GiB. Wrapper проверяет stdout 64 MiB/stderr 2 MiB каждые 100 ms, поэтому возможен небольшой overshoot между проверками; это не filesystem quota. Offline операция ограничена 300 секундами, DB update - 600. Последний лимит увеличен после реального 300-second timeout при распаковке DB размером более 3 GiB на Windows bind mount; freshness/TLS/hash validation не изменены. В host administrator trust boundary входит целостность локального Docker daemon и файлов run.

## Проверка и evidence

2026-10-11: [RB-18](operations/image-audit-troubleshooting.md) фиксирует потерю длинных JSON-строк в обычном просмотре CI и сравнение с raw job API. Audit и отдельный publisher теперь выводят bounded pretty JSON вместо одной строки; canonical report на диске и severity policy не меняются. Семь publication tests проверяют полный round trip и safe failure; formatter не является новым scanner или redactor и не разрешает release.

- Контрактные suites: 43 report/policy checks, 15 archive checks, 25 runner checks, 18 controlled orchestration, 16 candidate binding и 6 comparison checks, всего 123 на `d4b5514`. Включены malformed/stale/foreign reports, пустой inventory, отсутствие обязательного package, fake DB validity, exit/report disagreement, mutation DB/SBOM/source, очистка старого pass, scoped cleanup и реальные child processes с oversized output/deadline. Mocked flow не является native scanner test. CI отдельно требует >=95% combined и branch coverage пяти audit/candidate modules; проверено 98/100 branches. Это не полное coverage M18.
- 2026-10-08 локальный native Syft каталогизировал worker (1 152 packages, Debian 13.7) и storage (151 package, Debian 12.15). Обязательные packages найдены. Exported archives и source/config IDs сохранены в ignored report.
- Ранние локальные попытки DB update дали TLS handshake timeout и позднее 300-second timeout при распаковке. Их итог `inconclusive`, число уязвимостей `null`, не 0. Последующий four-image run `653dbcbaaa934d8aa34527fdc9a2bd1c` завершил DB/control/scans: fail, с теми же counts/deltas, что CI. Старые результаты не переписаны в pass.
- Первый [clean-checkout CI 37840696361](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37840696361) на `4c9e9da` подтвердил native SBOM обоих images, но отклонил DB metadata в detection control. Это проверенный failure, не успешный audit; добавлена allowlisted диагностика descriptor и сохранение DB snapshot digest до проверки control.
- Последующие native runs установили точный формат `descriptor.db.status` и prefix `v6.1.10`. Fixtures исправлены через red/green checks, без ослабления freshness/validity. Run `37842817452` выполнил DB/control/оба scans: 173 worker и 436 storage advisory/package matches, всего 189 различных advisory IDs. Scan прошёл техническую верификацию, но severity policy дала fail. Контрактные suites на этом commit прошли и выполнили оба coverage thresholds; остальной R1 не объявлен принятым.
- [Workflow](../.github/workflows/image-audit.yml) исполняет тот же код из clean checkout и публикует только summary в logs даже при failure. Его наличие не доказывает успешный run; проверенные run IDs и результаты фиксируются в [STATUS](../STATUS.md).
- Изменение DB может менять findings для того же image. Повторяемы процедура, identity checks и решение для сохранённых inputs, но не обещается одинаковый сегодняшний вывод из постоянно обновляемой базы.

## Не завершено этим срезом

Полный inventory control-plane/system images, независимая проверка scanner signatures, полный P0/M01, ONNX intake M21, доверенный audit sink M23, политика retention DB/raw files и итоговая >=95% branch coverage M18 остаются отдельной работой. Findings не освобождаются от исправления только потому, что приложение работает или unit tests зелёные. При DB outage не подменять источник случайным mirror, не выключать TLS/age проверки и не публиковать прежний pass как новый.

Основания: [ADR 0014](decisions/0014-container-audit.md), [официальные Grype scan targets](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/), [DB lifecycle](https://oss.anchore.com/docs/guides/vulnerability/database/) и [JSON fields](https://oss.anchore.com/docs/guides/vulnerability/json/). Native версии дополнительно проверяются тестами и живым запуском, а не только latest документацией.
