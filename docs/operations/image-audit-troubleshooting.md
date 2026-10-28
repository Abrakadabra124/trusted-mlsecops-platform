# RB-18: отказ image audit и неполный просмотр CI

Ответственные: platform operator и security reviewer. Процедура относится к scanner evidence лаборатории, не к production-инциденту. Рабочие SQL volumes, runtime tags и foundation не меняются.

## CP2: Brotli в закреплённых Wolfi images

Продолжение после описанного ниже первоначального исправления: [publication/adoption 2026-10-28](../evidence/cp2-runtime-adoption-2026-10-28.md). PostgreSQL опубликован workflow `40755338187`, manifest/config прочитаны анонимно, shared pin обновлён для fresh states. Tracking также переведён на Wolfi/MLflow 3.17.2. Component audit `40758097499` success: 0 Critical/High/Unknown во всех пяти images; worker/tracking сохраняют 6 Medium/1 Negligible. Отдельные ограничения runtime/system coverage и модели остаются. Старые failures ниже сохраняют историю, а не описывают новый image как всё ещё непубликованный.

2026-10-28, native `22371d8`, [40750705961](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40750705961): worker и storage получили по 3 Critical matches CVE-2026-111497 для `libbrotlicommon1`, `libbrotlidec1`, `libbrotlienc1` версии `1.2.0-r6`; GHSA alias дал ещё 3 Unknown matches. Это находки установленного пакета, не проверка достижимости уязвимого кода и не шесть независимых CVEs. Политика сохраняет refusal.

Источники проверены 2026-10-28: [Wolfi recipe](https://github.com/wolfi-dev/os/blob/main/brotli.yaml) содержит upstream `1.2.1`, epoch `2`; [advisory](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) описывает Brotli decoder issue. Публичный [APK index x86_64](https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz) содержит все три `1.2.1-r2`; SHA-256 полученного архива `56c90c1fd9740197d6c47e035361ed60073e5907133b62713e219897b4dba64f`. Чтение index не заменяет проверку подписи APK при native build и повторный scanner result.

Исправление ограничено девятью pins: основной worker и отдельные worker/storage candidate recipes переходят на `1.2.1-r2`. Остальные packages, base digests, Python lock, модель и thresholds сохраняются. Опубликованный storage digest и действующие volumes пока не меняются: новый storage image сначала должен пройти signed restore, 1 000 golden predictions, package audit и отдельную публикацию с immutable readback.

Плейбук: запустить существующий `image-audit.yml` на точном feature ref в disposable hosted CI; проверить builds, worker compatibility, signed storage restore, все пять components и severity counts. Успех только трёх исправленных images не закрывает baseline storage, tracking и runtime system coverage. Не добавлять scanner ignores. При неуспехе сборки сохранить старый pin как исторический artifact без разрешения release; установить package/ABI/source причину и повторить новый run. Rollback working database не нужен, поскольку rehearsal использует отдельный target. Native результат нового pin фиксируется в STATUS; до него исправление не считается подтверждённым.

Предыдущий Brotli playbook проверен в [40753468138](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40753468138), `edc6862`: 74 worker / 435 storage checks, 1 000 golden predictions/error 0.0, основной worker и оба candidates без Critical/High/Unknown. Storage comparison удалил все шесть прежних advisory/package pairs, новых нет. Общий workflow failure сохранён из-за baseline storage и tracking. Следующий этап - отдельная guarded publication нового storage artifact и adoption по pinned digest; эти действия данным run не выполнены. Повторный общий image audit после adoption обязателен.

## CP2: состав системного приложения

Native [40761233745](../evidence/cp2-system-images-2026-10-28.md) сохранил состав 13/14 targets; один дал `image_audit_package_observation_invalid`. Установлен отдельный parser defect: [optional поля Syft LinuxRelease](https://github.com/anchore/syft/blob/v1.54.1/syft/format/syftjson/model/linux_release.go) ошибочно считались обязательными даже для diagnostic observation. Controlled RED/GREEN проверяет отсутствие id/versionID; теперь они сохраняются как null, неверный тип по-прежнему отвергается. Native причинная связь с единственным отказом пока не доказана. После нового run проверить наличие observation у того же config/приложения; при повторном отказе сохранить конкретный stage, не объявлять app coverage успешным и не подставлять Debian по предположению.

Для system targets с `image_audit_required_packages_missing` или неподдержанным distro сначала читать `package_observation`, `observed_reference`, `local_alias` и `host_roles` в summary. Observation сохраняется до отказа coverage и связан с фактическим config digest; alias служит только указателем на containerd bytes, не доверенным release identity. Сверить имя/версию/тип/cataloguer и путь исполняемого приложения, отдельно его Go `stdlib` и dependencies. Отсутствие `libc6` у минимального образа само по себе не доказывает отсутствие пакетов. Нельзя объявлять образ scratch по пустому distro или разрешать его по наличию любого одного Go module. Новый application profile требует конкретного native inventory и отрицательной проверки отсутствующего/неверного приложения. Unknown versions и неполное покрытие сохраняют отказ.

## CP2: отсутствующий образ tracking

**Симптом:** прежний успешный worker/storage audit не содержит MLflow, хотя tracking service использует отдельный образ. Причина установлена по списку targets: в нём было только два runtime components. Это пробел покрытия CP2/R1-B02, а не подтверждённая эксплуатация уязвимости.

**Исправление:** policy v2 требует tracking в обычном audit и при candidate comparison. Before-scan identity проверяет recipe digest и non-root USER; после scan проверяются неизменность materials, package coverage и тот же DB snapshot. Оба workflow, вызывающие audit, предварительно строят tracking image. Storage publication verifier принимает только новый полный scope; старый четырёхкомпонентный report не подходит.

**Диагностика без запуска services:** открыть sanitized summary `.runtime/evidence/image-audit.json`, сверить policy ID, наличие `tracking`, `recipe_digest`, `scan_executed`, `status` и `reason`. Сопоставить recipe с `images/tracking/Dockerfile`, lock и server/probe sources. Не публиковать raw Docker inspect: он может содержать environment. Пользоваться выбранными полями summary.

**Плейбук на разрешённом disposable runner:**

```text
uv sync --locked --python 3.12.15
uv run --locked python -m scripts.image_suite_qualification
uv run --locked python -m unittest scripts.storage_publication_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.tracking_spike build
uv run --locked python -m scripts.image_audit
uv run --locked python -m scripts.image_audit_publication
```

Команды build/scan изменяют cache/images и создают evidence, но не запускают приложение MLflow и не переключают рабочие БД. Ожидаемый корректный результат включает три runtime components. Код 1 означает findings, 2 означает неполную проверку; оба запрещают трактовать общий audit как pass. Publisher выводит данные, а не переопределяет результат предыдущей команды. Для `--compare-candidates` сначала нужны отдельные candidate builds и compatibility checks из существующего image-audit workflow.

- `image_audit_tracking_materials_mismatch`: сохранить отчёт, сверить checkout и recipe, пересобрать tracking из тех же locked материалов. Не переписывать Docker labels вручную.
- Missing image: выполнить предусмотренную сборку, не заменять локальный tag случайным образом из registry.
- Missing package, crash, Unknown или stale DB: устранить причину неполного покрытия; пустой findings не является доказательством безопасности.
- High/Critical в tracking: сохранить advisory/package/version, исправить соответствующий dependency/base image и проверить затронутый service. Успешное сравнение worker/storage не снимает этот отказ.
- Sources изменились во время scan: текущий результат inconclusive, нужен один новый scan после фиксации материалов. Не смешивать SBOM предыдущего build с новым image.

**Проверка исправления:** 166 controlled audit cases и 9 publication methods прошли локально; в том числе tracking failure/missing image при успешном comparison. Реальный новый hosted scan ещё требуется. Full controller/system inventory и R1 не приняты. При отказе не менять рабочие volumes или уничтожать source artifacts; сохранить исходный checkout/report, исправить причину и повторить на чистом runner. Возврат к v1 не является допустимым способом получить новый pass.

## CP2: подготовка storage artifact к scoped adoption

[ADR 0050](../decisions/0050-runtime-image-adoption.md) ограничивает изменение новыми R1 states, без переключения рабочих SQL volumes. Это следующий обязательный шаг R1-B02, не новый необязательный scope.

Read-only перед запуском: проверить commit на `main`, [workflow](../../.github/workflows/storage-artifact.yml), pinned recipes, отсутствие секретов в Docker context и результаты candidate qualification. Изменяющее действие только на disposable hosted runner:

```text
gh workflow run storage-artifact.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
```

Workflow повторяет actual compatibility/restore и fresh audit. Publication gate отвергает чужие/неполные/старше двух часов reports, dirty source, несовпадающие image/recipe identities, неправильную policy и blocking findings. Оба candidate gates обязательны. Baseline failures сохраняются в полном comparison: разрешение подготовить storage artifact не является разрешением выпускать R1. Только после этих проверок job получает registry login, публикует проверенный image ID под уникальным commit/run/attempt tag, читает manifest и выполняет pull-by-digest/readback. Tokens не выводятся, PAT не нужен; login удаляется в always step.

Отказы и действия:

- `storage_publication_dispatch_invalid` / `storage_publication_dirty_source`: не запускать локально и не менять guard. Нужен ручной запуск из правильного `main` checkout.
- `storage_publication_evidence_invalid`: сопоставить scopes, timestamps, source revision/fingerprint, identities, controls и severity. Не редактировать reports ради публикации; исправить причину и повторить затронутый pipeline.
- Push denied: проверить связь package с этим repository, job permission `packages:write` и OCI source label. Не выдавать token полные account/admin scopes.
- Manifest/config/readback mismatch или сетевой сбой после push: статус inconclusive; artifact может существовать. Не удалять его автоматически и не принимать tag как identity. Проверить конкретный manifest/config и ownership.
- `public_access_verified=false` в успешной публикации ожидаем: authenticated readback не доказывает anonymous доступ. GHCR новый package по умолчанию private. Перед baseline adoption подтвердить public visibility и anonymous manifest/config readback; не добавлять PAT в bootstrap.

Встреченный preflight defect `6127048`: GitHub отклонил dispatch с HTTP 422 до создания run, потому что `runner.temp` недоступен в job-level `env`. Actionlint 1.7.12 воспроизвёл тот же expression error. Исправление: создать приватный registry-config directory внутри шага через `$RUNNER_TEMP` и передать путь последующим шагам через `$GITHUB_ENV`, после проверки candidates и до login. Ни runner job, ни push не произошли в неудачной попытке dispatch. Локальный actionlint проверяет Actions expressions/YAML; shellcheck/pyflakes в этой диагностике не выполняются, Python проверяется Ruff и unit suite.

Rollback до adoption: baseline не меняется, runtime rollback не требуется. Остановить дальнейшее принятие, сохранить отказ и digest для расследования. Старые рабочие states/volumes, private keys и единственная копия backup не удаляются. Package publication, anonymous access и новое baseline runtime acceptance отмечаются отдельно в STATUS; unit contracts не заменяют эти три native результата.

### Подключение опубликованного artifact

Native publication `bbc20b4` и отдельный anonymous manifest/config readback подтверждены в [ADR 0050](../decisions/0050-runtime-image-adoption.md#проверенная-публикация). Новый root worker recipe совпадает с проверенным candidate, storage и tracking используют один registry manifest pin. Не путать manifest digest `dbd9ead...` с local config ID `f407b8a...`.

Только disposable hosted CI, из clean `main`, после targeted contracts:

```text
gh workflow run runtime.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh workflow run storage.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh workflow run kubernetes.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh workflow run tracking.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh workflow run image-audit.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
```

Ожидается anonymous pull без login, native bootstrap/qualification, сохранение TLS/roles и idempotency, restore-to-new-target, оба audit controls и отсутствие Critical/High/Unknown. Отдельно проверить actual image/config IDs в конечных containers. Failure не исправлять повторным неизменённым запуском: сопоставить step/reason с [R1 blockers](../r1-delivery.md). Старый известный `serving_output_rejected` не является автоматически image regression; требует своего разбора R1-B04/B08. Частичный зелёный набор не закрывает CP2.

Если старый state отвергнут после обновления pin, это ожидаемая защита. Сохранить checkout, marker, исходный volume и signed backups; не переписывать marker и не выполнять bootstrap поверх старой истории. Rollback/migration границы заданы ADR 0050. Для tracking helper USER и policy mismatch использовать [tracking runbook](tracking-troubleshooting.md#cp2-переход-на-non-root-postgresql-image).

Встреченный `91aa1b7`: developer/tracking/image workflows success, Kubernetes signed migration failure с общей причиной `kubernetes_request_failed`. Storage bootstrap и Kubernetes training/evaluation прошли; это не доказательство успешной миграции. Прежняя диагностика скрывала даже вид операции. Исправленный wrapper публикует только фиксированные operation/category: `container_pending`, `timeout`, `not_found`, `forbidden`, `connection_refused` или `unknown`; private stderr, arguments, names и SQL не публикуются. Категория является диагностической подсказкой, не доказанной причиной и не разрешением игнорировать failure.

При `logs:container_pending` сначала исследовать status/termination reason собственного pod и его Job, а не считать пустые logs успешной проверкой. При `delete:timeout` проверить ownership и конечное существование Job/pods, не делать global cleanup. При `get:not_found` сопоставить lifecycle/TTL; `forbidden` требует проверки выбранной identity, не admin bypass. Transport timeout/refused требует отдельной проверки API availability. При `unknown` сохранить закрытое evidence и добавить точечную диагностику, не вывести raw stderr. Нельзя молча увеличить deadline, отключить NetworkPolicy/TLS или объявить случайный следующий pass исправлением причины.

### Отсутствующая зависимость egress probe

`f9054fc`, [run 39482741891](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39482741891): повторный отказ `exec:unknown`. Единственный `kubectl exec` через этот wrapper в migration/storage qualification запускает Bash TCP redirection. В принятом PostgreSQL image 56 APK нет Bash; [обычная конфигурация Wolfi BusyBox](https://github.com/wolfi-dev/os/blob/main/busybox/busyboxconfig) также не предоставляет Bash или nc. Это зависимость executable проверки, не доказанный отказ NetworkPolicy или SQL migration.

Исправление ограничено R1-B02: pinned `bash=5.3-r14`, `coreutils=9.12-r4`, `libacl1=2.4.0-r4`, `libattr1=2.6.0-r4` в candidate. Полный closure увеличивается с 56 до 60, остальные pins и PostgreSQL 18.6 сохраняются. Это сознательный trade-off дополнительного runtime инструментария ради проверки из настоящего PostgreSQL container: не подменяем его другим pod, не добавляем privileged debug container и не выдаём host namespace права. Дополнительные packages обязаны пройти тот же audit до adoption. Новый candidate не меняет текущий registry reference автоматически.

Self-review исключил использование SIGKILL 137 как доказательства timeout: этот код может означать внешнее завершение/OOM. [GNU timeout](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html) различает deadline 124, missing command 127 и SIGKILL 137. Поэтому build проверяет настоящий GNU timeout 9.12 и bounded sleep с exit 124. Native probe сначала открывает TCP `127.0.0.1:5432` в том же non-root PostgreSQL container, затем требует exit 124 и минимум 3 секунды для запрещённого DNS TCP. Прежний положительный контроль доступности того же DNS endpoint из разрешённой роли сохраняется. Открытая сеть, missing tool, раннее завершение, 137/143 и лишний stdout не проходят.

Последовательность: targeted contracts -> storage-artifact workflow с fresh audit/restore -> anonymous manifest/config readback -> новый immutable pin -> Kubernetes/storage/tracking regression. Эти три consumers используют общий PostgreSQL pin; GNU coreutils меняет также bootstrap utilities. Полная CI-матрица для этого исправления не требуется. До нового digest не запускать Kubernetes с прежним image и не считать unit success native fix. Если build/audit не проходит, сохранить fail/inconclusive и не отключать package-count/severity checks. Старый image и история отказов остаются доступны для rollback/диагностики; рабочие volumes не переключаются.

## CP2: новый Wolfi candidate не собрался или не прошёл audit

Причина изменения: повторные High/Critical findings прежних Debian candidates, не отказ работающей БД. [Новые recipes и источники](../image-candidates.md#cp2-wolfi-candidates-2026-10-20) требуют проверки для каждого нового image ID. Эта процедура не разрешает adoption.

1. Read-only: зафиксировать commit, stage, candidate recipe digest, image ID и `scan_executed`. Проверить pinned base/пакеты в Dockerfile, актуальный APK index, build/worker/restore/audit reports. Отсутствующий report не считать pass.
2. Ошибка package resolver: проверить доступность ровно заданных версий и signed repository metadata. Не заменять pin на `latest`, не использовать `--allow-untrusted`, не игнорировать ошибку загрузки. Изменение pin требует нового source review, build и qualification.
3. `image_audit_binding_or_coverage_invalid` / `image_audit_wolfi_package_coverage_invalid`: сравнить Syft и Grype distro/version/image IDs, наличие APK catalogue и обязательных Python/OS packages. Не удалять package database и не подменять distro вручную. Новый дистрибутив допускается только явным проверенным profile, а не wildcard.
4. `image_audit_wolfi_detection_control_failed` / `image_audit_wolfi_database_changed`: проверить свежесть и идентичность DB, exit code и detection известного уязвимого APK. До исправления причины candidate scan не считается надёжным, даже если список findings пуст. Не отключать control.
5. Worker или restore failure: сохранить конкретный отказ, не переключать baseline. Проверить Python/ONNX versions, PostgreSQL 18.6, UID 999, client binaries, TLS, signed backup и golden readback. Формат или model thresholds не менять для обхода compatibility failure.
6. После исправления проверить целиком changed image integration на disposable hosted CI: build -> actual training/inference -> signed restore в новый storage -> positive controls -> четыре scan на одной DB -> сохранение evidence. Общий audit может законно остаться fail из-за baseline; это не разрешение на adoption candidate.

Rollback: вернуть только candidate recipe/checker правку, не трогая рабочие volumes и tags. До принятия runtime необходимо зафиксировать весь установленный APK dependency closure из `apk_packages`, повторить compatibility/security проверки и выполнить предусмотренную миграцию. Локальная инфраструктура запрещена; без установленной причины не запускать неизменённую CI-матрицу повторно.

## Симптом и проверенная причина

### CP2: bootstrap наследует non-root USER image

[Run 39470747740](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39470747740), commit `e511f4f`: оба Wolfi images собраны, worker compatibility 74 cases pass; storage остановился с `storage_docker_failed:run`, audit не выполнялся. Исходный код не задавал пользователя для helper, подготавливающего новый volume. Wolfi recipe задаёт `USER 999:999`, а fresh volume требует root для подготовки ownership. Контракт воспроизвёл отсутствие explicit root; связь именно с native отказом требует нового integration run, поскольку старый report не сохранял этап.

Исправление ограничено helper: `--user 0:0`, `--network none`, read-only rootfs, `--cap-drop ALL`, только `CHOWN`, `no-new-privileges`, существующие resource limits и `--rm`. `initdb` и сервер остаются `999:999` без добавленных capabilities. Helper работает только с новым scoped volume, не с рабочей БД. Ошибки теперь различают `storage_docker_failed:volume_prepare` и `storage_docker_failed:initdb`, без вывода аргументов, сертификатов, stdout/stderr.

Read-only диагностика: проверить exact image ID, recipe USER, этап отказа и bootstrap command contracts. При `volume_prepare` проверить explicit UID и доступность shell/tar/chown; при `initdb` проверить user, client/server binaries и locale. Не лечить отказ `privileged`, снятием read-only или отключением TLS. До изменения причины не повторять тот же run. После исправления нужны полный signed restore/readback и ownership validation на disposable runner; controlled contracts не заменяют native recovery.

Image audit теперь выполняется после успешной сборки candidates даже при отказе compatibility, чтобы получить независимое evidence о packages. В workflow нет `continue-on-error`: compatibility failure сохраняет общий failure, scan pass не разрешает adoption. При build failure scan не запускается. Откат этой правки меняет только bootstrap harness/CI; действующие images и volumes не переключаются.

Native подтверждение: [run 39472427689](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39472427689), `2bb1afc`, 435 recovery checks pass, 1 000 golden rows/max error 0.0. Включены fresh target, signed backup, ownership/ACL/TLS, source/target collation и удаление собственных ресурсов. Storage ошибка устранена без ослабления runtime; это не полный M17.

### CP2: контрольная CVE имеет не ту severity

В том же run Grype DB и PyPI control прошли, все четыре SBOM прошли binding/inventory, но APK control отказал до image scans. Исходный контроль `libxml2@2.11.5-r0` требовал High для `CVE-2023-45322`, хотя [официальный advisory](https://github.com/advisories/GHSA-vqpg-m25j-7558) содержит Medium (6.5). Отсутствие image counts не трактовать как ноль findings.

Диагностика воспроизведена отдельно metadata-only PURL scan, без установки уязвимого APK и без локального контейнера/SQL service: Grype 0.120.1, тот же DB SHA256 `5bee2b8f39940a9eb07ae25eae384ae8b33fd334c9970f9f896f5941603ddbfc`; старый control дал точный match Medium и exit 0. Замена на Wolfi `openssl@3.0.7-r0` дала `CVE-2023-0286` High и exit 2; Wolfi advisory фиксирует исправление в `3.1.0-r0`. Версия бинарника проверена, официальный Windows archive SHA256 `32e3c811f31822d17592908bafdc6288aaaca3d52583c479167a8dc8399ed65d` сверён с GitHub release metadata и checksums. Это диагностический replay, не hosted acceptance образов.

Исправлен только контрольный пример, а не policy: High/Critical остаются блокирующими. Checker отвергает Medium, неправильные package/version/type/advisory/distro и exit 0. `wolfi_control_observation` сохраняет exit code, distro, выбранные ID/severity и digest исходного control report до проверки, в том числе при отказе. При новом отказе оператор сначала сравнивает эти поля с pinned profile и источником advisory; произвольный match, отсутствие данных или один exit 2 не достаточны. Отключать control, подменять distro образов либо добавлять scanner exceptions нельзя. После исправления необходим новый image audit на disposable hosted runner.

[Run 39474325096](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39474325096), `61b8e6b`, подтвердил исправление: оба controls pass, четыре scans выполнены, два Wolfi candidates pass при неизменной High policy. Baseline findings оставили весь workflow в failure. Для следующей сборки pinned полный APK closure из этого run. Если resolver или package-count guard отказывает, сначала сверить exact pins и новый inventory; не менять expected count и не снимать версии только ради зелёной сборки. Новая зависимость требует объяснения, обновления closure и повторных compatibility/security проверок. Полный список versions внутри каждого Dockerfile связан с уже существующим recipe digest, дополнительного неподписанного lock input нет.

Проверка конечного состояния с полной фиксацией packages: [run 39475658299](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39475658299), `0de97b6`, builds/count guards success, exact APK inventories 34/56 сохранены, actual worker 74 / storage 435 checks pass, оба candidate package gates pass. Общий workflow по-прежнему failure по baseline, не новый отказ control/restore. Дальше требуется отдельное принятие новых runtime references и полный image scope, а не повтор того же scan до случайного зелёного статуса. [Exact bindings и ограничения](../image-candidates.md#проверка-полностью-закреплённых-recipes).

В run `38151770889`, job `114506519932`, обычный `gh run view --log` через GitHub CLI 2.98.0 не показал итоговые JSON-строки audit и publication. Прямой job-log API сохранил обе строки длиной 188 989 байт с timestamp; сам canonical report занимает 188 960 байт и содержит 1 119 finding records. Отсутствие результата в одном viewer не означает отсутствие audit или нулевые findings. Это сравнение двух способов чтения логов, не доказательство конкретного внутреннего дефекта GitHub CLI.

Исправление: [publisher](../../scripts/image_audit_publication.py) выводит тот же JSON с переносами и отступами. Каждый символ данных сохраняется, JSON после parsing равен исходному; status, severity, findings и counts не переопределяются. Ограничения: 16 MiB canonical input и 16 KiB на строку, oversized/nonfinite input отклоняется целиком, не обрезается. Управляющие символы экранируются. Для сохранённого отчёта проверены 13 830 строк, максимум 110 байт/строка, все 1 119 findings сохранены.

Это formatter для уже очищенного image-audit summary, **не redactor для произвольного SBOM/raw log**. Не передавать ему приватные документы или model/data/keys. Исходный canonical JSON на диске не изменяется, формат остаётся обычным JSON, не NDJSON.

## Read-only диагностика

```text
gh run view 38151770889 --json status,conclusion,jobs
uv run --locked python -m scripts.image_audit_publication
```

Вторая команда читает локальный `.runtime/evidence/image-audit.json`, не CI report автоматически и не запускает scanner. Сверить его source revision, run ID, timestamps, image/config IDs, DB digest и `scan_executed` перед выводами о текущем состоянии.

Exit 0 publisher означает только успешную публикацию: внутри JSON может оставаться `status=fail`. Сам audit сохраняет exit 1 для findings, exit 2 для incomplete. Missing/invalid/oversized evidence даёт inconclusive и exit 2 publisher, без раскрытия содержимого ошибочного файла. Успешный шаг publication не разрешает выпуск после failed audit.

Если старый viewer теряет длинные строки, получить исходный job log **только в ignored файл**, не выводить terminal escape sequences на экран и не исполнять содержимое лога:

```text
gh api repos/Abrakadabra124/trusted-mlsecops-platform/actions/jobs/114506519932/logs --allow-escape-sequences > .runtime/image-audit-job.log
```

Команда проверена с gh 2.98.0. Флаг разрешает сохранение содержащих управляющие символы bytes в файл, а не отключает TLS/auth. Raw log не добавлять в Git. Для нового run сначала получить его job ID, не переносить исторические counts на текущий image.

## CP2: security patch Cilium 1.20.4

Основание: [официальный выпуск 1.20.4 от 2026-10-23](https://github.com/cilium/cilium/releases/tag/v1.20.4) устраняет CVE-2026-111943 обновлением Go до 1.26.10 и обновляет зависимости. Прежний pin 1.20.2 не включает этот security patch. Это устранение установленной зависимости, не утверждение, что все scanner findings или CP2 закрыты.

Оператор CP2 проверил SHA-256 скачанного chart против [официального Helm index](https://helm.cilium.io/index.yaml): `505abff8385811df1a949776fc42e9f10697989a332acc86d6e8933efcb855ed`; Chart.yaml version/appVersion равны 1.20.4. Содержимое архива проверялось без извлечения и исполнения. В values.yaml включён `useDigest`: agent `sha256:20fe92e4c86641233a450098c158d2d29085f3419931ab6bf681d2485dedf16e`, operator-generic `sha256:7a7a3489dc66ad67e420d285c8a8d2e169b0957ad15e120f593d27081bf38d82`. Оба digest совпадают с release notes. HTTPS и сверка hash подтверждают совпадение источников; независимая проверка подписи chart не заявляется.

Изменение затрагивает только version/hash в [bootstrap](../../mlsecops/cluster.py). NetworkPolicy, resource limits, namespace identities и остальные версии сохраняются. Рабочий Windows runtime не обновлять. Проверка разрешена только в новом disposable hosted checkout:

```text
gh workflow run kubernetes.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref codex/cp2-system-inventory
gh workflow run runtime-image-audit.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref codex/cp2-system-inventory
```

Перед запуском убедиться, что remote SHA соответствует проверяемому commit; сохранить оба run ID. Первый workflow должен подтвердить два bootstrap, Jobs, SQL/TLS и isolation denials с positive controls. Второй должен наблюдать фактические agent/operator digest, проверить неизменность inventory и просканировать те же bytes. Не выдавать успешную установку chart за устранение всех CVE. Сейчас native regression этого pin ещё ожидается.

При несовпадении chart hash ожидается отказ bootstrap. Не заменять digest на значение из неожиданного ответа и не отключать TLS. При regression сохранить очищенную причину и остановить adoption. Для воспроизведения прежнего поведения использовать отдельный checkout предыдущего commit и новый disposable runner; не делать автоматический downgrade живого кластера. Удалять только созданный и проверенный owned cluster через cleanup workflow. Возврат к старой версии сохраняет её security blocker и запрещает утверждать готовность release.

## CP2: сверка фактических образов

Симптом при расширении scope: прежние три scans ничего не доказывали о реально загруженных system/controller images. Исправление: read-only inventory, manifest/config reconciliation, дополнительное сканирование и повторный inventory после него. Controlled проверки воспроизводят ошибочные ownership, config/distro/source bindings, смену состава, отсутствующий image и неоднозначный digest. Реальный production-инцидент этим не заявляется.

Ответственный - оператор CP2. Prerequisites: чистая ветка с текущим кодом, доступ GitHub Actions и disposable hosted runner; запускать Docker/cluster этой процедурой на рабочей Windows запрещено. Для одного native прогона использовать workflow `Observed runtime image audit` на выбранном commit. Push в ветку `codex/cp2-runtime-image-audit` также запускает только этот workflow. Для ручного запуска после регистрации workflow в default branch:

```text
gh workflow run runtime-image-audit.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref codex/cp2-runtime-image-audit
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --workflow runtime-image-audit.yml --branch codex/cp2-runtime-image-audit --limit 5
```

Команды требуют действующей CLI-авторизации; наличие подключения GitHub в Codex её не заменяет. Зафиксировать конкретный run ID/head SHA и наблюдать тот же run, не повторять запуск из-за timeout интерфейса. Не открывать PR только ради запуска: он запустит общую regression matrix.

Проверенный отказ публикации после переноса Windows: `create_tree` через connector дал 403 `Resource not accessible by integration`, хотя repository metadata показывала account push/admin permissions. Это разные полномочия: права пользователя не доказывают права конкретной интеграции. `gh auth status` также подтвердил отсутствие CLI-входа, браузер показал Sign in. Владелец восстанавливает обычный вход `gh auth login --hostname github.com --git-protocol https --web` либо разрешения подключения для этого репозитория. Не извлекать старые tokens из Windows credential store и не включать их в команды, Git или логи. После входа проверить account identity, затем обычный non-force push в выделенную ветку, remote head и конкретный workflow run. Пока write-операция не прошла, успешное чтение профиля не считать восстановленной публикацией.

Workflow выполняет bootstrap, build worker/tracking, cluster, private storage, scoped controllers, tracking service, затем `python -m scripts.image_audit --runtime-state .runtime`. Это интеграция существующих компонентов без migration рабочего volume. Expected summary: scope `observed-runtime-image-audit-only`, source revision текущего checkout, runtime_scope с expected/covered counts. `release_ready` всегда false.

Ветви диагностики:

Native `1a9a26d` поднял весь disposable lab, но collector вернул `required_tool_failed` до первого SBOM. Диагностический `eacf4f9` установил этап `pod-cri-identity`. Controlled RED воспроизвёл случай, когда Pod сообщает manifest digest, а CRI lookup принимает разрешённый image config ID. Исправление использует уже hash-checked config для `crictl inspecti`, сохраняя проверки returned ID, registry digest и экспортированных bytes. Native `c899f43` прошёл lookup, но ответ не удовлетворил `image_scope_cri_identity_invalid`; audit ещё не начался. Теперь причины разделены: `image_scope_cri_config_mismatch`, `image_scope_cri_references_invalid`, `image_scope_cri_references_missing`. Ни одна не разрешает пропуск образа. CRI (Container Runtime Interface) - интерфейс Kubernetes к container runtime; manifest digest и config digest обозначают разные объекты. Первичная реализация [containerd ImageStatus](https://github.com/containerd/containerd/blob/v2.1.3/internal/cri/server/images/image_status.go) формирует ID и RepoDigests отдельно; наличие config само по себе не доказывает наличие registry reference. Это справочный источник, не утверждение версии containerd в стенде.

- `image_scope_*` / `image_audit_runtime_*`: сверить ownership, controller profile, image IDs и stage failure. Registry manifest обязан указывать на наблюдённый config. Не заменять reference на `latest` и не исключать проблемный Pod из inventory.
- [40749336227](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40749336227), `c8e2f23`, установил `image_scope_cri_references_missing`: config совпал, но RepoDigests пуст. Исправление сохраняет hash-checked config и bounded CRI repoTag только как локальный указатель для экспорта. `ctr images export --local --platform linux/amd64 - <alias>` читает фактический containerd image в private archive; [upstream export](https://github.com/containerd/containerd/blob/v2.1.3/cmd/ctr/commands/images/export.go) описывает совместимый manifest.json. `--local` исключает transfer progress из бинарного stdout. Перед Syft проверяются архивный config digest, OS/architecture/layers/labels; смена alias на другие bytes блокируется. Timeout 300 s, archive limit 4 GiB, stderr limit 2 MiB. Экспорт не выполняет pull, load, tag либо замену runtime. Отсутствие и tags, malformed identity либо изменившийся snapshot по-прежнему запрещают pass. Native результат исправления фиксируется в STATUS отдельно от controlled tests.
- `image_audit_runtime_changed`: сохранить refusal; выяснить, менялся ли lab во время scan. После исправления причины допустим новый отдельный run. Старый snapshot не переписывать.
- Если CRI сообщает RepoDigest, это ещё не доказывает возможность скачивания через registry: предзагруженный image может иметь только локальную историю. При наличии validated repoTag теперь также используется containerd export с проверкой manifest -> config -> archive. Если локального alias нет, прежний digest-only registry путь сохраняет refusal при недоступности. Native `22371d8` впервые завершил before/after inventory (14 images, 4 fully covered) и выявил отдельные scanner findings; новая ветка экспорта для RepoDigest ещё требует native подтверждения.
- Подтверждение исправления: [40752836255](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40752836255), `4012505`, получил все 14 config/archive bindings без `required_tool_failed`, before/after inventory совпал. Шесть Debian targets не удовлетворяют текущему required-packages profile; Ubuntu и нераспознанный distro не поддержаны; два system applications остаются unapproved. Не переводить эти 10 targets в pass из-за успешного экспорта. Полное покрытие 4/14, audit fail из-за findings, все owned cleanup steps success.
- `image_audit_runtime_application_coverage_unapproved` или `image_audit_runtime_distro_unsupported`: OS/package coverage недостаточно. По фактическому SBOM определить состав application binaries, поддерживаемые catalogers и обязательные packages; оформить профиль с отрицательными тестами. Не разрешать pass по одному наличию libc.
- High/Critical сохраняют fail даже при неполном application coverage. Unknown, scanner crash и недоступность digest сохраняют inconclusive. Успешная печать summary не означает успешный scan.

Recovery/rollback: job останавливает только проверенные tracking/host-storage containers и удаляет только кластер с подтверждённым ownership. Если bootstrap не успел сохранить marker, cleanup не угадывает владельца; остатки исчезнут с disposable VM. При несовпадении ownership оператор прекращает ручные удаления и фиксирует блокер. Вне этой VM нет deployment, следовательно rollback действующей платформы не нужен. Raw runtime snapshots, keys, Docker inspect и SQL credentials не загружать в публичные artifacts. Завершение CP2 требует native evidence и устранения coverage/findings blockers; текущие controlled tests это не заменяют.

## Решение по результату

1. `scan_executed=false`, invalid/stale DB, timeout или missing coverage: evidence неполно. Проверить доступность registry/DB, ownership процесса и его текущий handle. Не запускать новый audit только из-за timeout наблюдения и не менять severity threshold.
2. Полный scan с High/Critical: это security failure. Сверить package/version/advisory с vendor и фактическим image, зафиксировать доступный fixed version либо отсутствие подтверждённого fix. `wont-fix/no-dsa` не превращается в автоматическое исключение из политики проекта.
3. Новый кандидат строится и проверяется по [отдельному candidate flow](../image-candidates.md), затем [fresh-target restore](../storage-candidate.md) и same-DB audit. Не заменять image работающей БД и не монтировать её volume в candidate.
4. Не удалять package database ради уменьшения findings. Удаление действительно ненужных binaries требует проверки зависимостей, работоспособности и новой SBOM, а не одного меньшего числа CVEs.
5. Publisher не меняет deployment, поэтому runtime rollback не требуется. При ошибке форматирования сохранить canonical evidence, исправить formatter и повторить только publication; новый scan нужен при изменившихся/устаревших scanner inputs.

## Проверенная triage на 2026-10-11

Из raw report `d44d1fe`: baseline worker 0 Critical/56 High, baseline storage 11/118; worker candidate 0/55, storage candidate 3/88 и 1 Unknown. Все четыре scans fail. Это scanner matches, не четыре доказанные exploit paths и не общее количество уникальных уязвимостей.

- В локальных candidate images уже установлен glibc `2.41-12+deb13u4`. [Debian CVE-2026-5450](https://security-tracker.debian.org/tracker/CVE-2026-5450) указывает исправление для этой trixie-версии; повторная установка той же версии не устранит оставшиеся findings.
- Storage содержит libxml2 `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. [Debian CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653) отмечает её уязвимой; fixed package указан для forky/sid, не выбранной stable trixie. Суффикс `really2.9.14` важен, нельзя считать пакет исправленным по префиксу 2.12.7.
- [Debian CVE-2026-88647](https://security-tracker.debian.org/tracker/CVE-2026-88647) и [страница GnuTLS package](https://packages.debian.org/trixie/libgnutls30t64) подтверждают, что выбранный `3.8.9-3+deb13u4` не имеет объявленного fix для этого advisory. Upstream assessment ещё отмечен как ожидаемый; это не основание скрыть scanner Critical.
- Для [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) fixed GCC 14 указан в sid, тогда как trixie `14.2.0-19` уязвим. Смешивать stable/unstable packages без отдельного совместимого runtime плана нельзя.
- Третий Critical storage match `CVE-2026-95210` относится к тому же GnuTLS. Повторный vendor fetch в этой итерации завершился timeout; подтверждено наличие finding в scanner report, но не новый vendor fix. Отсутствующий ответ не доказывает отсутствие исправления.

Изменение форматирования не устраняет эти уязвимости. Нужны поддерживаемые исправленные runtime inputs и повторная квалификация; M01/R1 остаются непринятыми. Новые пороги, scanner ignores, расходы и перенос работающей истории этой процедурой не разрешаются.

## Проверка восстановления наблюдаемости

Unit suite: large-report round trip, сохранение всех outcomes/полей, escaping, size limits, отсутствие изменения input, generic failure на malformed/missing evidence и module entrypoint. Native критерий: из обычного `gh run view --log` нового completed run извлечён полный publication JSON, его fields/counts/DB/images доступны, audit всё ещё failure при прежних findings. Unit success сам по себе этот CI-критерий не доказывает. Ссылки на завершённые runs фиксируются в STATUS.

Критерий подтверждён в [clean-checkout CI 38153385533](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38153385533) на `57cfee7`: direct audit JSON и опубликованный JSON получены обычным CLI и совпали после canonical normalization, digest `cd3ce2c2d9180ae059ce0dbb827c9e5102cbae16e3046e5ad8f13a420be2edc3`. Все 1 119 finding records сохранены, maximum line 115 bytes. Семь tests и 21/21 statements/6/6 branches publisher прошли; audit завершился fail из-за оставшихся High/Critical. Publication success не замаскировал failure.
