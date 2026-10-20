# RB-18: отказ image audit и неполный просмотр CI

Ответственные: platform operator и security reviewer. Процедура относится к scanner evidence лаборатории, не к production-инциденту. Рабочие SQL volumes, runtime tags и foundation не меняются.

## CP2: новый Wolfi candidate не собрался или не прошёл audit

Причина изменения: повторные High/Critical findings прежних Debian candidates, не отказ работающей БД. [Новые recipes и источники](../image-candidates.md#cp2-wolfi-candidates-2026-10-20) ещё требуют native compatibility/security проверки. Эта процедура не разрешает adoption.

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
