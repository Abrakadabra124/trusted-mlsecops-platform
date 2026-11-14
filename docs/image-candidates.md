# Отдельные images для исправления findings

Scope T01/T02. Candidates не заменяют `trusted-mlsecops:dev`, pinned working PostgreSQL, работающие containers или persisted volumes. Пороги security audit не ослабляются. Решение и альтернативы: [ADR 0015](decisions/0015-image-candidates.md).

## R1-B02, кандидаты для проверки от e9883eb

Компонентный аудит от 6 ноября просканировал пять образов на одной базе Grype (`vulnerability.db` SHA-256 `01a5143d2e74a83468632a846dcd9d9ad5a2329f99754c64e72fdc9683cf1ee5`). У worker, worker-candidate и tracking было по 1 Critical / 5 High / 14 Unknown matches, у storage и storage-candidate по 0 / 2 / 0. Следующий запуск отменён во время аудита. Результаты относятся к образам первого запуска. Для PostgreSQL анонимное чтение GHCR по закреплённому manifest `sha256:bd279118884568f35de40901ee9438f17af7c2e75a0623be89b36bbd69b68fe5` подтвердило байты manifest и linux/amd64 config `sha256:ef426cb1343f72de96bcc72aade0ee57f552b806cdd7e93f80b98d41117fe059`, совпадающего с отчётом. [Завершённый аудит](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42251232450), [отменённый запуск](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42298587191).

| Образы для сборки | Изменение APK | Основание для проверки |
| --- | --- | --- |
| Worker-candidate, storage-candidate, tracking | Четыре связанных пакета glibc 2.44 с r8 на r17 | В рецепт r17 включён backport для High CVE-2026-84243. [Рецепт Wolfi](https://github.com/wolfi-dev/os/blob/12322098617a3121cd8f64275bbf4f130b9a4279/glibc-2.44.yaml) |
| Worker-candidate и tracking | Python и python-base 3.12.15-r4 на 3.12.16-r3 | Для ветки 3.12 Python Software Foundation указывает affected <3.12.16 для Critical CVE-2026-115557. r3 включает коррекцию набора backports в Wolfi. [Запись CNA](https://cveawg.mitre.org/api/cve/CVE-2026-115557), [изменение r3](https://github.com/wolfi-dev/os/commit/9d07f86d4c5758703508b67c6dc5e5a9ef322b77) |
| Worker-candidate и tracking | libexpat1 2.9.0-r0 на 2.10.0-r0, py3-pip-wheel 26.2.1-r4 на 26.2.2-r2 | Отчёт указывает эти диапазоны исправлений для двух High matches Expat и одного High match в pip wheel. [Отчёт сканера](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42251232450/job/128006556883) |

В проверенном x86_64 APKINDEX (SHA-256 `18d32c617496039a6c2d49cbe8c96cda959d1dffff9ded83a8038c8ca8ea1933`) у всех 34 pins worker-candidate и tracking и 60 pins storage-candidate есть записи. Их объявленные зависимости и конфликты разрешаются внутри каждого списка. Для High CVE-2026-119586 отчёт указывает `sqlite-libs=3.54.1-r0` без fixed version. В этом индексе более новой версии библиотеки нет. Запись CNA описывает команду SQLite CLI `.recover`; применимость к исполняемому образу отдельно не проверялась. На 6 ноября этот match блокировал аудит. [Индекс Wolfi](https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz), [запись CNA](https://cveawg.mitre.org/api/cve/CVE-2026-119586).

**Проверка на hosted runner.** На чистом ref с этой правкой выполнить [компонентный image-audit](../.github/workflows/image-audit.yml). В опубликованном отчёте сверить `source_revision` с SHA выбранного ref, `source_dirty=false`, пять выполненных scans, config IDs, digests архивов, SBOM и базы. Для точного варианта этой правки ожидаемые `recipe_digest` у worker-candidate, storage-candidate и tracking соответственно `44dd7a958f02b459ed967ec61aa6c9b88458aef0efadbcc3bbea70b41c10d2f3`, `d1cb675013b9d3863fcadeae6612da328df23b4bf6d8ac39110833edec486c21` и `88ad04fcc902ec0ea54220a194e4794b6e01f686e0e1d94d5e0f728691253d2f`. У tracking это digest всех build materials. Сравнить package/version/severity каждого кандидата и статусы совместимости worker и signed storage restore; tracking использует свой штатный [functional workflow](../.github/workflows/tracking.yml). Host закреплён на 3.12.15, обе сборки worker используют 3.12.16. При оставшихся High/Critical сохранить отказ.

На `c5cd429` новый worker прошёл 74 проверки, storage прошёл 435. Worker-candidate, storage-candidate и tracking получили 0 Critical / 0 High / 0 Unknown. Базовые worker и PostgreSQL получили соответственно 1/7/18 и 0/4/4 на той же базе Grype. Эта база не вернула прежний SQLite match при той же версии пакета. Для следующего прогона основной Dockerfile использует проверенный recipe worker. [Первый компонентный прогон](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43544490724).

Отдельный строгий аудит Python-зависимостей tracking обнаружил CVE-2026-126360. В `uv.lock` и tracking lock обновлён opentelemetry-api до 1.45.2. Tracking SDK 1.45.2 требует эту версию API и semantic-conventions 0.66b2. Перед обновлением привязки `data.lock` повторная генерация подтвердила исходные 1 915 576 байт и SHA-256 `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`. [Отказ tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43544495776), [advisory](https://github.com/advisories/GHSA-mf5v-w3w3-f6cg).

Для полного R1-B02 после исправления и принятия зависимостей требуется [observed runtime audit](../.github/workflows/runtime-image-audit.yml) на итоговой ревизии. Последний полный inventory просканировал 14/14 наблюдаемых ссылок, approved application coverage достигло 4/14. Системные findings и покрытие проверяются по собственным образам node, control plane, Cilium и остальных pods. [Результаты и границы покрытия](evidence/cp2-system-images-2026-10-28.md).

## CP2: Wolfi candidates, 2026-10-20

Обязательный scope R1-B02, не дополнительное усиление после R1. Последний audit `61c6849` оставил worker candidate 0 Critical / 55 High и storage candidate 1 Critical / 85 High. Для найденных glibc defects Debian trixie пока не выпускает security update: [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435), [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499). Это не разрешение игнорировать matches или менять threshold.

Новый isolated comparison сохраняет Python 3.12.15 и PostgreSQL 18.6, но использует публичный [Wolfi base](https://images.chainguard.dev/directory/image/wolfi-base/overview). OCI index SHA-256 `81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323` и amd64 manifest `76811b6958657eb28da6f2ce79bbb97516e5818df442a086e94ab4c67303608b` проверены через registry HTTP; layer readback подтвердил `ID=wolfi`, `VERSION_ID=20230201`. Контейнеры локально не запускались.

- Worker: Wolfi `python-3.12=3.12.15-r4`, `glibc-2.44=2.44-r8`, `libstdc++=16.2.0-r1`; uv используется только в build stage, interpreter указан явно, managed Python download запрещён. Locked Python dependencies остаются прежними.
- Storage: `postgresql-18=18.6-r5`, client той же версии, glibc pin; имя postgres связано с UID/GID 999, server и client version проверяются при build. Default auto-init не добавлен, runtime запускает существующий initdb/postgres flow.
- Версии сверены с [APK repository index](https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz), SHA-256 снимка `c5251e8283504eb1f5b25b120e7455fdbb77f4b5110f0b0869aa4b4d4e049c85`. Ответственность пакетов и пути binaries проверены по исходникам [Python](https://github.com/wolfi-dev/os/blob/main/python-3.12.yaml), [PostgreSQL](https://github.com/wolfi-dev/os/blob/main/postgresql-18.yaml), [glibc](https://github.com/wolfi-dev/os/blob/main/glibc-2.44.yaml). Наличие recipe и version pin не доказывает успешную установку или безопасность.
- Audit разрешает Wolfi только для двух явно выбранных candidate targets. Он требует совпадение distro/version/image между Syft и Grype, APK catalogue для системных пакетов и исходные Python/OS package coverage checks. Package database не удаляется. High/Critical, Unknown, ignored matches и coverage alerts сохраняют прежние результаты.
- Дополнительный positive control сканирует известный уязвимый Wolfi APK `openssl@3.0.7-r0` на том же DB snapshot и должен обнаружить `CVE-2023-0286` / `CGA-6vj8-747q-h83f` с High/Critical severity и exit 2. [Wolfi advisory](https://github.com/wolfi-dev/advisories/blob/main/openssl.advisories.yaml) задаёт fixed version `3.1.0-r0`; [GHSA](https://github.com/advisories/GHSA-x4qr-2fvf-3mr5) подтверждает High. Поддержка [APK](https://oss.anchore.com/docs/capabilities/apk/) и [PURL distro hint](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/) проверена по документации Anchore. Это metadata-only контроль feed, уязвимый пакет не устанавливается в images. `--fail-on high`, image thresholds и запрет exceptions сохранены.

### Native comparison и фиксация APK closure

[Run 39474325096](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39474325096), commit `61b8e6b`: оба positive controls pass, все четыре scans выполнены на одной DB SHA256 `8fe53df7787c1f89f11a03e33ee9bbe3d51037c55785fdfdabdfb0fa71a5a91f`. Worker compatibility 74 cases pass; storage recovery 435 cases pass, 1 000 golden rows/max error 0.0, SQL restore 3.617236 s, restore-to-golden 5.574964 s.

| Image | Critical | High | Medium | Low | Negligible | Unknown | Package gate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline worker | 0 | 56 | 59 | 11 | 47 | 0 | fail |
| Baseline storage | 9 | 132 | 153 | 47 | 125 | 0 | fail |
| Wolfi worker candidate | 0 | 0 | 6 | 0 | 1 | 0 | pass |
| Wolfi storage candidate | 0 | 0 | 0 | 0 | 0 | 0 | pass |

Это количества scanner matches, не доказанные exploitable paths. Worker не объявляется полностью свободным от уязвимостей. Общий workflow ожидаемо failure из-за baseline; ни один result не исключён из policy scope. Сравнение не означает adoption, complete M01/M17/M22 или R1.

Из native `apk_packages` зафиксированы **все 34 worker и 56 storage APK name/version**, включая транзитивные и base packages, прямо в recipes. Exact pins вместе с build-time проверкой количества установленных packages запрещают незаметное расширение dependency set. Локальная сверка подтверждает равенство всего списка native inventory, а не только основных трёх библиотек. SHA256 canonical inventory: worker `2017ad3ee392a37229abd633fdd210971ba03077ca4ed30eb6181a6c4ae2e0aa`, storage `3b2fdfdb4f229231d900258a61a1949a47ec1d912e602fdea77de06fd50b18e0`.

### Проверка полностью закреплённых recipes

[Run 39475658299](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39475658299), job `118810824029`, attempt 1, commit `0de97b6731347e051be5ff11d1705a84bc88c18a`: clean hosted build с полными pins и package-count guards success. Новые `apk_packages` точно равны предыдущим спискам, включая каждую name/version; closure hashes выше сохранены. Все четыре scans выполнены, counts/status совпадают с таблицей; controls pass. DB SHA256 этого run `5bee2b8f39940a9eb07ae25eae384ae8b33fd334c9970f9f896f5941603ddbfc`, canonical audit-report SHA256 `ccca020b32ea56b797382c6fe01ee8bb6e75521d2e2081f3b42636209df79324`. Разные snapshots между runs допустимы; внутри каждого comparison используется одна проверенная DB.

| Candidate | Exact image config ID | Recipe SHA256 |
| --- | --- | --- |
| Worker | `sha256:b46fee05289129d0e6d02dec11e1aa3aa2020219114604ceccc396e3eef04a61` | `f4db944536dbbe594adf5d650cd05aae042d4e9d1f269ca00e90a49e6174bec0` |
| Storage | `sha256:6887337f0ca77ecdbbbcd8c53a430345ff58a868022eaa483815566e04f0bf3b` | `0a86de8979589cf4f4bd1d2042c34ffba27d06364fe3413286d0d5a0bbe8059f` |

154 controlled audit, 40 storage-image, 14 orchestration contracts pass. Actual worker compatibility 74 cases pass, report digest `7684c7e4ca5f0fc1516f8254bb724ff8e2d42db4273934e7b7f17595b09cdeae`. Actual storage recovery 435 cases pass, report digest `3af7e4e508b76f885fbe0654ddec7c5ea952785a3873411f13e61c8255640f74`: 1 000 golden predictions/error 0.0, SQL restore 2.627095 s, restore-to-golden 4.079227 s. Resource ownership и cleanup проверены qualification. Эти времена не доказывают полный product RTO.

**До adoption:** scoped migration/rollback для принятия runtime и полный image scope, включая controllers. Рабочие tags, SQL volumes и baseline здесь не меняются; image config ID не является registry manifest digest и не используется как выдуманный опубликованный OCI reference. Package versions и base digest не доказывают bit-for-bit воспроизводимость OCI archive: registry retention, builder metadata, timestamps и scanner DB остаются отдельными inputs. При недоступном pin сборка должна отказать, а не выбирать новую версию. Общий workflow failure по baseline остаётся действительным запретом выпуска.

## Предыдущий Debian-вариант, 2026-10-09

Worker собирается в два этапа: pinned uv устанавливает locked Python dependencies, а отдельный pinned Python 3.12.15 runtime получает только venv и код. Исполняемые uv/uvx с Rust dependencies не попадают в final image. Debian libpcre2-8-0 установлен в точной исправленной версии `10.46-1~deb13u3` с проверкой APT signatures/hashes через HTTPS. Остальные пакеты не подвергаются плавающему dist-upgrade.

PostgreSQL candidate сохраняет версию 18.6 и использует pinned trixie вместо bookworm. Неиспользуемые проектом gosu/auto-init entrypoint удалены в подготовительном stage, final filesystem копируется в новый image без старых layers. Сохранены dpkg package inventory и библиотеки PostgreSQL. Это не попытка удалить metadata, чтобы scanner ничего не нашёл. Server запускается напрямую; UID 999 задаётся runner, как в текущем storage profile. По умолчанию image не инициализирует database и не является drop-in заменой обычного Docker Hub postgres entrypoint.

У recipes разные SHA-256 labels. Дополнительно проверяются role, app source fingerprint, Linux amd64 и immutable local image ID. App source fingerprint сам по себе недостаточен: разные recipes могут содержать одинаковый app code. Квалификация и audit повторно проверяют recipe binding.

## Воспроизведение

Для текущей работы выполнять только на разрешённом disposable hosted CI из clean checkout с Linux amd64 Docker Engine и locked Python environment. Локальные Docker/WSL/Kubernetes/SQL не запускать:

```bash
uv sync --locked --python 3.12.15
uv run --locked python -m scripts.image_suite_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.tracking_spike build
uv run --locked python -m scripts.image_candidates build
uv run --locked python -m scripts.image_candidates qualify-worker
uv run --locked python -m scripts.storage_candidate
uv run --locked python -m scripts.image_audit --compare-candidates
```

Команда `image_candidates build` создаёт только `trusted-mlsecops:worker-candidate` и `trusted-mlsecops:storage-candidate`; отдельная команда `tracking_spike build` подготавливает обязательный MLflow target. Worker qualification использует новый UUID state в `.runtime/image-candidates`, immutable image ID и existing developer suite, не рабочие signing keys или SQL. Отсутствие image и сбой нового запуска инвалидируют старый qualification pass.

С policy v2 от 2026-10-28 последняя команда сканирует пять images на одном read-only DB snapshot: worker, storage, tracking и два remediation candidates. Baseline findings сохраняются, даже если candidate лучше. Общий audit остаётся fail, пока любой image в scope содержит блокирующие findings; incomplete tracking запрещает общий pass. `comparison.status=pass` означает только полноту четырёхкомпонентного сопоставления worker/storage, не прохождение общей security policy; `release_ready` всегда false. Пары сравниваются по advisory ID и package name, а не installed version: обновление версии при сохранении того же advisory не выдаётся за исправление.

Результаты, ignored: `.runtime/evidence/image-candidate-build.json`, `.runtime/evidence/image-candidate-worker.json`, `.runtime/evidence/image-audit.json`. Raw SBOM/config и keys не публиковать. `--compare-candidates` не делает restore и не переключает deployment.

## Проверено локально 2026-10-09

- Build обоих recipes завершился. Worker: `sha256:7aa0567ae25dd6b376171b0fe371d896b552f9f8cd582a05d70d2b45bc4d0f35`, 649 129 357 bytes. Baseline tag остался `sha256:1d3097282d04d64be21329fc9c60690c6a64f3517a9df4d102335000a6e933e0`.
- Storage candidate: `sha256:05ddb14c7244f4c6d1264f8b6412a1fffe3882a6d88702173b02caa71775f012`. Ни одна working БД не заменялась.
- 74 developer checks worker candidate прошли. Три fresh training runs дали max probability difference 0.0, AUPRC 0.9323007296445032, max ONNX parity error 2.086162567138672e-7. Это synthetic component qualification, не доказательство бизнес-utility или прохождение M20 нового image.
- Native Syft подтвердил 128 package artifacts worker candidate и 145 storage candidate против 1 152/151 baseline. Package artifacts могут включать повторяющиеся libraries в разных binaries; уменьшение этого числа не измеряет снижение риска в процентах.
- 123 controlled checks: 43 policy/report, 15 archive, 25 scanner/CLI, 18 orchestration, 16 candidate и 6 comparison. У пяти audit/candidate modules branch coverage 98/100 (98%), combined 98,45%. Контрактные fixtures и mocks не заменяют native scan.
- Native comparison завершился локально и в [clean-checkout CI 37847315083](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37847315083) на `d4b5514`: одинаковая vulnerability DB, одинаковые findings/deltas. Worker High 56 -> 55; storage Critical 7 -> 1, High 101 -> 79. Оба candidates остаются fail, исключений нет. [Evidence и 37 residual triage groups](evidence/image-candidates-2026-10-09.md).
- Storage candidate добавил четыре advisory IDs, включая восемь High matches. Уменьшение общего количества не доказывает отсутствие регрессии. Pair deltas также включают переименования packages при смене Debian; их нельзя интерпретировать как число исправленных CVEs.
- CI повторил 74 worker checks и 123 controlled checks. После локального audit все 10 принадлежащих ему scanner containers отсутствуют; baseline worker tag не изменён. Старые timeout attempts сохраняют свой прежний inconclusive, но не определяют результат нового завершённого run.

## Что остаётся до adoption

1. Исправить или доказательно исследовать остаточные High/Critical, включая Critical libxml2 и новые GnuPG findings. Native comparison завершён, security gate не пройден. Не создавать исключения только по vendor marketing или названию hardened image.
2. [Signed backup/restore rehearsal](storage-candidate.md) выполнен 2026-10-11 на fresh synthetic source: 434 проверки, 1 000 golden predictions/error 0.0. Это не перенос рабочей истории; sample collation check не доказывает полную ABI/locale эквивалентность. Для adoption остаётся scoped migration актуальной истории.
3. Включить новый image в проверяемый bootstrap/migration policy, подготовить rollback и лишь затем менять deployed reference. К текущему volume candidate не подключать до этих проверок.
4. После adoption повторить затронутые M02/M03/M20 и связать все gates с одним candidate в M18. Старые source-compatible pass не являются доказательством безопасности нового runtime.

[Исходные findings](evidence/container-audit-2026-10-08.md), [audit runbook](container-audit.md), [CI](../.github/workflows/image-audit.yml). Полный R1 остаётся незавершённым.
