# Сравнение image candidates: 2026-10-09

Статус обоих candidates **fail**. Сборка, функциональная проверка worker и native scan выполнены; выпуск не разрешён. Baseline tags и работающая SQL-БД не изменены. Этот результат показывает реальную проверку гипотезы remediation, а не безопасную production-платформу.

## Воспроизводимый эксперимент

- Clean-checkout commit: `d4b55148d0c9c961fe709bf0422ad778b9949c8c`.
- [Image audit CI 37847315083](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37847315083), job 113551300006: failure именно по findings. Contracts, оба builds, worker qualification и публикация sanitized summary завершились success.
- CI run ID: `2221af1186cf46979c0064e358261ac2`, завершён `2026-10-08T21:34:41.396213+00:00`.
- Source fingerprint: `718367566a39b8d4d4f81fb731d89a012f5bee09333277a2d4e37bbbf7391436`.
- Policy digest: `b778b24407ac627c180067b62f0e28b7dcecd7328a4102516821d2e46911d9dc`; High/Critical блокируют, исключений нет.
- DB: `v6.1.10`, built `2026-10-08T06:33:47Z`, valid true; SHA-256 `13189d835d54559219f1774870455a8401ca01f538bd00fddef7f4ce55350f74`.
- PURL detection control: pass, report SHA-256 `e1642b348fbd1a644b7842e6a11e2410f55fa7f9878481ec18c6a95c8b46c9be`.
- Syft 1.54.1 и Grype 0.120.1, digest pins и команды: [runbook](../container-audit.md), [candidate flow](../image-candidates.md).

## Что измерено

| Image | Package artifacts | Matches | Critical | High | Medium | Low | Negligible | Unknown | Advisory IDs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| worker | 1152 | 173 | 0 | 56 | 59 | 11 | 47 | 0 | 81 |
| storage | 151 | 436 | 7 | 101 | 146 | 47 | 119 | 16 | 175 |
| worker-candidate | 128 | 172 | 0 | 55 | 59 | 11 | 47 | 0 | 80 |
| storage-candidate | 145 | 292 | 1 | 79 | 81 | 33 | 98 | 0 | 104 |

Package artifacts не равны уникальным библиотекам: один dependency может присутствовать в разных binaries. Matches не равны независимым эксплуатируемым CVEs. Advisory IDs не объединены по aliases. Все четыре scan reports прошли проверку identity/coverage/DB, native exit code каждого - 2 из-за High/Critical.

### Worker

Multi-stage recipe не переносит uv/uvx из builder. 1 024 Rust package artifact instances исчезли из runtime inventory, но все baseline High относились к Debian packages. Поэтому уменьшение SBOM с 1 152 до 128 нельзя называть снижением риска на 89%.

Единственная исчезнувшая advisory/package pair - `CVE-2026-103111` / `libpcre2-8-0`: установлен `10.46-1~deb13u3` вместо `10.46-1~deb13u2`. [Debian подтверждает fixed security version](https://security-tracker.debian.org/tracker/CVE-2026-103111). Оставшиеся 55 High matches не скрыты. Новых advisory IDs и pairs нет.

### PostgreSQL

Переход bookworm -> trixie и удаление неиспользуемого gosu дали 7 -> 1 Critical и 101 -> 79 High matches. Это улучшение части inventory, не достаточное основание для adoption.

Изменение package names при смене distro создаёт пары removed/introduced даже для прежнего advisory. Поэтому 185 removed pairs и 41 introduced pair **не означают 185 исправленных и 41 новых уязвимостей**. На уровне advisory IDs исчезли 75, добавились 4, сохранились 100. Установленная версия при сохранении того же ID/package не считается исправлением. 251 pair остаётся в обоих images.

Новые advisory IDs: `CVE-2026-24882`, `CVE-2026-86137`, `CVE-2026-86139`, `CVE-2026-86141`. Из них два ID дают 8 новых High matches: семь GnuPG packages и один libxml2. Это не скрыто за общим уменьшением counts.

Оставшийся Critical - `CVE-2026-6653` в `libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3`. [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-6653) указывает на возврат package к кодовой базе 2.9.14 и отсутствие stable fix: числовой префикс 2.12.7 не доказывает исправление. У Debian issue имеет minor/no-dsa, у scanner - Critical; это различие assessment, не автоматически одобренный waiver. [Новый GnuPG advisory](https://security-tracker.debian.org/tracker/CVE-2026-24882) относится к TPM-backed decryption; scanner package match сам по себе не доказывает доступность этого пути из приложения.

## Функциональная проверка и локальное повторение

- Worker candidate: **74 developer checks** в CI и локально, три настоящих fresh-process training runs. AUPRC каждого `0.9323007296445032`, baseline `0.4073333333333333`, positive holdout `1222`.
- Max probability difference `0`, max Python/ONNX parity error `2.086162567138672e-7`. Это synthetic numerical reproducibility, не business utility и не bit-for-bit image reproducibility.
- CI worker qualification report SHA-256: `07946312224200d90448ea5e5bb1606772e1ee8c8e112bd53432c1b9039a6401`.
- 123 controlled checks: 43 report/policy, 15 archive, 25 runner, 18 flow, 16 candidate binding, 6 comparison. Пять audit/candidate modules: 98/100 branches, combined 98,45%. Это не coverage всего проекта/M18.
- Локальный audit `653dbcbaaa934d8aa34527fdc9a2bd1c` завершён `2026-10-08T21:34:57.091503+00:00`, detection control pass, итог fail. В отличие от предыдущих timeout attempts, этот запуск скачал DB и выполнил все четыре scan.
- Local и CI использовали одинаковые bytes `vulnerability.db`; отдельно сравнены все 1 073 finding records четырёх images по advisory/package/version/severity/type/fix state/fixed versions - совпали. Severity counts и advisory/package deltas также одинаковы. Wrapper timestamps/DB last-check metadata и image IDs различаются, идентичность всех report bytes не заявляется.
- Локальный запуск начат на dirty tree предыдущего HEAD `d1a420d` перед публикацией `d4b5514`; в evidence есть hashes runner files. Clean-checkout evidence относится именно к CI `d4b5514`, а не переименованному локальному run.

## Регрессия baseline на том же commit

| Workflow | Проверенный результат |
| --- | --- |
| [Documentation 37847315061](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37847315061) | success |
| [Developer runtime 37847315045](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37847315045) | success |
| [Storage 37847315041](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37847315041) | success; M03 431 cases, recovery 430 cases, 1 000 golden predictions с error 0.0 |
| [Kubernetes 37847315026](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37847315026) | success; private storage 436 cases, migration 497 cases, M20 722 cases |
| [Image audit 37847315083](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37847315083) | failure; оба baseline и оба candidate нарушают severity policy |

M20 завершён `2026-10-08T21:42:55.261875+00:00`, baseline runtime image `sha256:d71259341efdea0dd70d4805bf8faa7c3804a280b52c8ec40949e390ea346a7a`. Workflow jobs строят images отдельно: совпадение source fingerprint не превращает их в один release candidate и не закрывает M18. Проверка M03/recovery использовала прежний PostgreSQL bookworm, не trixie candidate. M20 baseline не является приёмкой нового worker candidate. Независимое CI-исполнение не заменяет независимый human review.

## CI artifact bindings

### worker

- Runtime/config ID: `sha256:0c34df43c935e6fa10bb6ec7958ad99c44a01503ce5bf165a59ec2e0b8f11eee`.
- Archive SHA-256: `02e5edddcfcd1028fcf6fa69910458d2cbc064390f432e0098d601bc0b162682`.
- SBOM SHA-256: `b7baa1e159ab334cf528a8e1e28c336872d42e6dd0f683a93bc6086acec2a040`.
- Grype report SHA-256: `adbd746534b78111aff30a1b875213165d5954120ad69e88654372246b98817b`.

### storage

- Runtime/config ID: `sha256:2e182ed2ff8f5d0835353864264437a26dffc542a9a6c677ec495aa54e491627`.
- Archive SHA-256: `b08cb3eb11ee9c4f9f82ef58375c5c46836f0100450e722617b39cf5f00a6ac6`.
- SBOM SHA-256: `68e0e2389b012eabfb757308a815855eef2e7f836f6dc0fb0e296efcf3e2385e`.
- Grype report SHA-256: `b403aee059b194c877a9898874fc34fec5814c2e7c2c252e1b9b2cd857b2f943`.

### worker-candidate

- Runtime/config ID: `sha256:10821f5ed73c9ed7c5a261aae5c3ce80b2c8a997a223e79eca410d07a3c4e05c`.
- Archive SHA-256: `85e494c17aeb1b678dde15cd7d1f97bde56d9295386a53b89b4805436112b9b0`.
- SBOM SHA-256: `87af36c9cecbab6000ef948421b8198c8720a6d7a9606546ae596b2c9197b620`.
- Grype report SHA-256: `3419fd22381251b1e044a0426274514b5c206aa1dc506596898a84bdc6ec705e`.
- Candidate recipe SHA-256: `0d97ebef0ff0c6fbdcb0204de153384ab81b31fa6e57f3b9de3cd4753a918d83`.

### storage-candidate

- Runtime/config ID: `sha256:18bc88ec9586c74ff66e7827aad123d34aef538a5b9fb9a4ceb4cb20f8e6b3c6`.
- Archive SHA-256: `1fb326e51ba6707dd7e7f02aaeba8e14ef9485341fd7573ba1aa2527a487a4b9`.
- SBOM SHA-256: `cb6e8459f8a78a637d6d620eeeac03ed1a7e0ac544c3c140c80474a3297c7176`.
- Grype report SHA-256: `68ad5f229c6c6208ce4e6152f19cbcbca1c693fe5db04652f4e9733f4c69f212`.
- Candidate recipe SHA-256: `44c80c02c08c2140d34fead078b82d3e5187a55269405d640c0df5d410428de1`.

## Остаточные High/Critical candidates

Ни один finding не имеет утверждённого exception; fixed versions для этих blocking findings в использованной DB не указаны. Таблица группирует package matches по image/advisory/severity/fix state. Полные sanitized findings, включая non-blocking, находятся в CI logs. Raw SBOM/config и ключи не публикуются.

| Candidate | Severity | Advisory | Packages | Fix state |
| --- | --- | --- | --- | --- |
| storage-candidate | Critical | CVE-2026-6653 | libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3 | wont-fix |
| storage-candidate | High | CVE-2025-69720 | libncursesw6@6.5+20250216-2, libtinfo6@6.5+20250216-2, ncurses-base@6.5+20250216-2, ncurses-bin@6.5+20250216-2 | wont-fix |
| storage-candidate | High | CVE-2026-102010 | gcc-14-base@14.2.0-19, libgcc-s1@14.2.0-19, libstdc++6@14.2.0-19 | wont-fix |
| storage-candidate | High | CVE-2026-19499 | libc-bin@2.41-12+deb13u4, libc-l10n@2.41-12+deb13u4, libc6@2.41-12+deb13u4, locales@2.41-12+deb13u4 | wont-fix |
| storage-candidate | High | CVE-2026-24882 | dirmngr@2.4.7-21+deb13u1+b5, gnupg-l10n@2.4.7-21+deb13u1, gnupg@2.4.7-21+deb13u1, gpg-agent@2.4.7-21+deb13u1+b5, gpg@2.4.7-21+deb13u1+b5, gpgconf@2.4.7-21+deb13u1+b5, gpgsm@2.4.7-21+deb13u1+b5 | wont-fix |
| storage-candidate | High | CVE-2026-5435 | libc-bin@2.41-12+deb13u4, libc-l10n@2.41-12+deb13u4, libc6@2.41-12+deb13u4, locales@2.41-12+deb13u4 | wont-fix |
| storage-candidate | High | CVE-2026-54369 | libacl1@2.3.2-2+b1 | wont-fix |
| storage-candidate | High | CVE-2026-54370 | libacl1@2.3.2-2+b1 | wont-fix |
| storage-candidate | High | CVE-2026-74860 | libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3 | not-fixed |
| storage-candidate | High | CVE-2026-76642 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix |
| storage-candidate | High | CVE-2026-78408 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix |
| storage-candidate | High | CVE-2026-78409 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix |
| storage-candidate | High | CVE-2026-78410 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix |
| storage-candidate | High | CVE-2026-82560 | libperl5.40@5.40.1-6+deb13u1, perl-base@5.40.1-6+deb13u1, perl-modules-5.40@5.40.1-6+deb13u1, perl@5.40.1-6+deb13u1 | wont-fix |
| storage-candidate | High | CVE-2026-85091 | zlib1g@1:1.3.dfsg+really1.3.1-1+b1 | not-fixed |
| storage-candidate | High | CVE-2026-86138 | libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3 | not-fixed |
| storage-candidate | High | CVE-2026-86139 | libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3 | not-fixed |
| storage-candidate | High | CVE-2026-86140 | libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3 | not-fixed |
| storage-candidate | High | CVE-2026-86142 | libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3 | not-fixed |
| storage-candidate | High | CVE-2026-86143 | libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3 | not-fixed |
| storage-candidate | High | CVE-2026-86144 | libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3 | not-fixed |
| storage-candidate | High | CVE-2026-9538 | libperl5.40@5.40.1-6+deb13u1, perl-base@5.40.1-6+deb13u1, perl-modules-5.40@5.40.1-6+deb13u1, perl@5.40.1-6+deb13u1 | wont-fix |
| storage-candidate | High | CVE-2026-95619 | gcc-14-base@14.2.0-19, libgcc-s1@14.2.0-19, libstdc++6@14.2.0-19 | wont-fix |
| worker-candidate | High | CVE-2025-69720 | libncursesw6@6.5+20250216-2, libtinfo6@6.5+20250216-2, ncurses-base@6.5+20250216-2, ncurses-bin@6.5+20250216-2 | wont-fix |
| worker-candidate | High | CVE-2026-102010 | gcc-14-base@14.2.0-19, libgcc-s1@14.2.0-19, libstdc++6@14.2.0-19 | wont-fix |
| worker-candidate | High | CVE-2026-19499 | libc-bin@2.41-12+deb13u4, libc6@2.41-12+deb13u4 | wont-fix |
| worker-candidate | High | CVE-2026-5435 | libc-bin@2.41-12+deb13u4, libc6@2.41-12+deb13u4 | wont-fix |
| worker-candidate | High | CVE-2026-54369 | libacl1@2.3.2-2+b1 | wont-fix |
| worker-candidate | High | CVE-2026-54370 | libacl1@2.3.2-2+b1 | wont-fix |
| worker-candidate | High | CVE-2026-76642 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix |
| worker-candidate | High | CVE-2026-78408 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix |
| worker-candidate | High | CVE-2026-78409 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix |
| worker-candidate | High | CVE-2026-78410 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix |
| worker-candidate | High | CVE-2026-82560 | perl-base@5.40.1-6+deb13u1 | wont-fix |
| worker-candidate | High | CVE-2026-85091 | zlib1g@1:1.3.dfsg+really1.3.1-1+b1 | not-fixed |
| worker-candidate | High | CVE-2026-9538 | perl-base@5.40.1-6+deb13u1 | wont-fix |
| worker-candidate | High | CVE-2026-95619 | gcc-14-base@14.2.0-19, libgcc-s1@14.2.0-19, libstdc++6@14.2.0-19 | wont-fix |

## Решение и следующий шаг

1. Принять код воспроизводимого эксперимента и исправление PCRE2 как проверенный candidate increment. Не объявлять любой candidate разрешённым runtime/release.
2. Не смешивать Debian stable с sid packages ради зелёного scanner. Для libxml2 и других residual findings нужен поддерживаемый fixed runtime либо доказательный symbol/component review с отдельным решением владельца о риске. Пока policy не меняется.
3. Проверить более минимальный поддерживаемый runtime как отдельный эксперимент, не стирая историю текущего сравнения. [Distroless](https://github.com/GoogleContainerTools/distroless) не содержит обычного shell/package manager, но смена базы сама по себе не исправляет уязвимый необходимый libc/libstdc++/zlib. [Docker рекомендует](https://docs.docker.com/build/building/best-practices/) отделять builder от runtime и проверять resulting image.
4. До переключения PostgreSQL провести signed restore-to-new-target, сравнить ledger, TLS/roles, locale/collation, golden predictions и повторный запуск. Рабочий volume не подключать к непроверенному candidate.
5. Повторить M02/M03/M20 после любого изменения принятого runtime. Исторический pass не переносится на новые image IDs. Полные M01 и R1 остаются открытыми; serving/promotion/MLflow и остальные gates не заменяются этим экспериментом.

[Исходный аудит](container-audit-2026-10-08.md), [решение ADR 0015](../decisions/0015-image-candidates.md), [общий статус](../../STATUS.md).

