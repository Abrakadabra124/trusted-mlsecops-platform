# Native container audit: 2026-10-08

Статус **fail**, не допущенный release. Сканирование выполнено и отчёты проверены, а не пропущены. Положительный PURL detection control прошёл. Полные sanitized findings доступны в [GitHub Actions run 37842817452](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37842817452), job 113536183877. Raw SBOM/config не публикуются.

- Commit: `19c618c9086f4b8163ee006095ae08c1d4495680`.
- Run: `833c5e1d35354d49bc82ef8ec6d82b20`, завершён `2026-10-08T20:56:09.640887+00:00`.
- Source fingerprint: `718367566a39b8d4d4f81fb731d89a012f5bee09333277a2d4e37bbbf7391436`.
- DB: `v6.1.10`, built `2026-10-08T06:33:47Z`, valid true.
- DB SHA-256: `13189d835d54559219f1774870455a8401ca01f538bd00fddef7f4ce55350f74`.
- Policy SHA-256: `b778b24407ac627c180067b62f0e28b7dcecd7328a4102516821d2e46911d9dc`.
- Control report SHA-256: `ffbcba8c2a23fdcedcec61ce782e05a6dc1795e4b5a42a8fe43a7dea03bef01d`.
- Всего 189 различных advisory IDs на два image. Это не 189 независимо эксплуатируемых ошибок: aliases и несколько packages на один advisory требуют triage.

## Сводка

| Image | Packages | Matches | Critical | High | Medium | Low | Negligible | Unknown | Advisory IDs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| worker | 1152 | 173 | 0 | 56 | 59 | 11 | 47 | 0 | 81 |
| storage | 151 | 436 | 7 | 101 | 146 | 47 | 119 | 16 | 175 |

Каждый match - advisory/package pair. Семь Critical matches storage относятся к четырём advisory IDs, а не семи независимым CVEs. Unknown не интерпретируется как Low. Оба scanner exit codes равны 2, workflow завершился failure по реальным High/Critical findings. Отсутствие исправленной версии не делает пакет безопасным.

## Привязка артефактов

### worker

- Runtime/config ID: `sha256:4e7f68c2b63b02cab54662564fff1494caa3a0ab41046ee72da6ea4b2555daf9`.
- Archive SHA-256: `fd42c8de2581707730b1651df66273c81c3cb6283411b706cfb0a8d3e50d1e33`.
- SBOM SHA-256: `f02cec224b78dc810328c2f2440fcacafdfd9be116bd970dcc7cb766a7d91532`.
- Grype report SHA-256: `8c2452151045b6b51a82fb7a12fc8838bb58766b8e1b54d2c4d969980bd24bb8`.
- Package types: binary: 7, deb: 87, python: 34, rust-crate: 1024.

### storage

- Runtime/config ID: `sha256:2e182ed2ff8f5d0835353864264437a26dffc542a9a6c677ec495aa54e491627`.
- Archive SHA-256: `c514d0fed97a390a28c18088ae65ac949e8f2da051e0274d4b3f9178ccb9d947`.
- SBOM SHA-256: `68e0e2389b012eabfb757308a815855eef2e7f836f6dc0fb0e296efcf3e2385e`.
- Grype report SHA-256: `2714d7fac9affd99efab1b52cb7db9c0f3d13cfda6fcfac66e02d8e0d20ca536`.
- Package types: deb: 147, go-module: 4.


## High/Critical triage register

Ни один finding ниже не имеет утверждённого exception. Статус fixed означает наличие версии в DB, не применение исправления в образе. Список сгруппирован по image/advisory/severity/fix state; все non-blocking findings остаются в CI summary.

| Image | Severity | Advisory | Packages | Fix state | Versions из DB |
| --- | --- | --- | --- | --- | --- |
| storage | Critical | CVE-2025-7458 | libsqlite3-0@3.40.1-2+deb12u2 | wont-fix | не указаны |
| storage | Critical | CVE-2026-5450 | libc-bin@2.36-9+deb12u14, libc-l10n@2.36-9+deb12u14, libc6@2.36-9+deb12u14, locales@2.36-9+deb12u14 | wont-fix | не указаны |
| storage | Critical | CVE-2026-6653 | libxml2@2.9.14+dfsg-1.3~deb12u6 | wont-fix | не указаны |
| storage | Critical | GO-2026-4337 | stdlib@go1.24.6 | fixed | 1.24.13, 1.25.7, 1.26.0-rc.3 |
| storage | High | CVE-2023-2953 | libldap-2.5-0@2.5.13+dfsg-5 | wont-fix | не указаны |
| storage | High | CVE-2025-13151 | libtasn1-6@4.19.0-2+deb12u1 | wont-fix | не указаны |
| storage | High | CVE-2025-69720 | libncursesw6@6.4-4, libtinfo6@6.4-4, ncurses-base@6.4-4, ncurses-bin@6.4-4 | wont-fix | не указаны |
| storage | High | CVE-2026-102010 | gcc-12-base@12.2.0-14+deb12u1, libgcc-s1@12.2.0-14+deb12u1, libstdc++6@12.2.0-14+deb12u1 | wont-fix | не указаны |
| storage | High | CVE-2026-11822 | libsqlite3-0@3.40.1-2+deb12u2 | wont-fix | не указаны |
| storage | High | CVE-2026-11824 | libsqlite3-0@3.40.1-2+deb12u2 | wont-fix | не указаны |
| storage | High | CVE-2026-19499 | libc-bin@2.36-9+deb12u14, libc-l10n@2.36-9+deb12u14, libc6@2.36-9+deb12u14, locales@2.36-9+deb12u14 | wont-fix | не указаны |
| storage | High | CVE-2026-41992 | gzip@1.12-1 | wont-fix | не указаны |
| storage | High | CVE-2026-5435 | libc-bin@2.36-9+deb12u14, libc-l10n@2.36-9+deb12u14, libc6@2.36-9+deb12u14, locales@2.36-9+deb12u14 | wont-fix | не указаны |
| storage | High | CVE-2026-54369 | libacl1@2.3.1-3 | wont-fix | не указаны |
| storage | High | CVE-2026-54370 | libacl1@2.3.1-3 | wont-fix | не указаны |
| storage | High | CVE-2026-5928 | libc-bin@2.36-9+deb12u14, libc-l10n@2.36-9+deb12u14, libc6@2.36-9+deb12u14, locales@2.36-9+deb12u14 | wont-fix | не указаны |
| storage | High | CVE-2026-74860 | libxml2@2.9.14+dfsg-1.3~deb12u6 | wont-fix | не указаны |
| storage | High | CVE-2026-76642 | bsdutils@1:2.38.1-5+deb12u3, libblkid1@2.38.1-5+deb12u3, libmount1@2.38.1-5+deb12u3, libsmartcols1@2.38.1-5+deb12u3, libuuid1@2.38.1-5+deb12u3, mount@2.38.1-5+deb12u3, util-linux-extra@2.38.1-5+deb12u3, util-linux@2.38.1-5+deb12u3 | not-fixed | не указаны |
| storage | High | CVE-2026-78408 | bsdutils@1:2.38.1-5+deb12u3, libblkid1@2.38.1-5+deb12u3, libmount1@2.38.1-5+deb12u3, libsmartcols1@2.38.1-5+deb12u3, libuuid1@2.38.1-5+deb12u3, mount@2.38.1-5+deb12u3, util-linux-extra@2.38.1-5+deb12u3, util-linux@2.38.1-5+deb12u3 | not-fixed | не указаны |
| storage | High | CVE-2026-78409 | bsdutils@1:2.38.1-5+deb12u3, libblkid1@2.38.1-5+deb12u3, libmount1@2.38.1-5+deb12u3, libsmartcols1@2.38.1-5+deb12u3, libuuid1@2.38.1-5+deb12u3, mount@2.38.1-5+deb12u3, util-linux-extra@2.38.1-5+deb12u3, util-linux@2.38.1-5+deb12u3 | not-fixed | не указаны |
| storage | High | CVE-2026-78410 | bsdutils@1:2.38.1-5+deb12u3, libblkid1@2.38.1-5+deb12u3, libmount1@2.38.1-5+deb12u3, libsmartcols1@2.38.1-5+deb12u3, libuuid1@2.38.1-5+deb12u3, mount@2.38.1-5+deb12u3, util-linux-extra@2.38.1-5+deb12u3, util-linux@2.38.1-5+deb12u3 | not-fixed | не указаны |
| storage | High | CVE-2026-82560 | libperl5.36@5.36.0-7+deb12u4, perl-base@5.36.0-7+deb12u4, perl-modules-5.36@5.36.0-7+deb12u4, perl@5.36.0-7+deb12u4 | not-fixed | не указаны |
| storage | High | CVE-2026-84782 | libssl3@3.0.22-1~deb12u1, openssl@3.0.22-1~deb12u1 | not-fixed | не указаны |
| storage | High | CVE-2026-85091 | zlib1g@1:1.2.13.dfsg-1 | not-fixed | не указаны |
| storage | High | CVE-2026-86138 | libxml2@2.9.14+dfsg-1.3~deb12u6 | wont-fix | не указаны |
| storage | High | CVE-2026-86140 | libxml2@2.9.14+dfsg-1.3~deb12u6 | wont-fix | не указаны |
| storage | High | CVE-2026-86142 | libxml2@2.9.14+dfsg-1.3~deb12u6 | wont-fix | не указаны |
| storage | High | CVE-2026-86143 | libxml2@2.9.14+dfsg-1.3~deb12u6 | wont-fix | не указаны |
| storage | High | CVE-2026-86144 | libxml2@2.9.14+dfsg-1.3~deb12u6 | wont-fix | не указаны |
| storage | High | CVE-2026-9538 | libperl5.36@5.36.0-7+deb12u4, perl-base@5.36.0-7+deb12u4, perl-modules-5.36@5.36.0-7+deb12u4, perl@5.36.0-7+deb12u4 | wont-fix | не указаны |
| storage | High | CVE-2026-95619 | gcc-12-base@12.2.0-14+deb12u1, libgcc-s1@12.2.0-14+deb12u1, libstdc++6@12.2.0-14+deb12u1 | not-fixed | не указаны |
| storage | High | GO-2025-4006 | stdlib@go1.24.6 | fixed | 1.24.8, 1.25.2 |
| storage | High | GO-2025-4007 | stdlib@go1.24.6 | fixed | 1.24.9, 1.25.3 |
| storage | High | GO-2025-4009 | stdlib@go1.24.6 | fixed | 1.24.8, 1.25.2 |
| storage | High | GO-2025-4013 | stdlib@go1.24.6 | fixed | 1.24.8, 1.25.2 |
| storage | High | GO-2025-4155 | stdlib@go1.24.6 | fixed | 1.24.11, 1.25.5 |
| storage | High | GO-2026-4341 | stdlib@go1.24.6 | fixed | 1.24.12, 1.25.6 |
| storage | High | GO-2026-4601 | stdlib@go1.24.6 | fixed | 1.25.8, 1.26.1 |
| storage | High | GO-2026-4870 | stdlib@go1.24.6 | fixed | 1.25.9, 1.26.2 |
| storage | High | GO-2026-4918 | stdlib@go1.24.6 | fixed | 1.25.10, 1.26.3 |
| storage | High | GO-2026-4946 | stdlib@go1.24.6 | fixed | 1.25.9, 1.26.2 |
| storage | High | GO-2026-4947 | stdlib@go1.24.6 | fixed | 1.25.9, 1.26.2 |
| storage | High | GO-2026-4970 | stdlib@go1.24.6 | fixed | 1.25.12, 1.26.5, 1.27.0-rc.2 |
| storage | High | GO-2026-4971 | stdlib@go1.24.6 | fixed | 1.25.10, 1.26.3 |
| storage | High | GO-2026-4977 | stdlib@go1.24.6 | fixed | 1.25.10, 1.26.3 |
| storage | High | GO-2026-4981 | stdlib@go1.24.6 | fixed | 1.25.10, 1.26.3 |
| storage | High | GO-2026-4986 | stdlib@go1.24.6 | fixed | 1.25.10, 1.26.3 |
| storage | High | GO-2026-5026 | stdlib@go1.24.6 | fixed | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| storage | High | GO-2026-5037 | stdlib@go1.24.6 | fixed | 1.25.11, 1.26.4 |
| storage | High | GO-2026-5038 | stdlib@go1.24.6 | fixed | 1.25.11, 1.26.4 |
| storage | High | GO-2026-5972 | stdlib@go1.24.6 | fixed | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| storage | High | GO-2026-6088 | stdlib@go1.24.6 | fixed | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| storage | High | GO-2026-6089 | stdlib@go1.24.6 | fixed | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| storage | High | GO-2026-6090 | stdlib@go1.24.6 | fixed | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| worker | High | CVE-2025-69720 | libncursesw6@6.5+20250216-2, libtinfo6@6.5+20250216-2, ncurses-base@6.5+20250216-2, ncurses-bin@6.5+20250216-2 | wont-fix | не указаны |
| worker | High | CVE-2026-102010 | gcc-14-base@14.2.0-19, libgcc-s1@14.2.0-19, libstdc++6@14.2.0-19 | wont-fix | не указаны |
| worker | High | CVE-2026-103111 | libpcre2-8-0@10.46-1~deb13u2 | fixed | 10.46-1~deb13u3 |
| worker | High | CVE-2026-19499 | libc-bin@2.41-12+deb13u4, libc6@2.41-12+deb13u4 | wont-fix | не указаны |
| worker | High | CVE-2026-5435 | libc-bin@2.41-12+deb13u4, libc6@2.41-12+deb13u4 | wont-fix | не указаны |
| worker | High | CVE-2026-54369 | libacl1@2.3.2-2+b1 | wont-fix | не указаны |
| worker | High | CVE-2026-54370 | libacl1@2.3.2-2+b1 | wont-fix | не указаны |
| worker | High | CVE-2026-76642 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix | не указаны |
| worker | High | CVE-2026-78408 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix | не указаны |
| worker | High | CVE-2026-78409 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix | не указаны |
| worker | High | CVE-2026-78410 | bsdutils@1:2.41.5-0+deb13u1, libblkid1@2.41.5-0+deb13u1, liblastlog2-2@2.41.5-0+deb13u1, libmount1@2.41.5-0+deb13u1, libsmartcols1@2.41.5-0+deb13u1, libuuid1@2.41.5-0+deb13u1, login@1:4.16.0-2+really2.41.5-0+deb13u1, mount@2.41.5-0+deb13u1, util-linux@2.41.5-0+deb13u1 | wont-fix | не указаны |
| worker | High | CVE-2026-82560 | perl-base@5.40.1-6+deb13u1 | wont-fix | не указаны |
| worker | High | CVE-2026-85091 | zlib1g@1:1.3.dfsg+really1.3.1-1+b1 | not-fixed | не указаны |
| worker | High | CVE-2026-9538 | perl-base@5.40.1-6+deb13u1 | wont-fix | не указаны |
| worker | High | CVE-2026-95619 | gcc-14-base@14.2.0-19, libgcc-s1@14.2.0-19, libstdc++6@14.2.0-19 | wont-fix | не указаны |

## Следующий безопасный шаг

1. Сверить блокирующие findings с vendor advisories и достижимостью кода. Не переносить CVSS пакета автоматически на риск именно этого ML-сервиса и не переименовывать findings в false positive без доказательств.
2. Подготовить новые pinned images отдельными candidate tags. У worker все 56 High matches относятся к Debian packages, поэтому удаление uv/uvx само по себе этот результат не исправит. Для libpcre2-8-0 DB указывает исправленную версию; целый base image и package closure нужно перепроверить.
3. Проверить PostgreSQL candidate с исправленной libc и актуальным вспомогательным Go binary. Не подменять image работающей БД и не изменять persisted volume до restore-to-new-target, TLS/roles, signed history/golden checks и утверждённого rollback.
4. Повторить native audit без ignore rules и тем же способом измерить новое окружение. После изменения runtime fingerprint повторить все затронутые квалификации, включая M02/M03/M20; старые pass не становятся evidence нового image.
5. Отдельно закрыть полный control-plane inventory, scanner publisher verification и P0/M01. Этот scan workflow и Kubernetes qualification пока строят образы в разных jobs: итоговый M18 должен связывать gates с одним release candidate, а не просто одинаковым source fingerprint.

## Проверка первичных источников

[Debian CVE-2026-5450](https://security-tracker.debian.org/tracker/CVE-2026-5450) на момент проверки отмечает установленный bookworm glibc 2.36-9+deb12u14 vulnerable, а trixie 2.41-12+deb13u4 fixed. При этом Debian классифицирует bookworm issue как minor/no-dsa. Это важное различие vendor приоритета и scanner severity, но не автоматический exception.

[Go GO-2026-4337](https://pkg.go.dev/vuln/GO-2026-4337) относится к crypto/tls и конкретным условиям возобновления TLS session; таблица указывает исправления 1.24.13/1.25.7. Наличие старого Go stdlib в inventory ещё не доказывает вызов уязвимых symbols вспомогательной утилитой. Нужны binary/symbol review и evidence, а не отключение severity policy.

[Native Grype 0.120.1 root command](https://github.com/anchore/grype/blob/v0.120.1/cmd/grype/cli/commands/root.go) оборачивает DB status в `descriptor.db.status`; живой report использует schema version `v6.1.10`. Эти форматы воспроизведены в fixtures после обнаружения ошибки интеграционным запуском. Высокое unit coverage не заменило native test.

Инструкции: [container audit](../container-audit.md). Полный R1 не принят, production не развёрнут.
