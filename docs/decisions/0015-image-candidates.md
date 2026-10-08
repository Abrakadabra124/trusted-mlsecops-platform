# ADR 0015: исправление images через отдельные candidates

Дата: 2026-10-09. Статус: Proposed, implementation started. Scope: T01/T02, не завершение M01 и не переключение работающего SQL.

## Требование и критерий

Native audit обнаружил High/Critical matches в обоих runtime images. Нельзя просто обновить тег живой БД или скрыть findings через ignore rules. Нужны отдельные pinned candidates, функциональная проверка и сравнение baseline/candidate на одном DB snapshot. Уменьшение количества findings не равно pass: порог High/Critical сохраняется.

## Решение

1. Сохранить текущие Dockerfile, storage IMAGE и runtime tags. Новые recipes находятся в `images/candidates`, создают только отдельные candidate tags и несут labels source fingerprint/recipe SHA-256. Recipe fingerprint не заменяется одним app source fingerprint.
2. Worker: multi-stage build с существующим pinned uv builder и отдельным pinned Python 3.12.15 slim-trixie runtime. В runtime не переносить uv/uvx и Rust build-tool closure. Установить точную исправленную версию libpcre2-8-0; не делать плавающий dist-upgrade. Debian indexes/package hashes проверяет APT, mirrors используются по HTTPS, ошибки обновления не игнорируются.
3. Storage: тот же PostgreSQL 18.6, но официальный pinned trixie image вместо bookworm. Проект запускает initdb/postgres напрямую с UID 999, поэтому gosu для runtime не требуется. Удалить неиспользуемые gosu и стандартный auto-init entrypoint из prepared filesystem и скопировать filesystem в final stage, чтобы эти binaries не оставались в поставляемых lower layers. Package database не удалять и не редактировать ради scanner.
4. Сравнивать оба baseline и оба candidate одним audit invocation, с одной свежей frozen DB, positive detection control и прежними severity rules. Сохранять baseline failures, новые и устранённые advisory/package pairs. Изменённый recipe, foreign image, отсутствие baseline или разные snapshots запрещают заявлять сопоставимый результат.
5. Проверить настоящие fresh-process training/ONNX predictions worker candidate в новом owned state. Storage candidate пока только build/inventory/audit; перенос текущей signed history требует следующего явно scoped restore-to-new-target increment. Toy SQL smoke не заменяет этот restore.

## Риски и ограничения

Минимизация не гарантирует отсутствие CVEs. У baseline worker все High matches относятся к Debian packages, а не к Rust crates uv. Нельзя объявлять удаление build tools исправлением этих High findings. Вендор gosu указывает на необходимость проверки достижимости Go symbols; удаление действительно неиспользуемой утилиты не является доказательством её эксплуатируемости.

При смене Debian возможны изменения locale/collation, shared libraries, TLS и pg_dump/restore поведения. PostgreSQL major сохраняется, но живой volume не монтируется в candidate, rollback не проверяется заменой текущего container. Лаборатория остаётся single-host; подписи издателя, полный control-plane inventory и M18 на одном release candidate пока не завершены.

Docker Hardened Images рассмотрены, но community registry требует отдельной аутентификации. Новую зависимость от registry credentials в публичное clean-checkout воспроизведение пока не вводить. Самостоятельный минимальный Linux distro/rootfs вместо поддерживаемых upstream images без измеренной необходимости также не выбран.

## Основания

- [Debian PCRE2 advisory](https://security-tracker.debian.org/tracker/CVE-2026-103111): trixie security fix 10.46-1~deb13u3.
- [Debian glibc advisory](https://security-tracker.debian.org/tracker/CVE-2026-5450): выбранный trixie содержит fixed glibc, в отличие от baseline bookworm. Остальные findings проверяются отдельно.
- [Официальный PostgreSQL image](https://github.com/docker-library/docs/blob/master/postgres/README.md): варианты 18.6-trixie/bookworm и version-specific PGDATA.
- [gosu security policy](https://github.com/tianon/gosu/blob/master/SECURITY.md): версия compiler сама по себе не доказывает достижимость уязвимого кода.
- [DHI usage](https://docs.docker.com/dhi/how-to/use/): отдельная registry authentication и особенности minimal images.

Digest pins выбираются по registry metadata и проверяются при pull/build; наличие digest не доказывает publisher identity или успешную эксплуатационную квалификацию.
