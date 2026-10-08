# Аудит worker и PostgreSQL images

Срез T01/T02, не полный M01. Порог политики: найденные High/Critical дают `fail`; недоступность DB, неизвестная severity, неполное покрытие или ошибка дают `inconclusive`. Оба исхода возвращают ненулевой exit code и не разрешают выпуск. Даже `pass` этого компонента не означает `release_ready`: полный R1 требует остальных gates.

Актуальная native проверка: **fail по findings** в clean-checkout CI на `19c618c`. Worker: 56 High matches; PostgreSQL: 7 Critical и 101 High. Detection control и проверка обоих reports завершены. [Полное summary, привязка inputs и triage](evidence/container-audit-2026-10-08.md). Это работающий блокирующий audit, не безопасный release.

## Что делают технологии

Syft формирует SBOM (software bill of materials): перечень обнаруженных установленных пакетов и их версий. Grype сопоставляет этот перечень с базой известных уязвимостей. Это не malware scan модели, не доказательство отсутствия неизвестных уязвимостей и не оценка практической эксплуатируемости каждого finding.

Docker экспортирует образ, не запуская его приложение. SHA-256 связывает точные bytes архива, SBOM и report; digest pinning не заменяет проверку издателя. Отдельные scanner containers не получают Docker socket, kubeconfig, ML keys, БД проекта или весь checkout.

## Воспроизведение

Из корня чистого checkout на Linux amd64 или Windows с Linux Docker Engine:

```bash
uv sync --locked --python 3.12.15
uv run --locked python -m scripts.image_audit_qualification
uv run --locked python -m scripts.image_archive_qualification
uv run --locked python -m scripts.image_audit_runner_qualification
uv run --locked python -m scripts.image_audit_flow_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.image_audit
```

Нужны 8 GiB свободного диска, доступ к официальным registries и DB endpoint, локальный Docker daemon. На Linux запускать от обычного пользователя с доступом к Docker, не через root. Доступ к Docker сам по себе даёт сильные host privileges; изоляция scanner не устраняет этот риск оператора. Выходные коды Python CLI: 0/pass, 1/fail, 2/inconclusive; wrapper может нормализовать ненулевой код, поэтому проверяйте также JSON.

Путь summary: `.runtime/evidence/image-audit.json`. Полный raw SBOM, диагностика и DB snapshot: `.runtime/image-audit/<run_id>/`, ignored. Не запускать параллельно несколько writers для общего summary. При начале нового запуска старый `pass` заменяется на `inconclusive`, при crash старый успех не восстанавливается. Raw SBOM содержит image metadata/config и не предназначен для публикации.

## Как работает проверка

1. Фиксируются source revision/fingerprint, digest policy и audit scripts. Worker label должен совпасть с текущим fingerprint. PostgreSQL и scanner images указаны с immutable digests; ни один непроверенный latest tag не выбирается автоматически.
2. Каждый target экспортируется через `docker image save <resolved ID>` в новый owned run. Из tar без распаковки в host filesystem читаются bounded regular manifest/config entries. Несколько images, duplicate members, symlink metadata, traversal и несоответствие platform/layers/labels отклоняются.
3. В Docker Engine с containerd runtime `.Id` может быть manifest ID, а `source.metadata.imageID` Syft - hash image config. Поэтому сохраняются оба: `runtime_image_id` и `image_config_id`. SHA-256 вычисляется над конфигурацией из свежего экспорта, а не над произвольным старым SBOM.
4. Syft 1.54.1 без сети каталогизирует squashed filesystem. Проверяются version/source/image/distro, непустой уникальный inventory, обязательные packages и `foundBy`. Native schema использует `distro`; Debian minor version допустима, если Grype нормализует её к тому же major. Наличие SBOM не означает завершённый vulnerability audit.
5. Grype 0.120.1 отдельным контейнером обновляет официальную DB. Сохраняются TLS, hash validation и максимальный возраст 120 часов. После обновления cache монтируется read-only, сеть scanner выключена, auto-update выключен только для использования того же snapshot. Файлы DB хешируются до и после проверок.
6. Положительный контроль сопоставляет PURL `pkg:pypi/urllib3@1.26.7` с DB. Этот package не устанавливается и не исполняется. Ожидаются High/Critical `GHSA-v845-jxx5-vc9f` и native threshold exit 2; пустая или неправильная выдача запрещает pass.
7. Проверяются Grype reports обоих images: version, valid свежая DB, тот же DB snapshot, config ID, distro, связь каждого finding с SBOM package. Непустые ignored matches и coverage alerts не скрываются. High/Critical блокируют независимо от доступности fix; Unknown не становится Low.
8. Публикуются только выбранные поля findings, counts, hashes, версии и ограничения. Timeout/overflow останавливает CLI и удаляет только scanner по его собственному CID. Временные image archives удаляются после каталогизации; raw reports и DB остаются локально для разбора. Глобальные Docker prune и удаление чужих volumes не используются.

Контейнеры scanner работают non-root, с read-only rootfs, без capabilities, с no-new-privileges, 2 CPU/2 GiB RAM, 256 PIDs и tmpfs 1 GiB. Wrapper проверяет stdout 64 MiB/stderr 2 MiB каждые 100 ms, поэтому возможен небольшой overshoot между проверками; это не filesystem quota. Offline операция ограничена 300 секундами, DB update - 600. Последний лимит увеличен после реального 300-second timeout при распаковке DB размером более 3 GiB на Windows bind mount; freshness/TLS/hash validation не изменены. В host administrator trust boundary входит целостность локального Docker daemon и файлов run.

## Проверка и evidence

- Контрактные suites: 43 report/policy checks, 15 archive checks, 25 runner checks и 16 controlled orchestration checks, всего 99. Включены malformed/stale/foreign reports, пустой inventory, отсутствие обязательного package, fake DB validity, exit/report disagreement, mutation DB/SBOM/source, очистка старого pass, scoped cleanup и реальные child processes с oversized output/deadline. Mocked flow не является native scanner test. CI отдельно требует >=95% combined и branch coverage именно трёх audit modules; это не полное coverage M18.
- 2026-10-08 локальный native Syft каталогизировал worker (1 152 packages, Debian 13.7) и storage (151 package, Debian 12.15). Обязательные packages найдены. Exported archives и source/config IDs сохранены в ignored report.
- Локальные попытки DB update дали TLS handshake timeout и позднее 300-second timeout при распаковке. Итог `inconclusive`, число уязвимостей `null`, не 0. Положительный Grype control и native scan на этом хосте пока не подтверждены.
- Первый [clean-checkout CI 37840696361](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37840696361) на `4c9e9da` подтвердил native SBOM обоих images, но отклонил DB metadata в detection control. Это проверенный failure, не успешный audit; добавлена allowlisted диагностика descriptor и сохранение DB snapshot digest до проверки control.
- Последующие native runs установили точный формат `descriptor.db.status` и prefix `v6.1.10`. Fixtures исправлены через red/green checks, без ослабления freshness/validity. Run `37842817452` выполнил DB/control/оба scans: 173 worker и 436 storage advisory/package matches, всего 189 различных advisory IDs. Scan прошёл техническую верификацию, но severity policy дала fail. Контрактные suites на этом commit прошли и выполнили оба coverage thresholds; остальной R1 не объявлен принятым.
- [Workflow](../.github/workflows/image-audit.yml) исполняет тот же код из clean checkout и публикует только summary в logs даже при failure. Его наличие не доказывает успешный run; проверенные run IDs и результаты фиксируются в [STATUS](../STATUS.md).
- Изменение DB может менять findings для того же image. Повторяемы процедура, identity checks и решение для сохранённых inputs, но не обещается одинаковый сегодняшний вывод из постоянно обновляемой базы.

## Не завершено этим срезом

Полный inventory control-plane/system images, независимая проверка scanner signatures, полный P0/M01, ONNX intake M21, доверенный audit sink M23, политика retention DB/raw files и итоговая >=95% branch coverage M18 остаются отдельной работой. Findings не освобождаются от исправления только потому, что приложение работает или unit tests зелёные. При DB outage не подменять источник случайным mirror, не выключать TLS/age проверки и не публиковать прежний pass как новый.

Основания: [ADR 0014](decisions/0014-container-audit.md), [официальные Grype scan targets](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/), [DB lifecycle](https://oss.anchore.com/docs/guides/vulnerability/database/) и [JSON fields](https://oss.anchore.com/docs/guides/vulnerability/json/). Native версии дополнительно проверяются тестами и живым запуском, а не только latest документацией.
