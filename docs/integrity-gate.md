# M03: проверка целостности до обучения

## Результат и граница

Executable M03 проверяет подписанный dataset, неизменность split и реальные права SQL identities. Локальный запуск 2026-10-07 завершился `pass`: 36 файловых сценариев, 367 storage checks, 26 pipeline checks и 2 сквозные проверки неизменности SQL-dataset, всего 431 case. Переиспользованные component checks пересекаются с другими отчётами: это не 431 независимый эксперимент и не оценка вероятности взлома.

Это завершение T04 для synthetic-only профиля, не готовность всей платформы. M01 и M04-M23, production promotion, независимые controllers и semantic poisoning assurance остаются открытыми. Привилегированный host/curator входит в доверенную базу.

## Что именно проверяет gate

| Требование M03 | Исполняемый путь | Ожидаемый результат |
| --- | --- | --- |
| Подмена одного byte каждого split | Linux fixture -> `verify_dataset` | `dataset_content_mismatch`; повтор публикации не чинит/не затирает подмену молча |
| Подмена manifest, signature, signer или типа | Настоящие DSSE envelopes и Ed25519 verification | Точный отказ подписи, типа или dataset address binding |
| Подмена split | Swap validation/holdout, signed неверные count/digest | Отказ digest/schema, даже если документ подписан curator |
| Duplicate entity и cross-split leakage | Signed fixtures с согласованными новыми hashes | Отказ проверки строк или пересечения entity IDs |
| Missing object | Поочерёдное удаление manifest и трёх split только во временном fixture | `artifact_unavailable`, не старый cache result |
| Traversal и symlink escape | Реальные POSIX symlinks для файла, manifest и directory; absolute/parent/Windows-style paths | Отказ пути или symlink до использования данных |
| Stale source version / expiry | Новое подписанное разрешение или истёкшее разрешение | Старый dataset не принимается как соответствующий текущему source approval |
| Запрет неавторизованной перезаписи | Реальные mTLS SQL clients, полная матрица SELECT/INSERT/UPDATE/DELETE/TRUNCATE | Конкретный SQLSTATE 42501, не timeout или недоступная БД |
| Нормальный путь после отказов | Idempotent publish -> SQL training/evaluation -> повторное чтение всех split curator | Dataset reference и hashes до/после совпадают; source bytes совпадают с lock |

Файловые случаи реализованы в [dataset_integrity.py](../mlsecops/dataset_integrity.py), сборка gate в [integrity_qualification.py](../mlsecops/integrity_qualification.py). Существующие [storage](../mlsecops/storage_qualification.py) и [pipeline](../mlsecops/storage_pipeline_qualification.py) квалификации выполняются заново, а не читаются из старого зелёного JSON.

## Почему два разных контура

Filesystem используется только как trusted curator staging. Там verifier обязан отвергать повреждённый вход, но права обычных directories не объявляются защитой от другого пользователя host. Для долговременных approved artifacts используется PostgreSQL: ingestor и publisher не могут менять approved tables, а training worker вообще не получает DB credentials. Реальное разделение controller processes остаётся M04/M20.

Ограничения SQL проверяются прямыми запросами, не только через Python API. Владелец и superuser могут менять права, поэтому append-only privileges не называются WORM или защитой от администратора. Это соответствует [модели привилегий PostgreSQL](https://www.postgresql.org/docs/18/ddl-priv.html).

Windows host не разрешил создавать symlink без дополнительной привилегии (WinError 1314). Проверка не пропускается и ОС не перенастраивается: весь файловый suite всегда запускается внутри текущего Linux worker image с проверенным source fingerprint. Контейнер работает без сети и mounts, non-root, readonly, без capabilities, с 2 CPU / 1 GiB / 32 PID / 64 MiB tmpfs и deadline 120 s. Он генерирует только собственные временные данные и ключи. [Ресурсные ограничения Docker](https://docs.docker.com/engine/containers/resource_constraints/) дополняют, но не заменяют проверки содержимого.

## Воспроизведение

Выполнять из корня отдельного checkout, с установленными Git, uv и Docker Linux/amd64:

```bash
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops.storage_bootstrap
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.acceptance --gate M03 --output .runtime/evidence/M03.json
```

Первый bootstrap скачивает pinned PostgreSQL image; сборка устанавливает locked dependencies. Успешный gate возвращает exit code 0. Без storage bootstrap результат `inconclusive`, exit code 2; stale image, неправильные права, неподходящий отказ или повреждённый объект дают `fail`, exit code 1. Отсутствие symlink capability в самом Linux runtime также не превращается в pass.

Не запускать qualification одновременно с пользовательской работой в этой БД. Mutating SQL probes используют rollback-only transactions; при ошибочном разрешении TRUNCATE возможен кратковременный lock. Cleanup удаляет только собственные случайные fixture objects по digest и exact bytes. Настоящие dataset/candidate artifacts сохраняются. Другие Docker volumes, containers и кластеры не удаляются.

## Evidence

- `.runtime/evidence/M03.json`: gate status, время, Git SHA, source fingerprint, data lock, dataset/candidate references, image ID, storage config digest, cases и residual risks.
- `.runtime/evidence/integrity-qualification.json`: hashes реального SQL-dataset до/после и aggregate case counts.
- `.runtime/evidence/M03-filesystem.json`, `M03-storage.json`, `M03-pipeline.json`: component evidence, hashes которого включены в итоговый report.
- [Storage workflow](../.github/workflows/storage.yml): fresh checkout, новая БД и worker image, полный M03. Он печатает очищенный итоговый report, но не сертификаты, ключи, сырые данные или stderr модели.

Локальные SQL hashes остались неизменными; source SHA-256 `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`. AUPRC повторного обучения `0.9323007296445032`, parity error `2.086162567138672e-7`. Эти метрики подтверждают работоспособность пути чтения/обучения, не принятие M06/M07 или полезность на реальных релизах. Release остаётся `unapproved`.

Отчёты сами по себе не являются независимой attestation. Текущие CI links и границы проверенных commits находятся в [STATUS](../STATUS.md). Проверка уязвимостей container images, backup/restore, защита от host-admin, malicious curator и race с локальным привилегированным писателем этим gate не заявляются.
