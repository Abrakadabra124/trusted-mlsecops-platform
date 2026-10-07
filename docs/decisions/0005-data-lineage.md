# ADR 0005: Source snapshot без небезопасной cache-зависимости

Дата: 2026-10-07. Статус: принято. Технологическая корректировка T03-T04, не ослабление M02/M03/M06.

## Требование

Воспроизводимые исходные данные, карантин, provenance и запрет публикации неподтверждённого ввода. Успех генератора не даёт approved статус или право выпуска модели.

## Проверенный spike и отказ от DVC

DVC 3.67.1 был установлен в отдельное project environment, pipeline успешно создал 20 000 synthetic records и lockfile. Последующий полный pip-audit остановил adoption: транзитивный diskcache 5.6.3 имеет GHSA-w8v5-vhqr-4h9v / CVE-2025-69872 / PYSEC-2026-2447. Сервис вернул две alias-записи одного finding, а не две независимые уязвимости. На момент проверки PyPI не перечисляет исправленную версию.

[Advisory](https://github.com/advisories/GHSA-w8v5-vhqr-4h9v) описывает выполнение кода при чтении cache, изменённого атакующим с правом записи. Это не означает удалённую компрометацию любого DVC; однако незачем добавлять pickle-based cache в controller, которому позднее доверяются подписи. Не вводятся scanner ignore, переименование dependency или неподдерживаемый monkeypatch. DVC и его транзитивные пакеты удаляются из active lock/environment; историческое исследование сохраняется как история решения.

## Решение

- Существующий подписанный SHA-256 dataset manifest остаётся authority для данных. Для одного synthetic source достаточно фиксированного шага подготовки, без нового общего оркестратора.
- Git хранит `data.lock`: schema, точные SHA-256/размеры входных файлов и ожидаемого output. Изменение inputs требует явного обновления lock; простой запуск воспроизведения не переписывает утверждённый lock молча.
- Source и копия cache находятся в ignored `.runtime`. Cache читается только после проверки SHA-256, не использует pickle, symlinks, hardlinks или remote adapters. Fresh regeneration обязательна в qualification; cache не является доказательством обучения.
- Curator отдельно подписывает source snapshot, связанный с текущим разрешением источника. Ingestor не может разрешить произвольные rows, просто указав известную строку `source`.
- Intake сохраняет bounded JSON и отчёт в quarantine. Approval повторно проверяет schema, bytes, source signature/expiry, затем публикует новый dataset. Signed lineage связывает source, data lock, policy и dataset.
- Старые preview manifests остаются читаемыми, но отсутствие source lineage не достаточно для будущего R1 promotion.

## Альтернативы и последствия

Риск-исключение для DVC не принято. Изолированный DVC без доступа к controller secrets можно пересмотреть позже, с отдельной scan policy и проверенными правами cache. lakeFS/S3 control plane сейчас добавил бы сервисы без необходимости для одного 2 MB synthetic source. Собственный механизм ограничен одним фиксированным шагом, не объявляется аналогом всего DVC. При нескольких sources/transforms потребуется пересмотр, а не бесконтрольное расширение home-grown DAG.

Curator/host-admin пока доверенные; CLI-разделение не заменяет OS/storage ACL. Это provenance, не detector семантически корректно оформленного poisoning. Все количественные пороги исходной приёмки сохраняются.

## Проверка

Clean regeneration, повторение, восстановление отсутствующего output из verified cache, отказ от corrupted cache, mutation input/lock/source, перепроверка между intake/curator, idempotency, forged/expired source и feedback rejection. Полный dependency audit повторяется без исключений. M03/M04 остаются открыты до фактических storage ACL checks.
