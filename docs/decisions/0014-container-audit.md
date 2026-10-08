# ADR 0014: воспроизводимый container audit без Docker socket у scanner

Дата: 2026-10-08. Статус: **Implemented and native-verified slice, severity gate failed**. Относится к T01/T02 и M01, не заменяет полный gate. [Runbook](../container-audit.md), [native evidence](../evidence/container-audit-2026-10-08.md).

## Проблема

Локальные ручные Grype attempts не завершились: TLS timeout при загрузке DB. Один успешный запрос metadata не доказывает audit. Нельзя переводить vulnerability count в 0, ослаблять TLS/freshness или считать Python dependency audit проверкой Debian packages. Нужен одинаковый исполняемый путь локально и в clean CI, сохраняющий inconclusive при недоступной базе.

## Решение

1. Host operator разрешает текущий worker image и pinned PostgreSQL в immutable image IDs и экспортирует точные images через Docker save. Scanner не получает Docker socket, kubeconfig, credentials, SQL data или весь workspace.
2. Отдельный pinned Syft container без сети создаёт SBOM (software bill of materials, перечень пакетов). Grype JSON с пустым matches сам по себе не доказывает, что пакеты найдены. Проверяются image binding, непустой package inventory и обязательные пакеты выбранного профиля.
3. Pinned Grype получает свежую официальную DB в отдельном owned cache. Затем offline scan использует этот snapshot, сохраняя hash/age verification. Age limit остаётся 120 часов. Недоступная, повреждённая или устаревшая DB запрещает pass; произвольный mirror и insecure TLS не добавляются.
4. SBOM поступает в Grype read-only, отчёт проверяется по image ID, scanner version, DB validity/time и policy. High/Critical findings блокируют этот component, unknown severity/неподтверждённое покрытие остаются inconclusive. Ignore/only-fixed/exclude rules не добавляются. Все уровни сохраняются в очищенном summary.
5. Контрактные отрицательные fixtures предшествуют implementation. Живой positive detection control сканирует известный уязвимый package identifier без установки или исполнения этого пакета. Его обнаружение не доказывает полноту vulnerability базы, но исключает простое принятие постоянно пустого scanner output.
6. CLI сначала инвалидирует старый output, результаты и временные файлы принадлежат конкретному run. Raw reports/diagnostics сохраняются только в ignored state; публикация ограничена summary без ключей, labels и dump содержимого filesystem. Timeout останавливает только собственный scanner container.

## Scope и оставшаяся работа

Первый slice сканирует ML worker и PostgreSQL artifact storage. Это не полный inventory всех Kubernetes/system images, не независимое подтверждение scanner signatures, не model malware intake M21 и не завершённый M01. T01/T02 остаются открытыми до полного inventory/P0/bootstrap evidence. Existing foundation не меняется. Новые известные findings не маскируются success рабочего ML path.

## Основания

- [Grype scan targets](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/) описывают Docker archives, SBOM и PURL input. Передача архива позволяет не выдавать scanner полномочия Docker daemon.
- [Grype database](https://oss.anchore.com/docs/guides/vulnerability/database/) описывает cached DB и отказ при слишком старой базе. Offline evaluation фиксированного snapshot не равна отключению проверки возраста.
- [Grype JSON](https://oss.anchore.com/docs/guides/vulnerability/json/) описывает matches, severity, package и fix fields. Отсутствие matches не является числом проверенных пакетов.
- Pinned CLI Grype 0.120.1 сообщает exit 2 при `fail-on` threshold, тогда как текущий configuration reference описывает 1. Runner должен проверять реальную pinned версию и содержимое отчёта, а не полагаться на непроверенное описание latest.

Выбор ограниченного execution wrapper и policy - решение проекта, не гарантия Anchore о нашем runtime. Подпись scanner image и расширение на control-plane inventory требуют отдельного проверяемого продолжения, а не подразумеваются digest pinning.
