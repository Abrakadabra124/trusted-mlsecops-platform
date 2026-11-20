# Native Go PURL interface observation

20 ноября 2026 года. [Run 44673045898](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44673045898),
[job 136078266185](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44673045898/job/136078266185),
source `bfc5a5cd352bf1a963688ae9b08ef7bdf3552e8e`: **success**.
Это проверка интерфейса scanner, а не application coverage или B02/M18/R1.

## Что реально выполнено

Стандартный disposable Ubuntu 24.04 runner получил точный source checkout,
Python 3.12.15 и locked dependencies через uv 0.12.23. Docker client 28.0.4.
Использован прежний Grype 0.120.1 image digest из `scripts.image_audit.GRYPE_IMAGE`.
Новых scanner images, исключений severity или credentials нет.

После одного DB update выполнены три фиксированных PURL. Во время scans
network disabled, cache read-only; snapshots и DB descriptors совпали,
возраст DB проверялся прежним правилом не более 120 часов. Один invocation
на PURL создал JSON stdout, CycloneDX JSON и приватный trace.

У каждого case: JSON и CycloneDX доступны и разобраны; `source` соответствует
фиксированному PURL; в CycloneDX ровно один component с правильными name,
version, PURL, `type=library` и `syft:package:type=go-module`.

| Case | PURL | Exit | JSON matches | Trace с точным PURL | Zero-match summary |
|---|---|---:|---:|---:|---:|
| control | `pkg:golang/golang.org/x/net@v0.16.0` | 2 | 23 | 1 | 0 |
| streaming | `pkg:golang/k8s.io/streaming@v0.36.4` | 0 | 0 | 1 | 1 |
| malformed-version | `pkg:golang/golang.org/x/net@not-a-version` | 0 | 0 | 1 | 1 |

Число matches не названо числом уникальных CVE. Existing positive-control
validator прошёл на control. Для него распознан один ERROR-level log и ноль
generic final-summary строк; raw error text публичная проекция не содержит.
Причина этой log-строки отдельно не доказана. Exit 2 согласован с обнаружением
High/Critical по прежнему fail-on policy, но не является сам по себе полным
доказательством правильной обработки.

Для streaming и malformed-version распознана строка о нуле matches по одному
package. У всех трёх cases counters известных matcher/search errors равны нулю;
у последних двух ERROR-level counter тоже ноль. Это наблюдения распознанных
сообщений, а не универсальный parser всех возможных scanner ошибок.

## Практический вывод для следующей реализации

Grype принял `not-a-version`, создал обычные package reports и вернул exit 0
с пустым набором matches. Значит, parsed package, trace и пустой report вместе
не доказывают существование или корректность version coordinate.

Будущий supplemental scanner должен сначала выбрать exact coordinate из
[проверенной source-to-publication mapping](kubernetes-module-mapping-2026-11-20.md),
отклонить неизвестный/подменённый input и только затем проверять результаты.
Нужны все 28 derived PURLs, исходные exact inventories, та же свежая DB,
правильные image/binary bindings и сохранение всех исходных C/H/U findings.
В этом run выполнялись только три диагностических cases.

## Очистка и воспроизведение

Основной projection: `stage=observe`, `phase=export`,
`status=observations_captured`, `failure_code=null`, cleanup **4/4**.
Все четыре записи содержат valid CID и `cleanup_stage=verified`.
Отдельный cleanup step повторно подтвердил **4/4**. Его пустой `cases` и
`scanner_returned=false` ожидаемы: он не повторяет scanner calls.

Job: **2 min 12 s**; основной observe step: **1 min 54 s**. Терминальные
job/step states, SHA, обе закрытые проекции и соответствующий source сверены.
Raw reports остались на disposable runner; постоянного приватного backhaul
и их локального offline replay этот workflow не реализует.

[Runbook и playbook](../operations/go-purl-observation.md) содержит команды
наблюдения, порядок повторения и историю трёх неудачных попыток. В третьей
установлен relative bind source, отклонённый Docker 28.0.4. Исправление
`STATE.absolute()` прошло parent **21 controlled tests / 1.112 s**, review,
статические проверки и этот native run. Controlled tests отдельно проверяли
реальную сборку Docker command с заменой process boundary; это не CI test count.

`docker_stderr.other=true` означает отсутствие распознанных фиксированных фраз,
в том числе при штатном выполнении. Это поле не означает отдельную ошибку.
Coverage остаётся **6/14**; полный R1, independent M22 и private cross-job
transport не приняты этим диагностическим запуском.
