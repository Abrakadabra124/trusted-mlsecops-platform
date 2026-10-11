# Ранбук: воспроизводимость и наблюдение за CI

Владелец - ML/platform engineer; расхождение lineage или возможная подмена требует security review. Процедуры относятся к synthetic local CPU component, не разрешают release. [Контракт и evidence](../reproducibility.md).

## RB-05. `invalid_json_value` при фиксации predictions

**Реально встречено 2026-10-11:** первый native reproducibility запуск завершился inconclusive после обучения. Причина - проверенный prediction protocol возвращает `numpy.ndarray`, а строгий canonical JSON допускает обычные JSON-совместимые типы. NumPy представляет числовые массивы для вычислений; это не стандартный JSON-тип.

**Исправлено:** в [run_one](../../scripts/reproducibility_native.py) массив преобразуется через `.tolist()` **после** `PredictionBatch.consume`, затем строгие checks проверяют форму, конечность, диапазон вероятностей и digest. Глобальный serializer не ослаблен; NaN/bool/out-of-range по-прежнему отвергаются.

**Диагностика и повторная проверка:**

1. Сохранить время/причину отказа и приватный report. Неполный run не считать принятой моделью; не удалять его как будто ошибки не было.
2. Проверить consumer boundary, не приводить произвольный worker stdout к «удобным» типам до валидации.
3. Запустить чистые comparator contracts:

```text
uv run --locked python -m scripts.reproducibility_qualification
```

4. После исправления повторить PB-03. Новый UUID и настоящие процессы исключают reuse прошлого candidate. Последний report сначала становится inconclusive, поэтому прерванный запуск не оставляет старый pass.

**Проверено:** 31 controlled case и два последовательных native successes после исправления; последний локальный результат `2026-10-11T10:47:42.826468Z`. Первая ошибка не была положительным evidence. При regression остановить этот runner, сохранить рабочий tracking; откат host script не требует отката database.

## PB-03. Native reproducibility campaign

Prerequisites: Docker Linux amd64, locked Python environment, собранные worker/tracking images, достаточно места и отсутствие параллельной qualification. Перед стартом прочитать [tracking runbook](tracking-troubleshooting.md). Действия **не read-only**: создаются datasets, ключи локального тестового state, шесть training runs, шесть prediction runs, один временный image и шесть записей MLflow. Сервис при необходимости поднимается/возобновляется; private данные остаются в `.runtime`.

```text
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.tracking_spike build
uv run --locked python -m scripts.reproducibility_native
```

Build выполняет pinned dependency/image downloads. Если уже есть подходящие образы, повторный build не нужен. Для локальной candidate-квалификации используется `--worker-image trusted-mlsecops:worker-candidate`; это не делает candidate approved или безопасным по image audit.

Ожидания: три одинаковых input bundles, 3 000 общих golden rows, max probability difference <= `1e-6`, AUPRC difference <= `1e-4`. AUPRC характеризует precision/recall при разных порогах; её значение на синтетике не доказывает полезность для реальных релизов. Model/vector hashes сохраняются, даже если они различаются в пределах допустимой воспроизводимости.

Далее **по одному** меняются seed, training data и environment; выполняются реальные новые обучения. Все три попытки сравнить их с исходными повторами должны завершиться `reproducibility_inputs_changed`, даже когда числа предсказаний не изменились. Одинаковый результат не делает разные входы одинаковыми.

**Ветви отказа:**

- Input mismatch в baseline -> сверить request/dataset/policy/source/environment/golden digests, не увеличивать численный допуск.
- Numeric tolerance failure при одинаковых входах -> сохранить все vectors и hashes приватно, проверить профиль и версии, остановить принятие. Не удалять «неудачный» повтор из тройки.
- Native mutation не обнаружена -> fail, проверить, что изменённый input реально использовался. Не заменять live training словарём фиктивных digests.
- Tracking/TLS недоступен -> PB-01; обучение само по себе не доказывает сохранение/read-back истории.
- Docker build/cleanup прерван -> исследовать только UUID-owned temporary image tags. Cleanup проверяет immutable ID и ownership label; global image prune запрещён.

**Конечная проверка:** `.runtime/evidence/reproducibility.json` содержит pass, шесть разных training IDs и шесть разных tracking receipts, три отрицательных mutation outcomes и `release_ready=false`. Отчёт component не закрывает полный M06. Не публиковать state/keys/model blobs; в Git включать только очищенное описание/CI evidence.

## RB-06. GitHub API/TLS не отвечает во время CI

**Наблюдалось:** отдельные запросы статуса Actions завершались transport/TLS timeout. Это ошибка наблюдения; без статуса job нельзя считать CI упавшим или успешно завершённым. Постоянная первопричина сетевых сбоев не установлена.

1. Сохранить repository, commit SHA и уже полученный run ID. Если shell/tool вернул live session ID, ждать **тот же** handle, не запускать дубликаты.
2. В другой read-only проверке получить статус того же run, например `gh run view <RUN_ID> --repo Abrakadabra124/trusted-mlsecops-platform --json status,conclusion,headSha,jobs`.
3. При повторном timeout увеличить интервал наблюдения. Не отключать TLS, не выводить credentials и не делать Actions rerun только из-за отсутствия ответа API.
4. Сверить `headSha`, terminal status и conclusion; затем конкретный step и очищенный report. Зелёный старый run не относится автоматически к новой версии.
5. Если сервер подтвердил реальный сбой, исправлять конкретную причину. Новый push может отменить ещё работающий run из-за workflow concurrency; cancelled не считать pass.

**Rollback:** для ошибки наблюдения не требуется изменение кода/сервисов. При невозможности получить terminal evidence оставить CI «не подтверждён», продолжать локально проверяемую работу. Исторические runs после повторного наблюдения получили terminal results, но устранение причины сетевой нестабильности не заявляется.

Для всех случаев использовать [incident template](incident-template.md). Исходные M01-M23 и release blockers не ослаблять ради зелёного статуса.

## RB-07. Допуск проверен только относительно первого повторения

**Выявлено при review, воспроизведено controlled test:** значения второго и третьего повторов на `+9e-7` и `-9e-7` относительно первого отдельно укладываются в `1e-6`, но отличаются друг от друга на `1.8e-6`. Первоначальный comparator ошибочно принимал эту тройку. Это дефект проверки, не наблюдавшаяся нестабильность native модели: в реальных baseline runs разница была 0.0.

**Исправление:** для каждого golden row рассчитывать `max(probabilities)-min(probabilities)` по всем трём повторам, затем общий максимум. Digest/shape checks и порог не изменены. Добавлены failing-before-fix случай и positive control с допустимым разбросом.

**Порядок проверки:** comparator contracts -> PB-03 -> убедиться в pass baseline и отказах native mutations. После исправления comparator имеет 33 controlled cases. Возвращать прежнюю first-reference-only проверку как rollback нельзя; при regression остановить принятие результатов и сохранить векторы для расследования. Старый pass с ненулевым расхождением потребовал бы пересчёта, не автоматического доверия.

## Дополнение к RB-06: watcher показывает устаревшее состояние

2026-10-11 при проверке `c2597e5` собственный процесс `gh run watch 38157424605` продолжал работать и сохранял in-progress для M20. В 17:12 UTC direct query уже показывал `completed/success`, remote `updatedAt=17:06:04Z`; лог содержит `M20: pass` в 17:05:56Z. Наблюдаемое расхождение подтверждено; внутреннюю причину CLI, сети или output handling не удалось установить, не называть её исправленной.

Безопасная последовательность для собственного watcher:

```powershell
$runId = 38157424605
gh run view $runId --json headSha,status,conclusion,updatedAt,jobs
gh run view $runId --log > .runtime/ci-watch-recheck.log
```

Путь для raw logs должен быть игнорируемым локальным каталогом этого проекта; не публиковать файл. Проверить exact head SHA, terminal state и релевантный gate outcome. Один timeout, ошибка HTTP или неполный output не подтверждают завершение. Если прямой запрос тоже неизвестен, повторять наблюдение того же run, не запускать новый workflow из-за истечения локального ожидания.

Когда remote state действительно terminal, разрешено Ctrl+C только в собственном локальном watcher. В наблюдённом случае локальный helper завершился exit 1 после Ctrl+C, но remote workflow остался success. Это не failed CI и не команда `gh run cancel`; GitHub job не отменялся, повторный запуск не создавался. Перед продолжением подтвердить, что собственный handle завершён. Не останавливать чужие shell/gh процессы и не делать массовый process kill.

Rollback инфраструктуры при сбое наблюдения не нужен. В [STATUS](../../STATUS.md) записываются результаты remote run, не exit code остановленного watcher. При устойчивом расхождении сохранить версию CLI, run ID, timestamps и безопасные excerpts для диагностики; credentials и raw logs оставлять приватными.
