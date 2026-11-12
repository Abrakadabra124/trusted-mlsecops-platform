# T29: serving probe в одной ConfigMap

Неделя 11 - Security events и потеря telemetry; T29. Срез на 2026-11-12:
исправление проверено локально, Security и Primary завершились успешно.
M11 на этом source отменён по лимиту 30min: принятия M11 и нового release нет.
Полные T29/M23, M18 и R1 остаются открытыми.

- Код исправления: [a59e6f27db6e787dfb261c80c0a20d67d0854b63](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/a59e6f27db6e787dfb261c80c0a20d67d0854b63).
- Опубликованный successor: [59bff943fd6395cb5bf4b82f6fa98fdc660ab79b](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/59bff943fd6395cb5bf4b82f6fa98fdc660ab79b).
  Между commits изменены только STATUS.md и runbook; код и workflows совпадают.
  Все свежие hosted результаты ниже относятся к `59bff943fd6395cb5bf4b82f6fa98fdc660ab79b`.
- Диагностика и ограничения: [runbook](../operations/trust-acceptance.md#probe-bundle-в-прежнем-бюджете-configmap).

## Симптом и установленная причина

Предыдущий [M11 43255736643, job 131313326734](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43255736643/job/131313326734)
на `cf019804ae1e0a154bac0ba9e67e0ec26d1c8e72` завершился отказом после
`root-rotation-completed`. Создание второго временного ConfigMap (`index=1`)
получило конечную категорию `quota`: `count/configmaps`, requested=1,
used=4, limited=4. Native campaign шла 16:14:18.765150-16:29:29.914562 UTC;
cases/metrics остались пустыми. Остановка исходного SQL-сервиса и удаление
собственного кластера подтверждены в исторической проверке.

Это прямое свидетельство превышения квоты, но не полного inventory объектов.
Контролируемый harness моделирует три постоянные карты: CA namespace,
конфигурацию HTTP serving и rotated observer. Прежние две временные карты
требовали пятый слот; privacy/CLI режим добавлял третью карту с Python-кодом.
Harness воспроизвёл отказ со значением квоты из настоящего resource manifest.

Отдельный ранний [Primary 43255745071](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43255745071)
на `cf01980` отказал до первого native case/stage. Его причина остаётся
неизвестной и не приравнивается к M11 quota refusal; SQL/cluster cleanup прошёл.
Новый Primary pass не устанавливает причину этого исторического отказа.

## Исправление и границы ресурсов

[invoke](../../scripts/kube_serving_native.py) собирает один временный bundle
на Job. ConfigMap - объект Kubernetes для несекретных данных конфигурации;
его `immutable=true` запрещает изменение данных после создания.

1. `config.json` и `request.json` находятся в одной ConfigMap с уникальным именем
   и workspace ownership label. Прежние read-only `subPath` mounts сохранены.
2. Privacy/CLI Python-файлы добавляются в тот же объект. Явные `items` проецируют
   в `/app/scripts` только `.py`, включая `__init__.py`; JSON туда не попадает.
   Annotation `trusted-mlsecops/qualification-source` сохраняет hash Python
   bundle, а не заявляет hash всей объединённой ConfigMap.
3. До первого API `create` считается сумма UTF-8 байтов ключей и значений `data`.
   При размере больше 1 MiB (1048576 байт) следует
   `kube_serving_probe_bundle_limit`, без создания ресурсов. Проверяется размер
   в байтах, не количество символов.
4. [ResourceQuota](../../mlsecops/kube_storage_resources.py) остаётся
   `count/configmaps=4`: модель harness использует три постоянных объекта плюс
   один временный. Credentials остаются в отдельных Secrets; права serving,
   изоляция worker и deadlines не расширены.
5. [Cleanup](../../mlsecops/kube_promotion.py) работает с зарегистрированными
   Job и bundle: сверяет ownership и UID (уникальный идентификатор объекта),
   удаляет в обратном порядке и проверяет отсутствие. Затем ожидается отсутствие
   probe Pods. Чужой UID не разрешает удаление; ошибки cleanup не маскируются.

Если фактический inventory не оставляет даже одного слота, требуется отдельная
диагностика. Удаление неизвестных ConfigMaps и увеличение квоты не входят в fix.
Primary failure report также получил ограниченную source location и конечную
классификацию Kubernetes request без текста исключения и private payload.

## Проверенные результаты

Clean checkout кода `a59e6f2`: 38 affected tests, 0 skips; внутренний review
зафиксировал 0 Critical и 0 Important. Проверка документации точного clean
`59bff94` прошла. Отдельный локальный повтор
двух непосредственно изменённых test modules при подготовке этой сводки:
32 tests, 0 skips, 0 failures/errors, `-W error`, exit 0.

Harness проходит девять сочетаний ordinary/privacy/CLI, success/failure,
coordinator и foreign UID. Проверяются ровно одна карта, правильные JSON,
Python-only projection и cleanup. Отдельный oversized case подтверждает отказ
до API writes. Это controlled tests; результат свежего M11 ими не подменяется.

[Security 43259909260](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43259909260)
завершился `success`. Пересчёт приватного вывода unittest: 1063 выполнения
в 24 пакетах, 24 результата OK, 0 skips. Повторные запуски тестов входят в число
выполнений, поэтому оно не обозначает 1063 уникальных теста.

Четыре разобранных native JSON reports дали следующие размеры `cases`:

| Native проверка | Cases | Status |
| --- | ---: | --- |
| Promotion audit admission и SQL rollback | 25 | pass |
| Trust history observer | 37 | pass |
| Периодический trust observer | 17 | pass |
| HTTP identity source и owned child | 46 | pass |

Итого 125 cases. Во всех четырёх отчётах source равен `59bff94`,
`release_ready=false` и одинаковый fingerprint:
`a38a58161647f54ea3ccdb0cf32d7594d288c45ffbc507416e98db57aaec4752`.
Эти проверки подтверждают свои компонентные сценарии, не полный M23.

[Primary 43259935227, job 131328180423](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43259935227/job/131328180423)
завершился `success`. Две полные копии native report идентичны: `status=pass`,
source `59bff94`, `source_dirty=false`, тот же fingerprint. Native interval:
16:36:08.511637-16:47:48.785837 UTC. Пересчитаны 21 aggregate case,
17 controlled cases и 12 audit checks; это отдельные вложенные наборы,
не сумма независимых тестов.

| Наблюдение Primary | Результат |
| --- | --- |
| Actual startup до admission | 32.299194 s, heartbeat 0 -> 1 |
| Controlled startup | 54.625198 s |
| Возврат serving owner, включая final validation | 40.006074 s, 2 identity receipts |
| Несовместимая конфигурация / восстановление | 59.853612 s / 56.883185 s, при восстановлении 1 receipt |
| Максимальная абсолютная ошибка относительно golden scores | 7.583384781240099e-08 |
| Конечное состояние serving | 0 service Pods, 0 worker Jobs, audit state сохранён |

Terminal SQL stop и owned cluster deletion подтверждены по шагам workflow.
`full_M10=inconclusive` и `release_ready=false` сохранены: controlled admission
не означает разрешённый production release.

[M11 43259927815](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43259927815),
job131328156026, завершился **cancelled**. Job выполнялся16:33:22-17:03:41 UTC;
GitHub check annotation прямо подтверждает превышение максимального времени30m0s.
SQL stop и owned cluster deletion имеют terminal success. M11 report остался
`inconclusive`, exit_code2, с предупреждением о незавершённой acceptance.

Root rotation завершилась16:47:40 UTC. После неё Jobs с одной ConfigMap прошли
прежнюю точку quota-отказа, появились результаты четырёх controlled faults.
Actual candidate начался16:56:39, его root rotation16:57:03, HTTP matrix16:58:39,
outage16:59:57 и blackhole17:02:00 UTC. Отмена зарегистрирована17:03:35.
Это подтверждает продвижение исправленного orchestration, но не полную M11:
завершённого gate, live signer acceptance и recovery на этом run нет.

Повторные owner transfers теперь являются конкретным направлением исправления
наблюдаемого превышения общего бюджета. При этом точную долю времени каждого
компонента нельзя вывести из одних stage markers. Подготовленная группировка
сохраняет отдельные Jobs и все проверки; её достаточность требует нового CI.

## Последующее исправление временного бюджета

Подготовлены два явных ownership windows после соответствующей root rotation:
семь controlled Jobs и восемь candidate Jobs. Первые пять controlled windows и
candidate root/peer transition остаются отдельными. На полном пути22Jobs
выполняются по-прежнему, а возвраты owner сокращены с21 до8. Каждый Job сохраняет
свежие проверки и собственную cleanup; один ownership report записан на группу.
Все deadlines, permit и отрицательные сценарии остаются прежними.

Отдельно исправлен воспроизведённый setup busy до retry-loop в audit readback.
Setup/snapshot делят прежние3s; поздний результат и постоянная ошибка не дают pass.
Это не доказанная причина раннего Primary или30min timeout. Ограничения и порядок
диагностики описаны в [runbook](../operations/trust-acceptance.md#m11-не-укладывается-в-общий-бюджет).

Совместная проверка:170tests/0skips pass. Отдельный coverage suite58tests прошёл,
пять ownership/campaign modules покрыты165/165statements и40/40branches.
Ruff check/format прошли для573Pythonfiles. Три scoped внутренних review не нашли
Critical/Important; это не независимый reviewer M22 и не native acceptance.
Новая CI-кампания необходима до M11 milestone release.

## Воспроизведение

Локальная проверка использует существующую `.venv` из корня checkout точного
source. Она не требует запуска Docker, WSL, Kubernetes или SQL. Для проверки
исходного fix допустим также точный `a59e6f2`; код этих modules совпадает.

```powershell
if ((git rev-parse HEAD) -ne '59bff943fd6395cb5bf4b82f6fa98fdc660ab79b') { throw 'source mismatch' }
$checkoutState = git status --porcelain
if ($LASTEXITCODE -ne 0 -or $checkoutState) { throw 'checkout is not clean' }
./.venv/Scripts/python.exe -W error -m unittest scripts.kube_serving_native_qualification scripts.kube_promotion_native_qualification
if ($LASTEXITCODE -ne 0) { throw 'focused tests failed' }
./.venv/Scripts/python.exe scripts/check_docs.py
if ($LASTEXITCODE -ne 0) { throw 'docs check failed' }
```

Ожидаемый focused результат для этого source: 32 tests, 0 skips.
38-test clean campaign выше - отдельная ранее выполненная проверка.
Проверка docs не заменяет runtime campaign или проверку внешних ссылок.

Полный повтор выполняется только в разрешённом disposable hosted CI
(continuous integration, автоматическая проверка в GitHub Actions), через
существующие [M11 workflow](../../.github/workflows/kubernetes-serving.yml) и
[Primary workflow](../../.github/workflows/kubernetes-promotion.yml).
Следующая инструкция воспроизводит исторический `59bff94`, включая известный
30min timeout M11; она не является командой приёмки нового исправления.
При подготовке документа повтор не выполнялся.
`gh run rerun` сохраняет source исходного run, вместо выбора движущейся ветки.
При незавершённом run блок останавливается до rerun. Перед повтором не должно
быть другой активной кампании того же workflow/ref, чтобы не вызвать её отмену.

```powershell
$repository = 'Abrakadabra124/trusted-mlsecops-platform'
$source = '59bff943fd6395cb5bf4b82f6fa98fdc660ab79b'
$runIds = @(43259927815, 43259935227)
foreach ($runId in $runIds) {
    $run = gh run view $runId --repo $repository --json headSha,status,conclusion,jobs | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $run.headSha -ne $source) { throw 'run source mismatch' }
    if ($run.status -ne 'completed') { throw 'current run is still pending' }
    foreach ($cleanupName in @('Stop verified owned source SQL', 'Remove verified owned disposable cluster')) {
        $cleanup = @($run.jobs.steps | Where-Object { $_.name -eq $cleanupName })
        if ($cleanup.Count -ne 1 -or $cleanup[0].conclusion -ne 'success') { throw 'cleanup is not verified' }
    }
}
foreach ($runId in $runIds) {
    gh run rerun $runId --repo $repository
    if ($LASTEXITCODE -ne 0) { throw 'rerun rejected' }
}
```

Внутри M11 workflow используется существующий acceptance runner:

```bash
uv run --locked python -m mlsecops.acceptance --gate M11 --state .runtime --output .runtime/evidence/M11.json
```

При принятии повтора сверить exact source, terminal jobs, первичные отчёты и
traces, отсутствие skips и сохранение исходных deadlines, затем SQL stop и
удаление собственного кластера. `fail`/`inconclusive`, неизвестная причина или
неподтверждённый cleanup не становятся pass. Raw logs, полные private JSON,
идентификаторы ресурсов и credentials остаются в `.runtime` вне публикации.
