# PB-14 / RB-29 / RB-30 / RB-31: независимое сканирование модели

Владелец: инженер MLSecOps lab. Scope: synthetic CPU, свой checkout и отдельный qualification state. [Контракт](../artifact-intake.md), [ADR](../decisions/0024-independent-artifact-intake.md). Нет production recovery, расходов, очистки чужих services или пересоздания рабочего holdout ledger.

## PB-14: проверка цепочки после изменения scanner

Prerequisites: locked uv/Python, Linux Docker daemon, место для своего image, ожидаемый Git revision. Команды из корня проекта. Сначала read-only:

```powershell
git status --short
git rev-parse HEAD
docker info --format '{{.OSType}} {{.ServerVersion}}'
docker ps --format '{{.Names}} {{.Status}}'
```

Если daemon недоступен, сначала RB-30. При занятом ресурсе или subnet exhaustion использовать [RB-28](qualification-environment-troubleshooting.md), не global prune. Сами intake workers используют network none, не создают bridge networks. Не запускать SQL qualification поверх рабочего state.

Следующий этап изменяет только local dev image tag и создаёт временные workers/новый evidence state. Не перезапускает существующие сервисы. Выбрать новый каталог и не публиковать его содержимое:

```powershell
$state = '.runtime/intake-recheck-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
if (Test-Path -LiteralPath $state) { throw 'fresh state required' }
uv run --locked python -m mlsecops build
if ($LASTEXITCODE -ne 0) { throw 'image build failed' }
$scripts = Join-Path (Get-Location) 'scripts'
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65532:65532 --pids-limit 64 --cpus 2 --memory 4g --tmpfs /tmp:rw,noexec,nosuid,size=64m --mount "type=bind,source=$scripts,target=/app/scripts,readonly" trusted-mlsecops:dev python -m unittest scripts.artifact_intake_qualification
if ($LASTEXITCODE -ne 0) { throw 'intake contracts failed' }
uv run --locked python -m scripts.artifact_intake_native --output "$state/native.json"
if ($LASTEXITCODE -ne 0) { throw 'native intake failed' }
uv run --locked python -m mlsecops.qualification --state "$state/developer"
if ($LASTEXITCODE -ne 0) { throw 'developer chain failed' }
```

Expected: все 21 contracts, 5 native cases и developer chain pass. В native reports должны остаться fail для unsafe input и inconclusive для timeout/crash, пустые approved_outputs и cleanup=true для двух injections. Восстановление доказывает clean-after-faults, а не только exit 0. Developer report остаётся full_acceptance=inconclusive; source/image digests должны соответствовать текущему build. В каждом новом evaluation есть intake pass, exact model digest и release_status=unapproved.

Native CLI является тестовым playbook, не production endpoint. Подмена процесса для fault injection ограничена собственным именованным worker-контейнером и его pinned image, удаление делает штатный runner по точному имени. Fixtures и raw state остаются в .runtime; в Git только очищенные counts/digests/evidence links. Если cleanup не подтверждён, сначала установить конкретное имя/ownership, затем отдельное scoped действие. Автоматическая очистка всех stopped containers не разрешена.

Rollback: не удалять evidence и не добавлять forged intake в старый signed report. При регрессии остановить новые evaluations; восстановить согласованный предыдущий код/image отдельным reviewed change, сохранив связь с его исторической схемой. Это не разрешает release непроверенной модели. Working DB и budget не сбрасывать. Эскалировать владельцу при повторном protocol mismatch, неясном ownership, изменённом trust context или нехватке ресурсов.

## RB-29: model_intake_fail / model_intake_inconclusive

**Симптом и влияние:** prediction/evaluation не продолжается. Status=fail означает model/profile/protocol rejection; inconclusive означает недоступную или не завершённую инспекцию. Ни один не даёт approval. На SQL пути попытка уже может быть потрачена.

**Диагностика:** сверить model SHA-256, image/source fingerprint, версии ONNX/policy, origin, request/response hashes, counts и time interval. Пользоваться очищенным report из qualification или `IntakeFailure.report`; не сохранять stdout неизвестной модели или exception body в public logs. Если CLI оставил только краткую ошибку, не придумывать отсутствующий scan report.

- `origin=worker`, model_parse/profile rejection: воспроизвести на тех же bytes в изоляции. Проверить support matrix, не менять расширение и не грузить pickle для диагностики. Исправление export создаёт новые bytes и требует новой инспекции.
- `scanner_protocol_rejected`: проверить nonce/subject/image/tool/counts. Подстановка прошлого успешного ответа и добавление approved output вручную недопустимы. Повторять только после установленного исправления binding.
- `scanner_timeout`, `scanner_crash`, `scanner_unavailable`: сначала runtime/process/resource диагностика. Не преобразовывать в pass и не повышать лимиты вслепую. Injections PB-14 подтверждают fail-closed поведение, но не объясняют настоящий crash.
- `unexpected_fields` для исторической evaluation: новая схема требует intake. Старый report не был принят этим кодом, даже если его подпись валидна. Сохранить исторический evidence; новая evaluation требует budget и повторного исполнения, не редактирования подписи.

**Восстановление:** после исправления PB-14 на новом qualification state, затем согласованная повторная evaluation. Критерий: exact bytes проходят новый scan и downstream reader, неисправный input по-прежнему блокируется, у failure approved set пуст. Полный M21/release этим не закрывается. При подозрении на parser exploitation остановить candidate и эскалировать security owner, не выполнять его на host.

## RB-30: ограничения Windows и выключенный Docker

**Наблюдение 2026-10-13:** Docker engine был недоступен после перерыва; установленные Desktop/WSL не переустанавливались. Запущен существующий Docker Desktop скрыто, затем `docker info` подтвердил Linux daemon 29.8.0. Это восстановление доступности процесса, не установленная причина его прежней остановки. Никаких daemon network/security settings не менялось.

При отсутствующем daemon проверить Desktop status и путь установленного приложения. Запуск разрешён только для найденной собственной установки; например, на этом стенде использовался `C:/Users/Abrakadabra124/AppData/Local/Programs/DockerDesktop/Docker Desktop.exe` через `Start-Process -WindowStyle Hidden`. После запуска повторить read-only info, не повторять установку/перезагрузку автоматически. Если engine не готов, сохранить environmental limitation и эскалировать владельцу.

**Наблюдение tests:** Windows вернул WinError 1314 при создании symlink fixture. Это отсутствие privilege у host test process, не отказ path validator и не уязвимость модели. Тест отделён от остальных path/mutation cases и выполнен в Linux container; Linux/CI suite не содержит skip для этой проверки. Не требуются Administrator, отключение проверки symlink или изменение Developer Mode.

**Проверено:** 20 tests в read-only/non-root Linux container, включая настоящий symlink; 19 остальных на Windows, 100% statements/branches intake module в host coverage. Negative fault recovery выполнен отдельным native Docker suite. Проблемы candidate, SQL и production не объявляются устранёнными по этим результатам.

## RB-31: evidence создан до ownership bootstrap

**Реальный CI failure:** [developer run 38430228251](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38430228251) на `f6e3560` прошёл все 20 intake contracts, 100% coverage и 5 native cases, но затем bootstrap отказал с `refusing_nonempty_unowned_workspace`. Report записался в `.runtime/evidence` до создания `.runtime/workspace.json`. Это дефект порядка CI steps, не unsafe model acceptance и не отказ guard.

**Диагностика без изменений:** сверить порядок steps и error code; проверить существование marker и историю создания каталога. Не выводить keys или содержимое private state. Само отсутствие marker не означает, что каталог можно очистить.

**Исправление:** CI сначала выполняет штатный bootstrap, затем native script сохраняет evidence. Guard не отключён. Regression test воспроизводит отказ для unowned state с report, затем проверяет bootstrap -> evidence -> повтор bootstrap с теми же workspace/key digests. Исходный failed run сохранён, новый CI выполняется на исправленном commit, а не rerun до случайного green.

**Восстановление локально:** сохранить проблемный каталог для диагностики; для qualification выбрать новый owned state и сначала bootstrap. Не создавать workspace.json вручную и не стирать каталог ради прохода. PB-14 намеренно использует `$state/native.json` и отдельный `$state/developer`, поэтому отчёт не загрязняет дочерний developer bootstrap root.

**Критерий завершения:** новый clean-checkout developer CI проходит bootstrap, intake и последующую трёхкратную developer qualification; прежний отрицательный ownership case остаётся reject. Последний verified CI записывается в STATUS. При неясном ownership остановить изменяющие действия и эскалировать владельцу. Rollback CI change не должен сопровождаться удалением данных или ослаблением guard.

**Проверка исправления:** [run 38431906395](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38431906395) на `813783b` success. 21 contracts, 100% statement/branch coverage intake, 5 native cases и 74 developer checks/3 fresh runs после штатного bootstrap. Исходный failed run остаётся в истории. Это завершение конкретного CI recovery, не общая R1 acceptance.

### R1-B01: неполная identity при повторном bootstrap

**Controlled reproduction 2026-10-20, не production incident.** При удалённом private key повторный bootstrap создавал новый ключ до отказа сравнения с trust anchor; при удалённом `trusted-keys.json` создавал файл молча. Это небезопасное изменение существующего workspace, а не разрешённая ротация. Малформатный marker также не проверялся полностью.

**Read-only диагностика:** остановить повторные bootstrap; проверить наличие `workspace.json`, `trusted-keys.json` и четырёх role keys, их происхождение и последнюю согласованную копию. Не выводить PEM, не создавать marker/anchor вручную и не удалять workspace. Отсутствие файла не даёт права восстановить доверие из оставшихся файлов.

**Исправление CP1:** existing marker проходит strict schema/ID validation; существующие ключи только читаются, public keys сверяются с имеющимся anchor. Генерация разрешена лишь для нового пустого workspace. Неполный первый bootstrap тоже требует явного восстановления, а не скрытой генерации новой identity. Нет нового механизма migration/rotation.

**Проверка в рабочей копии:**

```bash
uv run --locked coverage run --data-file=.coverage-bootstrap --source=mlsecops.bootstrap -m unittest scripts.bootstrap_qualification scripts.artifact_intake_qualification.ArtifactIntakeContracts.test_evidence_must_not_precede_workspace_ownership
uv run --locked coverage report --data-file=.coverage-bootstrap --fail-under=95
```

9 methods прошли, statement/branch coverage bootstrap 100%; исходный RED дал 9 failures в 5 methods. Эти tests используют настоящие временные файлы и ключи, но controlled inventory без Docker. Это **локальное исправление CP1, ещё не опубликованное как проверенный runtime-код**; команды нового модуля доступны в рабочей копии. Полный M01/native checkpoint ещё не принят. После CP1 заменить эту отметку ссылкой на code/evidence.

**Recovery / rollback:** при missing/mismatch identity не запускать serving/promotion. Владелец может восстановить согласованный backup в отдельном проверенном owned workspace и сверить trust pins по существующей процедуре recovery; здесь такая операция не выполнялась. Если подтверждённого backup нет, сохранить отказ и эскалировать owner/security reviewer, не «исправлять» trusted file. Не откатывать guard ради запуска; rollback приложения не разрешает смену ключей или удаление единственной копии.
