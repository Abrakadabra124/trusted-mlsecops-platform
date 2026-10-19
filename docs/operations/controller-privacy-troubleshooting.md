# RB-63 / PB-37: controller privacy и неполная очистка transport

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Владелец: platform operator, при подозрении на раскрытие данных подключается security reviewer. [ADR 0044](../decisions/0044-controller-process-privacy.md), [evidence](../evidence/controller-privacy-2026-10-19.md). Не является полной M13/R1-приёмкой.

## Симптом и влияние

- controller_rejected / controller_probe_rejected / serving_configuration_rejected: CLI завершился без успешного результата; причина не отражается в stdout/stderr, чтобы не раскрыть private path/credential/exception.
- Intake probe возвращает status=fail, reason=kube_intake_probe_incomplete, release_ready=false. Прежнее свободное kube_intake_* сообщение не считается доверенной диагностикой.
- worker_transport_rejected: worker/output/cleanup не подтверждён. Отсутствие traceback не означает исправную инфраструктуру.
- worker_transport_cancelled и exit 130: отмена; cleanup предпринят, но этот код не является подтверждением освобождения всех ресурсов.
- serving_lifecycle_rejected в Uvicorn: запуск/закрытие приложения не подтверждён; CLI не должен сообщать успешное завершение после failed shutdown.

Новые training/evaluation результаты и promotion не принимаются. Не подставлять empty JSON или status=pass для продолжения pipeline.

## Read-only диагностика

Prerequisites: точный checkout, uv и locked Python 3.12; доступ только к собственному job/run. Нельзя просматривать raw private requests, signer key или весь container environment.

```powershell
git rev-parse HEAD
git status --short
uv run --locked python -c "import sys; print(sys.version.split()[0]); print(sys.platform)"
uv run --locked python -c "from pathlib import Path; from mlsecops.data_source import validate_lock; validate_lock(Path.cwd()); print('source_lock_valid')"
```

Ожидание: зафиксированы revision/dirty state; source lock валиден. Windows controlled tests допустимы, но production CLI требует Linux и fail closed на неподдерживаемой платформе. Не отключать guard ради Windows demo.

Для уже известного CI run получить только metadata, без raw log dump:

```powershell
gh run view <RUN_ID> --repo Abrakadabra124/trusted-mlsecops-platform --json headSha,status,conclusion,jobs
```

`<RUN_ID>` заменяет оператор после проверки repository/run ownership. Сверить exact headSha, completed status и все jobs. Pending/skipped не доказывают исправление. Publisher/scorer snapshot должен быть получен от реальных controller processes в disposable Linux qualification: dumpable=0 и core_limits=[0,0]. Запуск нового readback в другом процессе не проверяет старый процесс.

## Ветви отказа

1. **Guard unavailable.** Проверить OS/профиль образа и доступность штатных Linux prctl/resource. Не добавлять privileged, SYS_PTRACE, host sysctl или разрешение core dumps. Если профиль не поддерживает policy, оставить fail и эскалировать.
2. **Reader construction/start failure.** Служебное состояние готовится до Popen, после получения child cleanup действует сразу. Partial startup приводит к kill/reap child и независимым попыткам закрыть безопасные pipes. Ошибка Thread.start может быть неоднозначной: системный поток уже создан, Python ident ещё отсутствует.
3. **Cleanup incomplete или cancellation.** Нельзя повторять capture в том же процессе или считать отсутствие ident завершением reader. Bounded wait/join не гарантируют успешную остановку; непроверенный busy pipe не закрывается из другого потока. Завершить принадлежащий задаче CLI/container process boundary через его supervisor; не убивать произвольные PID по имени Python и не выполнять global prune.
4. **Lifecycle failure.** Сохранить finite symptom, revision, stage и exit code. Проверять startup и shutdown отдельно, включая audit close. Не включать verbose/raw traceback для обхода privacy policy. Controlled fault tests локализуют дефект без реальных credentials.
5. **readback mismatch.** Заблокировать результат. Не применять enforcement повторно внутри observer ради зелёного отчёта. Проверить порядок startup и credential/process transitions; исправление требует новой native qualification.

## PB-37: воспроизводимая проверка

Эти команды используют synthetic fixtures, принадлежащие тестам Python children/threads и controlled lifecycle без listener. Linux kernel enforcement выполняется только в отдельном disposable child; общий test runner не изменяет hard RLIMIT_CORE.

```powershell
uv run --locked python -m unittest scripts.controller_privacy_qualification scripts.worker_transport_privacy_qualification scripts.serving_lifecycle_qualification scripts.controller_readback_qualification scripts.process_privacy_qualification scripts.intake_denial_qualification scripts.serving_http_qualification
uv run --locked python scripts/check_docs.py
```

На Windows native Linux tests skipped, а не pass. В CI storage.yml запускает native guard/readback suite и coverage: process_privacy/private_cli/serving_lifecycle 100%, transport минимум 95%. Kubernetes qualification проверяет отдельные publisher/scorer kernel-privacy-readback cases и M20/M21. Другие image/ML failures не становятся допустимыми из-за pass этих tests.

Контроль конечного состояния: собственный child терминален и reap выполнен; reader completion подтверждён; stream закрыт только при безопасном ownership. Для неоднозначного startup ожидается явный incomplete, а test harness отдельно освобождает созданный им delayed-bootstrap reader. Не объявлять это production recovery test.

## Восстановление, rollback и эскалация

Изменяющие действия отделены от read-only диагностики. Перед остановкой supervisor/container проверить owner, job UID, image digest и отсутствие чужих workload. На локальном компьютере Docker/WSL/Kubernetes/SQL в этом increment не запускались и не изменялись; команды их автоматического reset здесь намеренно отсутствуют.

После исправления повторить focused tests, полный regression и disposable native matrix на новом commit. Возобновление допустимо только для проверенного scoped workflow. Rollback к версии без guard/lifecycle redaction возвращает известный пробел и не является безопасным автоматическим действием; предпочтительнее остановить affected CLI и оставить promotion запрещённым до исправления.

Эскалировать: необъяснённый readback, неостанавливаемый child, непроверенный reader, повторная отмена cleanup, обнаруженный private canary в diagnostics или отсутствие native evidence. Запись инцидента содержит время, revision, finite stage, exit, проверенные ресурсы и остаточный риск, но не credentials/raw payloads. Реального production-инцидента этим документом не заявляется.
