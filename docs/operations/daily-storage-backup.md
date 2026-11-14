# Ежедневная копия promotion journal

Владелец local-cpu хранилища устанавливает [таймер](../../infra/systemd/mlsecops-daily-backup.timer) и [службу](../../infra/systemd/mlsecops-daily-backup.service) на постоянно работающий Linux-хост с systemd. На этом хосте обычный [backup CLI](../../mlsecops/storage_backup.py) уже должен иметь доступ к локальному Docker socket, собственной PostgreSQL и установленной promotion schema. Ежедневно в 02:00 UTC таймер запускает согласованный снимок CAS и journal. При пропуске срабатывания `Persistent=true` позволяет запустить службу после возвращения хоста.

## Подготовка

1. Разместить закреплённый checkout в `/srv/trusted-mlsecops-platform` с готовой `.venv`. Нужна версия CLI с флагами `--include-promotion --recovery-point`. Учётной записи `mlsecops` необходимы чтение кода и приватных исходных материалов, запись в свой `.runtime`, доступ к Git revision и локальному Docker. Доступ к Docker socket даёт административные возможности на хосте. Использовать выделенный lab host. Владелец отвечает за свободное место и время UTC.
2. Владелец сверяет полный workspace ID и публичный trust bundle с независимой записью bootstrap. От имени администратора установить `/etc/mlsecops/backup-owner.json` с полями `workspace_id` (32 hex) и `trusted_keys` (исходный JSON-объект публичных ключей). Файл и родительский каталог доступны службе для чтения и защищены от её записи. Отдельная доверенная копия исходного public bundle понадобится для restore. Передача закрытых ключей в target не требуется.
3. Проверить units без установки и сеанса пользователя. Команда проверяет календарь, привязку service и его ExecStart, затем вызывает локальный `systemd-analyze calendar` для двух фиксированных дат в UTC. Она не обращается к SQL или менеджеру служб.

```sh
cd /srv/trusted-mlsecops-platform
.venv/bin/python -B -m mlsecops.daily_backup check-timer
```

После проверки оператор устанавливает и включает расписание. Инвентарь в `/var/lib/mlsecops-backup/latest.json` отделён от архивов. Systemd создаёт родительский каталог с режимом 0700.

```sh
sudo install -m 0644 infra/systemd/mlsecops-daily-backup.service infra/systemd/mlsecops-daily-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mlsecops-daily-backup.timer
systemctl list-timers --all mlsecops-daily-backup.timer
```

## Проверка копии и передача в restore

До первого срабатывания проверке требуется первая копия. Для немедленного выполнения оператор может вызвать `sudo systemctl start mlsecops-daily-backup.service`. Служба вызывает обычный CLI, сверяет подпись, workspace, обе истории, размер и SHA-256 архива, повторно вычисляет backup ID и проверяет подписанные времена. Точка SQL `recovery_point_at` должна попасть между началом и концом создания снимка. Проверяется возраст от начала снимка, включая границу 24 часа. По завершении служба атомарно публикует pin в инвентарь.

```sh
cd /srv/trusted-mlsecops-platform
sudo -u mlsecops .venv/bin/python -B -m mlsecops.daily_backup verify \
  --state "$PWD/.runtime" --owner /etc/mlsecops/backup-owner.json \
  --inventory /var/lib/mlsecops-backup/latest.json
```

Код 0 и JSON с `workspace_id`, `backup_id`, `source_revision`, `started_at`, `recovery_point_at`, `completed_at` подтверждают проверку выбранных bytes. Проверка работает при остановленной source SQL. На ненулевом коде остановить recovery и проверить `systemctl status`, журнал службы, часы, owner и доступность архивов. Ошибка нового запуска сохраняет последний проверенный pin. Прежняя копия годится только после новой проверки свежести. При длительном простое целевые 24 часа могут быть превышены.

Передать полученный **backup_id** в `--expected-backup-id` и открыть именно `.runtime/backups/<backup_id>`. Для `--trust` использовать отдельно сверенный публичный bundle владельца на стороне оператора. Восстанавливать в новый target по [PB-22](promotion-recovery-troubleshooting.md). Сохранить выбранный pin в журнале операции, поскольку следующая успешная копия обновит `latest.json`. Старые каталоги снимков сохраняются. Для lab не задан срок автоматического удаления. При заполнении диска сохранить последнюю проверенную копию и согласовать место с владельцем.

## Вызов из hosted qualification

В подготовленном контексте GitHub Ubuntu вызвать `scripts.daily_backup_systemd_native.capture(root, state, owner_path, inventory)`. Каталог нового файла inventory уже должен существовать, быть приватным для runner и находиться вне source state. `owner_path` также находится вне state. Результат - пара `(receipt, scheduler)`. Передать `receipt["backup_id"]` в actual restore как `backup_pin`, а `digest(canonical(owner["trusted_keys"]))` как `keys_pin`. Оба шага используют один снимок.

Проверка требует системный manager, доступ runner через `sudo -n`, `busctl`, `systemd-analyze` и работающий owned source. Она создаёт уникальные временные units в `/run/systemd/system`, сохраняет календарь UTC и добавляет разовое срабатывание `OnActiveSec=3s`. Срабатывание принимается после этой задержки и до следующего календарного срока. После исполнения проверяются фактические LastTrigger, следующий календарный запуск, код завершения службы, временное окно подписанного снимка и отдельный inventory. После остановки удаляются runtime units, drop-ins и timer stamp этого экземпляра. При ошибке cleanup результат не публикуется.

Возвращённый `trigger=controlled-on-active` документирует ускоренный запуск. Для доказательства суточной периодичности нужны последовательные календарные срабатывания, успешные service exits и соответствующие проверенные pins на постоянном хосте. Полная проверка M17 также требует независимого восстановления и измерений RTO/RPO. Для остановки расписания оператор использует `sudo systemctl disable --now mlsecops-daily-backup.timer`; архивы и inventory остаются у владельца.
