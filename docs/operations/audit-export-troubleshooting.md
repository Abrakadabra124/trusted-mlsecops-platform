# RB-64 / PB-38: публичная сводка закрытого audit journal

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0045](../decisions/0045-public-audit-export.md), [evidence](../evidence/audit-export-2026-10-19.md).

## Назначение и prerequisites

Runbook отличает неполное retention-окно, занятую lease и повреждение evidence. Playbook экспортирует фиксированные счётчики, не private JSONL. Это не repair/resume writer, release approval или полный M13. Native Linux обязателен; Windows не доказывает Unix ownership, no-follow, fsync или kernel guard.

Ответственный: владелец serving instance. Security reviewer подключается при неизвестном владельце lease, смене digest/identity или privacy failure. Нужны checkout с locked dependencies, Python 3.12, Linux и тот же UID. Нельзя направлять CLI на чужой каталог или единственную копию активного production-журнала без согласованного maintenance window.

## RB-64: диагностика

1. Установить instance/owner и абсолютный `SPOOL` из конфигурации именно этого процесса, не из HTTP input/чужих logs. Остановку serving выполняет его штатный owner; exporter не останавливает процессы.
2. Подтвердить успешный HTTP stop и `Journal.close()`, отсутствие живых writers и ожидаемое retained window. Отсутствие процесса не доказывает clean close: нужны manifest, неизменные segments и отсутствие writer lease.
3. Выполнить read-only диагностику без payload/manifest/имён клиентов:

```bash
uv run --locked python -c 'import os, pathlib, stat, sys; root=pathlib.Path(sys.argv[1]); assert root.is_absolute() and root.resolve()==root; info=root.lstat(); assert stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode & 0o077; print({"directory_private": True, "lease_present": (root/".lease").exists()})' "$SPOOL"
```

4. Выбрать ветвь, не маскировать ошибку повторным экспортом:

| Сигнал | Возможная причина | Безопасное действие |
| --- | --- | --- |
| Lease существует | Живой writer/reader, неуспешный close, crash | Сверить owner lifecycle. Не удалять `.lease`, не вызывать writer close как repair. Unknown/stale lease: сохранить private source и эскалировать; automatic crash recovery вне scope. |
| Exit 1, `audit_export_rejected` | Guard/path/mode, schema/inventory/sequence/digest/identity, cleanup/I/O | Разделить environment failure и corruption через private metadata. Не выводить private exceptions и не переписывать digest/manifest ради pass. |
| Exit 2, inconclusive | Retained suffix без старта или tail без terminal | Не дописывать события и не обнулять unresolved. Если нужен полный период, получить новое согласованное окно. |
| Exit 130 | Отмена | Не публиковать stdout; проверить завершение exporter и lease. Повтор только после подтверждения ownership/clean source. |
| Неполный stdout/JSON | Ошибка output channel | Nonzero/verifier reject: удалить только собственный временный output, источник сохранить. Stdio не является атомарной файловой транзакцией. |
| Pass при HTTP 503/aborted | Структурно полная история отказов | completed не равно успешный inference; observed context не равно approval. Serving диагностировать отдельно. |

Reader временно создаёт exclusive lease и закрепляет inode открытым FD. Payload/manifest не меняются, rotation/prune не выполняются. Ошибка cleanup запрещает успешный output; отсутствие lease после ошибки не доказывает успех export.

## PB-38: воспроизводимый экспорт

Выполнять после RB-64 в отдельном Bash script. `SPOOL` уже выбран оператором. Новый temporary directory содержит только output этого запуска. Не включать `set -x`; остановиться при ошибке его создания.

```bash
umask 077
work=$(mktemp -d) || exit 1
status=0
uv run --locked python -m mlsecops.audit_export --spool "$SPOOL" > "$work/public.json" 2> "$work/diagnostic.txt" || status=$?
case "$status" in
  0|2)
    uv run --locked python -c 'import pathlib, sys; from scripts.audit_export_probe import scan; content=pathlib.Path(sys.argv[1]).open("rb").read(4097); result=scan(content); assert (result["status"]=="pass") == (int(sys.argv[2])==0); print(content.decode(), end="")' "$work/public.json" "$status" || exit 1
    ;;
  *) printf 'export failed, exit=%s; do not publish output\n' "$status" ;;
esac
exit "$status"
```

Публиковать только вывод успешного verifier, сохраняя inconclusive при exit 2. Не публиковать diagnostic/source JSONL. Счётчики раскрывают объём и структуру; перед публикацией реального workload владелец privacy purpose/retention должен разрешить этот disclosure. Это не differential privacy или анонимизация.

После проверки вручную удалить только два созданных output-файла и пустой `work`, сверив абсолютный путь. Запрещены global prune, рекурсивное удаление spool, mass chmod/chown и отключение guard. Повтор на неизменном закрытом spool даёт ту же сводку, создавая новую временную lease.

## Проверка конечного состояния и rollback

```bash
uv run --locked python -m unittest scripts.audit_export_qualification scripts.audit_snapshot_qualification scripts.audit_export_probe_qualification scripts.audit_export_site_qualification
```

Disposable Linux CI дополнительно запускает реальный CLI после actual-candidate HTTP fixture, сверяет counters с source, проверяет отсутствие всех наблюдавшихся request/principal/context canaries и повторно читает неизменные source bytes. Callback не вызывается после body/shutdown/close failure. Playbook не выполняет Docker/WSL/SQL команды. Реальный CI статус фиксируется в evidence, а не выводится из наличия кода.

Rollback exporter не требует миграции: прекратить его вызов, использовать предыдущий reviewed code через обычный release process. Не применять destructive reset и не менять writer формат. Сохранить failed/inconclusive evidence. Stale-lease recovery этим increment не квалифицировано.

## Проблемы, обнаруженные при реализации

- Controlled red test выявил, что первая projection принимала отсутствие start при sequence 1 и внутренний пропуск stage как unresolved. Исправлена классификация prefix/tail vs повреждённая observed chain; regression проходит.
- Design review выявил несовместимость writer close с read-only export и недоступность spool после fixture cleanup. Добавлены отдельный leased reader и post-close hook внутри владельца fixture.
- Short-write/cleanup faults проверяются fixtures, не называются production-инцидентами. Open lease FD и сравнение записанного prefix предотвращают ложное освобождение неподтверждённого ownership.
- Cycle 2 воспроизвёл import/отложенный stdout-flush canaries в отдельных Python children, нулевые manifest times и невозможный two-event abort с context. Импорты перенесены в защищённый bootstrap, CLI flush/exit выполняются явно после owned cleanup, диапазоны и independent accounting ужесточены. Нельзя заменять этот cleanup надеждой на atexit.
- Cross-model review не выполнялся по выбору пользователя. Native результаты и остаточные ограничения сохраняются отдельно в evidence.
- На f0d0542 exporter suite прошёл обе Linux attempts. Первая Storage attempt остановилась позже на M07: один connection rejection из 32 concurrent attempts; actual-candidate step был skipped. Один диагностический rerun того же SHA прошёл сквозной export. Причина первого отказа неизвестна: не объявлять retry исправлением, не снижать M07 budget и не добавлять бесконечные retries. [Сохранённый отказ и полный report](../evidence/audit-export-f0d0542-native.md).
