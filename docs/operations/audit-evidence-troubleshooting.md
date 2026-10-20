# RB-68 / PB-42: private primary audit packet

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0049](../decisions/0049-private-audit-evidence.md), [local evidence](../evidence/audit-evidence-2026-10-20.md), [предыдущий RB-67](privacy-evidence-troubleshooting.md).

## Назначение и ограничения

Владелец процедуры - инженер disposable qualification campaign; при signature/source mismatch подключается security reviewer. Packet содержит первичные audit bytes и pseudonymous request IDs, поэтому остаётся приватным в `.runtime/serving-qualifications/<campaign>/audit-evidence/packet.json`. Не публиковать содержимое, raw logs, credentials и private keys. Digest и агрегаты synthetic campaign не превращают private packet в анонимные данные.

Локально разрешены pure tests и собственные loopback/temporary fixtures. Не запускать Docker, WSL, Kubernetes или SQL. Реальный container/SQL native прогон делает существующий GitHub-hosted `storage.yml`. Не подделывать hosted guards, не запускать команды на shared runtime.

## RB-68: read-only диагностика

```bash
git status --short
git rev-parse HEAD
uv run --locked python -m unittest scripts.audit_evidence_qualification scripts.audit_http_observation_qualification scripts.audit_evidence_probe_qualification scripts.audit_evidence_parent_qualification
```

Зафиксировать SHA, CI run/job/attempt и последний завершённый step. Публичная ошибка намеренно constant: `serving_output_rejected`. Причину устанавливать через ограниченное synthetic reproduction, а не verbose dumping приватного процесса.

| Симптом | Установленная или возможная причина | Безопасное действие |
| --- | --- | --- |
| Receipt fresh, campaign rejected | Старый packet/permit либо nonce другого запуска | Не менять timestamps/nonce и не переподписывать старые данные. Новая disposable campaign должна получить новый parent nonce и пройти upstream pipeline. |
| Parent signature/subject rejection | Подмена/истечение permit, ключ другой роли, другой source/image/model | Сохранить отказ. Проверить signed primary на том же SHA, не ослаблять signature/window/authority checks. |
| Packet readback/ownership rejected | Частичная запись, fsync failure, active lease, неверные права, symlink/hardlink или посторонний файл | Не удалять lease/каталог и не chmod автоматически: ownership неизвестна. При неоднозначности остановить campaign; расследовать в owned VM. |
| Ledger отказал после перехваченного exception | Ошибка чтения/декодирования, duplicate ID, превышение лимита или несовпадение admission | Это необратимый failure текущего окна. Нельзя продолжить старый ledger и получить pass. Новый ledger допускается только в новой полной campaign. |
| 404 без request ID | Реальный framework response не содержит ID | Ожидаемая schema: отдельный ordinal exchange, `request_id=null`, `admitted=false`. Не придумывать ID и не исключать ответ из наблюдения. |
| 429/503 отсутствует в журнале | Может быть pre-admission либо потерянный admitted request | Сверить независимый admission observer. Только admitted=false позволяет отсутствие journal; одного status code недостаточно. |
| Summary совпал, первичный packet rejected | Summary сам по себе не доказательство; подмена bytes/sequence/public export | Не пересчитывать hashes для «исправления». Отказать и сохранить evidence приватно. |
| Native Linux tests skipped | Запущен Windows/local-only профиль | Не считать Linux IO проверенным. Требуется hosted Linux job, без изменения skip guards. |

Эскалировать повторяемый отказ с неизменным clean SHA, неизвестный private output, сомнение в ownership, отсутствие единственной копии packet или неподтверждённое завершение child. Не объявлять известным root cause по одному generic diagnostic.

## PB-42: последовательность воспроизведения

1. Проверить SHA и границы ресурса read-only командами выше. Не делать global prune, reset, clean, ручное удаление evidence или чужих процессов.
2. Проверить pure verifier, HTTP observer и retention orchestration:

```bash
uv run --locked coverage run --data-file=.coverage-audit-evidence --source=mlsecops.audit_evidence,scripts.audit_http_observation,scripts.audit_evidence_probe -m unittest scripts.audit_evidence_qualification scripts.audit_http_observation_qualification scripts.audit_evidence_probe_qualification
uv run --locked coverage report --data-file=.coverage-audit-evidence --fail-under=100
uv run --locked python -m unittest scripts.audit_evidence_parent_qualification scripts.serving_output_native_qualification scripts.audit_packet_io_qualification
uv run --locked ruff check mlsecops scripts
uv run --locked ruff format --check mlsecops scripts
uv run --locked python scripts/check_docs.py
```

3. Negative checks обязаны отвергать replay, неверную подпись/ключ/subject, изменённые manifest/segments/public stdout, пропущенный HTTP outcome и восстановление ledger после ошибки. Test-double IO checks не доказывают Linux ownership.
4. После разрешённого push дождаться всех terminal CI на одном SHA. Linux step дополнительно проверяет private modes, nooverwrite, symlink/hardlink, short writes/fsync failures и реальный owned loopback с удалением source journal. Production native campaign затем запускает isolated ONNX/HTTP и parent recheck.
5. Конечное состояние: два новых cases `closed-audit-primary-packet-retained` и `closed-audit-primary-packet-reverified`; parent marker только после child exit, nonce/signature/primary packet checks. `release_ready=false`, full M13 inconclusive. В evidence сохранить SHA/image, packet digest, объяснимые HTTP/audit counts и все CI failures.
6. Recovery: не ремонтировать невалидный packet in-place и не удалять единственную копию для rerun. После диагностики завершить disposable job и повторить весь pipeline в новой VM. VM teardown уничтожает private packet; долговременное forensic хранение здесь не реализовано.
7. Rollback: прекратить потребление новых отчётов, оставить gate inconclusive; при подтверждённой регрессии reviewed revert только этого increment и новый полный CI. Возврат прежнего кода не делает historical receipt актуальным и не разрешает release.

## Что проверено

Процедура описывает controlled implementation failures, не production incident. Локальная проверенность и native статус перечислены в [evidence](../evidence/audit-evidence-2026-10-20.md). Реальное power-loss recovery, shared-host cleanup, production storage encryption/backup/retention и полный M13 этим increment не подтверждаются.
