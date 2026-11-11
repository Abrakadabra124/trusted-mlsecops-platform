# Проверка inventory и восстановление доставки событий

[Проверка78871de](../evidence/inventory-security-events-2026-11-11.md):
392 Linux-теста/0skips,37 native inventory assertions на настоящем SQL candidate
и controlled graph, actual observer CLI/collector outage/retry прошли.
Clean checkout99/0; source SQL остановлен workflow, collector cleanup подтверждён.

Ответственные: оператор inventory и оператор security collector.
[ADR0062](../decisions/0062-inventory-security-source.md) описывает typed source.
Новый observer не заменяет перечисление deployments и полную приёмку M19.

## Конфигурация и запуск

Нужна разрешённая Linux среда, действующий pinned registry, private producer
key роли controller/promoter/serving и существующий outbox. Один producer/epoch
использует **одну очередь**, даже если отправляет разные типы событий.
Нельзя создавать вторую очередь с тем же ключом/epoch и sequence=1.
Для inventory применяют producer config schema1 из
[общего ранбука](security-events.md); у promotion audit schema2, но shared
state_directory/state_sha256/key/registry сохраняются. Разница номера schema
не разрешает переинициализацию существующего state.

Observer config содержит ровно schema_version=1, mode (candidate либо graph),
request_file, request_sha256, producer_config. Пути абсолютные, config<=16KiB,
request<=4MiB. SHA256 закрепляет **точные bytes** request, поэтому смена пробелов
также требует осознанного обновления operator pin. Producer credentials выбирает
config оператора, не request. Private request сохраняют для расследования;
пароли, ключи и raw source data в Git/командную строку не помещают.

Candidate request: metadata_client, review_client, context. Первые два поля -
абсолютные directories прежних TLS clients ml_publisher и ml_promoter.
Context содержит ровно candidate_reference, evaluation_reference, policy,
trust, expected, owners, known_owners - существующий контракт candidate_lineage.
Expected фиксирует image_id, source_fingerprint, source_revision. Читаются
signed metadata и bounded model bytes для integrity, но не final-holdout labels.
Observed event subject - candidate reference; утверждённый baseline оператора
остаётся в закреплённом private request.

Graph request: document, trusted_owners, environment, snapshot, revoked -
существующий asset_graph contract. Event subject - digest **всего request**,
включая конкретный snapshot. Достоверность сбора snapshot обязан обеспечить
оператор; наличие его digest не является подтверждением live Kubernetes inventory.
Настоящий collector CLI harness и controlled fixtures находятся в
[native campaign](../../scripts/security_inventory_events_native.py).

Изменяющий запуск в разрешённой Linux среде:

```bash
uv run --locked python -m mlsecops.security_inventory_events --config /absolute/private/inventory-observer.json
```

Перед новой проверкой доставляется pending прежней очереди. При mismatch
создаётся inventory.mismatch с reason digest/dangling/owner/cycle, сохраняется
до network I/O и отправляется в security.inventory. Исходный отказ сохраняется.
Ошибки parser/SQL/файлов не классифицируются по тексту как атака или mismatch.

Success означает state=verified, subject_sha256, scope, full_M19=inconclusive,
release_ready=false. CLI не печатает graph, модель, данные или credentials.
При valid input без pending сеть collector может не использоваться: такой
результат не доказывает health audit sink и не разрешает promotion.

## Диагностика и плейбук восстановления

1. Без изменений проверить ownership процессов/файлов, права и registry expiry,
   request digest, expected build, scoped SQL TLS clients. Не печатать credentials
   или полные envelopes. `inventory_security_rejected` намеренно не раскрывает
   причину в публичном CLI; private source diagnostics отделять от общего лога.
2. Прочитать существующий producer через
   `security_event_delivery.configured(absolute_producer_config).store.snapshot()`.
   Сверить count pending, original event IDs и signed receipts с operator inbox.
   Failure кода команды не доказывает, что event уже записан или доставлен.
3. Если проблема только в collector/сети, после ownership checks восстановить
   **тот же state** collector. В private Linux Python процессе выполнить
   `security_event_delivery.configured(absolute_producer_config).retry()`.
   Это изменяющий шаг: отправляет существующие pending и сохраняет receipts.
4. Проверить отсутствие pending, неизменность envelope/event ID/sequence и
   receipt для каждого original event. Повторный retry должен доставить0.
   Новый запуск inventory observer является **новой попыткой проверки** и может
   создать новый инцидент; его не использовать как замену retry старого события.
5. Реальное несоответствие устраняет владелец source/deployment. Не менять
   expected digest/owner, чтобы искусственно получить success. После независимой
   сверки baseline и источника повторить проверку с одобренным pinned request.

При повреждённом/full outbox, утерянных counters, expired registry, старом pending
или unknown receipt сохранить private evidence и эскалировать. Не reset/evict,
не менять timestamps, не отключать подписи/TLS/pins. Автоматической registry
migration или восстановления потерянной очереди здесь нет. Rollback кода не
отменяет recorded mismatch и не разрешает ранее отклонённый release.

## Проверки и ограничения

Локально разрешены pure contracts:

```text
python -W error -m unittest scripts.security_inventory_events_qualification scripts.asset_graph_qualification scripts.candidate_lineage_qualification
```

Hosted [workflow](../../.github/workflows/promotion-entrypoint.yml) создаёт
настоящий trained candidate в fresh SQL, затем запускает observer CLI и реальные
collector faults. Графовые негативные случаи отдельно помечены controlled;
их четыре deployments являются fixture, а не развёрнутыми workloads.
Collector process/port/private files очищаются самим harness; source SQL
останавливает и проверяет существующий always-cleanup workflow. На текущей
Windows локальные Docker/WSL/Kubernetes/SQL не запускать и не менять.

Scheduler/heartbeat, обязательный deployment profile и полные M19/M23/R1
остаются отдельными работами; legacy pure APIs без audit не доказывают его наличие.
