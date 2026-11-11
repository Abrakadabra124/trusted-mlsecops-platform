# T29: реальные источники inventory.mismatch

Runtime: `78871de1b1d75f49df1ca3188da498ccf4b8f755`.
Linux source fingerprint:
`228fc93b24130f14a17f30599ccaa95ee9f4c9048e29f52a61ed8f0ec6ff4e01`.
Компонент связывает существующие inventory rejection predicates с подписанной
доставкой. Он не закрывает полный M19/M23/M18/R1.

## Настоящий candidate и доставка

[Run43072235491](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43072235491),
[job130702879303](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43072235491/job/130702879303)
завершились success. Workflow построил image, подготовил данные, обучил и оценил
настоящий synthetic candidate в fresh owned PostgreSQL. Затем отдельный CLI
прочитал его через прежние TLS clients и реальные storage validators.

Candidate reference:
`5386128c1968aba1e27bc4e2dae4ef71c48b2c2dd72390e155edab69976d1eb4`.
Новый native report:37 assertions, включая повторные CLI проверки,
status=pass, release_ready=false; source/fingerprint сверены с опубликованным
runtime. Это не37 независимых сценариев.

- Valid candidate проходит inventory-проверку без события и без разрешения
  выпуска. CLI возвращает только конечный summary, не полные материалы.
- Умышленно неверные expected source_revision и image_id дают два typed digest
  mismatch на настоящем candidate. Исходные SQL данные не подменяются: это
  controlled baseline disagreement, не доказательство реальной атаки.
- При остановленном collector второе событие остаётся pending. Следующая
  попытка не создаёт новый incident, пока pending не доставлен. После запуска
  того же collector новый Emitter подтверждает исходный envelope/receipt.
- Missing candidate object не превращается в вымышленное mismatch event.
  Неверный operator request SHA pin также отказывает без нового события.
- Четыре **controlled graph fixtures** вызывают digest/owner/dangling/cycle.
  Их deployments являются данными fixture, не развёрнутыми workloads.
  Event subject закрепляет весь request, включая graph и observation snapshot.
- Все шесть event IDs различны, подписи/receipts/route security.inventory,
  категории и subject digests проверены. Canary source string не попала в outbox.
- Повтор доставки после подтверждения возвращает0 и не меняет records.
  Максимальное время одного из12 CLI вызовов: **0.958505287 s**. Это измерение
  bounded harness, не обещание continuous detection SLA.
- Collector process/port/private files очищены. SQL metadata snapshot и
  принадлежность source container сохранились; исходный код/image не менялись.
  Source SQL затем остановлен и проверен always-cleanup шагом workflow.
  Удаление source SQL volume этим наблюдением не заявляется.

В том же job прошли54 unit tests(41+13) и прежняя45-case promotion CLI campaign:
настоящий candidate получает refusal без отсутствующей assurance, controlled
positive проходит отдельно. Это сохраняет fail-closed поведение, не даёт M10 pass.

## Локальные contracts и чистое воспроизведение

[Contracts run43072217340](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43072217340)
завершился success. Job130702812093: **392 Linux-теста,0 skips**
(21+25+47+10+1+24+85+65+9+14+60+31). Он подтвердил100% statements/branches
каждого из трёх модулей ниже, Ruff/format/docs. Job130702811695 повторил25
native promotion assertions и37 trust observer assertions с тем же полным
source/fingerprint и проверенным owned cleanup. Это регрессии предыдущих
компонентов; количество unittest executions и assertions учитывается отдельно.

Негативный тест сначала воспроизвёл отсутствие категории у реального owner
rejection. После реализации прошли60 tests inventory/graph/lineage и39 смежных
material/release/native-runner tests, все с-Werror и без skips.
Local branch coverage: asset_graph139statements/68branches,
candidate_lineage62/26, security_inventory_events74/14, каждый100% в этом наборе.
Эта метрика не относится ко всей платформе и не заменяет native qualification.

Detached checkout78871de, новая locked .venv с Python3.12.15,
`uv sync --locked --no-build --python 3.12.15 --link-mode copy`.
Проверены фактические interpreter/import paths и пустой git status:

```text
python -W error -m unittest scripts.security_inventory_events_qualification scripts.asset_graph_qualification scripts.candidate_lineage_qualification scripts.material_bundle_qualification scripts.release_bundle_qualification scripts.candidate_lineage_native_qualification
Ran 99 tests in 6.981s
OK, 0 skips
```

Локальная инфраструктура не запускалась. Raw logs/state/keys сохранены private.
Native runner отказывает до infrastructure calls вне GitHub hosted Linux.

## Ограничения

Подключение candidate collect с audit и observer CLI явное; legacy pure вызовы
с audit=None не доказывают security delivery. Graph pin удостоверяет выбранные
оператором bytes, а не источник observation. Candidate source читает bounded
model bytes для digest, не final-holdout labels; они не экспортируются в события.
Обычные parser/SQL/I/O ошибки не классифицируются по строкам как inventory attack.

Одна очередь на producer/epoch обязательна. Queue/registry expiry, corruption
и capacity дают отказ, автоматической очистки/reset нет. Новая проверка и retry
старого события - разные операции. Valid result без pending не доказывает health
collector; отдельный promotion audit gate остаётся обязательным.

Остались identity source, scheduler/producer heartbeat, mandatory deployment,
elapsed sequence-gap и outage при здоровой ML dashboard, полная M23 campaign.
Полный M19 с двумя datasets/тремя моделями/четырьмя реальными deployments,
M10, independent M22(0/2), M16/M17, image findings, R1-B08 и M18 на одном
candidate сохраняются.

[Решение](../decisions/0062-inventory-security-source.md),
[ранбук и плейбук](../operations/inventory-security-events.md),
[план](../../tasks/inventory-events-plan.md).
