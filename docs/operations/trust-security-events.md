# Наблюдение и восстановление событий отзыва доверия

Ответственные: оператор authority и оператор security collector. Компонент
T29 читает подтверждённую историю и доставляет изменения в security.trust.
[ADR0061](../decisions/0061-trust-history-security-events.md) фиксирует semantics
и ограничения. Наличие команды не означает включённый постоянный observer.

Условия: разрешённая Linux среда с проверенными SQL TLS materials роли
ml_serving; сохранная история с первой версии; original root pin; действующий
signed registry; отдельный producer key роли trust; private outbox и collector
в общем loopback namespace. Authority private key observer не нужен.
Существующий [producer config schema1](security-events.md) используется без
изменения. Новую пустую очередь provision один раз, существующую не обнулять.

Observer config содержит ровно schema_version=1, trust_client (абсолютная
директория TLS client), environment, initial_root (public pin), producer_config
(абсолютный путь) и rotations (список). В rotations каждый элемент содержит
version, next_root (независимый public pin), package_file (абсолютный путь к
публичному подписанному package). Начальный список пустой. Файл config<=16KiB,
package<=1MiB, до4 ротаций. Значения приватных ключей/token не помещать в JSON,
аргументы процесса или Git. Для ключей передаются только private file paths.

Диагностика без изменений:

1. Проверить ownership PID/port/файлов, действительность registry и наличие
   исходного outbox. Не печатать credentials, SQL URLs или полные envelopes.
2. В private Python процессе вызвать
   `security_trust_events.read(absolute_client, environment)`, затем
   `project(history, environment=..., initial_root=..., rotations=...)`.
   Здесь rotations содержит decoded package вместо package_file. Это только
   SELECT/криптографическая проверка, без enqueue/delivery. Не публиковать history.
3. Сверить документ head и наличие всех версий, public root pins и ротаций.
   В producer `configured(absolute_producer_config).store.snapshot()` сверить
   pending count и сохранённые event ID. Сравнить receipts с operator inbox;
   один exit0 ещё не подтверждает непрерывность наблюдения.

Плейбук доставки после остановки observer или collector:

1. Сохранить private evidence при отказе, определить конкретную причину.
   `trust_security_rejected` в CLI намеренно постоянный и не раскрывает материалы.
   После подтверждения ownership восстановить тот же collector/state. Рабочие
   SQL данные ради доставки событий не менять.
2. В разрешённой Linux среде выполнить изменяющий шаг с прежним config:

   ```bash
   uv run --locked python -m mlsecops.security_trust_events --config /absolute/private/trust-observer.json
   ```

   Процесс заново проверит всю историю, сверит outbox, повторит pending, затем
   добавит ещё не замеченные отзывы. Сохранённые события не получают новые
   timestamps или event ID. Подтверждённый отзыв, произошедший до старта
   наблюдателя, восстанавливается из SQL, если история сохранна.
3. Проверить state=observed, точные version/document_sha256, events и
   release_ready=false. Сверить отсутствие pending, исходные event ID,
   подписи receipts и маршрут security.trust в inbox. Повторить ту же команду;
   повтор не должен добавлять событие или менять ранее сохранённые records.
4. После ротации authority прежняя конфигурация откажет. Оператор отдельно
   сверяет next_root pin и dual-signed package с committed document, добавляет
   его в rotations, сохраняя initial_root и старые packages, затем повторяет
   доставку. Не брать новый pin автоматически из непроверенного SQL/запроса.

При gap/подмене истории, конфликте outbox, заполнении64версий/1024records,
превышении8MiB, expired registry, слишком старом pending или утрате state
остановить retry и эскалировать обоим операторам. Без проверенного восстановления
истории/backup и отдельной процедуры смены epoch автоматического лечения нет.
Не удалять документы, не reset sequence, не отключать TLS/signatures/freshness,
не переинициализировать outbox. Rollback кода не отменяет совершённый отзыв;
развёртывание прежнего непонимающего rotation клиента не является восстановлением.

Воспроизведение: pure Python contracts запускаются локально командой
`python -W error -m unittest scripts.security_trust_events_qualification`.
Настоящие SQL/HTTP faults запускает только hosted job audit-promotion-sql в
[workflow](../../.github/workflows/security-events-contracts.yml). Native script
проверяет GitHub hosted Linux до infrastructure calls, создаёт только собственные
ресурсы и проверяет cleanup. Намеренное удаление версии внутри этого disposable
теста является negative fixture, не эксплуатационной процедурой восстановления.
На текущей Windows локальные Docker/WSL/Kubernetes/SQL не запускать.

Риск, предотвращённый проектированием: commit authority без последующего enqueue
мог потерять callback notification. Replay committed history закрывает этот
промежуток в сохранной bounded history. Это не production incident и не гарантия
доставки после потери authority/outbox. Непрерывный scheduler, heartbeat и полная
приёмка M23 вместе с остальными источниками пока не заявляются.
