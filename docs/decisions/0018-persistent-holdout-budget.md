# ADR 0018: постоянный бюджет доступа к holdout

Дата: 2026-10-11. Статус: реализованный компонент T10/M07, не полная приёмка. [Эксплуатация и evidence](../operations/holdout-budget.md).

## Требование и граница доверия

Повторный запрос независимой оценки расходует общий бюджет до чтения контрольных labels и до запуска prediction worker. Новый candidate, run ID, controller Pod или перезапуск PostgreSQL не должны давать новый бюджет. Worker и publisher не могут изменять ledger. Scorer и администратор control plane остаются доверенными: scorer имеет SQL-доступ к holdout и подписывающему ключу. Этот механизм не защищает от злонамеренного scorer или администратора.

## Решение

1. `storage_dataset.read_manifest` проверяет подписи curator, policy/source approval и lineage без чтения split bytes. В scorer сверяется candidate binding.
2. `holdout_budget.reserve` привязывает слоты к digest точного holdout content, не к candidate, run, alias, manifest signature или policy digest. Повторная подпись того же dataset не обнуляет бюджет.
3. Каждый слот - канонический JSON неизменяемого вида: schema version, kind, holdout digest, slot. Его content digest является первичным ключом в существующей append-only таблице `ml.evaluations`. В запись намеренно не входят случайный nonce, model digest или время: это сломало бы взаимное исключение.
4. `storage.claim` выполняет параметризованный `INSERT ... ON CONFLICT DO NOTHING RETURNING sha256`. Только новый INSERT и успешно завершённая транзакция разрешают чтение. Старый объект не считается новой резервацией. Обычный идемпотентный `storage.put` для этого непригоден.
5. После commit scorer читает holdout, запускает worker с features без labels, проверяет ответ и подписывает report, включающий `holdout_access` со slot/reservation/policy digests. Отказ или потеря ответа после commit расходуют слот без refund. Ошибка SQL не превращается в «попробовать следующий слот».
6. Read-only inspection возвращает занятые слоты и верхнюю оценку остатка, но не разрешение на доступ: конкурентный запрос может немедленно занять оставшиеся слоты.

## Замороженный synthetic-only профиль

В code-bound policy задано **32 попытки на один holdout digest в одной authoritative БД**. Число допускает полный negative transport campaign из 19 мутаций и двух positive controls, а также начальную проверку controller. Любая неуспешная попытка тоже расходует слот. Это инженерный лимит лаборатории, не статистически обоснованная гарантия против adaptive overfitting и не разрешение 32 итераций настройки по final holdout. Настройка модели использует validation; реальный пилот требует отдельно согласованного меньшего бюджета и методики оценки.

Лимит нельзя передать параметром запроса или environment variable. Policy возвращается копией, её digest входит в подписанный report, а реализация входит в source fingerprint controller image. Изменение числа требует review кода и новой qualification, не пользовательского переопределения. При изменении policy digest прежние reservation IDs сохраняются. Отдельная policy не меняет уже замороженный `data.lock` и не заставляет пересоздавать данные.

## Почему не новая mutable таблица

Существующие роли уже позволяют scorer INSERT/SELECT, но не UPDATE/DELETE; publisher не может INSERT в evaluations. Используется реальный PostgreSQL unique constraint без read-then-write гонки и без общей памяти процесса. Не нужны новая DB migration, привилегированная SECURITY DEFINER функция или Redis. Backup/restore уже включает всю evaluations table, включая reservations. В recovery qualification добавлено доказательство, что восстановленный слот нельзя занять снова.

Плата за простоту: до 32 коротких попыток INSERT, потерянные попытки не возвращаются, signed evaluations и reservations находятся в одной таблице. Consumers обязаны проверять тип/подпись, а не считать любую строку evaluation approval. Native M20 probe теперь отдельно проверяет reservation delta и отсутствие подписанного report при ошибке.

## Ограничения и условия отказа

- Одна authoritative БД. Fork старого snapshot или параллельное использование source и restored DB может повторно предоставить ранее потраченный бюджет. Сейчас нет внешнего монотонного witness. После restore оценка запрещена операционным порядком до сверки ledger; автоматический anti-rollback gate остаётся дальнейшей работой.
- Curator может утвердить другие holdout bytes, включая перестановку строк. Это новая доверенная data-authority операция, а не гарантированная семантическая дедупликация выборок. Synthetic generator публичен, поэтому секретность labels на синтетике не заявляется.
- Host/file developer helper не превращается в production scorer. Budget enforced в SQL `storage_pipeline.evaluate`, который вызывается также scoped Kubernetes controller. Полный M07/M18 не принимается этим компонентом; promotion должен требовать актуальную общую приёмку.
- Старые подписанные reports без `holdout_access` не являются доказательством работы нового контроля. Тесты не присваивают им этот receipt задним числом.

## Первичный источник

PostgreSQL документирует, что `RETURNING` возвращает только действительно вставленные или обновлённые строки, а `DO NOTHING` не вставляет конфликтующую строку. Именно это свойство, вместе с commit, использовано как условие выдачи слота. [PostgreSQL 18 INSERT](https://www.postgresql.org/docs/18/sql-insert.html), просмотрено 2026-10-11. Защита от административного restore этой семантикой не обеспечивается.
