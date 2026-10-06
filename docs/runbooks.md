# Проект эксплуатационных процедур

Эти процедуры - **спецификация для T14-T23**, не готовые команды к существующему кластеру. Конкретные CLI, permissions и alert routes появятся при реализации. Любое действие сохраняет audit и не раскрывает raw data/keys. Ответственные роли описаны в [карте продукта](product-map.md).

## 1. Dataset или model tampering

**Сигнал:** digest/signature/subject mismatch. **Ответственный:** security reviewer + platform operator.

1. Остановить promotion и изолировать объект, не удаляя forensic evidence.
2. Записать actual/expected digest, identities, source request и текущий approved release.
3. Если affected object уже используется, отозвать конкретный release; не ограничиваться сменой alias.
4. Проверить audit источника, storage write permissions и возможности скомпрометированного credential.
5. Пересоздать candidate из отдельно проверенных inputs; провести полный gate set.

**Восстановление:** только новый approval или разрешённый совместимый release без компрометации. **Проверка:** M03, M10-M12; runtime digest соответствует принятому решению.

## 2. Poisoning или подозрительная разметка

**Сигнал:** targeted probe anomaly, ухудшение slice, необычный источник labels. **Ответственный:** data owner + ML engineer + security reviewer.

1. Freeze promotion и обратную связь из подозрительного источника.
2. Отделить integrity violation от семантически допустимых, но подозрительных данных.
3. Сравнить clean control, affected sample IDs, label provenance и attacker budget.
4. Не считать высокий confidence или нормальную среднюю accuracy оправданием модели.
5. Проверить исправленную независимую выборку и необходимость полного retrain.

**Восстановление:** утверждённый clean dataset и полный independent evaluation. **Проверка:** M07-M09; пропущенные challenge cases остаются в отчёте.

## 3. Drift без подтверждённого ухудшения

**Сигнал:** data/prediction shift при достаточном window. **Ответственный:** ML owner.

1. Проверить schema, пропуски, изменения upstream и состояние самой telemetry.
2. Проверить sample size, bins/reference version и сезонность.
3. Дождаться зрелых labels или явно оставить качество неизвестным.
4. При необходимости ограничить использование/включить abstain и отправить данные на review.
5. Не запускать auto-promotion. Новое обучение возвращается через quarantine и все gates.

**Проверка:** M15, отдельные alerts для распределений и подтверждённой model quality.

## 4. Revocation, compromise key или недоступный trust service

**Ответственный:** security operator, с approver для повторного выпуска.

1. Отозвать затронутый key/release/policy и ограничить credential.
2. Проверить распространение revocation до работающих replicas.
3. Истечение trust lease переводит ML-путь в 503; это ожидаемая безопасная деградация, не повод выключать verifier.
4. Проверить, какие прежние releases тоже подписаны скомпрометированным key. Автоматически доверять им нельзя.
5. Перепроверить материалы, обновить trust roots разрешённой процедурой и выдать новые approvals.

**Проверка:** M11; measured reject time, audit reason и отсутствие serving отозванного digest. Root-of-trust recovery требует отдельного защищённого доступа, не секретов из Git.

## 5. Canary failure и rollback

**Ответственный:** platform operator + release approver.

1. Остановить дальнейшее увеличение traffic при превышении error/latency threshold.
2. Выбрать предыдущий whole bundle с действующей policy, совместимой schema и без revocation.
3. Создать новое rollback approval, связанное с source/target digests и причиной.
4. Переключить desired state, дождаться verified readiness и проверить несколько реальных ответов с digest.
5. Если подходящего release нет, выключить ML-advice и оставить ручной путь, не возвращаться к сомнительной модели.

**Проверка:** M16; RTO, отсутствие mixed artifacts, logs и клиентские ответы.

## 6. Disaster recovery

**Ответственный:** platform operator, data owner подтверждает доступность/retention данных.

1. Выбрать согласованный metadata+artifact snapshot и записать момент начала recovery.
2. Восстанавливать в отдельное окружение, не поверх единственной рабочей копии.
3. Восстановить metadata, immutable objects и approvals; ключи через отдельный защищённый процесс.
4. Сверить все referenced digests и текущую trust policy. Старый backup не отменяет последующую revocation.
5. Выполнить golden inference, проверить модель/схему/логи и измерить полный RTO/RPO.

**Проверка:** M17. Успешное чтение backup archive без usable verified inference недостаточно.

## 7. Retention и вывод модели из эксплуатации

**Ответственный:** data owner + release owner.

Найти все model/dataset references, запретить новые approvals, отозвать serving-разрешение, перевести клиентов на согласованную замену. Только затем удалять артефакты по политике хранения; запрещено удалять объект, ещё нужный действующему разрешённому release. Правовые сроки и основания устанавливаются для реального набора отдельно, не придумываются в lab.

Если удаление данных влияет на обученную модель, определить необходимость retrain или retirement. Удаление raw rows само по себе не доказывает machine unlearning. Сохранять минимальный допустимый audit без запрещённых персональных данных.

## Обязательный incident record

Время, тип инцидента, затронутые dataset/model/bundle digest, исполнители и права, выполненные действия, разрешённый следующий state, влияние на пользователей, ссылки на redacted evidence, остаточный риск и owner follow-up. Пароли, signing keys и исходные payloads сюда не включаются.
