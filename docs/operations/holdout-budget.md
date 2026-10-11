# Holdout: бюджет оценки и безопасная диагностика

Компонент T10/M07. [Решение и границы доверия](../decisions/0018-persistent-holdout-budget.md). Это инструкции лаборатории, не описание production-инцидента.

## Что делает технология

Holdout - отдельная контрольная выборка, которую не используют для настройки модели. Слишком частое измерение на ней превращает независимую оценку в неявное обучение по ответам. PostgreSQL хранит неизменяемые резервации, а уникальный первичный ключ предотвращает двойное занятие одного слота конкурентными процессами. TLS и отдельные SQL identities уже проверяют доступ к БД; этот компонент добавляет ограничение в доверенный scorer.

## PB-05: read-only диагностика

**Ответственный:** platform operator вместе с владельцем оценки. **Условия:** нужный checkout/locked environment; client certificate scorer или promoter для конкретной authoritative БД; digest holdout из проверенного curator manifest либо ранее проверенного signed evaluation. Не брать digest из произвольного пользовательского ввода как свидетельство выбранной модели.

Из корня checkout выполнить, заменив пример digest и путь клиента на проверенные значения:

```text
uv run --locked python -m mlsecops.holdout_budget --client .runtime/storage-clients/scorer --holdout b291da7859f7ead97e57f29fe9cb0f2c4bb386f4d11f9f4f5f7ed05cac90f1cf
```

Этот digest относится к текущему synthetic fixture, не к произвольному бизнес-dataset. CLI делает только SELECT; не запускает БД, не создаёт состояния, не читает labels и не резервирует слоты. Результат содержит `occupied_slots`, `remaining_upper_bound`, policy и scope. Exit 0 означает успешное наблюдение, а не разрешение evaluation. Exit 1 означает невозможность проверки: missing credentials, TLS, SQL permissions или повреждение ledger не трактуются как нулевой расход. Вывод не содержит credentials/labels; пути и private reports не публиковать автоматически.

Если несколько процессов ещё выполняют evaluation, значение остатка устаревает сразу. Только новый успешный `reserve` в scorer выдаёт право чтения. Сохранять snapshot диагностики с временем; сравнивать policy digest с подписанным report и source fingerprint применяемого образа.

## RB-08: `holdout_budget_exhausted`

**Симптом:** scorer отказывает до holdout SELECT и worker; новый run ID не помогает. **Влияние:** новая оценка и новый выпуск не разрешаются. Это ожидаемый fail-closed отказ, а не неисправность PostgreSQL.

1. Остановить автоматические повторные запуски оценки. Сохранить candidate reference, report/error, policy digest и время; не выгружать labels или ключи.
2. Выполнить PB-05 для authoritative БД и точного holdout digest. Если заняты все 32 слота, контроль работает согласно lab policy.
3. Сверить подписанные reports и доступные reservation receipts. Число reports может быть меньше числа slots: сбой после commit намеренно оставляет слот потраченным. Резервация не содержит candidate ID; незавершённая попытка не всегда полностью атрибутируется. Полный audit sink M23 ещё не реализован.
4. Найти причину повторных запусков: retry-loop, transport failure, ручная настройка по holdout. Исправить первопричину, проверяя модель на validation, а не на final holdout.
5. Эскалировать владельцу оценки. Возможны отказ от кандидата или новый независимо подготовленный holdout с новым approval и заранее согласованной policy. Нельзя просто перемешать строки, пересоздать alias, удалить reservations, восстановить старую БД или увеличить лимит ради зелёного теста.

**Rollback:** изменения модели откатываются отдельно; ledger не откатывается. Остановка новой оценки не требует остановки уже доверенного serving, когда такой путь реализован. Сейчас serving/release остаются незавершёнными, поэтому это не проверенная процедура production rollback.

**Критерий конечного состояния:** причина retry устранена; прежний holdout по-прежнему exhausted; без нового решения владельца новый report не появляется. Отказ до labels/worker/signature проверяется native qualification. Независимость нового реального holdout не проверена синтетическими тестами.

## RB-09: connection/commit failure или восстановление snapshot

При `storage_connection_rejected`/`storage_claim_rejected:*` не отключать TLS и не переключаться на memory counter. Проверить identity БД, client certificate, срок действия, сеть и ownership по storage-процедурам. Сообщение о неуспешном commit не доказывает, что INSERT не произошёл: после потери соединения слот может быть уже занят. Автоматического refund нет; повторная попытка, если разрешена оператором, тратит следующий слот.

Backup включает reservations вместе с evaluations. [Recovery qualification](../../mlsecops/storage_recovery_qualification.py) проверяет перенос уже занятого слота и запрет повторного claim. Но старый snapshot может не содержать последних расходов, а source и target могут стать двумя независимыми бюджетами.

До разрешения новой оценки после restore: остановить scorer на source и target, сверить ledger с последней доверенной историей, выбрать единственную authoritative БД и исключить конкурентную запись в старую. Если полноту доказать невозможно, не продолжать работу со старым holdout. Автоматического reconciliation/anti-rollback witness пока нет; эти действия - требование к дальнейшему восстановлению, а не проверенная автоматическая процедура. Простая повторная подпись того же manifest проблему не решает.

## RB-10: тест ожидал неизменную evaluations table

В ходе интеграции обнаружена несовместимость прежнего инварианта M20: отрицательный worker output раньше не добавлял ни одной строки. Теперь до обращения к worker сохраняется reservation, даже если результат отвергнут. Исправлен именно тестовый инвариант, а не fail-closed проверка: для каждого отказа допускается ровно одна новая reservation, **ни одного нового подписанного evaluation**. Positive case добавляет reservation и report. Полная итоговая delta проверяется; посторонние строки не игнорируются.

Для controlled protocol fixtures явно отделён mock ledger от native SQL tests. Нельзя засчитывать случайный отказ подключения вместо проверяемого некорректного worker output. Проверяются существующие 164 protocol checks; настоящие SQL/concurrency/restart проверяются отдельной native campaign, а actual Kubernetes receive matrix - workflow Kubernetes.

## Воспроизвести qualification

Требуются Docker Linux amd64, pinned worker build, PostgreSQL image из storage baseline, свободный loopback port 15446 и ресурсы согласно README. Никакого paid cloud. **Следующие команды изменяют только новый qualification state и его owned контейнер.** Не использовать рабочий state.

```text
uv run --locked python -m scripts.holdout_budget_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m mlsecops.holdout_budget_qualification
```

По умолчанию создаётся `.runtime/holdout-budget-qualification`. Повторное использование существующего state запрещено, чтобы не сбросить использованный бюджет. Для новой отдельной lab campaign передать уникальный `--state .runtime/holdout-budget-lab-002` и при необходимости другой свободный `--port`. Это новый **тестовый** trust domain, не восстановление рабочего бюджета. Параметр output указывает только private evidence.

Campaign обучает настоящую модель и оценивает её через SQL scorer, затем расходует оставшиеся слоты четырьмя процессами, проверяет SQL запреты, новый candidate/run ID, перезапуск owned PostgreSQL и новый процесс. После проверки контейнер останавливается по сверенной identity, volume и evidence сохраняются; глобальной очистки нет. Авария/отказ могут оставить ресурсы для диагностики, не удалять их вслепую.

## Проверенные результаты

2026-10-11: 16 controlled unit tests; модуль budget покрыт 46/46 statements и 14/14 branches. Первый native запуск прошёл 13 checks: реальное обучение/оценка, 32 уникальных слота, four-process contention, отказ publisher, запрет UPDATE/DELETE scorer, новый run/candidate и перезапуск. Digest policy: `735ef4d25eedf4bddfc4296c329e61ab8f6b5c624a216b37303aec85341ab945`.

Финальный локальный rerun: 2026-10-11T12:13:49.561266Z, source fingerprint `3e4f7e862b5fb170243d6cc94789343d328bf534c84a2ca270c75eb5c40577f0`, worker `sha256:4eefb2ad49a7b89e9acfb2709a0ddba2faa5b6b9865576b117b35801dc9887ee`, dirty checkout. Report digest `60f5a8d976ab9f1d492eca4f76a9db6de913ffbf2604eb6e63120e868947f34c`. Отдельная storage recovery campaign 2026-10-11T12:14:21.621979Z прошла **433 checks**, включая `holdout-reservation-restored-without-refund`, и 1 000 golden predictions с max error 0.0; restore-to-golden 11.969 секунды на этом стенде, не production SLO.

Clean-checkout CI фиксируется в STATUS, а не выводится из локального pass. Native pass не закрывает весь M07/T09/T10 и не подтверждает production/privacy/anti-rollback.
