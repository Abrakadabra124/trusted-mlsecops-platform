# T29: события отзыва из подтверждённой истории SQL

Runtime: `0e59a927be5a815e8e64be7ca20e93f6aafeb445`.
Linux source fingerprint:
`5a617e39a6f225c06d5b319c111ca672a3156b9f1697362713c574bf0dba68ec`.
[Hosted run43069121670](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43069121670).
Область: bounded trust source component, не полный M23/M18/R1.

Run завершился success. Contracts job130691928363: **301 Linux-тест,0 skips**
(21+25+47+10+1+24+85+65+9+14). Новый trust source:143/144 statements
(99.31%) и57/58 branches(98.28%); единственная непокрытая ветвь в этом
замере - module main, который отдельно реально выполняется native CLI.
Branch threshold>=95% проверен отдельно от combined coverage. Остальная
платформа этим процентом не покрывается. Ruff, format и docs checks прошли.

## Что проверено

[Native job130691927800](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43069121670/job/130691927800)
завершился success. Новый
[campaign](../../scripts/security_trust_events_native.py) выполнил37 assertions
(включая повторные CLI checks), прежний promotion audit campaign25. Оба
primary reports сверены с полными source/fingerprint и status=pass,
release_ready=false. Synthetic keys/digests используются как управляемые
fixtures; SQL, TLS, подписи, отдельный observer CLI и collector работают реально.

- Первоначальная история даёт два события, затем реальный authority update
  сохраняет дополнительный отзыв без запущенного observer. Outbox остаётся
  прежним до чтения истории.
- При остановленном collector observer сохраняет третье событие до I/O и
  возвращает постоянный безопасный отказ без payload. Новый процесс после
  запуска того же collector доставляет исходный envelope и получает receipt.
- Повтор CLI не меняет records. Продление trust без изменения revocations
  также не добавляет событие.
- Настоящая SQL ротация требует прежнюю и новую подписи. Observer со старым
  config отказывает без изменения очереди. Добавление отдельно подтверждённого
  next_root pin и public rotation package позволяет отразить отзыв старого ключа.
- Смена policy под новым root создаёт пятое событие. Reasons равны
  artifact,key,artifact,key,policy; каждый asset SHA совпадает с конкретным
  сохранённым документом. Все пять event IDs различны, signed receipts и
  security.trust route проверены.
- SQL подтвердил current_user=ml_serving, SELECT documents разрешён,
  INSERT/UPDATE/DELETE и SELECT root_rotations запрещены. Права не расширялись.
- Удалённая тестом версия в disposable authority даёт отказ до изменения
  очереди. Это негативный тест, не процедура восстановления или production fault.
- Максимальная длительность успешного отдельного CLI наблюдения:
  **0.362027322 s**. Это измерение шести коротких online вызовов, не гарантия
  непрерывного обнаружения от commit и не закрытый M23 delivery SLA.
- Collector PID/port, SQL container/network/volume и private test directories
  очищены; source остался прежним. Cleanup failures не маскируются success.

## Чистое воспроизведение

Detached checkout `0e59a92`, новая `.venv`, Python3.12.15,
`uv sync --locked --no-build --python 3.12.15 --link-mode copy`.
Подтверждены interpreter/import paths из нового checkout, git status пустой.

```text
python -W error -m unittest scripts.security_trust_events_qualification scripts.trust_rotation_qualification scripts.trust_qualification scripts.security_event_outbox_qualification scripts.security_event_delivery_qualification scripts.security_event_admission_qualification
Ran 52 tests in 6.085s
OK, 0 skips
```

Локальные Docker/WSL/Kubernetes/SQL не запускались и не менялись. Native
campaign проверяет hosted Linux guard до любых infrastructure calls;
контракт на эту границу включён в suite. Raw logs/keys/state остаются private.

## Ограничения и продолжение

Событие описывает изменение категории и ссылается на документ; это не отдельное
сообщение для каждого digest. Время события обозначает enqueue observer,
не SQL commit. Все исторические документы проверяются до первого enqueue.
History<=64версии/8MiB, rotation<=4; общий transport может быть до65MiB
document bytes до aggregate проверки. Registry/outbox freshness и capacity
не отключаются. Превышение/утрата/конфликт дают отказ, автоматического reset нет.

Наблюдатель запускается явно. Постоянный scheduler, producer heartbeat и
обязательный deployment profile ещё нужны, как и остальные identity/inventory
источники, sequence elapsed campaign и audit outage при здоровой ML dashboard.
Сохранная история закрывает промежуток commit-before-enqueue; полный SQL fork
или совместный rollback всех trusted stores администратором не доказаны.
Завершение этого компонента не закрывает M10/M19, independent M22(0/2), image
findings, M16/M17, R1-B08 и окончательную M18 на одном candidate.

[ADR0061](../decisions/0061-trust-history-security-events.md),
[ранбук и плейбук восстановления](../operations/trust-security-events.md).
