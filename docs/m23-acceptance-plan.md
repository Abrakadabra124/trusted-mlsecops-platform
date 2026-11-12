# M23: план полной приёмки security events

Продолжение T29 на source после `0aad732`. Это план реализации, не evidence
завершённого M23. [Исходные критерии](acceptance.md#m23) и остальные M01-M23
сохраняются. M11 milestone не закрывает M23 или R1.

## Требуемый результат

Связать семь типов событий с доверенными источниками, проверить подписанные
маршруты доставки, replay и реальные сроки обнаружения пропусков. Отдельно
показать отказ нового promotion при потере audit collector одновременно с
правильным inference и актуальным мониторингом без drift.

## Решения и границы

- Использовать существующий collector, outbox, Kubernetes ownership и monitoring.
  Новый оркестратор или backend не нужен; Sigma deployment не заявляется.
- Для sequence gap нужен реальный hosted scheduler, monotonic-время и сохранение
  episode после restart. Подставные часы остаются дополнительными unit tests.
  Проверить и пропуск между событиями, и пропуск, раскрытый только heartbeat head.
- Для outage использовать scoped Cilium deny и проверку его удаления. Зелёный
  dashboard до отказа недостаточен: probe продолжает подавать валидные данные,
  проверять prediction bindings и получать свежие monitoring snapshots во время
  работы родительского оператора.
- Generic `promotion_rejected` недостаточен: настоящий candidate пока не имеет
  обязательного assurance и может отказать раньше audit. Отдельный явно
  обозначенный controlled authorization/trust fixture должен дойти до настоящего
  `promotion.promote` audit boundary с реальными SQL и collector. Проверка требует
  конкретного audit refusal и исходного durable denial; actual candidate
  не получает фиктивный production approval.
- Контрольные роли не смешиваются: serving probe не получает promoter credentials.
  SQL ledger и артефакты сверяются оператором. Положительный ML-путь использует
  уже существующий qualification permit и остаётся synthetic-only.
- Частные HTTP observations и signed packets остаются в `.runtime`.
  Публичный результат содержит только конечные коды, метрики, bindings и hashes.

## Последовательность исполнения

1. Дописать hosted sequence campaign для двух источников пропуска, проверку
   signed notice/receipt, исходного таймера, позднего события, duplicate и cleanup.
2. Дописать controlled promoter audit-boundary probe с отрицательными тестами:
   ошибка до audit, другой reason, недоставленное событие без durable intent,
   неожиданное разрешение и неполная очистка не дают pass.
3. Добавить фиксированный фазовый обмен operator/probe, связанный с campaign и
   digest запроса. Этапы: ready, outage, attempt, recover, finish. Проверить
   повторы, неверную очередь, подмену, дедлайны и прекращение после отказа.
4. Соединить actual candidate, обычный мониторинг и scoped outage operator.
   Сохранять первичные records; пересчитывать green windows и HTTP bindings
   после cleanup. Удалять fault даже при ошибке child до возврата HTTP ownership.
5. Собрать семь source fixtures и transport cases в общий source-bound gate.
   Сверять точный inventory, уникальность case IDs, method hashes, timestamps,
   candidate bindings где они применимы, и terminal cleanup. Компонентные runs
   с разными candidates не представлять как общий M18.
6. Выполнить fresh hosted campaign из чистого checkout, review, scoped regression,
   ранбук, публикацию evidence и проверку удалённых артефактов.

Каждый исполняемый подпункт начинается с отрицательного теста. Локально разрешены
только pure/controlled tests без Docker, WSL, Kubernetes или SQL. Native probes
запускаются только в принадлежащем задаче disposable hosted CI. До выполнения
всех пунктов M23 остаётся открытым.
