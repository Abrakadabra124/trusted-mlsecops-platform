# Serving lifecycle output observation

Дата: 2026-10-19. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0047](../decisions/0047-serving-output-observation.md), [карта каналов](../privacy-output-map.md), [RB-66/PB-40](../operations/serving-output-troubleshooting.md).

## Статус

Реализовано локально; native CI нового increment пока не подтверждён. Предыдущий [54cbe50](audit-correlation-54cbe50-native.md) доказывает correlation, но не новый full-lifecycle observer. Полные M13/T16/R1 открыты.

## Локальное evidence

- RED: отсутствующие observer/CLI; затем reproduced late cached handler bypass (Rejected не возник) и отсутствие strict wire API.
- 2026-10-20 дополнительный RED: real HTTP exercise с cached handler после hot loop и в atexit дал два Rejected not raised. Shared LifecycleCapture + ExitStack seal закрыли вложенный обход.
- Финальные 43 methods, 0 failures/skips, 14.976 s: output/native/privacy/candidate suites. Output probe 45 statements / 12 branches, 100%; privacy probe 200 statements / 90 branches, 100%; native CLI 63 statements / 12 branches, mixed 97%, parent __main__ line не покрыта этим запуском. Пороги CI не снижены.
- Проверены clean child, поздний handler с точной длиной constant diagnostic, seal всех трёх вложенных buffers на success/exception/KeyboardInterrupt. Предыдущие regression 62 methods / 0 skips сохраняют историю; suites пересекаются, числа не складывать.
- Расширенная regression 2026-10-20 после snapshot fix: 113 methods, 0 failures, 1 skip, 26.499 s. Controller/privacy/transport/lifecycle/HTTP/intake/output/native/privacy/candidate suites. Предшествующий запуск 112 methods с coverage дал worker_transport 137 statements / 48 branches, mixed 99% (непокрыт CLI __main__). Ещё 64 correlation regression methods прошли без skips за 6.739 s. Это Windows pure/owned-loopback checks, не native container proof; пересекающиеся suites не суммируются.
- Frozen source lock сохранён; инфраструктура локально не запускалась.
- Внешняя модель не используется по выбору владельца. Завершены три same-model review cycles: cached streams/premature report/strict wire исправлены, forced-stop recovery отражён как ограничение; cycle 2 выявил nested capture, cycle 3 выявил mutable report snapshot. Оба новых дефекта независимо воспроизведены RED-тестами и исправлены. Четвёртого review cycle не было; финальный snapshot fix проверяется тестами, а не заявляется повторно одобренным reviewer.
- Snapshot RED: published report differs from scanned bytes после controlled mutation исходного report при первом getvalue. Исправление возвращает decode именно проверенного payload, не mutable producer object; regression проверяет exact bytes и последующую мутацию вложенного runtime.
- Forced-stop cleanup ограничен: внешний transport не доказывает удаление Docker resources. Новый wrapper только для disposable hosted CI, failure не даёт pass; details в ADR/RB.

## Что ещё требуется

Native observer + actual candidate из clean checkout, complete CI matrix, canonical report digest, source binding, readonly publication verification. После этого - отдельная M13 acceptance aggregation, а не автоматическое закрытие gate по нескольким зелёным компонентам.

