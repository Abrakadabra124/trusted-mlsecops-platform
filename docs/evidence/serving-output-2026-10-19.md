# Serving lifecycle output observation

Дата: 2026-10-19. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0047](../decisions/0047-serving-output-observation.md), [карта каналов](../privacy-output-map.md), [RB-66/PB-40](../operations/serving-output-troubleshooting.md).

## Статус

**[Native 2a70ffc verified](serving-output-2a70ffc-native.md): 82 cases, zero native stderr, 6 canaries; все 10 CI terminal, 6 success / 4 failure.** Первый ff3f25f CI остановился на тестовом import defect и сохранён ниже. Исправленный commit проверен отдельной полной matrix. Полные M13/T16/R1, image/ML blockers и исторический M07 reliability debt остаются открытыми.

## Локальное evidence

- RED: отсутствующие observer/CLI; затем reproduced late cached handler bypass (Rejected не возник) и отсутствие strict wire API.
- 2026-10-20 дополнительный RED: real HTTP exercise с cached handler после hot loop и в atexit дал два Rejected not raised. Shared LifecycleCapture + ExitStack seal закрыли вложенный обход.
- После snapshot fix: 43 methods, 0 failures/skips, 14.976 s. После Linux test-import fix: 44 methods, 0 failures/skips, 16.873 s, output/native/privacy/candidate suites. Output probe 45 statements / 12 branches, 100%; privacy probe 200 statements / 90 branches, 100%; native CLI 63 statements / 12 branches, mixed 97%, parent __main__ line не покрыта этим запуском. Пороги CI не снижены.
- Проверены clean child, поздний handler с точной длиной constant diagnostic, seal всех трёх вложенных buffers на success/exception/KeyboardInterrupt. Предыдущие regression 62 methods / 0 skips сохраняют историю; suites пересекаются, числа не складывать.
- Расширенная regression 2026-10-20 после snapshot fix: 113 methods, 0 failures, 1 skip, 26.499 s. Controller/privacy/transport/lifecycle/HTTP/intake/output/native/privacy/candidate suites. Предшествующий запуск 112 methods с coverage дал worker_transport 137 statements / 48 branches, mixed 99% (непокрыт CLI __main__). Ещё 64 correlation regression methods прошли без skips за 6.739 s. Это Windows pure/owned-loopback checks, не native container proof; пересекающиеся suites не суммируются.
- Frozen source lock сохранён; инфраструктура локально не запускалась.
- Внешняя модель не используется по выбору владельца. Завершены три same-model review cycles: cached streams/premature report/strict wire исправлены, forced-stop recovery отражён как ограничение; cycle 2 выявил nested capture, cycle 3 выявил mutable report snapshot. Оба новых дефекта независимо воспроизведены RED-тестами и исправлены. Четвёртого review cycle не было; финальный snapshot fix проверяется тестами, а не заявляется повторно одобренным reviewer.
- Snapshot RED: published report differs from scanned bytes после controlled mutation исходного report при первом getvalue. Исправление возвращает decode именно проверенного payload, не mutable producer object; regression проверяет exact bytes и последующую мутацию вложенного runtime.
- Forced-stop cleanup ограничен: внешний transport не доказывает удаление Docker resources. Новый wrapper только для disposable hosted CI, failure не даёт pass; details в ADR/RB.

## Что ещё требуется

Native observer + actual candidate из clean checkout, complete CI matrix и canonical report/source binding подтверждены в [полном evidence](serving-output-2a70ffc-native.md). Следующий этап - отдельная M13 acceptance aggregation, а не автоматическое закрытие gate по нескольким зелёным компонентам. Shared/local forced-stop recovery нового wrapper отдельно не квалифицирован.

## Первый Linux отказ и исправление

Code commit ff3f25f97afbd0868eff6345adb0b732148931e3, [Storage run 39428436953](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436953), job 118646838094, attempt 1. Observer test step: 18 methods, 2 failures / 1 error, 4.881 s; до native actual-candidate не дошёл.

Root cause: импорт PrivacyProbeContracts тянул serving_native_qualification -> mlsecops.model -> ONNX Runtime. На Linux этот ненужный inference import вывел 369 bytes PCI discovery warning в native FD2; clean control был корректно отвергнут, late-write controls получили 395 bytes вместо 26. Это не утечка input в production и не дефект zero-stderr enforcement. Windows не воспроизводил native warning, но новый независимый import-boundary test в owned child подтвердил наличие ONNX Runtime в sys.modules (RED).

Исправление: engine_fixture импортируется только в двух тестах, которым он нужен; simulated HTTP fixture больше не загружает inference runtime. Запрет любого stderr, exact marker length и strict wire не меняются; warning allowlist и redirect-to-DEVNULL не добавлялись. Green: 44 methods / 0 skips и прежние coverage thresholds. Import actual candidate harness отдельно проверен: ONNX Runtime не загружается. Прежний failed run сохраняется, не переименовывается в pass.

Все 10 runs этого commit terminal, attempt 1: **5 success / 5 failure**. Это отдельная первая matrix, не итог исправленного кода.

| Workflow | Run | Conclusion |
| --- | --- | --- |
| Developer runtime | [39428436525](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436525) | success |
| Documentation | [39428436667](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436667) | success |
| Frozen evasion | [39428436769](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436769) | failure |
| Frozen poisoning | [39428436621](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436621) | failure |
| Intake evidence | [39428437062](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428437062) | success |
| Kubernetes isolation | [39428436919](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436919) | success |
| MLflow private service | [39428436649](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436649) | success |
| Paired robust training | [39428436794](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436794) | failure |
| Storage role/TLS | [39428436953](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436953) | failure |
| Image audit | [39428436618](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39428436618) | failure |

