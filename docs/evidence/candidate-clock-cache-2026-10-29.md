# Actual candidate: clock/cache отказ и восстановление

Дата: 2026-10-29. Неделя 8, T14 Trust lifecycle, CP3/R1-B04.
Code commit: `2b11bf587aeb7be29f4a97e94f15f052e517e236`.
[GitHub Actions 40916783930](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40916783930), job `123599028125`: **success**.

## Результат и границы

Пять controlled clock/response injections выполнены внутри настоящего CandidateReader/Lease/Engine на actual обученной модели в isolated Kubernetes worker. Обычный HTTP serving подтвердил положительные predictions до каждого fault, затем точную причину отказа и 503. Trust payload и Reader.current очищены, старый Engine остаётся fenced после возврата исправных providers. После injection не было вызовов Worker.predict. Новый Reader проверяет тот же model/subject; следующий свежий Engine выполняет успешный inference и полный HTTP contract.

Часы Windows, Kubernetes node и SQL не изменялись. Это проверка injected Reader dependencies, не доказательство реального clock skew инфраструктуры или ремонта NTP. Invalid-signature case изменяет один бит копии настоящего ответа trust authority; private signer в Pod отсутствует. Permit остаётся purpose-bound qualification с максимумом 600 s, `release_ready=false`. Actual production promotion отказан точно по `release_assurance_required`.

## Пять отрицательных сценариев

Время ниже измерено monotonic clock от начала probe injection section до полного первого HTTP 503. Это одиночные наблюдения в этом прогоне, не latency SLO.

| Case | Точная причина | Первый полный 503, s | Denial observations | Golden error до fault |
| --- | --- | --- | --- | --- |
| wall-backward, -0.25 s от последней выборки | trust_clock_invalid | 0.003636247 | 5 | 0.0 |
| monotonic-backward, -1 s от последней выборки | trust_clock_invalid | 0.003364620 | 5 | 0.0 |
| wall-jump, +30 s | trust_clock_invalid | 0.003433019 | 5 | 0.0 |
| server-skew, server timestamp -10 s | trust_server_clock_skew | 0.013918349 | 5 | 0.0 |
| invalid-signature, один изменённый бит | invalid_signature | 0.016708151 | 5 | 0.0 |

Каждый trace содержит predict/readiness при injection, два predict и readiness после восстановления providers. Все 25 observations дали 503 без predictions. Для каждого fault проверены warm cache, exact cause, cache/Reader invalidation, same fenced generation, zero worker calls после injection, fresh Reader с теми же hashes и worker absence после закрытия. Причину может обнаружить HTTP check либо heartbeat; report не заявляет, что исключительно HTTP поток первым заметил отказ.

В базовом actual Job **185 typed assertions**, включая прежние 60 и 125 новых. Все IDs в этом report уникальны. Последующий fresh Engine прошёл golden prediction с max error `0.0` на трёх фиксированных строках; эта проверка не измеряет бизнес-качество модели.

## Соседние native проверки того же candidate

| Сценарий | Typed assertions | Первый полный 503, s |
| --- | --- | --- |
| Outage | 174 | 59.773185707 |
| TCP blackhole | 152 | 13.754299116 |
| Policy change | 72 | 5.777122250 |
| Publisher key revocation | 70 | 5.487284630 |

Суммарно 653 typed assertions с повторением общих contract checks между Jobs. Outage/blackhole traces охватывают границу 60 s, не допускают ML после неё или после первого отказа. Exact cold denial, same-candidate Reader recovery и no-auto-reactivation подтверждены. Последний key revoke не отменялся.

В том же run ordinary controlled release прошёл signed approval expiry, отказ ещё действующему предыдущему sequence 1 с точным `promotion_sequence_conflict`, неизменный journal и retry sequence 2. Старый sequence оставался time-valid ещё 1598 s. Это controlled release evidence; его нельзя объединять с actual qualification и объявлять полной M11 приёмкой настоящего разрешённого release.

## Проверяемые привязки

Source fingerprint пересчитан из 135 Git blobs проверенного code commit. Две копии общего primary report в CI побайтно эквивалентны после canonical serialization. Report/file hashes ниже используют canonical JSON + LF.

| Поле | Значение |
| --- | --- |
| Source fingerprint | `053a01e002cc6a9e219a5c4c32fdc392f68fbc20577e8b5bf04893c8db03f7fd` |
| Image ID | `sha256:5d1024af51916662f028a4165a90b150bdf0a1fac8a72f6ba9f7701a0bc4c175` |
| Synthetic candidate | `3d1b44bbd046d51e81b4072a1e16c44b2d904b97c569ed26a8a15e9b09f50452` |
| Model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Subject | `f22132681082ca71ee586ca1e6f53f43c4551e4c82752636892ea3c7fe7d275b` |
| Proposal | `b5f629239b8cde672de27c8a2625550ec751872e8d27e153a2af1c8360686d0e` |
| Qualification permit | `583369d9c1a486f5f7bc445dd75b54c369bb7cfebfbe6955c8aa22a3888ebe0d` |
| Full native report | `a34101b10ea5a9ca86fa23796abd8df39132a95b7154a1fd940b67a884cde33d` |
| Actual base probe.json | `1218ffc341f9f63f15f574a4e3cc4dd67992ec0af2c695dae3d36654f4ade3ad` |
| Full CAS + promotion snapshot | `a93adda13d1933188204c4067ec92fd42e367fb91f04102c9870383613f44c81` |
| outage.json | `575a2c174372540d4356462d5e223affb574fb0121d8c86a99632f1a8a181886` |
| blackhole.json | `7fe20a978724df99fe5e9c6bdfca86c04235fc8e1da810fb1c10d980bb68c1d4` |
| policy-change.json | `a991f785aa5cf322e3d37996e003b98889b6896a7eb2fb2c298923c691fdeb2a` |
| key-revocation.json | `4190056c2c4990abc2ca6ffbdf0c5fc161643f4c48785f7795c8d56b45984610` |

Полный snapshot до/после начального clock/cache Job совпал; тот же hash подтверждён для всех четырёх authority fault Jobs. Сверка охватывает CAS и authorities/events/heads журнала promotion. Trust authority имеет отдельную историю версий; её ожидаемые policy/revocation updates не выдаются за отсутствие изменений в authority.

Full native interval UTC: `17:01:39.371749` - `17:14:41.143847`. Actual-candidate interval: `17:10:02.058417` - `17:14:41.142876`. Raw logs и primary JSON сохранены приватно в `.runtime/evidence/ci-40916783930-*`; секреты и private keys в этот документ не включены.

## Тесты, cleanup и оставшаяся работа

Linux CI: **264 method executions** = 11 + 145 + 31 + 30 + 5 + 14 + 28, без skipped. Это число запусков методов разных групп, не заявление об уникальности всех тестов.

- Новая clock probe: 81/81 statements, 10/10 branches, 100%.
- Fault/snapshot modules: 274/274 statements, 104/104 branches, 100%.
- Bootstrap: 41/41 statements, 12/12 branches; replay: 230/230, 72/72; expiry: 50/50, 12/12.
- Attach/runtime: 257/258 statements и 91/92 branches, общий coverage report 99%.
- До публикации локально 72 methods pass. Проверены транспортное исключение, wrong recovered candidate, поздний вызов worker при 503, finite error reporting и исключение повторного запуска clock matrix в live fault Jobs.

Все проверки worker absence прошли. Final CI steps `Stop verified owned source SQL` и `Remove verified owned disposable cluster` завершились success с проверками конечного состояния. При чтении GitHub API были TLS timeout и HTTP 503; повторное чтение того же run восстановило наблюдение. Второй run из-за этих ошибок не создавался.

Полные M11, T14, CP3 и R1 остаются открыты. Следующие обязательные случаи: actual stale signed trust-version replay, независимые actual model/key revocation states, root/key rotation и разрешённый rollback целого bundle. Независимый M22 review 0/2, system-image findings и остальные обязательные gates не сняты этим increment. [Ранбук и команды](../candidate-clock-cache.md).
