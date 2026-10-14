# Evidence: HTTP qualification неизменённого actual candidate

Дата: 2026-10-15 Europe/Moscow. Реализация после `afdc05c`; UTC timestamps native campaign фиксируются отдельно. [ADR 0032](../decisions/0032-candidate-serving-qualification.md), [PB-26/RB-50/RB-51](../operations/candidate-serving-troubleshooting.md). Это T15 increment, не полная M12/M18/R1-приёмка.

## Проверено локально

- `scripts.candidate_serving_reader_qualification`: 17 methods pass, branch-aware coverage 94% (111 statements, 26 branches). Исходные signed fixtures контролируемые; это не настоящее обучение.
- `scripts.candidate_serving_native_qualification`: семь methods pass, включая реальный loopback HTTP с подставным worker, 14 input/lock-pressure checks, CLI confirmation/error redaction, configurable port, invalidation старого отчёта до Docker preflight и fresh-subprocess import boundary.
- Итоговый объединённый regression: 129 distinct methods pass за 13.316 s. Это 17 qualification Reader и 112 adjacent/harness methods; harness не считается дважды. Покрыты serving core/HTTP/runtime/native helpers, release reader/bundle/policy/authorization и trust.
- Review обнаружил expiry-after-refresh и Base64 key alias defects. Новые тесты сначала воспроизвели четыре expiry failures, три source-key alias bypasses, неправильный тип campaign и нежелательные parser/fixture imports. После исправления 21 method новой suite проходит.
- Второй read-only reviewer обнаружил конфликт 15445 с tracking-service, отсутствие cleanup после частичного bootstrap и stale pass при раннем preflight failure. Добавлены failure-first regressions, configurable default 15446, проверка local workspace перед invalidation и cleanup/readback по подтверждённой identity. Если marker ещё не создан, ресурсы не удаляются вслепую: unconfirmed cleanup с сохранением state. Native partial-bootstrap fault injection не выполнен.
- Reviewers - агенты, не независимый человек и не внешняя security certification. Отдельно повторены 50 serving methods, 94% coverage (523 statements, 156 branches).
- Ruff check/format: pass, 322 files formatted. Documentation check: 351 files, 126 Markdown documents, 915 local links; внешние URLs/runtime эта проверка не подтверждает. `git diff --check` pass.

## Что именно реализовано

Serving-only TLS SQL reader получает неизменённый proposal настоящего upstream training/evaluation. Отдельный ephemeral signer выдаёт permit только на испытание, без M-gate reports. Отдельная authority проверяет текущий trust; same Engine/HTTP/Docker worker принимает exact verified bytes. Production Reader/config не изменены, исходный release без assurance по-прежнему отвергается.

Reference predictions получаются отдельным one-shot ONNX worker на тех же bytes и трёх фиксированных synthetic rows. Это проверяет consistency persistent runtime и протокола, не независимую sklearn parity. Report явно хранит release_ready false и full_M12 inconclusive.

## Native / CI

Fresh clean-checkout CI этой ревизии ещё не проверен. Не переносить 34-case результаты прежнего fixture path с `2942255` на новый actual-candidate path. Docker/WSL и существующая платформа на компьютере владельца в этом increment не запускались и не изменялись.

## Остаётся

Полная M12 acceptance с production release Reader, timestamped HTTP trust-outage trace M11, privacy/audit/quotas M13, нагрузка M14 и остальные R1 gates. Текущие image/poisoning/evasion/paired robustness failures не обходятся квалификационным permit. Это разрешение получить проверочные данные, не разрешение выпустить модель.
