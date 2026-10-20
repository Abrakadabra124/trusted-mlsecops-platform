# T16: fresh private serving receipt, local evidence

Дата: 2026-10-20. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0048](../decisions/0048-privacy-acceptance.md), [RB-67/PB-41](../operations/privacy-evidence-troubleshooting.md). Status: local verified component; далее **[native b0df48e verified](privacy-evidence-b0df48e-native.md)**, 83 cases, все 10 CI terminal: 6 success / 4 failure, attempt 1. Полный M13/T16/R1 не принят.

## Изменение

Parent observer независимо проверяет signed primary proposal и выводит пять subject references до запуска child. После full FD observation и повторной source проверки он проверяет структуру, freshness, обязательные cases/components и accounting private receipt. Only-parent case `current-private-receipt-admitted` появляется после admission, не является release approval.

Это не primary audit snapshot verifier и не public-safe projection. Успех согласованных summaries не доказывает всю M13 privacy. M13 acceptance dispatch явно проверен как inconclusive/exit 2.

## Failure-first и review

- Начальный RED: новый module отсутствовал; затем 10 методов прошли.
- Review cycle 1: пять design-пробелов full M13 признаны actionable и остаются открытыми в ADR: subject composition, production lifecycle/429/503, service logs, primary snapshots и private/public boundary.
- Review cycle 2: добавлены четыре теста, RED **14 методов, 12 failed subtests / 2 errors**. Существующие uppercase ONNX/CPU case IDs отвергались; согласованно подменённые totals проходили; malformed limitations принимался; большой JSON integer вызывал OverflowError. Исправлены все четыре причины.
- Integration RED: отсутствовал `verified_subject`. Первая попытка дополнительно выявила ошибку импорта в самом тесте; она исправлена до production implementation. Затем positive crypto fixture выявил short/long Windows path mismatch в expected mock call, исправлено ожидание `.resolve()`, не production path semantics.
- Дополнительный RED: child мог включить parent marker, после чего result содержал duplicate. Теперь reserved marker от child отклоняется.
- Review cycle 3: signature-negative test добавлял неизвестное поле вместо повреждения настоящей подписи. Уточнённый assertion воспроизвёл RED `unexpected_fields` вместо `invalid_signature`. Теперь меняется один byte decoded signature при неизменных schema/Base64/length/key ID/payload; verifier даёт именно `invalid_signature`. Это исправление тестового доказательства, не ослабление verifier.
- Внешняя модель не использовалась по просьбе владельца. Три bounded same-model review cycles завершены, четвёртый не запускался. Полные M13 design findings остаются открытыми, а не считаются исправленными.

## Проверенные команды

```bash
uv run --locked python -m unittest scripts.privacy_evidence_qualification scripts.serving_output_native_qualification
uv run --locked coverage run --data-file=.coverage-privacy-evidence --source=mlsecops.privacy_evidence,scripts.serving_output_native -m unittest scripts.privacy_evidence_qualification scripts.serving_output_native_qualification
uv run --locked coverage report --data-file=.coverage-privacy-evidence -m
```

В рабочем окружении использован установленный `.venv/Scripts/python.exe` с project dependencies. Финальный focused coverage run после всех fixes: **36 test methods, 0 skips, 13.067 s** (`privacy_evidence`, native integration, output observer suites). `privacy_evidence.py`: **89 statements / 34 branches, 100%**. Parent observer: **80 statements / 14 branches, 98%**, не исполнен только `__main__` entrypoint. Existing output probe: **45 statements / 12 branches, 100%**.

Расширенная регрессия: **135 methods / 0 skips / 26.662 s**: дополнительно HTTP privacy, candidate native/reader, release bundle, audit correlation/context/event и production release reader. Этот запуск был до уточнения signature-negative assertion; после него полный focused suite повторён успешно. Ruff check и format прошли для всех 246 Python files. Documentation checker: **476 files / 199 Markdown / 1445 local links**, внешние URLs и runtime этим checker не проверяются.

Crypto test не подменяет signature verification: создаёт настоящий signed bundle/capsule и вызывает existing verifier. Storage read заменён in-memory fixture; проверяются source/model mismatch, expiry, invalid capsule signature и изменённый dependency lock. Это не native SQL/TLS qualification.

Сохранённый actual receipt `2a70ffc` также принят checker по формату: 82 cases / 84 requests. Expected source/subject/time для этой совместимости взяты из самого исторического документа, поэтому этот прогон **не является независимой проверкой bindings или fresh acceptance**.

Локальные raw failure logs остаются в ignored `.runtime`; не публикуются. Docker/WSL/Kubernetes/SQL локально не запускались. Пользовательские AGENTS.md/GOAL.md не входят в increment.

## Остаточные ограничения

Открытые design findings перечислены в ADR, а не заменены декларацией pass. Существующие image/ML release blockers и прежний intermittent M07 debt не исправлялись этой работой. Hosted guard не является attestation; forced-stop nested resource cleanup на shared/local host не доказана. Полный M13 runner и acceptance dispatch не включены.
