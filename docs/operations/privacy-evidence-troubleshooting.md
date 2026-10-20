# RB-67 / PB-41: fresh private serving receipt

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0048](../decisions/0048-privacy-acceptance.md), [evidence](../evidence/privacy-evidence-2026-10-20.md), [предыдущий observer RB-66](serving-output-troubleshooting.md).

## Назначение и границы

Владелец - инженер disposable GitHub-hosted qualification job. Security reviewer участвует при digest/signature/canary mismatch. Receipt - машинный отчёт проверки; это не approval, не аттестация доверенного хоста и не полный M13.

Локально допустимы только pure contracts и собственные временные файлы/loopback-процессы тестов. Не запускать Docker/WSL/Kubernetes/SQL, не подделывать hosted environment guard. Native command исполняется только существующим workflow `storage.yml` в отдельной disposable VM. Не выводить private receipt, credentials, raw logs или exception values в публичные diagnostics.

## RB-67: диагностика

1. Зафиксировать SHA, workflow run/job/attempt и упавший step. `serving_output_rejected` намеренно не раскрывает внутреннее исключение. Публичный вывод содержит только constant diagnostic; подробную причину воспроизводить scoped synthetic test, не включая verbose SQL/log output.
2. Сначала read-only сверить код и scope:

```bash
git status --short
git rev-parse HEAD
uv run --locked python -m unittest scripts.privacy_evidence_qualification scripts.serving_output_native_qualification
```

3. Интерпретировать проверенное воспроизведение:

| Ветка | Возможная причина | Безопасное действие |
| --- | --- | --- |
| Primary rejected до child | Неверная signature/capsule, expired bundle, другой source/model | Не редактировать receipt, ключ или expected digest. В новой disposable campaign повторить upstream proposal generation на одном clean SHA. |
| Timestamp/binding rejected | Старый отчёт, другое image/subject либо несогласованные часы | Проверить границы нового запуска и authoritative CI timestamps. Не подставлять прошлые timestamps; при clock instability результат inconclusive. |
| Cases/components rejected | Producer/checker разных revisions, отсутствующий обязательный control, malformed JSON | Прогнать contracts на том же SHA; сравнивать schema, не только число cases. Не удалять обязательные проверки. |
| Accounting rejected | Несогласованные public/private totals или totals ниже обязательных непересекающихся фаз | Проверить exact producer phases и первичные snapshots, если они сохранены приватно. Не «чинить» counters арифметически. |
| `current-private-receipt-admitted` пришёл от child | Reserved parent marker в недоверенном receipt | Отказать; marker добавляет только родитель после admission. |
| Child timeout/cancel/cleanup | Полная native cleanup не подтверждена | Следовать RB-66: прекратить disposable job, не публиковать pass/private state, повторить только в новой VM. |
| Компонент зелёный, M13 inconclusive | Полный gate ещё не реализован | Это ожидаемый безопасный результат, не инцидент. Не менять acceptance dispatch на pass. |

## PB-41: воспроизводимая последовательность

1. Read-only проверить SHA/status и отсутствие изменения пользовательских файлов. Не использовать reset/clean для получения удобного clean checkout.
2. Выполнить unit/contract suites выше и обязательное покрытие:

```bash
uv run --locked coverage run --data-file=.coverage-privacy-evidence --source=mlsecops.privacy_evidence -m unittest scripts.privacy_evidence_qualification
uv run --locked coverage report --data-file=.coverage-privacy-evidence --fail-under=100
uv run --locked ruff check mlsecops scripts
uv run --locked ruff format --check mlsecops scripts
uv run --locked python scripts/check_docs.py
```

3. Negative controls должны отвергнуть stale/future receipt, wrong five subject refs, missing case/component, unsafe types, contradictory totals, подменённый signed capsule/material и expired primary. Positive fixture обязан проходить без нормализации case IDs.
4. После разрешённого push существующий CI выполняет native observer с current signed proposal. Дождаться terminal всех workflows, не отменяя старый запуск новым push. Записать первый отказ и номер attempt даже после исправления.
5. Конечное состояние: родитель добавил единственный reserved case после полного child exit и проверки fresh receipt; `release_ready=false`. Сохранить sanitized synthetic evidence, SHA, image, timestamps и полную CI-матрицу. Успешный unit test не заменяет этот native шаг.
6. Rollback: остановить использование нового отчёта и оставить результат inconclusive. При подтверждённой регрессии подготовить отдельный reviewed revert только этого increment, затем снова пройти CI. Возврат прежнего checker не превращает historical evidence в fresh acceptance. Не менять thresholds, signatures или чужие ресурсы.

## Проверенность

Это инструкции по встреченным controlled test failures, не отчёт о production-инциденте. Локальные команды проверяются в evidence; native результат фиксируется отдельно. Автоматическое восстановление shared/local Docker, private primary snapshot retention, service-log observation и полный M13 остаются вне выполненного increment. Эскалировать повторную несовместимость schemas, неизвестный private output, неподтверждённую ownership/cleanup либо отсутствие обязательного primary evidence.
