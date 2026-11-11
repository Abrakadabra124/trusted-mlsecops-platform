# T29: события intake и постоянная очередь отправителя

Дата2026-11-11. Проверенный runtime:
`a2056460f65856eb9a0fa8329f493ccc8858813f`.
[CI43057291164](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43057291164),
job130650050209: **completed/success**. Hosted Ubuntu24.04, Python3.12.15,
uv0.12.23, `uv sync --locked --no-build`. Неделя11/T29/M23 остаются открытыми;
результат ниже не является общей приёмкой R1.

## Реальный путь и его полномочия

`controller -> storage_pipeline.evaluate -> pipeline.evaluate_verified_candidate
-> artifact_intake.inspect_candidate -> producer outbox -> loopback HTTP
-> collector journal -> fixed incident route -> signed receipt -> outbox settlement`.

Controller получает operator config через `--security-event-config`; worker
request не может выбрать ключ/URL/role. Event key принадлежит controller и
отделён от receipt key. Worker output проверяется существующим intake contract
до построения ограниченной event projection. В событие не включаются model
bytes, paths, labels, error text или произвольный stdout.

| Наблюдённое решение | Событие | Маршрут |
| --- | --- | --- |
| Digest полученных bytes не совпал с expected | artifact.rejected / integrity | security.artifacts |
| Настоящий ONNX parser отклонил неподдерживаемые bytes | artifact.rejected / unsupported_format | security.artifacts |
| Controller установил нарушение response schema/binding worker | worker.policy_violation / output_schema | security.workers |
| Scanner отсутствует, истёк timeout или процесс упал | Нет ложного security finding | Остаётся исходный inconclusive отказ |

Live harness вызывает настоящий pipeline/intake/parser с synthetic executor
в процессе harness. Collector работает отдельным настоящим Linux процессом.
Тест доказывает source hook, queue/HTTP/receipt, но **не** новый Kubernetes worker
deployment, его mounts/network isolation или production keys custody.

## Проверки и измерения

| Набор | Фактический результат Linux |
| --- | --- |
| Event/config contracts | 21 tests |
| Смежные key/signature/monitoring/policy | 25 tests |
| Collector journal/health/routes | 47 tests |
| Collector lifecycle/ASGI | 10 tests |
| Настоящий collector, elapsed heartbeat/restart/cleanup | 1 test,95.810s |
| Новые outbox/delivery/wire/source/live | 24 tests,3.555s |
| Смежные intake/evaluation/holdout | 85 tests,7.666s |
| Всего | **213 tests,0 skips** |

Повтор измерения collector: heartbeat notice91.027817689s при пороге120s;
максимальный HTTP round trip0.016775146s на трёх событиях. Это малый synthetic
сценарий, не load/percentile SLO. Новые native source cases проверяют:

- Настоящий отказ intake до prediction, trusted event и receipt в outbox.
- Controller-observed protocol violation на маршруте security.workers.
- Реально остановленный collector: source получает постоянный отказ,
  signed envelope остаётся pending. После restart явный retry сохраняет ID.
- После реального HTTP commit искусственно теряется исход на producer стороне:
  повтор не создаёт второй incident, receipt совпадает с collector.
- File I/O fault до rename не создаёт event; после rename reopen находит один
  исходный event. Это управляемая fault injection, не power-loss proof.
- Неверный producer для state pin и повторная initialize отвергаются.
- Owned collector завершается, port закрыт; временные keys/state/log очищены
  harness. Canary отсутствует в incident page.

Отдельные настоящие loopback socket tests отклоняют redirects, duplicate lengths,
encoding, oversized/partial/malformed response и slow headers по total deadline.
Каждый принадлежащий тесту listener/thread закрыт. Pending batch может содержать
до16 попыток по2s; общий batch не обещает deadline2s.

## Отрицательные проверки и обнаруженные ошибки

Первый тест показал отсутствие audit hook в actual intake. После подключения
проверены projection, unchanged denial и запрет prediction при отказе.
Другой negative test воспроизвёл принятие valid receipt другого pending event
в новом sender. Исправлено: receipt сверяется с конкретным отправленным event
до settlement. Forged receipts и correlated conflicts не меняют state.

Смежный тест порядка holdout резервирования использовал stub без нового keyword
`audit`; обновлена только его сигнатура. Все85 adjacent tests прошли. Этот старый
набор использует runpy для уже импортированного holdout_budget и выводит
RuntimeWarning; он запущен в обычном прежнем режиме. Новые24 tests запущены
с `-W error`; глобальное подавление warnings не добавлялось. ResourceWarning
в Linux log отсутствует.

Collector coverage после изменения общего filesystem adapter:
events105/105statements42/42branches, config101/10132/32,
health134/13454/54, ledger178/17951/52, store154/15536/36.
Существующие пороги не снижены. Эти цифры **не** являются coverage всего
нового outbox/delivery/source кода.

## Чистый checkout и инструкции

Отдельный detached checkout `a205646`, новая `.venv`, locked Python3.12.15:
72 выбранных теста за5.056s, из них17 Linux-only пропусков. Проверены путь
интерпретатора и import module именно из checkout, git clean. Результат Windows
не заменяет native Linux run. Основная Windows suite128tests/24skips, adjacent85
pass также зафиксированы отдельно; сумма этих исполнений не новая Linux приёмка.

[ADR0059](../decisions/0059-security-event-producer-outbox.md) объясняет очередь
и полномочия. [Ранбук](../operations/security-events.md#producer-outbox-и-отказ-intake)
содержит config/provisioning, команды контроллера и тестов, diagnosis/retry/readback
и причины эскалации. Raw logs, ключи и tokens не публикуются.

## Оставшиеся обязательные работы

Явный CLI параметр сейчас подключает профиль; старые вызовы без него продолжают
работать без новой доставки и не считаются M23-ready. Manifest/network/mount
integration для всего стенда, обязательность audited profile, остальные реальные
источники, producer heartbeat, sequence elapsed campaign, promotion audit admission
и общий M23 всё ещё нужны. Loopback не позволяет обращаться к collector в другом
pod без дополнительного согласованного deployment решения.

Outbox не удаляет историю и не меняет timestamps; предел1024/16, expiry и
утерянный state требуют расследования. Registry/epoch migration, backup/rotation
не реализованы. При audit outage источник остаётся denied; это не доказательство
запрета новой promotion при зелёной drift dashboard. Старые M13/M15 evidence не
переносятся автоматически на новый source fingerprint/образы. Общие M10/M19,
M22 independent0/2, M16/M17, image/R1-B08 и M18 на одном candidate сохраняются.
