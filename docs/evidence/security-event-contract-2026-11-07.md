# T29/M23: подписанный контракт событий безопасности

Дата: 2026-11-07. Статус: **компонент проверен; полная M23 acceptance не пройдена**.
Runtime source: `c2f7bf95fe50af96f3e74c4121c3aadeb3346fbd`.

## Что проверено

Реализованы семь фиксированных типов событий, правила producer roles, подписанный
registry с внешними root/pin, immutable event value и отдельные domains для
event, heartbeat, receipt и config. Event ID зависит от всех полей намерения,
payload не допускает сырые данные или произвольный текст. Подпись проверяет
происхождение сообщения, но не заменяет проверку source adapter.

[ADR 0058](../decisions/0058-security-event-contract.md) описывает контракт и
оставшиеся этапы. [Ранбук](../operations/security-events.md) содержит команды
воспроизведения, конечные reason codes и диагностику.

## Результаты

| Среда и проверка | Результат | Граница доказательства |
| --- | --- | --- |
| Windows, контракт с реальными Ed25519 signatures | 21 tests, 0 skips, 0.926 s | Контролируемые данные и часы, нет runtime collector |
| Windows, смежные key/monitoring/release-policy проверки | 25 tests, 3 POSIX skips, 0.461 s | Пропуски не считаются pass соответствующих Linux checks |
| [Linux CI 42345739729](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42345739729) | 21 contract tests / 0 skips / 0.217 s; 25 adjacent tests / 0 skips / 0.079 s | Чистый hosted checkout, Python 3.12.15, locked dependencies |
| Чистый Windows checkout того же commit, новая `.venv` | 46 tests, 3 POSIX skips, 1.305 s | Проверены import path, Python 3.12.15 и пустой git status после тестов |

CI job `128322966809`: все steps success, terminal timestamp
`2026-11-07T06:09:40Z`. Это workflow без контейнеров, SQL и Kubernetes.
CI не создаёт внешние модели или платную инфраструктуру; локальные запрещённые
среды также не запускались. Тесты завершились, временные ключи удалены собственной
`TemporaryDirectory` cleanup. Private raw logs не опубликованы.

Source и точное покрытие каждого модуля сверены по CI log:

| Модуль | Покрытые statements | Покрытые branches |
| --- | --- | --- |
| `mlsecops/security_events.py` | 105/105 | 42/42 |
| `mlsecops/security_event_config.py` | 101/101 | 32/32 |

Проверка CI требует именно эти два модуля, ненулевые totals и отсутствие
пропущенных строк/ветвей в каждом. Это не процент готовности M23 или проекта.
Проверка документации на runtime commit: 844 files, 306 Markdown documents,
2290 local links в чистом Linux checkout. Ruff и format check прошли.

## Отрицательные случаи и исправления

Проверены чужой ключ, неправильная роль, изменённые policy/epoch/producer,
неверный domain, подпись и неканонический payload, неправильные schema/types,
пропущенные поля, лишний raw payload, размеры и вложенные envelope values,
expiry/skew, mutable input и неверные receipt bindings/deadlines.

Failure-first тесты отдельно выявили две ошибки нового кода: registry мог
отключить все обязательные heartbeat, а receipt мог указывать ingest до начала
срока config. Оба случая теперь отклоняются. Это ошибки, обнаруженные при
разработке компонента, а не зарегистрированные production incidents.

## Что остаётся открытым

Постоянного collector, атомарной дедупликации, recovery после сбоя, scheduler
пропусков/heartbeat, HTTP ingress, actual source adapters и audit admission
в promotion path в этом increment нет. Receipt builder с допустимыми timestamps
не доказывает реальную доставку за 60 s. Контракт heartbeat не доказывает
обнаружение потери telemetry за 120 s. Полная campaign должна это измерить.

T29/M23 остаются unchecked. M18 должен последним объединить все обязательные
gates на одном candidate; предыдущие M13/M15 runs на другом source не объявляются
новой общей acceptance. Independent M22, остальные R1 blockers и ограничения
сохраняются.
