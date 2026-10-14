# Promotion ledger: evidence 2026-10-14

Scope: T13 admission + durable SQL journal component. [Контракт](../promotion-ledger.md), [PB-21/RB-40/RB-41](../operations/promotion-ledger-troubleshooting.md). Full M10, scoped controller, lease, serving и полный recovery ещё не приняты.

## Проверенное локально

После snapshot correction объединённые 106 methods pass на Windows: release policy/bundle/authorization, lineage, material bundle, promotion request/admission и CLI boundary, включая проверку snapshot scope. Promotion Python core: 97 statements/32 branches, 100%; это **не SQL branch coverage** и не покрытие всего native orchestrator. Ruff check/format и документационные проверки прошли: 304 files, 110 Markdown documents, 765 local links.

Положительные admission tests используют настоящие подписи и заменённый SQL transport. Missing assurance проверяется до любого CAS write. Воспроизведена и исправлена недетерминированность retry из-за времени новой попытки. Reviewer-agent нашёл гонку legacy backup; проверка перенесена также внутрь экспортируемого snapshot. Self/agent review не является human challenge M22.

Docker Linux Engine локально недоступен: pipe dockerDesktopLinuxEngine отсутствует. Не запускались working Docker/SQL/cluster, не выполнялись reset/prune. Наличие SQL script и unit tests не доказывает его исполнение; native результаты будут добавлены после завершённого clean-checkout CI.

## Native scope

Workflow устанавливает ledger только после прежней storage/recovery qualification, в owned disposable state. Native campaign использует controlled transport payloads, проверяет настоящие SQL locks/grants/transactions и restart. Реальному candidate без assurance новый SDK обязан отказать без записи; эта отдельная проверка добавлена в release_native. Ни один native ML candidate не получает сфабрикованные M01-M23 pass.

Текущий backup намеренно отказывает при наличии ledger; полное согласованное восстановление ещё не реализовано. Это deployment limitation, не пройденный M17. Открытые image/poisoning/evasion failures сохраняются.
