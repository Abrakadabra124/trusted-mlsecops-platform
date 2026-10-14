# Online trust evidence: 2026-10-14

Scope: T14 current authority, lease и T13 SDK admission. [ADR 0029](../decisions/0029-online-trust.md), [PB-23/RB-44/RB-45](../operations/trust-troubleshooting.md). Не полная M11/M12 приёмка или production trust infrastructure.

## Controlled checks

TDD сначала получил ImportError отсутствующих trust/authority modules и отказ старого SDK на новом trust argument. Fresh-context same-model reviewer воспроизвёл unrevocation после сброса кеша и продление server expiry на задержку запроса. Три regression tests сначала failed, после исправления прошли. История revocations хранится независимо от lease, root revoke защёлкивается, server expiry привязан к началу запроса. Cross-model review пропущен в автономном режиме, внешние model CLI не запускались.

Локально 23 trust/authority unittest methods pass. Trust core 117 statements/48 branches, authority Python 126 statements/50 branches, 100% coverage. Это Python coverage при controlled SQL transport, не покрытие SQL engine и не подтверждение live TLS. Отдельно 18 promotion/request methods pass, 116 statements/36 branches, 100%; добавлены missing trust, environment mismatch, ancestor revocation и потеря trust после journal commit. Три runner CLI/redaction methods pass. Объединённая adjacent suite: **156 methods pass** за 12.871 s на Windows. Ruff check и format check прошли для 175 Python files; docs integrity прошла, внешние URLs/runtime ею не проверяются. Native CI будет зафиксирован отдельно.

Второй bounded review выявил неполный revocation scope: proposal envelope, source approval и raw split digests не проверялись. Расширенный тест независимо воспроизвёл 10 пропусков, без накопления ранее отозванных subjects между subtests. Добавлены также policy/assurance/approval envelopes, lineage ID и source fingerprint. Все 10 отказов теперь возникают до CAS/journal writes, positive idempotent admission проходит. Reviewer повторно подтвердил обе группы fixes; SQL native им не запускался.

Docker Engine локально недоступен через dockerDesktopLinuxEngine named pipe. Working Docker/WSL/SQL/cluster не перезапускались. Native runner предназначен для свежего CI и использует отдельный owned PostgreSQL workspace/CA. Планирует реальные SQL concurrency/roles/restart/revocation и 60-second outage, а не ускоренный fake-clock эксперимент.

## Не завершено

HTTP inference endpoint и проверка lease перед/после каждого ML response, scoped promotion controller, current deployed inventory, rollback authorization, root rotation и recovery самой authority остаются открытыми. Controlled all-pass release fixtures не становятся ML approvals; native subjects - контрольные digests, не принятые модели. Image audit и statistical robustness failures не обходятся. R1 и полный M11 не приняты.
