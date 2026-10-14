# Online trust evidence: 2026-10-14

Scope: T14 current authority, lease и T13 SDK admission. [ADR 0029](../decisions/0029-online-trust.md), [PB-23/RB-44/RB-45](../operations/trust-troubleshooting.md). Не полная M11/M12 приёмка или production trust infrastructure.

## Controlled checks

TDD сначала получил ImportError отсутствующих trust/authority modules и отказ старого SDK на новом trust argument. Fresh-context same-model reviewer воспроизвёл unrevocation после сброса кеша и продление server expiry на задержку запроса. Три regression tests сначала failed, после исправления прошли. История revocations хранится независимо от lease, root revoke защёлкивается, server expiry привязан к началу запроса. Cross-model review пропущен в автономном режиме, внешние model CLI не запускались.

Локально 23 trust/authority unittest methods pass. Trust core 117 statements/48 branches, authority Python 126 statements/50 branches, 100% coverage. Это Python coverage при controlled SQL transport, не покрытие SQL engine и не подтверждение live TLS. Отдельно 18 promotion/request methods pass, 116 statements/36 branches, 100%; добавлены missing trust, environment mismatch, ancestor revocation и потеря trust после journal commit. Три runner CLI/redaction methods pass. Объединённая adjacent suite: **156 methods pass** за 12.871 s на Windows. Ruff check и format check прошли для 175 Python files; docs integrity прошла, внешние URLs/runtime ею не проверяются. Native CI зафиксирован отдельно.

Второй bounded review выявил неполный revocation scope: proposal envelope, source approval и raw split digests не проверялись. Расширенный тест независимо воспроизвёл 10 пропусков, без накопления ранее отозванных subjects между subtests. Добавлены также policy/assurance/approval envelopes, lineage ID и source fingerprint. Все 10 отказов теперь возникают до CAS/journal writes, positive idempotent admission проходит. Reviewer повторно подтвердил обе группы fixes; SQL native им не запускался.

Docker Engine локально недоступен через dockerDesktopLinuxEngine named pipe. Working Docker/WSL/SQL/cluster не перезапускались. Native runner выполнен в свежем CI с отдельным owned PostgreSQL workspace/CA. Реальный outage описан далее, он не подменён ускоренным fake-clock экспериментом.

## Проверенный native SQL component

[Storage run 38619009002](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619009002) завершился success на `214cc3cb728ab05d21bae50965955bf45f24a1f1`. Campaign **dbdfcecb0c0f4fad8fa0c0ae72af784b**, **45 native checks pass**, все 45 case labels уникальны, source_dirty=false. Интервал 2026-10-14 18:56:43.904025 - 18:57:53.512442 UTC.

- Source fingerprint: `cdcb47df302b2edf407c93e0ba6b26d11a697645860302bdbf12ca744719ae97`.
- Native runner SHA-256: `00b1f0aa06a71fc95eb6941e9d0b43728bb49437b4825bc5592cf5e799e57a74`.
- Trust migration v1 SHA-256: `dda68e8cc35bf4b8f555cf0716f9b9c9d860296b20b5cd82e2df8de5e09902b7`.
- От последней успешно завершённой online проверки: последний разрешённый check **59.990946574 s**, deadline **59.991310564 s**, первый отказ **59.992019191 s**. SQL roundtrip уже вычтен из 60-second budget. Измерена работа настоящего клиента после остановки authority container, а не HTTP latency или full serving SLO.

Actual PostgreSQL/mTLS подтвердили отдельные workspace/CA, TLS 1.3, одинаковый документ у serving/promoter, immutable current retry, запрет direct DELETE/TRUNCATE для шести roles и запрет чтения четырём non-consumer roles. Отзыв model/key, foreign signer, old policy/document, unrevocation и conflicting versions отвергнуты; пара concurrent updates дала один commit. Version/revocations пережили restart БД. Независимый subject остался разрешённым, root revocation отменила lease без cached fallback.

Backup v1/v2 на authority workspace отказал до dump с ожидаемым snapshot error. Fresh consumer instance без online read не имеет lease; это проверка нового экземпляра, не отдельного OS-процесса. После восстановления service требовался fresh read. Созданные container/network/volume удалены по ownership. Исходные model CAS fingerprints, container identity, Git revision/fingerprint остались прежними.

В этом же storage run regression прошла: M03 431, M07 97, promotion journal 108 и combined promotion recovery 36 checks. Полный результат остаётся `scope=online-trust-component-not-full-M11`, `full_M11=inconclusive`, `release_ready=false`. Документационный commit с этой записью не является отдельным runtime replay.

## CI regression и ограничения наблюдения

Developer: 74 checks и три fresh trainings, max probability difference=0.0, ONNX parity error=2.086162567138672e-07. Tracking M06: 18 cases pass, завершён 2026-10-14 19:00:57.168117 UTC. Независимые image/research workflows остаются обязательными блокирующими проверками, не waived этим trust increment.

Image audit исполнил все четыре scans и получил fail. Critical/High/Unknown: worker 0/56/0, storage 9/115/19, worker-candidate 0/55/0, storage-candidate 1/85/0. Poisoning campaign `70423809bb69440694112354cca5df20`: integrity pass, 35 cases/251 files, 10 violations, 0 inconclusive. Baseline evasion `3a3128b5beec4202849a62b092f84ee0`: execution complete/reconciliation pass, source_dirty=false, recall drop=0.07183673469387755 >0.05. Paired campaign `be2760f46354497c982d0051adc7cfe3`: execution complete/reconciliation pass, source_dirty=false; candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611, все >0.05. Пороги, seeds и attacker budgets не менялись.

При наблюдении GitHub CLI несколько GET/watch завершились TLS handshake timeout. Это отказ локального наблюдателя, не evidence завершения CI. Повторные read-only запросы к тем же run/job IDs через подключённый GitHub подтвердили tracking success, poisoning failure и продолжающийся Kubernetes run; workflows не перезапускались, TLS verification не отключалась. Затем тот же Kubernetes job `116041374165` завершился success: **M20 723 cases pass**, 2026-10-14 19:07:56.961834 UTC; **M21 122 cases pass**, source_dirty=false, 19:10:18.797963 UTC. Локальный CLI transport не объявляется исправленным.

## Итоговая CI-матрица

GitHub API подтвердил все десять terminal runs на точном `214cc3cb728ab05d21bae50965955bf45f24a1f1`: **6 success / 4 failure**. Это не общий green CI и не разрешение release.

| Workflow | Run | Итог |
| --- | --- | --- |
| Storage role and TLS qualification | [38619009002](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619009002) | success |
| Developer runtime qualification | [38619008766](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008766) | success |
| MLflow tracking compatibility and private service | [38619008577](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008577) | success |
| Kubernetes isolation qualification | [38619008900](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008900) | success |
| Intake evidence contracts | [38619008654](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008654) | success |
| Documentation integrity | [38619008565](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008565) | success |
| Worker and storage image audit | [38619008748](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008748) | failure |
| Frozen poisoning research matrix | [38619008649](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008649) | failure |
| Frozen evasion and domain guard | [38619008545](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008545) | failure |
| Paired robust training research | [38619008721](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38619008721) | failure |

## Не завершено

HTTP inference endpoint и проверка lease перед/после каждого ML response, scoped promotion controller, current deployed inventory, rollback authorization, root rotation и recovery самой authority остаются открытыми. Controlled all-pass release fixtures не становятся ML approvals; native subjects - контрольные digests, не принятые модели. Image audit и statistical robustness failures не обходятся. R1 и полный M11 не приняты.
