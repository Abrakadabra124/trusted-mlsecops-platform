# Promotion ledger: evidence 2026-10-14

Scope: T13 admission + durable SQL journal component. [Контракт](../promotion-ledger.md), [PB-21/RB-40/RB-41](../operations/promotion-ledger-troubleshooting.md). Full M10, scoped controller, lease, serving и полный recovery ещё не приняты.

## Проверенное локально

После snapshot correction объединённые 106 methods pass на Windows: release policy/bundle/authorization, lineage, material bundle, promotion request/admission и CLI boundary, включая проверку snapshot scope. Promotion Python core: 97 statements/32 branches, 100%; это **не SQL branch coverage** и не покрытие всего native orchestrator. Ruff check/format и документационные проверки прошли: 304 files, 110 Markdown documents, 765 local links.

Положительные admission tests используют настоящие подписи и заменённый SQL transport. Missing assurance проверяется до любого CAS write. Воспроизведена и исправлена недетерминированность retry из-за времени новой попытки. Reviewer-agent нашёл гонку legacy backup; проверка перенесена также внутрь экспортируемого snapshot. Self/agent review не является human challenge M22.

Docker Linux Engine локально недоступен: pipe dockerDesktopLinuxEngine отсутствует. Не запускались working Docker/SQL/cluster, не выполнялись reset/prune. Native SQL проверен отдельно в fresh GitHub Actions runner, не на рабочей БД пользователя.

## Native scope

Workflow устанавливает ledger только после прежней storage/recovery qualification, в owned disposable state. Native campaign использует controlled transport payloads, проверяет настоящие SQL locks/grants/transactions и restart. Реальному candidate без assurance новый SDK обязан отказать без записи; эта отдельная проверка добавлена в release_native. Ни один native ML candidate не получает сфабрикованные M01-M23 pass.

Текущий backup намеренно отказывает при наличии ledger; полное согласованное восстановление ещё не реализовано. Это deployment limitation, не пройденный M17. Открытые image/poisoning/evasion failures сохраняются.

## Проверенный native результат

[Storage run 38605589120](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589120) завершился success на `fab72946a0153de206a8ce8259f7cd1728d2107a`. Promotion campaign `69d3f9738a564e22972c1b425288a94f`: **108 checks pass**, durable sequence=3. Интервал 2026-10-14 17:22:23.616652 - 17:22:29.431379 UTC. Подтверждены реальные concurrent transactions, наблюдаемый row-lock wait и последующий expiry denial, запреты DML, transaction rollback, обе backup scope checks и сохранение head/idempotency после service restart. Это restart, не power-loss recovery.

- Source fingerprint: `a9540b3f7108056142a6c6fb7e52d3967dab760a8fff94317543bfd88fbcf3cf`.
- Migration SHA-256: `d6378c6fbf34cbe6fe527f7ea87499bb205309654a3acb3b1e3ff2d3161e7304`.
- Native runner SHA-256 из исходного commit: `f1e8fe9dbd3a4f015f0c6f6f4804fa8fe0c5578ab019b5741fd35034d8f955cf`.
- Scope: `promotion-ledger-native-SQL-controlled-payloads-not-full-M10`; `full_M10=inconclusive`, `release_ready=false`. Контролируемые SQL requests не являются одобренными ML-моделями.

В том же run реальный release candidate прошёл **12 native checks**, 20 immutable objects и 9 документов. Дополнительный SDK admission отклонил missing assurance до записи. Campaign `780758aefcb940d4828250f03997e150`, source_dirty=false, интервал 17:21:05.433200 - 17:21:06.766147 UTC:

- Worker image: `sha256:0b820871506fbc798f49f11ec358bcb95e1b3bac078f6fffa3ee7922cffc4743`.
- Model SHA-256: `b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634`.
- Proposal reference: `c7d33258e70dcc40826a419a1da4ef09e6800838b034f32257c7ccc3e20bb63d`.
- Subject SHA-256: `91eca7ca1cbacb4b88f539180f8017b5f42def9f75eb38914c6afda93f623395`.
- Policy SHA-256: `b1b32f938367ab32ea9d12db9976a27eb949ec50bc9522dd08335a32dc52c013`.
- Release runner SHA-256: `1be5ade67d79b1830c969e4687d76bdc5e93dbb675f749d43a02f3d1aa31cebb`.

M03 431 cases, M07 97 cases и intake denial 25 checks pass. Прежний CAS recovery **до установки promotion ledger**: 433 checks, 1 000 golden rows, max error=0.0; storage restore 3.432683 s. Эти результаты не подтверждают backup нового journal: после установки отдельно проверяется отказ старого exporter.

[Developer run 38605589060](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589060) success: 74 checks, 3 fresh trainings, maximum probability difference=0.0, sklearn/ONNX maximum parity error=2.086162567138672e-07. Один зелёный storage run не означает общий green CI или R1 acceptance.

## Завершённая CI matrix

Все 10 workflows на `fab7294` завершились: **6 success / 4 failure**, без подмены обязательных проверок skipped. Runtime и statistical/security outcomes разделены.

| Workflow | Run | Итог и проверенный scope |
|---|---|---|
| Storage | [38605589120](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589120) | success; promotion 108, release 12, M03 431, M07 97 |
| Developer | [38605589060](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589060) | success; 74 checks, 3 trainings |
| Tracking | [38605589143](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589143) | success; M06 18 cases |
| Kubernetes | [38605588985](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605588985) | success; M20 723 и M21 122 cases |
| Intake contracts | [38605589159](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589159) | success; controlled contracts, не отдельный full M21 |
| Documentation | [38605589088](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589088) | success; документационная целостность, не runtime |
| Image audit | [38605589286](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589286) | failure; все четыре scan_executed=true, findings сохраняются |
| Poisoning | [38605589333](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589333) | failure; execution complete, 10 violating scenarios, 0 inconclusive |
| Baseline evasion | [38605589190](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589190) | failure; execution complete, primary reconciliation pass, recall drop выше 0.05 |
| Paired robustness | [38605589123](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38605589123) | failure; execution complete, primary reconciliation pass, candidate не принят |

M20 завершён 2026-10-14 17:33:04.117554 UTC, M21 - 17:35:25.057177 UTC, на том же source revision. Для M21 source_dirty=false. Наличие этих passes не закрывает более широкие lifecycle tasks или общий M18.

Image Critical/High/Unknown counts: worker **0/56/0**, storage **9/115/19**, worker-candidate **0/55/0**, storage-candidate **1/85/0**. Compatibility pass не стал adoption; исключения severity не добавлялись.

Poisoning campaign `b1741da8fe524cb2bdcd99257b2f1c6a`: 35 cases/251 primary files сверены, evidence_integrity=pass. Это целостность доказательств, **не устойчивость к poisoning**: 10 violations сохраняют fail.

Baseline campaign `4933b89ed3054ce6b47fe87811650bad`: 8 worker executions, 12 outside-support abstentions, recall drop=0.07183673469387755 при maximum=0.05. Paired campaign `351d22dc3fa84eae9eab59ed7e79b232`: 14 executions, по 12 abstentions на arm; candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 на трёх frozen probes. Ни thresholds, ни probes не менялись ради успешного статуса.

Raw logs сохранены локально вне Git в `.runtime`. Публично размещены только очищенные агрегаты и ссылки на CI. Полный R1, T13/M10, M11 и M17 остаются открытыми; следующий связанный increment должен устранить ограничение согласованного backup/restore journal, а не выключить guard.
