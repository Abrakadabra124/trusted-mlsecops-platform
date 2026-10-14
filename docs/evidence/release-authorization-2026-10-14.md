# Release authorization: evidence 2026-10-14

Scope: complete proposal materials и отдельный authorization contract для T13, не полный M10. [Контракт](../release-authorization.md), [PB-20](../operations/release-authorization-troubleshooting.md).

## Controlled результаты

После review на Windows 21 methods проверяют policy/bundle/authorization, ещё 8 проверяют native runner через controlled transport. Реальные Ed25519 signatures и digest reconciliation, но SQL заменён тестовым transport. Security core: 229 statements, 94 branches, 100% coverage. Runner: 100 statements, 16 branches, 98%; module entrypoint не покрыт этой suite. Coverage не доказывает отсутствие всех ошибок.

Проверены decoded-key separation, внешние policy/runtime pins, все отсутствующие M-gates, failed/inconclusive/skipped reports, true вместо integer schema/exit code, subject/environment/action/sequence/digest mismatches, сроки, полный material readback, idempotency, interrupted publication, missing/swapped documents и ложный status=pass при несовпадающих outcomes. Failed signed model quality не переопределяется all-pass fixture reports. Positive authorization существует только в controlled tests, state=authorized-not-activated/release_ready=false.

Два регрессионных дефекта воспроизведены до исправления: несовместимые case fields/ID и assurance раньше начала policy. Причины и безопасные действия в RB-38. Reviewer-agent - дополнительный source review, не независимый human challenge M22.

Adjacent regression на Windows: объединённые 85 methods pass (новые 26 плюс material bundle, candidate lineage и оба прежних native runner contracts). Ruff check/format прошли. Docs check обнаружил неверную локальную ссылку runbook на storage.md; исправлена на существующий storage-recovery.md перед публикацией. Рабочие runtime services эта suite не использует.

Второй source review обнаружил незаписанные derived materials и отсутствие прямого SQL write-denial probe. Оба дефекта воспроизведены до исправления; теперь 20 CAS objects/9 documents и отдельный SQL 42501 check. Дополнительно проверена длина каждого загруженного SQL material до накопления полного package. Ранний ownership failure сохраняет прежнее evidence намеренно: запись в неподтверждённый state запрещена, nonzero exit делает старый pass непригодным для текущего решения. Это documented trade-off, не попытка переписать чужую среду.

## Native и CI

Первый [storage CI на 9d3c965](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38597308956) завершился success. Campaign f59150337334430db2a71a9c2ca48810, source_dirty=false, 10 checks, 17 objects/6 documents, model SHA-256 09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f, release_ready=false. Это исторический результат до correction CAS closure/SQL probe, не доказательство новых 20 objects/11 checks.

После corrections объединённые **88 methods pass** на Windows; Ruff и docs integrity pass. [Clean-checkout storage CI на cd4c6fd](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571974) завершился success: **11 native checks, 20 CAS objects, 9 supplemental documents**, source_dirty=false, full_M10=inconclusive, release_ready=false. Рабочая локальная БД не использовалась для повторения.

| Binding | Значение |
| --- | --- |
| Source revision | cd4c6fd06a5803abef77a4c9ac2ae47b3d4972b5 |
| Campaign | c86e8f176b3c4a0a9d620c4be2beb500 |
| Worker image | sha256:8f2b6a27ec7e5b8ea95b2a4c1bf4073e6ada51e6ebe8f4593b133bd8fe9986d7 |
| Source fingerprint | a7cba338b6bb6f6df93bc01d55ec407275fa04e83b878c2f13a54fb43d4c2b42 |
| Native runner SHA-256 | bee280ca5b164bfcfa62c18d7fc00857204e0b4c68b3f239917ed9dfe2d61596 |
| Model SHA-256 | 09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f |
| Proposal envelope reference | 0ef91b37c923a2c6e133ab0e6e64d7495f709ca8f76e40d740d0e627881b66d4 |
| Release subject SHA-256 | 813b9968975c63d43e3d43614be30009b35cd368ca1bf9bc8128892b89ec450d |
| Policy SHA-256 | 10529a24599cd40b0fffc9af28d67282b002a893aaf871b64c427e6bcf32a0bb |

Native interval: 2026-10-14 16:32:08.044671 - 16:32:09.528454 UTC. В этом же завершённом workflow M03: 431 cases pass, M07: 97 cases pass, backup/restore и intake denials прошли. Текущий source/runner fingerprint сверены с checkout. Другой запуск закономерно имеет другие lab keys, campaign ID и timestamps: воспроизводимая проверка не означает одинаковые signed envelopes между независимыми лабораториями.

[Developer CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571980): 74 checks, 3 обучения, max probability difference=0.0, max parity error=2.086162567138672e-07, full acceptance inconclusive. [Baseline evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598572062) и [paired mitigation](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571907) terminal failure: execution complete/primary reconciliation pass/source_dirty=false, прежние recall-drop violations воспроизведены. Они не превращены в approved release ради положительной демонстрации.

## Все workflows на cd4c6fd завершены

| Workflow | Результат | Проверенное evidence |
| --- | --- | --- |
| [Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571974) | success | Release proposal 11 checks; M03 431 и M07 97 cases pass |
| [Developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571980) | success | 74 component checks / 3 runs |
| [Tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598572027) | success | M06 18 cases pass |
| [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598572011) | success | M20 723 и M21 122 cases pass |
| [Intake contracts](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571940) | success | Контрактные проверки intake evidence |
| [Docs](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598572007) | success | Documentation integrity, не runtime acceptance |
| [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571979) | failure | Все четыре scans исполнились; severity thresholds нарушены |
| [Poisoning](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571969) | failure | 35 cases / 251 primary files, integrity pass, 10 statistical violations |
| [Baseline evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598572062) | failure | 8 workers; recall drop 0.07183673469387755 >0.05 |
| [Paired mitigation](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38598571907) | failure | 14 workers; candidate recall drop 0.052245/0.062241/0.061433 >0.05 |

Итого **6 success / 4 failure**, ничего не skipped вместо обязательного gate. Kubernetes M21 завершён 2026-10-14 16:46:35.330423 UTC. Предыдущий Kubernetes run на 9d3c965 отменён concurrency policy после публикации correction; он не считается проверкой, его заменяет завершённый run на cd4c6fd.

Audit Critical/High/Unknown counts: worker 0/56/0, storage 9/115/19, worker-candidate 0/55/0, storage-candidate 1/85/0. Это findings scanner database на дату запуска, не все доказанно exploitable paths и не waiver. Poisoning campaign a5aa070d6f864dbb91b5146786a4246b: 0 inconclusive scenarios, но status=fail. Paired campaign 0511be3df6534d9a8c3a2b0e049e40f7: по 12 actual abstentions; модель не adopted. Полные private logs не публикуются; здесь только очищенные агрегаты и bindings.

Рабочая локальная SQL/cluster среда не изменялась. Не создано фиктивных all-pass reports для native candidate. Существующие image, poisoning и evasion blockers сохраняются; M10/M11/M12 и общий R1 не закрыты.
