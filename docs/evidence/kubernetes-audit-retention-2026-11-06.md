# Kubernetes audit: сохранение и проверка после cleanup

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit», CP3/R1-B04.
Компонент **pass**; полный M13 и R1 остаются **inconclusive**.

Проверенный source: `bc8948cd0dc26cb210065ab85b41159a2abddc88`.
[GitHub Actions 42218670322](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42218670322),
job `127894956609`, завершён success. Campaign: 2026-11-06 12:34:11-12:38:18 UTC.
Public projection напечатана дважды и совпадает; source SHA и оба cleanup steps проверены отдельно.

## Требование и исправление

[Предыдущий компонент 90385fa](kubernetes-privacy-2026-11-06.md) уже проверял первичный audit packet на runner. Однако host-копия записывалась через замену файла, а после завершения child сверялись квитанции в памяти. Это не доказывало сохранность той же копии после удаления источника и не выполняло весь parent recheck из [ADR 0049](../decisions/0049-private-audit-evidence.md).

Использован существующий [audit_snapshot](../../mlsecops/audit_snapshot.py), без нового формата или криптографического протокола:

1. [Operator](../../scripts/kube_privacy_operator.py) проверяет packet, HTTP ledger и canaries, затем вызывает `store_packet` для нового `audit-evidence` directory. Создание однократное, без overwrite; owner/mode, symlink/hardlink, exclusive lease, bounded readback и fsync остаются прежними.
2. После успешного terminal состояния точного probe Pod оператор заново читает сохранённые bytes через `load_packet`. Pure verifier сверяет manifest/segments, HTTP outcomes, context и public export. Результат, включая digest всего packet, должен совпасть с прежней receipt.
3. После возврата `invoke`, то есть после завершения child и удаления owned probe Job/ConfigMaps, [candidate runner](../../scripts/kube_candidate_native.py) вызывает существующий [parent verifier](../../scripts/serving_output_native.py). Для Kubernetes передаются фиксированные пути текущей campaign вместо Docker-era default paths.
4. Parent заново загружает proposal и связанные материалы из CAS (content-addressed storage, хранилища с адресацией по digest), читает permit и публичный ключ из host directory. Проверяет подписи, разделение ключей, source/image/campaign/subject, срок permit и derivation lineage из primary materials. Контекст из самого audit packet не принимается как основание доверия.
5. Только после совпадения первичных bytes и результатов добавляются два cases: `post-exit-retained-packet-reverified` и `post-cleanup-primary-materials-reverified`. Публичная проекция содержит только фиксированные флаги, counters и source revision.

Candidate permit разрешает qualification inference, не production release. Actual production остаётся отказан с `release_assurance_required`; `release_ready=false` во всех успешных компонентных отчётах.

## Native результат

| Наблюдение | Проверенный результат |
| --- | --- |
| Cases | 28 pass, включая два новых parent rechecks |
| HTTP responses / audit events | 25 / 68 |
| Requests с candidate context | 8; это подмножество ответов, не общее число HTTP requests |
| Input canaries | 9 |
| Privacy matrix | 12 requests / 36 durable events |
| Approved metric series | 69 |
| Native stderr | 0 bytes |
| Worker | Exact complete terminal stream; owned cleanup подтверждён |
| PostgreSQL/trust | Два проверенных Running log windows |
| Private packet | Однократное host-сохранение; повторная проверка после exit и cleanup |
| Source SQL / disposable cluster | Остановлен / удалён, проверено конечное состояние |

## Проверка кода и воспроизведение

Linux CI выполнил **203 test method executions / 0 skips** четырьмя группами: 2 + 47 + 81 + 73. Включены реальные POSIX packet IO/lease/permission/fsync contracts, parent signature tests, regression старого Docker-parent verifier, Kubernetes orchestration contracts и privacy/audit regressions. Успешные mocked contracts не выдаются за live Kubernetes: native step указан отдельно выше.

Новые отрицательные проверки отклоняют отсутствующий или изменённый сохранённый packet, согласованную подмену child receipt, неверные proposal/permit и потерянные parent flags в public projection. Тест с явно неуспешным default Docker report доказывает, что Kubernetes parent использует собственную proposal текущей campaign. До реализации новые проверки завершались ошибками отсутствующего подключения snapshot и отсутствующих path arguments; после реализации они прошли.

Чистый detached checkout того же source получил **новое** virtual environment Python 3.12.15 и 64 packages через `uv sync --locked --no-build --python 3.12.15`. Проверены фактические пути interpreter/import и чистота Git до/после. Windows: **88 tests / 5.759 s + 73 tests / 11.385 s**, 161 total / 0 skips в этих двух группах. Локальные Docker/WSL/Kubernetes/SQL не запускались. Отдельный широкий локальный набор имел 5 POSIX-only skips; он не подменяет Linux IO validation.

Changed operator: **157/158 statements (99.37%)**, **55/56 branches (98.21%)**. Непокрытая ветвь - отказ unpinned service image, уже обязательный в runtime guard. Это coverage одного оператора, не всей оркестрации или M18.

Воспроизводить native через [workflow](../../.github/workflows/kubernetes-privacy.yml) на точном source и отдельном разрешённом disposable hosted runner. Локальные pure contracts:

```powershell
$env:PYTHONUTF8='1'
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.kube_privacy_operator_qualification scripts.audit_evidence_parent_qualification scripts.kube_privacy_native_qualification
```

Файловые гарантии POSIX запускать в Linux CI; Windows permission semantics этим набором не доказываются. Диагностика отказов и порядок безопасного повторения: [ранбук](../operations/kubernetes-privacy.md).

## Retention и оставшаяся работа

По ADR 0049 packet сохраняется **в пределах disposable campaign и жизни VM**. Этого хватает для parent recheck после child/source cleanup. Экспорт raw packet, credentials или log files из runner не выполняется. Утверждение, что внешний долговременный storage обязательно нужен для этого increment, было слишком широким; это отдельное production-требование с собственной retention/encryption/access/backup спецификацией.

Этот результат не даёт внешнему reviewer возможность восстановить приватный packet после уничтожения VM и не защищает от администратора host с возможностью заменить код и все файлы. Primary audit linkage не является differential privacy и не исключает membership inference.

Полный M13 требует normal CLI/configured lifecycle, всех обязательных output channels и service-container boundaries, композиции actual/controlled subjects и общей source-bound acceptance. Два service windows не доказывают полные lifecycles и init containers. M22 independent review 0/2, image findings, CP4/CP5 и M18/R1 остаются открытыми. Исторические зелёные runs разных commits не складываются в приёмку одного release.
