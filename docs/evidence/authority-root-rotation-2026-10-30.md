# T14: плановая ротация ключа online trust authority

Дата: 2026-10-30 МСК. Неделя 8 «Bundle, approval и отзыв доверия», T14 «Trust lifecycle», CP3/R1-B04. Код: `d18c361fda5c5d6cb261bfda2a89b02901adad58`, протокол: `e6678e5`.

Статус: **плановая ротация проверена в hosted Linux, обычный serving восстановлен после явной смены config**. [Запуск 40959762631](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40959762631), job `123749151197`, conclusion success. Source, reports, history, snapshots и cleanup проверены отдельно после завершения. Это controlled qualification, не полный M11 или R1.

## Требование и реализация

Сменить ещё доверенный ключ подписания online trust-policy без сброса истории, номеров версий, отозванных артефактов и ключей. Release approval, release-signing roots и модель не изменяются этой операцией. Пропавший или уже отозванный старый ключ не разрешает восстановление по этой процедуре.

- [Протокол](../../mlsecops/trust_rotation.py): один intent подписывается старым и новым ключами в DSSE domain `trust-root-rotation`. DSSE связывает тип подписываемого сообщения с его байтами. Ed25519 проверяет обе подписи; SHA-256 связывает intent с точными previous/next envelopes.
- Public keys закрепляет оператор отдельно от package. Проверяются environment, непрерывные versions, окно до 600 s, действительность обеих policies и точное сохранение revocations. Старый ключ добавляется в revoked keys.
- [Хранилище](../../mlsecops/trust_root_store.py): явная additive migration 2 добавляет receipt table. Исходная migration 1 сохраняется побайтно. PostgreSQL transaction с advisory lock проверяет current root/version/digest/environment и clock перед записью next document, нового root и подписанного package.
- Readback сверяет конечный root/document и сохранённые bytes receipt. Неизвестный результат не объявляется успехом. Точный действующий retry не добавляет записей; истёкший или уже вытесненный переход не применяется повторно.
- Старый serving config не принимает новый ключ из ответа. Оператор отдельно меняет public pin и minimum trust version, после чего обычный Reader снова проверяет bundle, signatures, policy и revocations.

Полный контракт и trade-offs: [ADR 0053](../decisions/0053-authority-root-rotation.md). Диагностика, применение и восстановление: [ранбук и плейбук](../operations/authority-root-rotation.md).

## Локальная проверка

43 targeted test methods прошли. Coverage проверен для четырёх файлов:

| Файл | Statements | Branches | Покрытие обоих видов |
| --- | ---: | ---: | ---: |
| `mlsecops/trust_authority.py` | 140 | 52 | 100% |
| `mlsecops/trust_root_store.py` | 73 | 28 | 100% |
| `mlsecops/trust_rotation.py` | 37 | 10 | 100% |
| `scripts/kube_root_rotation.py` | 76 | 18 | 100% |
| Всего | 326 | 108 | 100% |

Ещё 51 смежный method прошёл для source lock, promotion controller, trust probe/native coordinator и serving/rollback orchestration. Эти проверки используют реальные криптографические операции и mocked infrastructure transport. Локальные Docker, WSL, Kubernetes и SQL не запускались.

Негативные проверки включают missing/mismatched signatures, неверные public pins, schema/types/size, timestamps, history/reference mismatch, попытку снять отзыв, повторное использование root, незнакомую migration, неизвестный результат commit и ошибочные native reports.

## Подтверждённый native результат

В [native coordinator](../../scripts/kube_root_rotation.py) перед сменой root добавляются synthetic revoked artifact и key. Проверяется migration retry; затем действующими подписями формируются неверная previous reference и попытка снять artifact revocation. Отдельно проверяется отсутствие acceptance signature.

Разрешённый переход сохранил прежнюю history prefix, policy, CA, PVC и ownership identity и добавил ровно один document и один rotation record. Trust version увеличилась с 2 до 3. Точный retry сохранил состояние. Update старым ключом отказан. Полный model/promotion snapshot остался прежним.

После перехода [обычный serving CLI](../../scripts/kube_serving_native.py) со старым config дал `trust_authority_missing_or_foreign`: ready/predict 503, worker не запущен, **14 cold checks**. Явно обновлённый config загрузил тот же bundle/model и прошёл **22 serving checks**. Golden maximum error `7.583384781240099e-08`, идентичен исходному и восстановленному A, меньше допуска `1e-6`.

| Отрицательный сценарий | Точная причина | Состояние |
| --- | --- | --- |
| Две валидные подписи, неверная previous reference | `rotation_head_changed` | Snapshot неизменен |
| Отсутствует подпись нового владельца | `invalid_signature_count` | Snapshot неизменен |
| Две валидные подписи, попытка снять artifact revocation | `trust_update_conflict_or_unrevocation` | Snapshot неизменен |
| Обычный update старым ключом после перехода | `untrusted_key` | Snapshot неизменен |

В CI выполнены **502 test method executions, 0 skips**. Это число выполнений, не число уникальных сценариев: группы повторно используют некоторые methods. Указанные выше четыре файла имеют 326 statements / 108 branches, 100% по обоим видам покрытия. Audit regression тоже прошла: `contracts.py` 146/50, `key_files.py` 47/14, `tracking_sql_probe.py` 33/12, каждый 100%; cross-UID private-file canary 6/6 с ожидаемым отчётом.

Прежний whole-bundle rollback повторно проверен: две разные модели A -> B -> A, sequence 1 -> 2 -> 3, по 22 ordinary serving checks; три history refusals, точный retry, revoked target refusal и ожидаемые +1 event / +2 release objects. Ротация после rollback не изменила model/promotion storage.

Actual-candidate regression содержит **900 typed assertions с повторами**: base 193, outage 243, blackhole 179, policy/replay 131, model revoke 78, key revoke 70, final cold 6. Проверены пять clock/signature faults с 25 отказами, signed replay ещё действительного v7 после v9, отдельные model/key authority и неизменный полный snapshot. Primary versions при terminal revokes: 9/9/10, model authority: 1/2/2.

| Actual-candidate fault | Первый полный HTTP 503 |
| --- | ---: |
| Model revoke | 3.968655623 s |
| Key revoke | 3.962934016 s |
| Trust outage | 59.785249005 s |
| TCP blackhole | 13.340399969 s |
| Policy change | 4.767035248 s |

Actual production promotion сохранил отказ `release_assurance_required`; `release_ready=false`. Смена root не выдала отсутствующее assurance. Native mutation использует Python operator API; CLI routing/confirmation проверены контрактными tests, отдельный native запуск mutation через CLI здесь не заявляется.

Source fingerprint пересчитан по **142 Git blobs**. Два экземпляра полного native report совпали. Native interval: `2026-10-29T21:43:26.429041Z` - `2026-10-29T21:58:52.293973Z`; job завершён `2026-10-29T21:59:00Z`. Остановка owned source SQL и удаление owned disposable cluster завершены success; финальная проверка не обнаружила kind cluster.

| Привязка | SHA-256 |
| --- | --- |
| Source fingerprint | `0312588cfa21ba42377baa9c91712d961d312142aeaea4f1a3daa8c135f881a9` |
| Worker image | `ac0a3080918e3bb34f5f801b5f8a1a978a7a3068d491c540f96081bc254761df` |
| Full native report, canonical JSON + LF | `d2f5f657e8873128b037eb02eb8215c277cd29566ae973dce233bc29b4d66067` |
| Root rotation subsection, canonical JSON + LF | `107c4e71046540141a6c664c195099dc3db82ecbfca1d823783a61e0ca5cfc20` |
| Model/promotion snapshot во время ротации, canonical JSON без LF | `dafdd3232b604cbef53c65283f2acc7888ec0ecbd98f4e29804373e225843d43` |
| Migration 1, неизменные bytes | `dda68e8cc35bf4b8f555cf0716f9b9c9d860296b20b5cd82e2df8de5e09902b7` |
| Migration 2 | `e2b5f5a163a610823ef2f04b147cbfe2b0e8c3f91fd7d138623b8458bf7b2f42` |
| Old root fingerprint | `7088dfacaa33dea8178e90337aec537e2a46d9ab184842a3906a22c547bd7d14` |
| New root fingerprint | `7f03071edf111c045cc3a1de57a123eec183a7fe889606faddfeecb3a9ab5f11` |
| Actual full CAS/promotion snapshot | `15e830211e22e3d78969754f1341e06ef99e33be97cc61d6979013f661acccb6` |

## Повторение из чистого checkout

Локальная проверка контрактов не требует инфраструктуры:

```powershell
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git trusted-mlsecops-root-rotation
git -C trusted-mlsecops-root-rotation checkout --detach d18c361fda5c5d6cb261bfda2a89b02901adad58
Set-Location trusted-mlsecops-root-rotation
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.trust_rotation_qualification scripts.trust_root_store_qualification scripts.trust_authority_qualification scripts.trust_qualification scripts.kube_root_rotation_qualification
```

Инструкция проверена на новой Windows в отдельном fresh GitHub clone commit `d18c361`: Python 3.12.15, `uv sync --locked --no-build`, 64 установленных пакета, 43 tests / 0 skips / OK за 0.682 s. `git status --porcelain` пуст до и после тестов. Между cache и checkout `uv` использовал копирование вместо hardlinks; это предупреждение о способе установки, не пропуск зависимости или проверки. Инфраструктура при этом не запускалась.

Полная native последовательность и coverage requirements закреплены в [kubernetes-serving.yml](../../.github/workflows/kubernetes-serving.yml) этого commit. Инфраструктурный повтор выполняется только через существующий workflow на разрешённом disposable GitHub-hosted runner, с branch/tag на проверяемом commit. Новый run получает собственные synthetic keys/timestamps: report hashes сравниваются внутри run, а не требуют равенства между разными runs. Обязательны source revision/fingerprint, image ID, точные отказы, неизменность snapshots и конечный cleanup.

## Ограничения

- Это плановая смена online trust-policy root при наличии действительного старого ключа. Emergency root recovery и release-signing key rotation этим протоколом не закрываются.
- В lab обе подписи формируются тестовым оператором. Это не доказательство независимости людей, защищённости production KMS или совместимости с TUF.
- Отдельный live root-change HTTP trace и native concurrent-writer сценарий ещё не проверены. Cold refusal и новый serving процесс не заменяют измерение остановки уже работающего процесса.
- `rotated-not-activated` не является release approval. Actual production release по-прежнему должен отказать без обязательной assurance.
- Полные T14/M11/M16/M18/R1 не приняты. M22 independent challenges остаются 0/2; системные image findings и остальные обязательные gates сохраняются.
- Основной внешний `security-review.ru.md` отсутствует в полученном supplemental package. Исправленные U01-U03 и этот trust increment не заменяют независимые ML challenge cases.
- Raw logs, внешний архив, private key material и локальные diagnostics не публикуются в Git. GitHub Actions logs публичны, сценарий использует синтетические данные.
